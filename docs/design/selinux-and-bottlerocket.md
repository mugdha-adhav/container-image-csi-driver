# SELinux and Bottlerocket: Design History and Current State

This document is the source of truth for how the driver handles SELinux on
Bottlerocket nodes. It covers the full history: why Bottlerocket required a
new mounting strategy, what SELinux problems surfaced after that change, how
they were addressed, and what the current open issue is.

---

## Chapter 1: Bottlerocket Incompatibility and the nsenter Solution

### Background

Before Bottlerocket support was added, the driver mounted container image
layers inside the CSI node plugin container and relied on
`mountPropagation: Bidirectional` to make those mounts visible to the host
kubelet.

### The Catch-22

Bottlerocket enforces a strict SELinux policy. This created an inescapable
conflict:

1. The driver needed `mountPropagation: Bidirectional` so mounts were visible
   to the host kubelet.
2. Kubernetes requires `privileged: true` for Bidirectional propagation — this
   is hardcoded in kubelet and cannot be bypassed through configuration.
3. When containerd runs a `privileged: true` container, it ignores any
   `seLinuxOptions` and assigns the `control_t` SELinux context instead.
4. Bottlerocket's SELinux policy blocks `control_t` containers from performing
   mount operations.

**Error observed on Bottlerocket:**
```
Warning Failed kubelet Error: failed to generate container spec:
failed to apply OCI options: relabel with "system_u:object_r:data_t:s0:c24,c483"
failed: lsetxattr: read-only file system
```

Traditional fixes (setting `privileged: false` with explicit capabilities and
SELinux options) were rejected at the Kubernetes API level before even reaching
the container runtime.

### Solution: nsenter-Based Mounting

Instead of mounting inside the container and propagating to the host, the
driver now mounts **directly in the host mount namespace** using `nsenter`:

```
Container → nsenter → Host Mount Namespace → mount created → kubelet sees immediately
```

This eliminates the dependency on bidirectional mount propagation entirely.
The approach is validated by Bottlerocket itself — the Bottlerocket admin
container's `sheltie` tool uses the same `nsenter` pattern to access the host.

**Changes made (containerd path only — CRI-O is unchanged):**

| Component | Before | After |
|---|---|---|
| Mount location | Inside container, propagated to host | Directly in host mount namespace via nsenter |
| Security context | `privileged: true` | `privileged: false` + SYS_ADMIN, SYS_CHROOT, SYS_PTRACE |
| Mount propagation | Bidirectional | HostToContainer |
| `/host/proc` volume | No | Yes (read-only, for nsenter) |
| `util-linux` package | No | Yes (provides `nsenter`) |

**Why containerd and CRI-O differ:**
- Containerd's API returns mount *specifications* (instructions). These can
  be executed in any namespace, making nsenter viable.
- CRI-O's API returns *already-mounted filesystems* in the container namespace.
  Source paths only exist there, so bidirectional propagation is required and
  the original implementation is preserved.

**Reference:** [`docs/design/nsenter-based-mounting-containerd.md`](nsenter-based-mounting-containerd.md)

---

## Chapter 2: SELinux Relabelling and Pod Startup Latency

### Problem Discovered After Bottlerocket Support

After the nsenter-based mounting was deployed on Bottlerocket nodes, a new
problem emerged: **significant pod startup latency on ephemeral volumes**.

When an overlay mount is created in the host namespace without an explicit
SELinux context label, the kernel performs **per-file SELinux relabelling** —
it walks every file in the overlay mount and assigns the correct label. For
container images with many files, this is a slow operation and directly
contributes to pod startup time.

### Root Cause

The nsenter mount commands did not pass a `context=` option. Without it, the
kernel falls back to per-file relabelling on every ephemeral volume mount on
SELinux-enforcing hosts (which Bottlerocket always is).

### Fix: Explicit `context=` Mount Option

The driver was updated to pass `context="system_u:object_r:container_file_t:s0"`
as a mount option when SELinux is enforcing on the host. This instructs the
kernel to treat all files in the mount as having that label, applied once at
mount time — no per-file walk occurs.

The implementation in `pkg/backend/containerd/containerd.go`:

- `isSELinuxEnforcing()` — reads `/sys/fs/selinux/enforce`; returns `true`
  only when SELinux is enforcing on the host.
- `selinuxContext()` — returns the context label to use. Reads from the
  `CSI_SELINUX_CONTEXT` environment variable, falling back to
  `system_u:object_r:container_file_t:s0`. The default aligns with the
  standard container file label used by containerd on Bottlerocket.
- In `mountInHostNamespace()`: when enforcing, appends
  `context="<label>"` to mount options if not already present.

The context label is configurable at deploy time via the Helm value
`selinuxContext` (which sets the `CSI_SELINUX_CONTEXT` env var on the node
plugin DaemonSet). If `selinuxContext` is not set in values, the env var is
not injected and the code falls back to the hardcoded default.

**Key constraint:** `context=` must be preserved. Removing it causes the
per-file relabelling problem to return.

### nsenter Batching

At the same time, the per-mount `nsenter` invocation (one `exec` per overlay
layer) was replaced with a **batched** approach: all mount commands for a
single volume are collected into a shell script and executed in a single
`nsenter` call. This further reduced mount latency by eliminating repeated
process spawning overhead for multi-layer images.

---

## Chapter 3: Open Issue — Bottlerocket 1.57.0 Mount Failure

### What Broke

Bottlerocket 1.57.0 upgraded the kernel from 6.1.161 to 6.1.163. On this
kernel, **overlay mounts that include a `context=` SELinux option fail**:

```
MountVolume.SetUp failed for volume "target": rpc error: code = Internal
desc = mount failed: exit status 32, output: mount: wrong fs type, bad option,
bad superblock on overlay
```

Pods with container image-backed ephemeral volumes get stuck in `Pending`
indefinitely on Bottlerocket 1.57.0 nodes.

### Scope

| Cluster | Bottlerocket version | Kernel | Affected |
|---|---|---|---|
| wrecker, granger | 1.57.0 | 6.1.163 | Yes |
| zonk, electro, ronan, janus | 1.56.0 | 6.1.161 | No |

### Why This Is Difficult to Fix

This issue sits at the intersection of two hard constraints:

1. **`context=` must be present** — removing it reintroduces per-file
   relabelling and pod startup latency on SELinux-enforcing nodes (Chapter 2).
2. **`context=` is now rejected** — kernel 6.1.163 on Bottlerocket 1.57.0
   rejects overlay mounts with `context=`, with `exit status 32`.

Bottlerocket 1.57.0 release notes confirm no intentional SELinux policy
changes were made, which isolates the regression to a behavioral change in
the kernel 6.1.163 overlay implementation itself.

The workaround currently in place is reverting affected clusters to
Bottlerocket 1.56.0. This is not a permanent solution.

**Upstream issue:** https://github.com/warm-metal/container-image-csi-driver/issues

---

## Summary of Constraints

Any future change to SELinux context handling must satisfy all of the
following:

| Constraint | Reason |
|---|---|
| Must work on Bottlerocket (SELinux enforcing) | Primary target environment |
| Must not require `privileged: true` | Breaks on Bottlerocket SELinux policy |
| Must not use bidirectional mount propagation without `privileged` | Rejected by kubelet API |
| Must not cause per-file relabelling | Causes pod startup latency on ephemeral volumes |
| Must work with kernel 6.1.163 (Bottlerocket 1.57.0) | Current regression |
| Must work with kernel 6.1.161 (Bottlerocket 1.56.0) | Must not regress working clusters |

---

## References

- [`docs/design/nsenter-based-mounting-containerd.md`](nsenter-based-mounting-containerd.md) — nsenter mounting design
- [`pkg/backend/containerd/containerd.go`](../../pkg/backend/containerd/containerd.go) — implementation
- [Bottlerocket Admin Container](https://github.com/bottlerocket-os/bottlerocket-admin-container/) — validates nsenter pattern
- [Bottlerocket Security Guidance](https://github.com/bottlerocket-os/bottlerocket/blob/develop/SECURITY_GUIDANCE.md) — SELinux labels and security model
- [Linux mount(8) — `context=` option](https://man7.org/linux/man-pages/man8/mount.8.html)
- [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
