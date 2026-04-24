# SELinux and Bottlerocket: Design History and Current State

This document is the source of truth for how the container-image-csi-driver
handles SELinux on Bottlerocket nodes. It covers the full history: why
Bottlerocket required a new mounting strategy, what SELinux problems surfaced
after that change, how they were addressed, the current open regression, and
a critical re-evaluation of whether the approach taken was correct.

**Table of Contents**

1. [Bottlerocket Incompatibility and the nsenter Solution](#chapter-1-bottlerocket-incompatibility-and-the-nsenter-solution)
2. [SELinux Relabelling and Pod Startup Latency](#chapter-2-selinux-relabelling-and-pod-startup-latency)
3. [Open Issue — Bottlerocket 1.57.0 Mount Failure](#chapter-3-open-issue--bottlerocket-1570-mount-failure)
4. [Research Findings — Root Cause Analysis](#chapter-4-research-findings--root-cause-analysis)
5. [How containerd Handles SELinux on Overlay](#chapter-5-how-containerd-handles-selinux-on-overlay--the-driver-is-the-outlier)
6. [How Other CSI Drivers Handle SELinux](#chapter-6-how-other-csi-drivers-handle-selinux)
7. [Kubernetes Upstream SELinux Evolution (KEP-1710)](#chapter-7-kubernetes-upstream-selinux-evolution-kep-1710)
8. [Critical Evaluation of Past Decisions](#chapter-8-critical-evaluation-of-past-decisions)
9. [Possible Fix Directions](#chapter-9-possible-fix-directions)
- [Summary of Constraints](#summary-of-constraints-updated)
- [Open Questions](#open-questions)
- [References](#references)

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

**Key constraint:** `context=` was added to prevent per-file relabelling.
However, Chapter 8 revisits whether this was the correct fix — the root
cause of relabelling and a better approach are discussed there.

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

Clusters running Bottlerocket 1.57.0 (kernel 6.1.163) are affected.
Clusters on Bottlerocket 1.56.0 (kernel 6.1.161) are not affected.

### Why This Is Difficult to Fix

This issue sits at the intersection of two hard constraints:

1. **`context=` must be present** — removing it reintroduces per-file
   relabelling and pod startup latency on SELinux-enforcing nodes (Chapter 2).
2. **`context=` is now rejected** — kernel 6.1.163 on Bottlerocket 1.57.0
   rejects overlay mounts with `context=`, with `exit status 32`.

Bottlerocket 1.57.0 release notes confirm no intentional SELinux policy
changes were made, which isolates the regression to a behavioral change in
the kernel 6.1.163 overlay implementation itself.

The workaround currently in place is pinning to Bottlerocket 1.56.0.
This is not a permanent solution.

**Upstream issue:** https://github.com/warm-metal/container-image-csi-driver/issues

---

## Chapter 4: Research Findings — Root Cause Analysis

_This chapter documents research into the kernel regression, how containerd
itself handles SELinux on overlay, how other CSI drivers approach the
problem, and Kubernetes upstream evolution._

### 4.1 The `context=` Option Never Officially Worked with Overlay

**Critical finding: overlayfs does not recognize the `context=` mount option.
It worked on older kernels only by accident through the legacy VFS mount
path, not because overlayfs explicitly supports it.**

The mount flow on kernel 6.1.x (using the `mount(2)` syscall) for overlayfs
through the legacy path:

1. `do_new_mount()` is called in `fs/namespace.c`.
2. `alloc_fs_context()` creates an `fs_context`. Since overlayfs in 6.1.x
   does NOT set `.init_fs_context`, the VFS falls back to
   `legacy_init_fs_context()` (`fs/fs_context.c`).
3. `legacy_parse_monolithic()` is called with the raw mount options string.
   It calls `security_sb_eat_lsm_opts()`, which invokes
   `selinux_sb_eat_lsm_opts()` (`security/selinux/hooks.c`). This function
   **strips** `context=`, `fscontext=`, `rootcontext=`, `defcontext=` from
   the options string in-place and stores the parsed SELinux SIDs in
   `fc->security`.
4. `legacy_get_tree()` calls `ovl_mount()` → `mount_nodev()` →
   `ovl_fill_super()` → `ovl_parse_opt()` with the **already-stripped**
   options string. Overlayfs never sees `context=`.
5. After `vfs_get_tree()` succeeds, `security_sb_set_mnt_opts()` applies the
   previously-parsed SELinux context to the superblock.

**Overlayfs never parsed `context=`. SELinux stripped it before overlayfs
option parsing ran.** The `ovl_parse_opt()` function explicitly returns
`-EINVAL` for any unrecognized option in its `default:` switch case.

### 4.2 The Upstream Kernel Is Identical Between 6.1.161 and 6.1.163

Diffing the upstream stable kernel source confirms:

- `fs/overlayfs/super.c` is **byte-for-byte identical** in v6.1.161,
  v6.1.162, and v6.1.163.
- The upstream changelogs for 6.1.162 and 6.1.163 contain **zero changes**
  to overlayfs, SELinux, or VFS mount infrastructure.
- No `fs/overlayfs/params.c` exists in the 6.1.x series (introduced in 6.5+
  with the fs_context conversion).

### 4.3 The Breakage Is in the Amazon Linux Kernel, Not Upstream

Bottlerocket does not use the vanilla upstream kernel. It uses the Amazon
Linux kernel SRPM:

- **Before (working):** `kernel-6.1.161-183.298.amzn2023.src.rpm`
- **After (broken):** `kernel-6.1.163-186.299.amzn2023.src.rpm`

The kernel-kit PR that bumped the version:
[bottlerocket-os/bottlerocket-kernel-kit#384](https://github.com/bottlerocket-os/bottlerocket-kernel-kit/pull/384)
(commit `5bb0814fbdcd`). The Amazon Linux kernel applies hundreds of
additional patches on top of upstream stable. Amazon Linux kernel SRPM patches
are not publicly visible in standard GitHub repos — they're inside the source
RPM at `cdn.amazonlinux.com`.

**Most likely root cause:** Amazon Linux backported the **overlayfs
conversion to the `fs_context` API** from kernel 6.5+ into their 6.1.x
branch. When overlayfs uses `fs_context` natively (setting
`.init_fs_context = ovl_init_fs_context`), the mount flow changes:

1. `alloc_fs_context()` calls `ovl_init_fs_context()` instead of
   `legacy_init_fs_context()`.
2. `ovl_parse_monolithic()` is used instead of `legacy_parse_monolithic()`.
3. Each option goes through `vfs_parse_fs_param()` where
   `security_fs_context_parse_param()` is called before
   `ovl_parse_param()`.
4. SELinux's `fs_context_parse_param` hook should consume `context=` before
   overlayfs sees it. If this hook fails, has a conditional that now
   evaluates differently, or the ordering was changed in the Amazon patch
   set, `context=` falls through to `ovl_parse_param()` which rejects it.

This theory is consistent with the error (`exit status 32` = `EINVAL` from
mount) and the fact that upstream is unchanged.

### 4.4 Modern Kernel State (6.5+, 6.6.x, 6.12.x)

In mainline kernel 6.5+, overlayfs uses the `fs_context` API with
`fs/overlayfs/params.c`. `context=` is NOT in overlayfs's `enum ovl_opt`.
However, `context=` **works correctly** in mainline because
`security_fs_context_parse_param()` intercepts and consumes the SELinux
options before `ovl_parse_param()` runs. SELinux also explicitly includes
`"overlay"` in the allowlist for context mounts in
`selinux_set_mnt_opts()`.

**Conclusion:** The `context=` + overlay combination works in both old
(legacy path) and new (fs_context path) mainline kernels. The breakage is
specific to the Amazon Linux kernel's backport of the fs_context conversion
into 6.1.x.

### 4.5 Verification Steps (Not Yet Executed)

To confirm the theory, run on a Bottlerocket 1.57.0 node:

```bash
# Check if overlayfs now uses fs_context (presence of ovl_init_fs_context)
cat /proc/kallsyms | grep ovl_init_fs_context
# If symbol exists → fs_context API is in use (confirms Amazon backport)

# Check kernel config for overlay
zcat /proc/config.gz | grep OVERLAY

# Check dmesg for specific mount error details
dmesg | grep -i overlay

# Direct mount test
mount -t overlay -o "lowerdir=/tmp/lower,context=system_u:object_r:container_file_t:s0" \
    overlay /tmp/merged
```

---

## Chapter 5: How containerd Handles SELinux on Overlay — The Driver Is the Outlier

### 5.1 containerd's Overlay Snapshotter: No SELinux at All

containerd's overlay snapshotter (`plugins/snapshots/overlay/overlay.go`)
constructs overlay mounts with only filesystem options (`lowerdir`,
`upperdir`, `workdir`, `index=off`). There is **zero SELinux-specific code**
in the snapshotter. No `context=`, no `seclabel`, no `selinux`.

containerd creates bare overlay mounts for **every container's rootfs**
without any SELinux mount option — on every Linux distribution, including
Bottlerocket.

### 5.2 SELinux Is Split Across Two Layers in the Container Stack

The container runtime stack splits SELinux handling into two separate
concerns:

**Layer A — Process label (runc, at exec time):**
runc calls `selinux.SetExecLabel()` just before exec, writing the container
process label (e.g., `system_u:system_r:container_t:s0:c123,c456`) to
`/proc/self/attr/exec`. The kernel enforces MAC policy based on the process
label. This is the primary enforcement mechanism.

**Layer B — Mount label (runc, for tmpfs/bind mounts only):**
runc uses `label.FormatMountLabel()` to append `context="<label>"` to mount
data, but **only for mounts that runc creates inside the container** — tmpfs,
mqueue, bind mounts for `/etc/resolv.conf`, `/etc/hostname`, etc. It is
**NOT used for the rootfs overlay mount** because containerd already created
that overlay before runc is invoked.

### 5.3 Why This Works on Bottlerocket

containerd on Bottlerocket creates overlay mounts for container rootfs
**without `context=`**. It works because:

1. **Overlay supports per-file xattr labels.** Since kernel 4.19+, overlayfs
   passes through `security.selinux` xattrs from underlying layers. Each
   file's SELinux label comes from the image layer's xattr, not from a
   blanket mount-level context.

2. **SELinux enforcement is process-based.** The container process gets a
   label like `container_t`, and the SELinux policy allows `container_t` to
   access files labeled `container_file_t`. The kernel enforces this at
   access time based on process label + file xattr — not the mount context.

3. **Bottlerocket's SELinux policy explicitly allows the containerd domain
   to create overlay mounts.** The policy grants `runtime_t` permissions
   for overlay operations on the data partition.

### 5.4 What containerd Does for Volume SELinux

For specific volume mounts (not rootfs), containerd CRI uses the
`SelinuxRelabel` flag in CRI mount specs. When set, it calls
`label.Relabel()` which does a recursive xattr walk — but only on specific
small paths like `/etc/resolv.conf`. This is acceptable because those paths
contain a handful of files.

### 5.5 Implication

**The container-image-csi-driver is the only component in the Bottlerocket
container stack that passes `context=` to an overlay mount.** containerd
does not do this. runc does not do this. The standard approach is to rely on
per-file xattr labels from the image layers plus process-level SELinux
enforcement. The driver's `context=` usage was a workaround that happened to
work on older kernels through the legacy VFS path — it was never the
intended way to handle SELinux on overlayfs.

---

## Chapter 6: How Other CSI Drivers Handle SELinux

### 6.1 AWS EBS CSI Driver

**Repository:** https://github.com/kubernetes-sigs/aws-ebs-csi-driver

**Approach: Delegate entirely to kubelet.**

The EBS CSI driver has **zero SELinux-specific code** in its
`NodeStageVolume` / `NodePublishVolume` implementations. Instead:

- The Helm chart exposes `node.selinux` (default: `false`). When enabled,
  the CSIDriver object gets `spec.seLinuxMount: true`.
- When `seLinuxMount: true` is set, **kubelet** adds `-o context=<label>` to
  the mount flags it passes to the CSI driver in `NodeStageVolume` requests.
- The driver simply passes those mount options through to the `mount` syscall.
- The driver does not detect SELinux, does not determine labels, and does not
  inject context options independently.

**Why this works for EBS but not for us:** EBS mounts block filesystems
(ext4, xfs) which natively support the `context=` mount option. The option
is parsed by the filesystem itself, not by a legacy VFS path. Our driver
mounts overlayfs which does not recognize `context=` in its own option parser.

### 6.2 Secrets Store CSI Driver

**Repository:** https://github.com/kubernetes-sigs/secrets-store-csi-driver

**Approach: Ignore the problem.**

- No `seLinuxMount` field on the CSIDriver object.
- No SELinux handling in mount logic.
- Creates tmpfs mounts and writes secret files into them.
- Per-file relabelling cost is negligible because secrets volumes contain a
  handful of small files.

### 6.3 Kubernetes Native Image Volume (KEP-4639, Kubernetes 1.31+)

**Source:** `pkg/volume/image/image.go` in kubernetes/kubernetes

**Approach: Opt out of SELinux entirely.**

```go
func (o *imagePlugin) GetAttributes() volume.Attributes {
    return volume.Attributes{
        ReadOnly:       true,
        Managed:        false,
        SELinuxRelabel: false,  // No recursive relabelling
    }
}

func (o *imagePlugin) SupportsSELinuxContextMount(spec *volume.Spec) (bool, error) {
    return false, nil  // No context mount either
}
```

The native image volume plugin explicitly opts out of both relabelling and
context mounts. Since image volumes are read-only and content-addressed,
they bypass SELinux labelling entirely and rely on:
- Per-file xattr labels from the image layers
- Process-level SELinux enforcement

**This is the most directly relevant pattern for our driver.** However,
this interface (`volume.Attributes`) is only available for in-tree volume
plugins, not CSI drivers.

### 6.4 warm-metal/container-image-csi-driver (Upstream)

The upstream driver has no SELinux handling. Relevant issues:

- [#193](https://github.com/warm-metal/container-image-csi-driver/issues/193)
  — overlay mount failure on Bottlerocket 1.57.0
- [#145](https://github.com/warm-metal/container-image-csi-driver/issues/145)
  — `lsetxattr` failures on EKS/Bottlerocket
- [#178](https://github.com/warm-metal/container-image-csi-driver/issues/178)
  — Bottlerocket SELinux compatibility

### 6.5 Summary Comparison

| Driver | Approach | Uses `context=`? | Works on overlay? |
|---|---|---|---|
| **AWS EBS CSI** | Delegate to kubelet via `seLinuxMount: true` | Yes, passed by kubelet | N/A (block fs) |
| **Secrets Store CSI** | Ignore (small volumes) | No | N/A (tmpfs) |
| **K8s Native Image Vol** | Opt out (`SELinuxRelabel: false`) | No | Yes |
| **Our driver (current)** | Hardcode `context=` in driver | Yes, self-injected | **Broken on 6.1.163+** |
| **containerd (rootfs)** | No SELinux on overlay mounts | No | Yes |

---

## Chapter 7: Kubernetes Upstream SELinux Evolution (KEP-1710)

### 7.1 The KEP

[KEP-1710](https://github.com/kubernetes/enhancements/tree/master/keps/sig-storage/1710-selinux-relabeling)
addresses the exact performance problem we hit: recursive per-file
relabelling causing pod startup latency. The solution: kubelet mounts
volumes with `-o context=<label>` instead of letting the container runtime
walk every file.

### 7.2 Rollout Status

| Kubernetes Version | `SELinuxMountReadWriteOncePod` | `SELinuxMount` | `SELinuxChangePolicy` |
|---|---|---|---|
| v1.27 | Alpha (off by default) | — | — |
| v1.28 | **Beta, ON by default** | — | — |
| v1.29–v1.31 | Beta, on by default | Alpha (off) | — |
| v1.32 | Beta, on by default | Alpha (off) | Alpha (off) |
| **v1.33** | Beta, on by default | **Beta, OFF by default** | **Beta, ON by default** |
| v1.34–v1.35 | Beta, on by default | Beta, off by default | Beta, on by default |
| v1.36 | **GA (locked on)** | Beta, off by default | **GA (locked on)** |
| v1.37 (planned) | GA (locked on) | **GA (on by default)** | GA (locked on) |

Key:
- **Beta, ON by default** — active without any configuration change
- **Beta, OFF by default** — must be explicitly enabled via `--feature-gates=<Gate>=true`
- **GA (locked on)** — always active; feature gate is removed, cannot be disabled

**On EKS v1.33 (our current version):**
- `SELinuxMountReadWriteOncePod` — active by default, no config needed. Covers only `ReadWriteOncePod` PVCs (`SINGLE_NODE_SINGLE_WRITER`). Inline ephemeral CSI volumes use `SINGLE_NODE_WRITER` and are not covered by this gate. See section 7.3 for details.
- `SELinuxChangePolicy` — active by default, no config needed. The `pod.spec.securityContext.seLinuxChangePolicy` field is available.
- `SELinuxMount` — **not active by default**. Requires explicitly enabling `--feature-gates=SELinuxMount=true` on apiserver, kube-controller-manager, and kubelet. Without it, non-RWOP volumes (including our ephemeral volumes) still use the legacy recursive relabelling path.

### 7.3 How It Works

When all conditions are met, kubelet adds `-o context=<label>` to the
`mount_flags` in `VolumeCapability.MountVolume` of
`NodeStageVolume`/`NodePublishVolume` CSI requests. Conditions:

1. SELinux is enabled on the node
2. The relevant feature gate is enabled (see table above; for most volume
   types this requires explicitly enabling `SELinuxMount` in v1.33–v1.36)
3. The pod has `seLinuxOptions` set (at least `.level`; kubelet fills in
   `user`, `role`, `type` from OS defaults)
4. The CSI driver declares `CSIDriver.spec.seLinuxMount: true`
5. `seLinuxChangePolicy` is `MountOption` (default) or unset

**Does this require kubelet configuration changes?**

It depends on which feature gate is needed:

- **`SELinuxMountReadWriteOncePod`** — no configuration change needed on
  v1.28+. Active by default. Kubelet already passes `-o context=` for
  `ReadWriteOncePod` PVCs when the CSIDriver declares `seLinuxMount: true`.
  However, this gate does not apply to the driver's ephemeral volumes.

  The reason: `SELinuxMountReadWriteOncePod` specifically targets the
  `SINGLE_NODE_SINGLE_WRITER` CSI access mode (the Kubernetes
  `ReadWriteOncePod` PV access mode). When kubelet sends a
  `NodePublishVolume` request for an **inline ephemeral CSI volume**, it
  hardcodes `SINGLE_NODE_WRITER` as the access mode — not
  `SINGLE_NODE_SINGLE_WRITER`. These are distinct access modes and the gate
  only activates for the latter. Since the driver's workloads use inline
  ephemeral volumes (declared via `volumes[].csi` in the pod spec), they
  always arrive with `SINGLE_NODE_WRITER` and are never covered by this gate.
  The driver has no `ReadWriteOncePod` / `SINGLE_NODE_SINGLE_WRITER` support
  anywhere in its codebase (`cmd/plugin/node_server.go`).

- **`SELinuxMount`** (needed for all other volume types, including ephemeral)
  — requires explicit opt-in on v1.33 through v1.36. Must be enabled via
  `--feature-gates=SELinuxMount=true` on apiserver, kube-controller-manager,
  and kubelet. On managed EKS this means setting extra kubelet arguments in
  the nodegroup configuration. There is no separate SELinux-specific kubelet
  config knob — feature gates are the only mechanism.

  EKS does not enable `SELinuxMount` by default in any currently supported
  version. The gate becomes on-by-default only in v1.37 (planned GA).

- **`CSIDriver.spec.seLinuxMount: true`** — a cluster-level Kubernetes API
  object change, not kubelet configuration. Setting this field on the
  CSIDriver object is sufficient for the kubelet to start sending `context=`
  in mount flags (for whichever volume types the active feature gates cover).

### 7.4 What This Means for Our Driver

| Aspect | Our current approach | KEP-1710 approach |
|---|---|---|
| Who determines the label | Driver hardcodes a default | Kubelet computes from pod's `seLinuxOptions` + OS defaults |
| Who passes `-o context=` | Driver adds it in mount logic | Kubelet adds it to `mount_flags`, driver receives it |
| Multi-tenancy | Same context for all pods (no MCS) | Per-pod context with MCS categories |
| Conflict detection | None | Kubelet prevents conflicting mounts on same node |
| Opt-out mechanism | None | `seLinuxChangePolicy: Recursive` in pod spec |

**However, KEP-1710 still passes `-o context=` to the mount call.** For
drivers that mount overlayfs, this has the same kernel-level problem: the
overlay `mount()` may reject the option on kernels where the legacy VFS path
is no longer used for overlayfs.

### 7.5 Gap in the CSI Spec

There is no CSI-level mechanism to say "this driver does not need SELinux
relabelling and does not support context mounts either." The options are:

- `seLinuxMount: true` → kubelet passes `-o context=` (doesn't work for
  overlay on affected kernels)
- `seLinuxMount: false/unset` → kubelet tells the runtime to do recursive
  relabelling via `:Z` (causes the startup latency we're trying to avoid)

The native image volume plugin's `SELinuxRelabel: false` +
`SupportsSELinuxContextMount: false` combination has no CSI equivalent.

---

## Chapter 8: Critical Evaluation of Past Decisions

### 8.1 nsenter-Based Mounting (Chapter 1) — Correct Decision

The nsenter approach was the right call. It is the only way to satisfy all
Bottlerocket constraints simultaneously:
- No `privileged: true` required
- No bidirectional mount propagation
- Mounts are directly visible to kubelet
- Validated by Bottlerocket's own `sheltie` tool

No alternative has emerged that would be better. This decision stands.

### 8.2 Adding `context=` to Overlay Mounts (Chapter 2) — Incorrect Approach

This is where the wrong path was taken. The research shows:

1. **containerd itself does not pass `context=` to overlay mounts.** Every
   container's rootfs overlay is mounted without SELinux mount options. The
   driver is the only component in the stack doing this.

2. **`context=` never officially worked with overlayfs.** It only worked by
   accident through the legacy VFS mount path where SELinux stripped the
   option before overlayfs parsed it. Building on undocumented/accidental
   behavior created a fragile dependency.

3. **The correct model (used by containerd and the native image volume
   plugin) is to not set SELinux labels at the mount level for overlay.**
   Instead, rely on per-file xattr labels from image layers + process-level
   SELinux enforcement.

4. **The premise of Chapter 2 needs re-examination.** The claim was that
   "without `context=`, the kernel performs per-file SELinux relabelling."
   But containerd mounts overlay without `context=` for every container on
   Bottlerocket without per-file relabelling of the rootfs. The per-file
   relabelling observed may have been triggered by kubelet/CRI passing the
   `:Z` flag for CSI volumes specifically — not by the kernel spontaneously
   relabelling. If the relabelling is driven by the container runtime (via
   `:Z`), the fix is to prevent the runtime from receiving that flag, not to
   add `context=`.

### 8.3 The Root Cause of the Relabelling Problem (Revised Understanding)

The per-file relabelling most likely happens because:

1. Kubelet checks if the mounted filesystem supports SELinux (looks for
   `seclabel` in mount options).
2. The driver's overlay mounts likely expose `seclabel` (overlayfs on
   SELinux-enforcing hosts supports xattr-based labelling).
3. Kubelet sees `seclabel`, determines the volume needs relabelling, and
   passes `:Z` to the container runtime.
4. The container runtime recursively walks every file and calls
   `lsetxattr()`.

The correct fix is to prevent step 3 from triggering, not to add `context=`
at step 0. The Kubernetes-native way to do this is setting
`CSIDriver.spec.seLinuxMount: true` — but that causes kubelet to send
`-o context=` in mount flags, which brings back the overlay rejection
problem on affected kernels.

### 8.4 What Should Have Been Done (and the Correct Direction Forward)

The approach taken by the Kubernetes native image volume plugin is the
correct model: **opt out of SELinux mount handling entirely.** For CSI
drivers, this translates to ensuring that kubelet does not trigger per-file
relabelling for the driver's volumes, without relying on `context=`.

---

## Chapter 9: Possible Fix Directions

### Option A: Remove `context=` and Accept the Relabelling (Least Effort, Worst Performance)

Remove the `context=` injection from `mountInHostNamespace()`. Mounts work
on all kernels. Per-file relabelling returns for large images on SELinux-
enforcing hosts.

**Verdict:** Unacceptable for production due to startup latency.

### Option B: Match containerd's Approach — No `context=`, Rely on xattr Labels (Recommended Direction)

Mount overlay **without `context=`**, matching what containerd does for every
container rootfs. Then prevent the per-file relabelling by addressing the
actual trigger:

1. **Investigate why kubelet triggers relabelling for the driver's CSI volumes
   but not for containerd's rootfs overlay.** The difference is likely that
   rootfs mounts go through a different CRI path that doesn't add `:Z`, while
   CSI volumes go through kubelet's volume manager which checks `seclabel`.

2. **Use `seLinuxChangePolicy: MountOption`** in consuming pod specs
   combined with `CSIDriver.spec.seLinuxMount: true`. When `seLinuxMount` is
   `true`, kubelet adds `-o context=` to `mount_flags` but the driver
   **does not pass it to the overlay mount**. The driver would receive the
   option and acknowledge it, but skip applying it to the actual overlay
   `mount()` call. Kubelet would not trigger `:Z` relabelling because it
   believes the driver handled the SELinux context. This is pragmatic but
   involves the driver silently discarding a mount option kubelet believes
   was applied.

3. **Contribute to the CSI spec or Kubernetes to add an equivalent of
   `SELinuxRelabel: false` for CSI drivers.** This would be a new field on
   CSIDriver (e.g., `seLinuxRelabelNeeded: false`) that tells kubelet
   "don't relabel, don't send context= either." This is the correct long-term
   fix but requires upstream KEP work.

### Option C: File Bug Against Amazon Linux Kernel (Parallel Track)

The `context=` rejection is specific to the Amazon Linux kernel's backport
of the overlayfs fs_context conversion. If the backport is fixed to properly
handle SELinux option stripping (matching mainline 6.5+ behavior), then
`context=` would work again on Bottlerocket.

**Action:** File a bug against the Amazon Linux kernel or Bottlerocket,
referencing that `selinux_fs_context_parse_param()` is not correctly
consuming `context=` before it reaches overlayfs option parsing in the
backported fs_context path.

**This should be pursued regardless of which driver-side fix is chosen**
because the backport behavior diverges from mainline and affects any
software that passes `context=` to overlay.

### Option D: Accept `mount_flags` from Kubelet (Required Regardless)

The current implementation **ignores `VolumeCapability.MountVolume.mount_flags`**
entirely. This means that even if kubelet sends `-o context=<label>` via
KEP-1710, the driver drops it. The `Mounter` interface does not accept mount
flags:

```go
// Current: no mount flags parameter
Mount(ctx context.Context, volumeId string, target MountTarget, image reference.Named, ro bool) error
```

Regardless of which SELinux strategy is chosen, the driver should be updated
to:
1. Accept mount flags from the CSI request
2. Pass filesystem-appropriate flags through to the mount call
3. For overlay-specific flags (like `context=`), decide whether to apply,
   skip, or transform them based on the kernel's capabilities

This is also a prerequisite for proper KEP-1710 integration and for
eventual upstream contribution.

---

## Summary of Constraints (Updated)

Any future change to SELinux context handling must satisfy all of the
following:

| Constraint | Reason |
|---|---|
| Must work on Bottlerocket (SELinux enforcing) | Primary target environment |
| Must not require `privileged: true` | Breaks on Bottlerocket SELinux policy |
| Must not use bidirectional mount propagation without `privileged` | Rejected by kubelet API |
| Must not cause per-file relabelling | Causes pod startup latency on ephemeral volumes |
| Must work with kernel 6.1.163+ (Bottlerocket 1.57.0+) | Current regression |
| Must work with kernel 6.1.161 (Bottlerocket 1.56.0) | Must not regress working clusters |
| Should align with containerd's overlay mount approach | Avoid being the outlier in the stack |
| Should be compatible with KEP-1710 (`seLinuxMount`) | Future Kubernetes versions will expect this |
| Should accept `mount_flags` from CSI requests | Correct CSI driver behavior; prerequisite for upstream contribution |

---

## Open Questions

1. **What exactly triggers the per-file relabelling on the driver's CSI
   volumes?** Is it the `:Z` flag from the container runtime, or something
   else? Testing with `strace` or `audit2allow` on a Bottlerocket node would
   confirm.

2. **Does the overlay mount created by the driver expose `seclabel` in its
   mount options?** If not, kubelet would not trigger relabelling and the
   entire `context=` workaround may have been unnecessary.

3. **Can `seLinuxMount: true` be set on the CSIDriver while the driver simply
   does not apply the received `context=` to the overlay mount?** Would
   kubelet accept this gracefully, or does it verify the mount options after
   the fact?

4. **Is the Amazon Linux kernel backport of the fs_context conversion
   intentional and permanent?** If so, `context=` on overlay will never
   work on Bottlerocket kernels going forward, even if it works on mainline.

5. **What is the behavior on Bottlerocket versions beyond 1.57.0?** Testing
   on 1.58+ / 1.59+ is needed to determine if this is a one-version
   regression or a permanent change in the Amazon Linux kernel line.

---

## References

- [`docs/design/nsenter-based-mounting-containerd.md`](nsenter-based-mounting-containerd.md) — nsenter mounting design
- [`pkg/backend/containerd/containerd.go`](../../pkg/backend/containerd/containerd.go) — implementation
- [Bottlerocket Admin Container](https://github.com/bottlerocket-os/bottlerocket-admin-container/) — validates nsenter pattern
- [Bottlerocket Security Guidance](https://github.com/bottlerocket-os/bottlerocket/blob/develop/SECURITY_GUIDANCE.md) — SELinux labels and security model
- [Linux mount(8) — `context=` option](https://man7.org/linux/man-pages/man8/mount.8.html)
- [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [KEP-1710 — SELinux volume relabeling](https://github.com/kubernetes/enhancements/tree/master/keps/sig-storage/1710-selinux-relabeling) — Kubernetes upstream approach
- [Kubernetes blog — Scalable SELinux relabeling (2023)](https://kubernetes.io/blog/2023/04/18/kubernetes-1-27-efficient-selinux-relabeling-beta/)
- [KEP-4639 — Image volumes](https://github.com/kubernetes/enhancements/tree/master/keps/sig-node/4639-oci-volume-source) — native Kubernetes image volume (1.31+)
- [containerd overlay snapshotter](https://github.com/containerd/containerd/blob/main/plugins/snapshots/overlay/overlay.go) — no SELinux in overlay mount construction
- [runc SELinux handling](https://github.com/opencontainers/runc/blob/main/libcontainer/standard_init_linux.go) — process label via `SetExecLabel()`, mount label for tmpfs/bind only
- [AWS EBS CSI driver — seLinuxMount support](https://github.com/kubernetes-sigs/aws-ebs-csi-driver/blob/master/charts/aws-ebs-csi-driver/templates/csidriver.yaml)
- [bottlerocket-kernel-kit#384](https://github.com/bottlerocket-os/bottlerocket-kernel-kit/pull/384) — kernel bump from 6.1.161 to 6.1.163
- [warm-metal/container-image-csi-driver#193](https://github.com/warm-metal/container-image-csi-driver/issues/193) — upstream issue for Bottlerocket 1.57.0 failure
- [warm-metal/container-image-csi-driver#145](https://github.com/warm-metal/container-image-csi-driver/issues/145) — upstream `lsetxattr` issue
- [warm-metal/container-image-csi-driver#178](https://github.com/warm-metal/container-image-csi-driver/issues/178) — upstream Bottlerocket SELinux issue
