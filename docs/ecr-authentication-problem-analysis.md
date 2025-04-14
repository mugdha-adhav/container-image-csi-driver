# ECR Authentication Problem - Analysis & Solution

## Executive Summary

The `container-image-csi-driver` project lost ECR authentication support when migrating from v2.0.1 to v2.1.0. This document explains the root cause and details the solution being implemented via PR #172, which adds Kubernetes credential provider plugin support to properly handle ECR, GCR, and ACR authentication.

---

## Timeline of Events

### v2.0.1 (Last Working Version)
- ✅ ECR authentication worked out-of-the-box
- ✅ Used `k8s.io/kubernetes/pkg/credentialprovider` with built-in AWS SDK
- ✅ Automatically used node's IAM role for ECR authentication

### v2.1.0 (Breaking Change)
- ❌ Migrated to `github.com/google/go-containerregistry/pkg/authn`
- ❌ ECR authentication completely broken
- ❌ Lost all AWS/ECR integration capabilities

### Fix (PR #172)
- ✅ Implements Kubernetes credential provider plugin system
- ✅ Restores ECR authentication via `ecr-credential-provider`
- ✅ Adds support for GCR, ACR, and other registries
- ✅ Uses proper `cri.AuthConfig` types throughout

---

## Root Cause Analysis

### Why v2.0.1 Worked

```go
// v2.0.1 approach
import (
    "k8s.io/kubernetes/pkg/credentialprovider"
    _ "k8s.io/kubernetes/pkg/credentialprovider/aws"  // Magic import
)

func getCredentials(image string) {
    keyring := credentialprovider.NewDockerKeyring()
    authConfigs, found := keyring.Lookup(image)
    // AWS provider automatically:
    // 1. Detected ECR registry URLs
    // 2. Used node's IAM role
    // 3. Called AWS SDK to get ECR tokens
    // 4. Returned valid credentials
}
```

**Key features:**
- Built-in AWS SDK integration
- Automatic IAM role detection
- Registry-specific credential providers (AWS, GCR, ACR)
- Zero configuration required

### Why v2.1.0 Broke

```go
// v2.1.0 approach
import "github.com/google/go-containerregistry/pkg/authn"

func getCredentials(image string) {
    keychain := authn.DefaultKeychain
    authenticator, err := keychain.Resolve(reference)
    // go-containerregistry only:
    // 1. Reads ~/.docker/config.json
    // 2. Invokes Docker credential helpers (if configured)
    // 3. Has NO AWS SDK dependency
    // 4. Has NO built-in ECR support
}
```

**Why the migration happened:**
- `k8s.io/kubernetes/pkg/credentialprovider` became **internal-only** in newer Kubernetes versions
- Cannot be imported by external projects
- Forced migration to alternative credential management libraries

**Why ECR broke:**
- `go-containerregistry/pkg/authn` has **no AWS SDK dependency**
- No built-in understanding of ECR registry URLs
- No automatic IAM role integration
- Only understands Docker config files and credential helper protocol

### The Fundamental Problem

The CSI driver needs to:
1. Pull private container images from ECR (and other registries)
2. Use the Kubernetes node's IAM role for authentication
3. Pass credentials to the container runtime (containerd/CRI-O) in the correct format (`cri.AuthConfig`)

After v2.1.0, there's **no automatic bridge** between AWS IAM roles and the credential system.

---

## The Solution: Kubernetes Credential Provider Plugin (PR #172)

**Strategy:** Implement Kubernetes' official credential provider plugin system, which is the proper way to handle registry authentication in modern Kubernetes.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ CSI Driver                                                   │
│  ├─ pkg/secret/plugin.go (NEW - 429 lines)                  │
│  │   ├─ parsePluginConfigFile()                             │
│  │   ├─ matchImageToProvider()                              │
│  │   ├─ execPlugin()                                        │
│  │   └─ getCachedDockerKeyring()                            │
│  ├─ pkg/secret/types.go (NEW - 170 lines)                   │
│  │   └─ Uses cri.AuthConfig throughout                      │
│  └─ pkg/secret/cache.go (REWRITTEN)                         │
│      └─ Lookup() returns []*cri.AuthConfig                  │
└──────────────────┬──────────────────────────────────────────┘
                   │ Executes plugin binary
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ Credential Provider Plugin (e.g., ecr-credential-provider)  │
│  ├─ Kubernetes-native credential provider binary            │
│  ├─ Input: JSON with image URL                              │
│  ├─ Uses node's IAM role                                    │
│  ├─ Calls AWS ECR GetAuthorizationToken API                 │
│  └─ Output: CredentialProviderResponse (JSON)               │
└─────────────────────────────────────────────────────────────┘
```

### Key Code Changes

#### New File: `pkg/secret/plugin.go` (~429 lines)

Implements the credential provider plugin system:

```go
// Parses Kubernetes credential provider config
func parsePluginConfigFile(configPath string) (*CredentialProviderConfig, error)

// Executes external credential provider binary
func execPlugin(pluginBinary string, image string) (*CredentialProviderResponse, error) {
    cmd := exec.Command(pluginBinary, "get")
    cmd.Stdin = strings.NewReader(fmt.Sprintf(`{"image": "%s"}`, image))
    output, err := cmd.Output()
    // Parse JSON response
}

// Returns cached credentials or executes plugin
func (k *PluginKeyring) Lookup(image string) []*cri.AuthConfig {
    // 1. Check cache
    // 2. Match image to provider pattern
    // 3. Execute plugin binary
    // 4. Cache credentials (12h default)
    // 5. Return cri.AuthConfig
}
```

#### New File: `pkg/secret/types.go` (~170 lines)

Defines types using proper CRI format:

```go
// All types use cri.AuthConfig (correct type for CRI runtime)
type DockerConfig map[string]cri.AuthConfig

type DockerKeyring interface {
    Lookup(image string) ([]*cri.AuthConfig, bool)  // Returns CRI format
}
```

#### Rewritten: `pkg/secret/cache.go`

Complete rewrite to use credential provider plugins:

```go
// Completely removed authn.AuthConfig references
// Returns proper CRI format
func (k *BasicDockerKeyring) Lookup(image string) ([]*cri.AuthConfig, bool) {
    // 1. Try credential provider plugins first
    if configs := k.pluginKeyring.Lookup(image); len(configs) > 0 {
        return configs, true
    }

    // 2. Fall back to secrets from Kubernetes
    return k.lookupInConfigs(image)
}
```

#### Updated: `pkg/remoteimage/pull.go`

Proper CRI AuthConfig usage:

```go
// Proper CRI AuthConfig usage
authConfigs, withCredentials := p.keyring.Lookup(repo)  // Returns []*cri.AuthConfig

_, err = p.imageSvc.PullImage(ctx, &cri.PullImageRequest{
    Image: imageSpec,
    Auth:  authConfigs[0],  // Already in correct CRI format - no conversion needed
})
```

### Configuration

#### Credential Provider Config

Configuration file at `/etc/kubernetes/image-credential-providers/config.json`:

```json
{
  "apiVersion": "kubelet.config.k8s.io/v1",
  "kind": "CredentialProviderConfig",
  "providers": [
    {
      "name": "ecr-credential-provider",
      "matchImages": [
        "*.dkr.ecr.*.amazonaws.com",
        "*.dkr.ecr.*.amazonaws.com.cn",
        "*.dkr.ecr-fips.*.amazonaws.com",
        "public.ecr.aws"
      ],
      "defaultCacheDuration": "12h",
      "apiVersion": "credentialprovider.kubelet.k8s.io/v1"
    }
  ]
}
```

#### Helm Chart Changes

**values.yaml:**
```yaml
imageCredentialProvider:
  enabled: true
  configPath: "/etc/kubernetes/image-credential-providers/config.json"
  binDir: "/etc/kubernetes/image-credential-providers"
```

**nodeplugin.yaml volume mounts:**
```yaml
volumeMounts:
  - name: credential-provider-config
    mountPath: /etc/kubernetes/image-credential-providers
    readOnly: true
volumes:
  - name: credential-provider-config
    hostPath:
      path: /etc/kubernetes/image-credential-providers
```

#### Command Line Arguments

New flags added to the node plugin:

```bash
--image-credential-provider-config=/etc/kubernetes/image-credential-providers/config.json
--image-credential-provider-bin-dir=/etc/kubernetes/image-credential-providers
```

### Node Requirements

#### For ECR (AWS)

```bash
# Install ECR credential provider
wget https://github.com/kubernetes/cloud-provider-aws/releases/download/v1.28.0/ecr-credential-provider-linux-amd64
chmod +x ecr-credential-provider-linux-amd64
sudo mkdir -p /etc/kubernetes/image-credential-providers
sudo mv ecr-credential-provider-linux-amd64 /etc/kubernetes/image-credential-providers/ecr-credential-provider

# Create config (usually via automation/DaemonSet)
cat > /etc/kubernetes/image-credential-providers/config.json << 'EOF'
{
  "apiVersion": "kubelet.config.k8s.io/v1",
  "kind": "CredentialProviderConfig",
  "providers": [
    {
      "name": "ecr-credential-provider",
      "matchImages": [
        "*.dkr.ecr.*.amazonaws.com",
        "*.dkr.ecr.*.amazonaws.com.cn",
        "*.dkr.ecr-fips.*.amazonaws.com",
        "public.ecr.aws"
      ],
      "defaultCacheDuration": "12h",
      "apiVersion": "credentialprovider.kubelet.k8s.io/v1"
    }
  ]
}
EOF
```

#### For GCR (Google Cloud)

```bash
# Install GCR credential provider
wget https://github.com/kubernetes/cloud-provider-gcp/releases/download/v1.28.0/gcp-credential-provider-linux-amd64
chmod +x gcp-credential-provider-linux-amd64
sudo mv gcp-credential-provider-linux-amd64 /etc/kubernetes/image-credential-providers/gcp-credential-provider
```

### Authentication Flow

1. **Image pull request** for `672327909798.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0`

2. **Plugin matching** in `plugin.go`:
   - Checks image against patterns in config
   - Matches `*.dkr.ecr.*.amazonaws.com` → `ecr-credential-provider`

3. **Plugin execution**:
   ```bash
   echo '{"image": "672327909798.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0"}' | \
     /etc/kubernetes/image-credential-providers/ecr-credential-provider get
   ```

4. **Plugin response**:
   ```json
   {
     "kind": "CredentialProviderResponse",
     "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
     "auth": {
       "672327909798.dkr.ecr.us-east-1.amazonaws.com": {
         "username": "AWS",
         "password": "eyJwYXlsb2FkIjoiL..."
       }
     },
     "cacheDuration": "12h"
   }
   ```

5. **Credential caching**:
   - Credentials cached in memory for 12 hours
   - Subsequent pulls use cached credentials (no plugin re-execution)

6. **CRI pull with credentials**:
   ```go
   p.imageSvc.PullImage(ctx, &cri.PullImageRequest{
       Image: imageSpec,
       Auth:  &cri.AuthConfig{  // Correct type!
           Username: "AWS",
           Password: "eyJwYXlsb2FkIjoiL...",
       },
   })
   ```

### Benefits

- ✅ **Kubernetes-native solution** (officially supported since K8s 1.20)
- ✅ **Correct type usage** (`cri.AuthConfig` throughout)
- ✅ **Declarative configuration** via ConfigMap
- ✅ **Automatic credential caching** (configurable duration)
- ✅ **Scales across all nodes** (ConfigMap-based configuration)
- ✅ **Multi-registry support** (ECR, GCR, ACR via different plugins)
- ✅ **IAM role integration** handled by plugin
- ✅ **Better logging and observability**
- ✅ **Future-proof** (aligns with Kubernetes standards)
- ✅ **Clean separation of concerns** (plugin system vs CSI driver logic)

---

## Technical Deep Dive: Why CRI AuthConfig is Critical

### The Core Requirement

The container runtime (containerd via CRI) expects credentials in `cri.AuthConfig` format:

```go
// From k8s.io/cri-api/pkg/apis/runtime/v1/api.pb.go
service ImageService {
    rpc PullImage(PullImageRequest) returns (PullImageResponse) {}
}

message PullImageRequest {
    ImageSpec image = 1;
    AuthConfig auth = 2;  // ← Must be cri.AuthConfig
    PodSandboxConfig sandbox_config = 3;
}

message AuthConfig {
    string username = 1;
    string password = 2;
    string auth = 3;
    string server_address = 4;
    string identity_token = 5;
    string registry_token = 6;
}
```

### PR #172's Correct Approach

```go
// pkg/secret/types.go in PR #172
type DockerKeyring interface {
    Lookup(image string) ([]*cri.AuthConfig, bool)  // ← Returns CRI type directly
}

// pkg/secret/cache.go
func (k *BasicDockerKeyring) Lookup(image string) ([]*cri.AuthConfig, bool) {
    // Returns proper CRI format from the start
}

// pkg/remoteimage/pull.go
authConfigs, _ := p.keyring.Lookup(repo)  // []*cri.AuthConfig

p.imageSvc.PullImage(ctx, &cri.PullImageRequest{
    Image: imageSpec,
    Auth:  authConfigs[0],  // ✅ Correct type - no conversion needed
})
```

**Key advantage:** No type conversion needed, credentials flow directly from plugin to CRI runtime in the correct format.

---

## Testing & Validation

### Prerequisites

Install the credential provider binary on nodes:

```bash
# Install ECR credential provider
sudo wget https://github.com/kubernetes/cloud-provider-aws/releases/download/v1.28.0/ecr-credential-provider-linux-amd64
sudo chmod +x ecr-credential-provider-linux-amd64
sudo mkdir -p /etc/kubernetes/image-credential-providers
sudo mv ecr-credential-provider-linux-amd64 /etc/kubernetes/image-credential-providers/ecr-credential-provider
```

### Test Credential Provider Directly

Verify the credential provider works independently:

```bash
echo '{"image": "672327909798.dkr.ecr.us-east-1.amazonaws.com/test"}' | \
  /etc/kubernetes/image-credential-providers/ecr-credential-provider get
```

Expected response:
```json
{
  "kind": "CredentialProviderResponse",
  "apiVersion": "credentialprovider.kubelet.k8s.io/v1",
  "auth": {
    "672327909798.dkr.ecr.us-east-1.amazonaws.com": {
      "username": "AWS",
      "password": "eyJwYXlsb2FkIjoiL..."
    }
  },
  "cacheDuration": "12h0m0s"
}
```

### Verify CSI Driver Integration

Check CSI driver logs for credential provider activity:

```bash
kubectl logs -n kube-system daemonset/warm-metal-csi-driver-node-plugin | grep -i credential
```

Expected log messages:
```
Lookup: found credentials via credential provider plugin for 672327909798.dkr.ecr.us-east-1.amazonaws.com
Credentials cached for 12h
```

### Test ECR Image Pull

Create a test volume with an ECR image:

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: test-ecr-image
spec:
  capacity:
    storage: 5Gi
  accessModes:
    - ReadOnlyMany
  csi:
    driver: csi.warm-metal.tech
    volumeHandle: test-ecr-image
    volumeAttributes:
      image: "672327909798.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0"
```

Verify the image is pulled successfully and credentials are cached.

---

## Implementation Roadmap

### Phase 1: Code Integration

- [ ] Review PR #172 code changes thoroughly
- [ ] Merge PR #172 into main/development branch
- [ ] Update `go.mod` dependencies if needed
- [ ] Resolve any merge conflicts with current branch

### Phase 2: Configuration & Deployment

- [ ] Add Helm chart support for credential provider config
- [ ] Create ConfigMap template for credential provider config
- [ ] Add volume mounts to nodeplugin DaemonSet
- [ ] Add command-line flags to CSI driver deployment
- [ ] (Optional) Create DaemonSet to deploy credential provider binaries

### Phase 3: Documentation

- [ ] Document ECR setup (AWS)
- [ ] Document GCR setup (GCP) if needed
- [ ] Document ACR setup (Azure) if needed
- [ ] Create troubleshooting guide for credential provider issues
- [ ] Update README with new authentication requirements
- [ ] Create upgrade guide from v2.0.1/v2.1.0

### Phase 4: Testing

- [ ] Add integration tests for credential provider system
- [ ] Test with private ECR images
- [ ] Test with public ECR images
- [ ] Test credential caching behavior
- [ ] Test with GCR/ACR if supported
- [ ] Validate IAM role integration
- [ ] Performance testing under load
- [ ] Update CI/CD to test with private registries

### Phase 5: Release

- [ ] Tag release v2.2.0 with credential provider support
- [ ] Publish updated Helm charts
- [ ] Announce changes and migration path to users
- [ ] Monitor for issues in production deployments

---

## Migration Guide

### For Users on v2.0.1

1. **Deploy credential provider binary** to all nodes:
   ```bash
   wget https://github.com/kubernetes/cloud-provider-aws/releases/download/v1.28.0/ecr-credential-provider-linux-amd64
   chmod +x ecr-credential-provider-linux-amd64
   sudo mv ecr-credential-provider-linux-amd64 /etc/kubernetes/image-credential-providers/ecr-credential-provider
   ```

2. **Create credential provider config** on all nodes:
   ```bash
   sudo mkdir -p /etc/kubernetes/image-credential-providers
   sudo tee /etc/kubernetes/image-credential-providers/config.json > /dev/null <<EOF
   {
     "apiVersion": "kubelet.config.k8s.io/v1",
     "kind": "CredentialProviderConfig",
     "providers": [...]
   }
   EOF
   ```

3. **Upgrade CSI driver** to v2.2.0 via Helm:
   ```bash
   helm upgrade warm-metal-csi-driver ./charts/warm-metal-csi-driver \
     --set imageCredentialProvider.enabled=true \
     --namespace kube-system
   ```

4. **Verify functionality** with test ECR image pull

### For Users on v2.1.0+

Same steps as above - upgrade to v2.2.0 and deploy credential provider infrastructure.

---

## Troubleshooting

### Credential Provider Not Found

**Symptom:** Logs show "credential provider binary not found"

**Solution:**
```bash
# Verify binary exists
ls -la /etc/kubernetes/image-credential-providers/ecr-credential-provider

# Check permissions
sudo chmod +x /etc/kubernetes/image-credential-providers/ecr-credential-provider

# Verify binary works
echo '{"image": "account.dkr.ecr.region.amazonaws.com/test"}' | \
  /etc/kubernetes/image-credential-providers/ecr-credential-provider get
```

### IAM Role Issues

**Symptom:** Plugin returns authentication errors

**Solution:**
- Verify node has IAM role attached with ECR permissions
- Check IAM policy includes `ecr:GetAuthorizationToken`
- Test AWS credentials: `aws ecr get-login-password --region us-east-1`

### Config File Not Found

**Symptom:** Logs show "credential provider config not found"

**Solution:**
```bash
# Verify config file exists
cat /etc/kubernetes/image-credential-providers/config.json

# Verify volume mount in CSI driver pod
kubectl describe pod -n kube-system <csi-driver-pod> | grep credential-provider

# Check Helm values
helm get values warm-metal-csi-driver -n kube-system | grep imageCredentialProvider
```

### Credentials Not Cached

**Symptom:** Plugin executes on every image pull

**Solution:**
- Check `defaultCacheDuration` in config (should be 12h)
- Verify no errors in plugin execution logs
- Check memory limits on CSI driver pods

---

## Conclusion

The ECR authentication problem in `container-image-csi-driver` stems from the forced migration away from Kubernetes' internal credential provider package (which had built-in AWS support) to `go-containerregistry` (which has no AWS support).

**PR #172 provides the architecturally correct solution** by implementing the Kubernetes credential provider plugin system, which:

- Uses the correct types (`cri.AuthConfig`)
- Provides a Kubernetes-native approach
- Scales operationally across all nodes
- Supports multiple registries cleanly (ECR, GCR, ACR)
- Is future-proof and aligns with Kubernetes standards
- Enables automatic IAM role integration via plugins
- Provides configurable credential caching

This solution restores ECR authentication functionality while providing a solid foundation for multi-cloud registry authentication that follows Kubernetes best practices.
