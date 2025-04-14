# Credential Provider Plugins

The Warm Metal CSI Driver supports credential provider plugins for authenticating with private container registries such as AWS ECR, Google Container Registry (GCR), and Azure Container Registry (ACR).

## Overview

Credential provider plugins allow the CSI driver to automatically retrieve authentication credentials from external sources without requiring you to manually create and manage Kubernetes secrets. This is particularly useful when:

- Using cloud provider IAM roles for registry authentication
- Managing credentials for multiple registries
- Rotating credentials automatically
- Avoiding storing long-lived credentials in secrets

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│ CSI Driver Pod                                          │
│  ├─ Needs to pull private image                        │
│  └─ Calls credential provider plugin                   │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│ Credential Provider Binary (on host)                    │
│  ├─ Uses node's IAM role / service account             │
│  ├─ Calls cloud provider API (e.g., ECR GetAuthToken)  │
│  └─ Returns temporary credentials                       │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

Before enabling credential provider support, you must:

1. **Install credential provider binaries on your nodes**
   - For ECR: `ecr-credential-provider`
   - For GCR: `gcp-credential-provider`
   - For ACR: `acr-credential-provider`
   - Or use Docker credential helpers (see [Docker Credential Helpers](#docker-credential-helpers))

2. **Create a credential provider configuration file on your nodes**
   - Configuration file defines which provider to use for which registry patterns
   - Must be present at the path specified in Helm values (default: `/etc/kubernetes/image-credential-providers/config.json`)

3. **Ensure nodes have proper IAM permissions**
   - AWS: IAM role with `ecr:GetAuthorizationToken` permission
   - GCP: Service account with `artifactregistry.repositories.downloadArtifacts` permission
   - Azure: Managed identity with `acrpull` role

## Quick Start

### 1. Install Credential Provider Binary

Choose the appropriate method for your cloud provider:

#### AWS ECR
```bash
# Download and install ecr-credential-provider
sudo wget https://github.com/kubernetes/cloud-provider-aws/releases/download/v1.28.0/ecr-credential-provider-linux-amd64 -O /etc/kubernetes/image-credential-providers/ecr-credential-provider
sudo chmod +x /etc/kubernetes/image-credential-providers/ecr-credential-provider
```

#### Google GCR
```bash
# Download and install gcp-credential-provider
sudo wget https://github.com/kubernetes/cloud-provider-gcp/releases/download/v1.28.0/gcp-credential-provider-linux-amd64 -O /etc/kubernetes/image-credential-providers/gcp-credential-provider
sudo chmod +x /etc/kubernetes/image-credential-providers/gcp-credential-provider
```

#### Azure ACR
```bash
# Download and install acr-credential-provider
sudo wget https://github.com/kubernetes/cloud-provider-azure/releases/download/v1.28.0/acr-credential-provider-linux-amd64 -O /etc/kubernetes/image-credential-providers/acr-credential-provider
sudo chmod +x /etc/kubernetes/image-credential-providers/acr-credential-provider
```

### 2. Create Configuration File

Create the credential provider configuration file on each node:

```bash
sudo mkdir -p /etc/kubernetes/image-credential-providers

sudo tee /etc/kubernetes/image-credential-providers/config.json > /dev/null <<EOF
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

See [examples/](./examples/) for more configuration examples.

### 3. Enable in Helm Chart

Enable credential provider support when installing or upgrading the CSI driver:

```bash
helm upgrade --install warm-metal-csi-driver ./charts/warm-metal-csi-driver \
  --set imageCredentialProvider.enabled=true \
  --namespace kube-system
```

### 4. Verify Setup

Check that the CSI driver can use the credential provider:

```bash
# Check that the credential provider binary is accessible
kubectl exec -n kube-system daemonset/warm-metal-csi-driver-nodeplugin -c csi-plugin -- \
  ls -l /etc/kubernetes/image-credential-providers/

# Check CSI driver logs for credential provider messages
kubectl logs -n kube-system daemonset/warm-metal-csi-driver-nodeplugin -c csi-plugin | grep -i credential
```

## Detailed Guides

- [ECR Setup Guide](./ecr-setup.md) - Complete setup for AWS ECR
- [GCR Setup Guide](./gcr-setup.md) - Complete setup for Google GCR
- [ACR Setup Guide](./acr-setup.md) - Complete setup for Azure ACR
- [Multi-Cloud Setup](./multi-cloud-setup.md) - Using multiple providers

## Configuration Examples

See the [examples/](./examples/) directory for complete configuration examples:

- [ecr-config.yaml](./examples/ecr-config.yaml) - AWS ECR configuration
- [gcr-config.yaml](./examples/gcr-config.yaml) - Google GCR configuration
- [acr-config.yaml](./examples/acr-config.yaml) - Azure ACR configuration
- [multi-cloud-config.yaml](./examples/multi-cloud-config.yaml) - Multiple providers

## Docker Credential Helpers

The CSI driver also supports standard Docker credential helpers (e.g., `docker-credential-ecr-login`). These are alternative implementations that may be easier to install on some systems.

### Using docker-credential-ecr-login

1. **Install the credential helper:**
   ```bash
   # On Amazon Linux / AL2023
   sudo yum install -y amazon-ecr-credential-helper

   # Or download binary
   sudo wget https://amazon-ecr-credential-helper-releases.s3.us-east-2.amazonaws.com/0.8.0/linux-amd64/docker-credential-ecr-login -O /etc/kubernetes/image-credential-providers/docker-credential-ecr-login
   sudo chmod +x /etc/kubernetes/image-credential-providers/docker-credential-ecr-login
   ```

2. **Create configuration:**
   ```bash
   sudo tee /etc/kubernetes/image-credential-providers/config.json > /dev/null <<EOF
   {
     "apiVersion": "kubelet.config.k8s.io/v1",
     "kind": "CredentialProviderConfig",
     "providers": [
       {
         "name": "docker-credential-ecr-login",
         "matchImages": [
           "*.dkr.ecr.*.amazonaws.com"
         ],
         "defaultCacheDuration": "12h",
         "apiVersion": "credentialprovider.kubelet.k8s.io/v1"
       }
     ]
   }
   EOF
   ```

## Troubleshooting

### Credential provider binary not found

**Symptom:** Logs show "credential provider binary not found"

**Solution:**
```bash
# Verify binary exists on the node
ls -la /etc/kubernetes/image-credential-providers/

# Verify binary is executable
sudo chmod +x /etc/kubernetes/image-credential-providers/*-credential-provider
```

### Configuration file not found

**Symptom:** CSI driver pod fails to start or logs show config file errors

**Solution:**
```bash
# Verify config file exists on the node
cat /etc/kubernetes/image-credential-providers/config.json

# Verify JSON is valid
jq . /etc/kubernetes/image-credential-providers/config.json
```

### IAM permissions issues

**Symptom:** Credential provider returns authentication errors

**For AWS:**
```bash
# Test IAM role from node
aws ecr get-login-password --region us-east-1

# Verify IAM policy includes ecr:GetAuthorizationToken
aws iam get-role-policy --role-name <node-role> --policy-name <policy-name>
```

**For GCP:**
```bash
# Test service account from node
gcloud auth print-access-token

# Verify service account has artifactregistry.repositories.downloadArtifacts
```

**For Azure:**
```bash
# Test managed identity from node
az login --identity

# Verify managed identity has acrpull role
az role assignment list --assignee <identity-id>
```

### Image pulls still failing

1. **Check CSI driver logs:**
   ```bash
   kubectl logs -n kube-system daemonset/warm-metal-csi-driver-nodeplugin -c csi-plugin --tail=100
   ```

2. **Test credential provider directly:**
   ```bash
   # For ECR
   echo '{"image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-image"}' | \
     /etc/kubernetes/image-credential-providers/ecr-credential-provider get
   ```

3. **Verify image reference is correct:**
   - Ensure the image URL matches the `matchImages` patterns in your config
   - Check for typos in registry URLs

## Advanced Configuration

### Custom Cache Duration

You can customize how long credentials are cached:

```json
{
  "providers": [
    {
      "name": "ecr-credential-provider",
      "defaultCacheDuration": "6h",  // Cache for 6 hours instead of default 12h
      ...
    }
  ]
}
```

### Environment-Specific Paths

If your credential provider binaries are in a different location:

```yaml
# values.yaml
imageCredentialProvider:
  enabled: true
  configPath: "/custom/path/to/config.json"
  binDir: "/custom/path/to/binaries"
```

### Multiple Providers

You can configure multiple credential providers in a single configuration file. See [multi-cloud-config.yaml](./examples/multi-cloud-config.yaml) for an example.

## Architecture Notes

The credential provider plugin system in this CSI driver:

- Supports both Kubernetes credential provider plugins and Docker credential helpers
- Caches credentials to minimize API calls to cloud providers
- Falls back to Kubernetes secrets if no credential provider matches
- Prioritizes credentials in this order:
  1. Volume context secrets (pod-specific)
  2. Kubernetes secrets (cluster-wide)
  3. Credential provider plugins

## References

- [Kubernetes Credential Provider Plugin](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-credential-provider/)
- [AWS ECR Credential Provider](https://github.com/kubernetes/cloud-provider-aws)
- [GCP Credential Provider](https://github.com/kubernetes/cloud-provider-gcp)
- [Azure ACR Credential Provider](https://github.com/kubernetes/cloud-provider-azure)
- [Docker Credential Helpers](https://github.com/docker/docker-credential-helpers)
