// Package secret provides functionality for handling container registry authentication.
package secret

import (
	"strings"
	"sync"

	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
)

// DockerConfig represents the config file used by the docker CLI.
// This allows users to authenticate with multiple registries.
type DockerConfig map[string]cri.AuthConfig

// DockerConfigProviderFactory is a function that returns a DockerConfigProvider
type DockerConfigProviderFactory func(opts ...DockerConfigProviderOpts) DockerConfigProvider

// DockerConfigProviderOpts contains options for credential providers
type DockerConfigProviderOpts struct {
	UseAwsSdkDebugLog *bool
}

// A set of registered credential providers
var (
	providersMutex sync.Mutex
	providers      = make(map[string]DockerConfigProviderFactory)
)

// RegisterCredentialProvider registers a credential provider factory
func RegisterCredentialProvider(name string, factory DockerConfigProviderFactory) {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	providers[name] = factory
}

// DockerConfigProvider is the interface that registered credential providers implement
type DockerConfigProvider interface {
	// Enabled returns true if the provider is enabled
	Enabled() bool
	// Provide returns a DockerConfig for the given image
	Provide(image string) DockerConfig
}

// DockerConfigJSON represents the new docker config format that includes
// credential helper configs.
type DockerConfigJSON struct {
	Auths DockerConfig `json:"auths"`
}

// DockerKeyring tracks a set of docker registry credentials.
type DockerKeyring interface {
	// Lookup returns the registry credentials for the specified image.
	Lookup(image string) ([]*cri.AuthConfig, bool)
}

// BasicDockerKeyring is a trivial implementation of DockerKeyring that simply
// wraps a map of registry credentials.
type BasicDockerKeyring struct {
	Configs []DockerConfig
}

// UnionDockerKeyring is a keyring that consists of multiple keyrings.
type UnionDockerKeyring []DockerKeyring

// Add adds a new entry to the keyring.
func (dk *BasicDockerKeyring) Add(cfg DockerConfig) {
	dk.Configs = append(dk.Configs, cfg)
}

// Lookup implements DockerKeyring.
func (dk *BasicDockerKeyring) Lookup(image string) ([]*cri.AuthConfig, bool) {
	// Strip any tag/digest from the image name - we don't include this
	// when matching against the credentials.
	var registryURL string
	parts := splitImageName(image)
	if len(parts) > 0 {
		registryURL = parts[0]
	}

	if registryURL == "" {
		klog.V(2).Infof("No registry URL found for image: %s", image)
		return nil, false
	}

	klog.V(2).Infof("Looking up credentials for registry: %s from image: %s", registryURL, image)
	klog.V(2).Infof("Number of credential configs available: %d", len(dk.Configs))

	var matches []*cri.AuthConfig
	for i, cfg := range dk.Configs {
		klog.V(2).Infof("Checking config %d with registries: %v", i, getRegistryKeys(cfg))
		if auth, found := matchRegistry(cfg, registryURL); found {
			klog.V(2).Infof("Found matching credentials for %s with username: %s", registryURL, auth.Username)
			matches = append(matches, auth)
		}
	}

	klog.V(2).Infof("Found %d matching credential(s) for %s", len(matches), registryURL)
	return matches, len(matches) > 0
}

// Lookup implements DockerKeyring.
func (dk UnionDockerKeyring) Lookup(image string) ([]*cri.AuthConfig, bool) {
	var authConfigs []*cri.AuthConfig
	found := false

	// Lookup in all keyrings
	for _, subKeyring := range dk {
		if subKeyring == nil {
			continue
		}

		if configs, ok := subKeyring.Lookup(image); ok {
			authConfigs = append(authConfigs, configs...)
			found = true
		}
	}

	return authConfigs, found
}

// Helper function to split the image name into registry and repository parts
func splitImageName(imageName string) []string {
	// Parse the image name to extract the registry
	parts := strings.Split(imageName, "/")
	if len(parts) < 2 {
		return []string{"docker.io"} // Default to docker hub
	}

	// Check if this is a hostname (contains dots or port)
	if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
		return []string{parts[0]}
	}

	// Docker Hub with implicit registry
	return []string{"docker.io"}
}

// Helper function to match a registry URL against the Docker config
func matchRegistry(cfg DockerConfig, registryURL string) (*cri.AuthConfig, bool) {
	klog.V(4).Infof("Matching registry URL: %s against config entries: %v", registryURL, getRegistryKeys(cfg))

	// Direct match first
	if entry, ok := cfg[registryURL]; ok {
		klog.V(4).Infof("Found direct match for %s", registryURL)
		// Create copy to avoid modifying the original
		auth := entry
		auth.ServerAddress = registryURL
		return &auth, true
	}

	// Try with https:// prefix
	httpsRegistry := "https://" + registryURL
	if entry, ok := cfg[httpsRegistry]; ok {
		klog.V(4).Infof("Found match with https:// prefix for %s", registryURL)
		// Create copy to avoid modifying the original
		auth := entry
		auth.ServerAddress = registryURL
		return &auth, true
	}

	// Try with http:// prefix
	httpRegistry := "http://" + registryURL
	if entry, ok := cfg[httpRegistry]; ok {
		klog.V(4).Infof("Found match with http:// prefix for %s", registryURL)
		// Create copy to avoid modifying the original
		auth := entry
		auth.ServerAddress = registryURL
		return &auth, true
	}

	// Try to find a partial match
	for registry, entry := range cfg {
		if strings.Contains(registryURL, registry) || strings.Contains(registry, registryURL) {
			klog.V(4).Infof("Found partial match: config has %s, image uses %s", registry, registryURL)
			// Create copy to avoid modifying the original
			auth := entry
			auth.ServerAddress = registryURL
			return &auth, true
		}
	}

	klog.V(4).Infof("No credential match found for %s", registryURL)
	return nil, false
}

// Helper function to get registry keys for logging
func getRegistryKeys(cfg DockerConfig) []string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	return keys
}

// NewDockerKeyring creates a new empty keyring.
func NewDockerKeyring() DockerKeyring {
	return &BasicDockerKeyring{}
}
