// Package secret provides functionality for handling container registry authentication.
package secret

import (
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// DockerConfig represents the config file used by the docker CLI.
// This allows users to authenticate with multiple registries.
type DockerConfig map[string]DockerConfigEntry

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

// DockerConfigEntry represents a registry entry in the DockerConfig.
type DockerConfigEntry struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
	Auth     string `json:"auth,omitempty"`
}

// DockerConfigJSON represents the new docker config format that includes
// credential helper configs.
type DockerConfigJSON struct {
	Auths DockerConfig `json:"auths"`
}

// DockerKeyring tracks a set of docker registry credentials.
type DockerKeyring interface {
	// Lookup returns the registry credentials for the specified image.
	Lookup(image string) ([]AuthConfig, bool)
}

// BasicDockerKeyring is a trivial implementation of DockerKeyring that simply
// wraps a map of registry credentials.
type BasicDockerKeyring struct {
	Configs []DockerConfig
}

// AuthConfig contains authorization information for a container registry.
type AuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Auth          string `json:"auth,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// UnionDockerKeyring is a keyring that consists of multiple keyrings.
type UnionDockerKeyring []DockerKeyring

// Add adds a new entry to the keyring.
func (dk *BasicDockerKeyring) Add(cfg DockerConfig) {
	dk.Configs = append(dk.Configs, cfg)
}

// Lookup implements DockerKeyring.
func (dk *BasicDockerKeyring) Lookup(image string) ([]AuthConfig, bool) {
	// Strip any tag/digest from the image name - we don't include this
	// when matching against the credentials.
	var registryURL string
	parts := splitImageName(image)
	if len(parts) > 0 {
		registryURL = parts[0]
	}

	if registryURL == "" {
		klog.V(4).Infof("No registry URL found for image: %s", image)
		return nil, false
	}

	klog.V(4).Infof("Looking up credentials for registry: %s from image: %s", registryURL, image)

	var matches []AuthConfig
	for _, cfg := range dk.Configs {
		if auth, found := matchRegistry(cfg, registryURL); found {
			klog.V(4).Infof("Found credentials for registry: %s", registryURL)
			matches = append(matches, auth)
		}
	}

	return matches, len(matches) > 0
}

// Lookup implements DockerKeyring.
func (dk UnionDockerKeyring) Lookup(image string) ([]AuthConfig, bool) {
	var authConfigs []AuthConfig
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
	// Example: edge.jfrog.ais.acquia.io/devops-pipeline-dev/kaas-container-image-csi/hello-world:linux
	// Should extract: edge.jfrog.ais.acquia.io

	// Split by slash to get registry
	parts := strings.SplitN(imageName, "/", 2)
	if len(parts) < 2 {
		return []string{imageName} // No slash, return as is
	}

	registry := parts[0]

	// Check if this is a hostname (contains dots)
	if strings.Contains(registry, ".") || strings.Contains(registry, ":") {
		return []string{registry}
	} else {
		// If no dots, it's likely Docker Hub with an implicit registry
		return []string{"docker.io"}
	}
}

// Helper function to match a registry URL against the Docker config
func matchRegistry(cfg DockerConfig, registryURL string) (AuthConfig, bool) {
	klog.V(4).Infof("Matching registry URL: %s against config entries: %v", registryURL, getRegistryKeys(cfg))

	// Direct match first
	if entry, ok := cfg[registryURL]; ok {
		klog.V(4).Infof("Found direct match for %s", registryURL)
		return AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			RegistryToken: "", // Not stored in the DockerConfigEntry
		}, true
	}

	// Try with https:// prefix (some configs store it this way)
	httpsRegistry := "https://" + registryURL
	if entry, ok := cfg[httpsRegistry]; ok {
		klog.V(4).Infof("Found match with https:// prefix for %s", registryURL)
		return AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			RegistryToken: "",
		}, true
	}

	// Try with http:// prefix
	httpRegistry := "http://" + registryURL
	if entry, ok := cfg[httpRegistry]; ok {
		klog.V(4).Infof("Found match with http:// prefix for %s", registryURL)
		return AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			RegistryToken: "",
		}, true
	}

	// Try to find a partial match (useful for JFrog Artifactory where registry might be stored differently)
	for registry, entry := range cfg {
		if strings.Contains(registryURL, registry) || strings.Contains(registry, registryURL) {
			klog.V(4).Infof("Found partial match: config has %s, image uses %s", registry, registryURL)
			return AuthConfig{
				Username:      entry.Username,
				Password:      entry.Password,
				Auth:          entry.Auth,
				RegistryToken: "",
			}, true
		}
	}

	// No match found
	klog.V(4).Infof("No credential match found for %s", registryURL)
	return AuthConfig{}, false
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
