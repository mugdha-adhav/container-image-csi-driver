// Package secret provides functionality for handling container registry authentication.
package secret

import (
	"encoding/base64"
	"strings"

	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
)

// DockerConfig represents the config file used by the docker CLI.
// This allows users to authenticate with multiple registries.
type DockerConfig map[string]*cri.AuthConfig

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
		klog.V(4).Infof("No registry URL found for image: %s", image)
		return nil, false
	}

	klog.V(4).Infof("Looking up credentials for registry: %s", registryURL)
	klog.V(4).Infof("Number of credential configs available: %d", len(dk.Configs))

	var matches []*cri.AuthConfig
	for i, cfg := range dk.Configs {
		klog.V(4).Infof("Checking config %d", i)
		if auth, found := matchRegistry(cfg, registryURL); found {
			// Don't log auth details, only the fact that we found a match
			klog.V(3).Infof("Found matching credentials for %s", registryURL)
			matches = append(matches, auth)
		}
	}

	klog.V(4).Infof("Found %d matching credential(s) for %s", len(matches), registryURL)
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
	if len(parts) == 1 {
		return []string{"docker.io"} // Default to docker hub
	}

	// Check if this is a hostname (contains dots or port)
	if strings.ContainsAny(parts[0], ".:") {
		return []string{parts[0]}
	}

	// Docker Hub with implicit registry
	return []string{"docker.io"}
}

// normalizeAuthConfig ensures that both Auth field and Username/Password fields are populated.
// Some CRI runtimes prefer Username/Password while others use the Auth field.
// If Auth field exists but Username/Password are empty, decode Auth to populate them.
// If Username/Password exist but Auth is empty, encode them to populate Auth.
func normalizeAuthConfig(auth *cri.AuthConfig) {
	if auth == nil {
		return
	}

	klog.V(4).Infof("normalizeAuthConfig: BEFORE - Username='%s', Password='%s', Auth='%s'",
		auth.Username, auth.Password, auth.Auth)

	// If Auth field exists but Username/Password are empty, decode Auth
	if auth.Auth != "" && auth.Username == "" && auth.Password == "" {
		decoded, err := base64.StdEncoding.DecodeString(auth.Auth)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				auth.Username = parts[0]
				auth.Password = parts[1]
				klog.V(3).Infof("Decoded Auth field to populate Username='%s'", auth.Username)
			}
		} else {
			klog.V(3).Infof("Failed to decode Auth field: %v", err)
		}
	}

	// If Username/Password exist but Auth is empty, encode them
	if auth.Username != "" && auth.Password != "" && auth.Auth == "" {
		authStr := auth.Username + ":" + auth.Password
		auth.Auth = base64.StdEncoding.EncodeToString([]byte(authStr))
		klog.V(3).Infof("Encoded Username/Password to populate Auth field")
	}

	klog.V(4).Infof("normalizeAuthConfig: AFTER - Username='%s', Password='%s', Auth='%s'",
		auth.Username, auth.Password, auth.Auth)
}

// Helper function to match a registry URL against the Docker config
func matchRegistry(cfg DockerConfig, registryURL string) (*cri.AuthConfig, bool) {
	klog.V(5).Infof("Matching registry URL: %s", registryURL)

	// Direct match first
	if entry, ok := cfg[registryURL]; ok {
		klog.V(4).Infof("Found credentials for registry: %s", registryURL)
		// Return pointer
		result := &cri.AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			ServerAddress: registryURL,
			IdentityToken: entry.IdentityToken,
			RegistryToken: entry.RegistryToken,
		}
		normalizeAuthConfig(result)
		return result, true
	}

	// Try with https:// prefix
	httpsRegistry := "https://" + registryURL
	if entry, ok := cfg[httpsRegistry]; ok {
		klog.V(4).Infof("Found credentials for registry: %s (https prefix)", registryURL)
		result := &cri.AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			ServerAddress: registryURL,
			IdentityToken: entry.IdentityToken,
			RegistryToken: entry.RegistryToken,
		}
		normalizeAuthConfig(result)
		return result, true
	}

	// Try with http:// prefix
	httpRegistry := "http://" + registryURL
	if entry, ok := cfg[httpRegistry]; ok {
		klog.V(4).Infof("Found credentials for registry: %s (http prefix)", registryURL)
		result := &cri.AuthConfig{
			Username:      entry.Username,
			Password:      entry.Password,
			Auth:          entry.Auth,
			ServerAddress: registryURL,
			IdentityToken: entry.IdentityToken,
			RegistryToken: entry.RegistryToken,
		}
		normalizeAuthConfig(result)
		return result, true
	}

	// Try to find a partial match
	for registry, entry := range cfg {
		if strings.Contains(registryURL, registry) || strings.Contains(registry, registryURL) {
			klog.V(4).Infof("Found credentials for registry: %s (partial match with %s)", registryURL, registry)
			result := &cri.AuthConfig{
				Username:      entry.Username,
				Password:      entry.Password,
				Auth:          entry.Auth,
				ServerAddress: registryURL,
				IdentityToken: entry.IdentityToken,
				RegistryToken: entry.RegistryToken,
			}
			normalizeAuthConfig(result)
			return result, true
		}
	}

	klog.V(5).Infof("No credential match found for %s", registryURL)
	return nil, false
}

// NewDockerKeyring creates a new empty keyring.
func NewDockerKeyring() DockerKeyring {
	return &BasicDockerKeyring{}
}
