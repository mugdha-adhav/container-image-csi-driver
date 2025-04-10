package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

// CredentialProviderConfig represents the overall configuration for
// credential provider plugins
type CredentialProviderConfig struct {
	// Kind is the type of credential provider configuration (e.g., CredentialProviderConfig)
	Kind string `json:"kind"`
	// APIVersion is the API version of this configuration (e.g., credentialprovider.kubelet.k8s.io/v1)
	APIVersion string `json:"apiVersion"`
	// Providers is a list of credential provider plugin configurations
	Providers []CredentialProvider `json:"providers"`
}

// CredentialProvider represents the configuration for a single credential provider plugin
type CredentialProvider struct {
	// Name is the required name of the credential provider. It must match the name of the
	// provider executable in the plugin directory.
	Name string `json:"name"`
	// APIVersion is the preferred API version of the credential provider plugin.
	APIVersion string `json:"apiVersion,omitempty"`
	// Args are the optional command-line arguments to pass to the plugin.
	Args []string `json:"args,omitempty"`
	// Env are the optional environment variables to set for the plugin.
	Env []EnvVar `json:"env,omitempty"`
}

// EnvVar represents an environment variable present in a Container.
type EnvVar struct {
	// Name of the environment variable.
	Name string `json:"name"`
	// Value of the environment variable.
	Value string `json:"value,omitempty"`
}

var (
	// registeredPlugins contains the list of registered plugins
	registeredPlugins     = make(map[string]PluginConfig)
	registeredPluginsLock sync.RWMutex
)

// PluginConfig contains the information needed to invoke a credential provider plugin
type PluginConfig struct {
	Name       string
	Executable string
	Args       []string
	Env        []EnvVar
	APIVersion string
}

// RegisterCredentialProviderPlugins reads the specified config file and registers
// the external credential provider plugins
func RegisterCredentialProviderPlugins(configFilePath, executableDir string) error {
	// Check if the config file exists
	if _, err := os.Stat(configFilePath); err != nil {
		return fmt.Errorf("failed to stat credential provider config file: %s: %w", configFilePath, err)
	}

	// Read the config file
	configBytes, err := os.ReadFile(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to read credential provider config file %s: %w", configFilePath, err)
	}

	// Parse the config
	config := CredentialProviderConfig{}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return fmt.Errorf("failed to parse credential provider config file %s: %w", configFilePath, err)
	}

	// Register each provider
	for _, provider := range config.Providers {
		executable := filepath.Join(executableDir, provider.Name)

		// Check if the executable exists and is executable
		if info, err := os.Stat(executable); err != nil {
			klog.Warningf("Failed to find credential provider %s at path %s: %v", provider.Name, executable, err)
			continue
		} else if info.IsDir() {
			klog.Warningf("Credential provider %s is a directory, not an executable", executable)
			continue
		}

		// Register the plugin
		registeredPluginsLock.Lock()
		registeredPlugins[provider.Name] = PluginConfig{
			Name:       provider.Name,
			Executable: executable,
			Args:       provider.Args,
			Env:        provider.Env,
			APIVersion: provider.APIVersion,
		}
		registeredPluginsLock.Unlock()

		klog.Infof("Registered credential provider %s at path %s", provider.Name, executable)
	}

	return nil
}

// GetCredentialFromPlugin attempts to get credentials from registered plugins
// for the given image.
func GetCredentialFromPlugin(image string) (*AuthConfig, error) {
	registeredPluginsLock.RLock()
	defer registeredPluginsLock.RUnlock()

	if len(registeredPlugins) == 0 {
		return nil, nil
	}

	// For simplicity, we'll try each registered plugin
	for _, plugin := range registeredPlugins {
		auth, err := callPlugin(plugin, image)
		if err == nil && auth != nil {
			return auth, nil
		}

		if err != nil {
			klog.Warningf("Failed to get credentials from plugin %s for image %s: %v", plugin.Name, image, err)
		}
	}

	return nil, nil
}

// callPlugin executes the specified plugin to get credentials.
func callPlugin(plugin PluginConfig, image string) (*AuthConfig, error) {
	// Prepare the command
	cmd := exec.Command(plugin.Executable)
	cmd.Args = append(cmd.Args, plugin.Args...)
	cmd.Args = append(cmd.Args, "--image="+image)

	// Set environment variables
	cmd.Env = os.Environ()
	for _, env := range plugin.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
	}

	// Execute the command
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute plugin %s: %w", plugin.Name, err)
	}

	// Parse the output
	var response struct {
		Auth *AuthConfig `json:"auth"`
	}

	// Trim any leading/trailing whitespace
	outputStr := strings.TrimSpace(string(output))
	if err := json.Unmarshal([]byte(outputStr), &response); err != nil {
		return nil, fmt.Errorf("failed to parse plugin %s output: %w", plugin.Name, err)
	}

	return response.Auth, nil
}
