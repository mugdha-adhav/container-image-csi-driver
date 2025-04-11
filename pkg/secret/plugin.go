package secret

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"encoding/base64"

	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
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
func GetCredentialFromPlugin(image string) (*cri.AuthConfig, error) {
	registeredPluginsLock.RLock()
	defer registeredPluginsLock.RUnlock()

	klog.V(2).Infof("Getting credentials from plugins for image: %s", image)
	klog.V(2).Infof("Number of registered plugins: %d", len(registeredPlugins))

	if len(registeredPlugins) == 0 {
		klog.V(2).Info("No credential provider plugins registered")
		return nil, nil
	}

	// For simplicity, we'll try each registered plugin
	for name, plugin := range registeredPlugins {
		klog.V(2).Infof("Trying plugin %s for image %s", name, image)
		auth, err := callPlugin(plugin, image)
		if err != nil {
			klog.V(2).Infof("Plugin %s failed: %v", name, err)
			continue
		}
		if auth != nil {
			klog.V(2).Infof("Plugin %s returned credentials with username: %s", name, auth.Username)
			klog.V(2).Infof("Auth token length: %d", len(auth.Password))
			return auth, nil
		}
		klog.V(2).Infof("Plugin %s returned no credentials", name)
	}

	klog.V(2).Info("No credentials found from any plugin")
	return nil, nil
}

// callPlugin executes the specified plugin to get credentials.
func callPlugin(plugin PluginConfig, image string) (*cri.AuthConfig, error) {
	// Check if this is a docker credential helper (naming convention: docker-credential-*)
	if strings.HasPrefix(filepath.Base(plugin.Executable), "docker-credential-") {
		klog.V(2).Infof("Executing docker credential helper: %s for image %s", plugin.Name, image)
		// Docker credential helpers expect the server URL on stdin and use "get" command
		cmd := exec.Command(plugin.Executable, "get")

		// Extract server URL from image
		serverURL, err := extractServerURL(image)
		if err != nil {
			return nil, fmt.Errorf("failed to extract server URL from image %s: %w", image, err)
		}

		klog.V(2).Infof("Using server URL: %s", serverURL)

		// Set up pipes for stdin/stdout/stderr
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin pipe for plugin %s: %w", plugin.Name, err)
		}

		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Set environment variables
		cmd.Env = os.Environ()
		for _, env := range plugin.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
		}

		// Start the command
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start plugin %s: %w", plugin.Name, err)
		}

		// Write server URL to stdin - strip https:// prefix as docker credential helpers expect bare domain
		inputURL := strings.TrimPrefix(serverURL, "https://")
		if _, err := stdin.Write([]byte(inputURL + "\n")); err != nil {
			return nil, fmt.Errorf("failed to write to stdin of plugin %s: %w", plugin.Name, err)
		}
		stdin.Close()

		// Wait for the command to complete
		if err := cmd.Wait(); err != nil {
			stderrOutput := stderr.String()
			if stderrOutput != "" {
				klog.Errorf("Plugin %s stderr output: %s", plugin.Name, stderrOutput)
			}
			return nil, fmt.Errorf("failed to execute plugin %s: %w (stderr: %s)", plugin.Name, err, stderrOutput)
		}

		// Get output from stdout
		output := []byte(stdout.String())
		klog.V(2).Infof("Plugin %s raw output length: %d", plugin.Name, len(output))
		if len(output) > 0 {
			klog.V(2).Infof("Plugin %s first 20 chars of output: %s", plugin.Name, string(output)[:min(20, len(output))])
		}

		klog.V(2).Infof("Bare output returned by the plugin: %s", string(output))

		// Parse JSON output from ECR credential helper directly into struct we need
		// The output format is {"ServerURL":"...","Username":"...","Secret":"..."}
		var pluginOutput struct {
			ServerURL string `json:"ServerURL"`
			Username  string `json:"Username"`
			Secret    string `json:"Secret"`
		}

		if err := json.Unmarshal(output, &pluginOutput); err != nil {
			return nil, fmt.Errorf("failed to parse plugin %s output: %w", plugin.Name, err)
		}

		klog.V(2).Infof("Parsed credentials - Username: %s, Secret length: %d, ServerURL: %s",
			pluginOutput.Username, len(pluginOutput.Secret), pluginOutput.ServerURL)

		// Directly create and return CRI AuthConfig
		auth := &cri.AuthConfig{
			ServerAddress: pluginOutput.ServerURL,
			Username:      pluginOutput.Username,
			Password:      pluginOutput.Secret,
		}

		// Set the Auth field for ECR format (base64 encoded USERNAME:PASSWORD)
		// This is required by ECR as mentioned in AWS documentation
		if pluginOutput.Username != "" && pluginOutput.Secret != "" {
			authStr := fmt.Sprintf("%s:%s", pluginOutput.Username, pluginOutput.Secret)
			auth.Auth = base64.StdEncoding.EncodeToString([]byte(authStr))
		}

		return auth, nil
	} else {
		// Use the original custom plugin format (--image parameter)
		cmd := exec.Command(plugin.Executable)
		cmd.Args = append(cmd.Args, plugin.Args...)
		cmd.Args = append(cmd.Args, "--image="+image)

		klog.V(2).Infof("Executing custom credential plugin: %s for image %s", plugin.Name, image)

		// Set environment variables
		cmd.Env = os.Environ()
		for _, env := range plugin.Env {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", env.Name, env.Value))
		}

		// Set up pipes to capture stderr
		var stderr strings.Builder
		cmd.Stderr = &stderr

		// Execute the command
		output, err := cmd.Output()
		if err != nil {
			// Log the stderr output to help with debugging
			stderrOutput := stderr.String()
			if stderrOutput != "" {
				klog.Errorf("Plugin %s stderr output: %s", plugin.Name, stderrOutput)
			}
			return nil, fmt.Errorf("failed to execute plugin %s: %w (stderr: %s)", plugin.Name, err, stderrOutput)
		}

		klog.V(2).Infof("Plugin %s raw output length: %d", plugin.Name, len(output))
		if len(output) > 0 {
			klog.V(2).Infof("Plugin %s first 20 chars of output: %s", plugin.Name, string(output)[:min(20, len(output))])
		}

		// Parse the output - this already returns a CRI AuthConfig directly
		var response struct {
			Auth *cri.AuthConfig `json:"auth"`
		}

		// Trim any leading/trailing whitespace
		outputStr := strings.TrimSpace(string(output))
		if err := json.Unmarshal([]byte(outputStr), &response); err != nil {
			return nil, fmt.Errorf("failed to parse plugin %s output: %w", plugin.Name, err)
		}

		if response.Auth != nil {
			klog.V(2).Infof("Parsed auth - Username: %s, Password length: %d",
				response.Auth.Username, len(response.Auth.Password))
			if len(response.Auth.Password) > 0 {
				klog.V(2).Infof("First 20 chars of password: %s",
					response.Auth.Password[:min(20, len(response.Auth.Password))])
			}
		}

		return response.Auth, nil
	}
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// extractServerURL extracts the server/registry URL from an image reference
// For example, "672327909798.dkr.ecr.us-east-1.amazonaws.com/warm-metal/ecr-test-image"
// would return "https://672327909798.dkr.ecr.us-east-1.amazonaws.com"
func extractServerURL(image string) (string, error) {
	// Handle image references with and without tags/digests
	// Format: [registry/]repository[:tag][@digest]
	parts := strings.Split(image, "/")
	if len(parts) == 1 {
		// No registry specified, assume Docker Hub
		return "https://index.docker.io", nil
	}

	// Check if the first part looks like a registry (contains "." or ":")
	if strings.ContainsAny(parts[0], ".:") {
		// It's a registry
		return "https://" + parts[0], nil
	}

	// Check if this is a Docker Hub namespaced repository
	if len(parts) >= 2 && !strings.ContainsAny(parts[0], ".:") {
		return "https://index.docker.io", nil
	}

	return "", fmt.Errorf("could not extract server URL from image: %s", image)
}
