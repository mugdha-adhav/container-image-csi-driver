package secret

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// init registers the GCR credential provider
func init() {
	RegisterCredentialProvider("gcp-credential-provider", NewGCRProvider)
}

// gcrProvider is the GCP implementation of DockerConfigProvider
type gcrProvider struct {
	cache          *credentialsCache
	metadataClient *http.Client
}

var _ DockerConfigProvider = &gcrProvider{}

// NewGCRProvider creates a DockerConfigProvider for Google Container Registry.
func NewGCRProvider(opts ...DockerConfigProviderOpts) DockerConfigProvider {
	return &gcrProvider{
		cache: &credentialsCache{
			cacheTimeout: 5 * time.Minute,
			mutex:        &sync.RWMutex{},
		},
		metadataClient: &http.Client{
			Timeout: time.Second * 10,
		},
	}
}

// Enabled implements DockerConfigProvider.Enabled
func (p *gcrProvider) Enabled() bool {
	return true
}

// Provide returns a DockerConfig with credentials for Google Container Registry.
func (p *gcrProvider) Provide(image string) DockerConfig {
	// Check if this is a GCR image
	registry := parseGCRRegistryName(image)
	if registry == "" {
		klog.V(5).Infof("GCR credentials not available: image %s is not from GCR", image)
		return DockerConfig{}
	}

	// Get credentials from cache if available
	credentials, found := p.cache.get(registry)
	if found {
		klog.V(4).Infof("Using cached GCR credentials for %s", registry)
		return credentials
	}

	// Get a token from GCP
	username, password, err := p.getGCRToken()
	if err != nil {
		klog.V(4).Infof("Failed to get GCR credentials: %v", err)
		return DockerConfig{}
	}

	// Store credentials in cache
	dockerConfig := DockerConfig{
		registry: DockerConfigEntry{
			Username: username,
			Password: password,
		},
	}
	p.cache.set(registry, dockerConfig)

	return dockerConfig
}

// getGCRToken fetches an access token for GCR
func (p *gcrProvider) getGCRToken() (string, string, error) {
	// First try using metadata server for GKE/GCE environments
	accessToken, err := p.getTokenFromMetadataServer()
	if err == nil {
		klog.V(4).Info("Using GCP metadata server credentials for GCR")
		return "oauth2accesstoken", accessToken, nil
	}

	klog.V(4).Infof("GCP metadata server credentials not available: %v", err)

	// Next try using application default credentials
	accessToken, err = p.getTokenFromApplicationDefaultCredentials()
	if err == nil {
		klog.V(4).Info("Using GCP application default credentials for GCR")
		return "oauth2accesstoken", accessToken, nil
	}

	klog.V(4).Infof("GCP application default credentials not available: %v", err)

	// Next try to use a service account key file if specified
	accessToken, err = p.getTokenFromServiceAccountKey()
	if err == nil {
		klog.V(4).Info("Using GCP service account key for GCR")
		return "oauth2accesstoken", accessToken, nil
	}

	return "", "", fmt.Errorf("failed to get GCR credentials from any source")
}

// getTokenFromMetadataServer gets a token using the GCE metadata server
func (p *gcrProvider) getTokenFromMetadataServer() (string, error) {
	metadataURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.metadataClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata response: %v", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	err = json.Unmarshal(bodyBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse metadata response: %v", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("metadata response did not contain an access token")
	}

	return tokenResp.AccessToken, nil
}

// getTokenFromApplicationDefaultCredentials gets a token using application default credentials
func (p *gcrProvider) getTokenFromApplicationDefaultCredentials() (string, error) {
	// Look for application default credentials
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath == "" {
		// Check well-known locations
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not get user home directory: %v", err)
		}

		credPath = filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		if _, err := os.Stat(credPath); os.IsNotExist(err) {
			return "", fmt.Errorf("application default credentials not found")
		}
	}

	// If we found credentials, try to get an access token
	// This is a simplified version - in reality we would use the Google SDK
	// to handle this properly
	data, err := os.ReadFile(credPath)
	if err != nil {
		return "", fmt.Errorf("failed to read application default credentials: %v", err)
	}

	var creds struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}

	err = json.Unmarshal(data, &creds)
	if err != nil {
		return "", fmt.Errorf("failed to parse application default credentials: %v", err)
	}

	// In a real implementation we would use these credentials to fetch a token
	// Here we just return an error since this would require complex OAuth2 flow
	return "", fmt.Errorf("application default credentials found but OAuth2 flow not implemented")
}

// getTokenFromServiceAccountKey gets a token using a service account key
func (p *gcrProvider) getTokenFromServiceAccountKey() (string, error) {
	// Look for service account key file
	keyPath := os.Getenv("GOOGLE_SERVICE_ACCOUNT_KEY_FILE")
	if keyPath == "" {
		// Check well-known locations
		keyPath = "/var/run/secrets/google/key.json"
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			return "", fmt.Errorf("service account key not found")
		}
	}

	// If we found a key, try to get an access token
	// This is a simplified version - in reality we would use the Google SDK
	// to handle this properly
	_, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account key: %v", err)
	}

	// In a real implementation we would use this key to fetch a token
	// Here we just return an error since this would require complex JWT signing
	return "", fmt.Errorf("service account key found but JWT signing not implemented")
}

// parseGCRRegistryName extracts the GCR registry name from an image name.
func parseGCRRegistryName(image string) string {
	// Handle cases like:
	// gcr.io/project/image:tag
	// us.gcr.io/project/image:tag
	// asia.gcr.io/project/image:tag
	// eu.gcr.io/project/image:tag
	// pkg.dev/project/image:tag (Artifact Registry)

	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 0 {
		return ""
	}

	registry := parts[0]
	if strings.HasSuffix(registry, ".gcr.io") || strings.HasSuffix(registry, ".pkg.dev") {
		return registry
	}

	return ""
}
