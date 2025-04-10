package secret

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// init registers the Azure credential provider
func init() {
	RegisterCredentialProvider("azure-credential-provider", NewACRProvider)
}

// acrProvider is the Azure implementation of DockerConfigProvider
type acrProvider struct {
	cache       *credentialsCache
	serviceName string
	aadEndpoint string
	acrSuffix   string
	httpClient  *http.Client
}

var _ DockerConfigProvider = &acrProvider{}

// ACRRegistrySuffix is the default registry suffix for Azure Container Registry
const ACRRegistrySuffix = ".azurecr.io"

// NewACRProvider creates a DockerConfigProvider for Azure Container Registry
func NewACRProvider(opts ...DockerConfigProviderOpts) DockerConfigProvider {
	return &acrProvider{
		cache: &credentialsCache{
			cacheTimeout: 5 * time.Minute,
			mutex:        &sync.RWMutex{},
		},
		serviceName: "Azure Container Registry",
		aadEndpoint: "https://login.microsoftonline.com/",
		acrSuffix:   ACRRegistrySuffix,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled implements DockerConfigProvider.Enabled
func (p *acrProvider) Enabled() bool {
	return true
}

// Provide returns a DockerConfig with credentials for Azure Container Registry.
func (p *acrProvider) Provide(image string) DockerConfig {
	registry := parseACRRegistryName(image, p.acrSuffix)
	if registry == "" {
		klog.V(5).Infof("ACR credentials not available: image %s is not from ACR", image)
		return DockerConfig{}
	}

	// Get credentials from cache if available
	credentials, found := p.cache.get(registry)
	if found {
		klog.V(4).Infof("Using cached ACR credentials for %s", registry)
		return credentials
	}

	// Get a token from Azure
	username, password, err := p.getACRToken(registry)
	if err != nil {
		klog.V(5).Infof("Failed to get ACR credentials for %s: %v", registry, err)
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

// getACRToken gets a token from the specified registry using the Azure MSI endpoint.
func (p *acrProvider) getACRToken(registry string) (string, string, error) {
	// First try to get managed identity token
	token, err := p.getManagedIdentityToken(registry)
	if err == nil {
		klog.V(4).Infof("Got managed identity token for ACR registry %s", registry)
		return "00000000-0000-0000-0000-000000000000", token, nil
	}

	klog.V(4).Infof("Managed identity token acquisition failed for %s: %v, trying instance metadata", registry, err)

	// If managed identity failed, try IMDS endpoint
	token, err = p.getIMDSToken(registry)
	if err != nil {
		return "", "", fmt.Errorf("failed to get ACR credentials: %v", err)
	}

	return "00000000-0000-0000-0000-000000000000", token, nil
}

// getManagedIdentityToken gets a token using the managed identity endpoint
func (p *acrProvider) getManagedIdentityToken(registry string) (string, error) {
	// Azure resource ID for ACR
	resource := fmt.Sprintf("https://%s", strings.TrimSuffix(registry, p.acrSuffix))

	// Try the MSI endpoint
	msiEndpoint := "http://169.254.169.254/metadata/identity/oauth2/token"
	req, err := http.NewRequest(http.MethodGet, msiEndpoint, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("resource", resource)
	q.Add("api-version", "2018-02-01")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Metadata", "true")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query managed identity endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("managed identity endpoint returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read managed identity response: %v", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	err = json.Unmarshal(bodyBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse managed identity response: %v", err)
	}

	return tokenResp.AccessToken, nil
}

// getIMDSToken gets a token using the IMDS endpoint for VM environments
func (p *acrProvider) getIMDSToken(registry string) (string, error) {
	// This is a simplified implementation of the IMDS token acquisition
	// In production, we would use the full implementation from the Azure SDK
	msiEndpoint := "http://169.254.169.254/metadata/identity/oauth2/token"
	resource := fmt.Sprintf("https://%s", strings.TrimSuffix(registry, p.acrSuffix))

	req, err := http.NewRequest(http.MethodGet, msiEndpoint, nil)
	if err != nil {
		return "", err
	}

	q := req.URL.Query()
	q.Add("resource", resource)
	q.Add("api-version", "2018-02-01")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Metadata", "true")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query IMDS endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IMDS endpoint returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read IMDS response: %v", err)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	err = json.Unmarshal(bodyBytes, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse IMDS response: %v", err)
	}

	return tokenResp.AccessToken, nil
}

// parseACRRegistryName extracts the ACR registry name from an image name.
func parseACRRegistryName(image, acrSuffix string) string {
	// Handle cases like:
	// myregistry.azurecr.io/image:tag
	// myregistry.azurecr.io/namespace/image:tag

	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 0 {
		return ""
	}

	registry := parts[0]
	if strings.HasSuffix(registry, acrSuffix) {
		return registry
	}

	return ""
}
