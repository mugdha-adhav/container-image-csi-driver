package secret

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"k8s.io/klog/v2"
)

// init registers the ECR credential provider
func init() {
	RegisterCredentialProvider("ecr-credential-provider", NewECRProvider)
}

// ecrProvider is the AWS ECR implementation of DockerConfigProvider
type ecrProvider struct {
	cache       *credentialsCache
	client      ecrTokenClient
	expiration  time.Duration
	awsSdkDebug bool
}

var _ DockerConfigProvider = &ecrProvider{}

// ecrTokenClient is the interface for the AWS ECR client
type ecrTokenClient interface {
	GetAuthorizationToken(ctx context.Context, params *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

// NewECRProvider creates a DockerConfigProvider for the Amazon Elastic Container Registry.
func NewECRProvider(opts ...DockerConfigProviderOpts) DockerConfigProvider {
	// Create a context for configuration loading
	ctx := context.Background()

	klog.V(2).Infof("Initializing AWS ECR credential provider")

	// Load the AWS SDK configuration with explicit options for better instance metadata handling
	cfg, err := config.LoadDefaultConfig(ctx,
		// Make sure we have enough retries
		config.WithRetryMaxAttempts(5),
		// Default credentials chain will check env vars, instance profiles, etc.
	)

	if err != nil {
		klog.Warningf("Failed to load AWS SDK config: %v", err)
		// We continue anyway, as the client may still work in some environments
	} else {
		klog.V(2).Infof("Successfully loaded AWS SDK config")
	}

	ecrProvider := &ecrProvider{
		cache: &credentialsCache{
			cacheTimeout: 5 * time.Minute,
			mutex:        &sync.RWMutex{},
		},
		client:      ecr.NewFromConfig(cfg),
		expiration:  12 * time.Hour,
		awsSdkDebug: true, // Always enable debug for now to help with troubleshooting
	}

	// If requested, enable AWS SDK debug logging
	for _, opt := range opts {
		if opt.UseAwsSdkDebugLog != nil && *opt.UseAwsSdkDebugLog {
			ecrProvider.awsSdkDebug = true
		}
	}

	return ecrProvider
}

// Enabled implements DockerConfigProvider.Enabled
func (p *ecrProvider) Enabled() bool {
	return true
}

// Provide returns a DockerConfig with credentials from the Amazon Elastic Container Registry.
func (p *ecrProvider) Provide(image string) DockerConfig {
	klog.V(2).Infof("ECR provider checking image: %s", image)

	parsed, err := parseRepoURL(image)
	if err != nil {
		klog.V(5).Infof("ECR credentials not provided for %s: failed to parse repository: %v", image, err)
		return DockerConfig{}
	}

	if parsed == nil {
		klog.V(5).Infof("ECR credentials not provided for %s: not an ECR repository", image)
		return DockerConfig{}
	}

	klog.V(2).Infof("ECR provider identified registry %s in region %s", parsed.registry, parsed.region)

	// Get credentials from cache if available
	credentials, found := p.cache.get(parsed.registry)
	if found {
		klog.V(4).Infof("Using cached ECR credentials for %s", parsed.registry)
		return credentials
	}

	klog.V(2).Infof("No cached credentials found for %s, fetching new token", parsed.registry)

	// Extract account ID from registry for explicit authentication
	accountID := parsed.registry
	if strings.Contains(accountID, ".") {
		accountID = strings.Split(accountID, ".")[0]
	}

	klog.V(2).Infof("Using account ID: %s for ECR authentication", accountID)

	// Get a token from the Amazon ECR service
	authorizationToken, err := p.getAuthorizationToken(accountID, parsed.region)
	if err != nil {
		klog.Warningf("Failed to get ECR credentials for %s: %v", parsed.registry, err)
		return DockerConfig{}
	}

	// Extract username and password from the token
	username, password, err := decodeTokenResponse(authorizationToken)
	if err != nil {
		klog.Warningf("Failed to decode ECR token for %s: %v", parsed.registry, err)
		return DockerConfig{}
	}

	klog.V(2).Infof("Successfully obtained ECR credentials for %s", parsed.registry)

	// Store credentials in cache
	dockerConfig := DockerConfig{
		parsed.registry: DockerConfigEntry{
			Username: username,
			Password: password,
			Email:    "not@val.id",
		},
	}
	p.cache.set(parsed.registry, dockerConfig)

	return dockerConfig
}

// getAuthorizationToken gets an authorization token from the Amazon ECR service
func (p *ecrProvider) getAuthorizationToken(registryID, region string) (*types.AuthorizationData, error) {
	ctx := context.Background()
	var input *ecr.GetAuthorizationTokenInput

	klog.V(3).Infof("ECR: Getting authorization token for registry ID %s in region %s", registryID, region)

	if registryID == "" {
		// If no registryID is provided, get authorization token for current registry
		input = &ecr.GetAuthorizationTokenInput{}
	} else {
		// If a registryID is provided, get authorization token for that registry
		input = &ecr.GetAuthorizationTokenInput{
			RegistryIds: []string{registryID},
		}
	}

	// Create a new ECR client using the correct region
	client := p.client
	if region != "" {
		klog.V(3).Infof("Creating region-specific ECR client for %s", region)
		// Load config with the specified region
		cfg, err := config.LoadDefaultConfig(ctx,
			config.WithRegion(region),
			config.WithRetryMaxAttempts(5),
		)
		if err == nil {
			client = ecr.NewFromConfig(cfg)
		} else {
			klog.Warningf("Failed to create region-specific ECR client: %v", err)
		}
	}

	// Log request info if debug is enabled
	if p.awsSdkDebug {
		klog.V(2).Infof("AWS ECR Request: GetAuthorizationToken for registry: %s in region %s", registryID, region)
	}

	// Get authorization token with timeout
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	output, err := client.GetAuthorizationToken(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("error getting authorization token from ECR: %v", err)
	}

	if output == nil || len(output.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data received from ECR")
	}

	klog.V(2).Info("Successfully obtained ECR authorization token")
	return &output.AuthorizationData[0], nil
}

// decodeTokenResponse decodes the response from the ECR API
func decodeTokenResponse(authData *types.AuthorizationData) (string, string, error) {
	if authData == nil {
		return "", "", fmt.Errorf("authorization data is nil")
	}

	if authData.AuthorizationToken == nil || *authData.AuthorizationToken == "" {
		return "", "", fmt.Errorf("authorization token is nil or empty")
	}

	decodedToken, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode authorization token: %v", err)
	}

	parts := strings.SplitN(string(decodedToken), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid authorization token format")
	}

	return parts[0], parts[1], nil
}

// ecrURL represents an ECR repository URL broken down into components
type ecrURL struct {
	registry string
	region   string
}

// parseRepoURL parses an ECR repository URL into components
func parseRepoURL(image string) (*ecrURL, error) {
	parts := strings.Split(image, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid image name: %s", image)
	}

	registry := parts[0]

	// Log what we're checking
	klog.V(4).Infof("ECR: Checking if %s is an ECR registry", registry)

	// Check if this is an ECR registry
	if strings.HasSuffix(registry, ".amazonaws.com") && strings.Contains(registry, ".dkr.ecr.") {
		klog.V(2).Infof("ECR: Detected ECR registry %s", registry)

		// Parse the region from the registry
		regParts := strings.Split(registry, ".")
		if len(regParts) < 6 {
			klog.Warningf("ECR: Invalid ECR registry format: %s", registry)
			return nil, fmt.Errorf("invalid ECR registry: %s", registry)
		}

		region := regParts[3]
		klog.V(2).Infof("ECR: Detected region %s for registry %s", region, registry)
		return &ecrURL{
			registry: registry,
			region:   region,
		}, nil
	}

	// Not an ECR URL
	klog.V(5).Infof("ECR: %s is not an ECR registry", registry)
	return nil, nil
}
