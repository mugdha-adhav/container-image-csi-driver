package secret

import (
	"context"
	"encoding/json"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// Store is an interface for retrieving Docker credentials.
type Store interface {
	GetDockerKeyring(ctx context.Context, secrets map[string]string) (DockerKeyring, error)
}

func makeDockerKeyringFromSecrets(secrets []corev1.Secret) (DockerKeyring, error) {
	keyring := &BasicDockerKeyring{}
	for _, secret := range secrets {
		if len(secret.Data) == 0 {
			continue
		}

		cred, err := parseDockerConfigFromSecretData(byteSecretData(secret.Data))
		if err != nil {
			klog.Errorf(`unable to parse secret %s, %#v`, err, secret)
			return nil, err
		}

		keyring.Add(cred)
	}

	return keyring, nil
}

func makeDockerKeyringFromMap(secretData map[string]string) (DockerKeyring, error) {
	keyring := &BasicDockerKeyring{}
	if len(secretData) > 0 {
		cred, err := parseDockerConfigFromSecretData(stringSecretData(secretData))
		if err != nil {
			klog.Errorf(`unable to parse secret data %s, %#v`, err, secretData)
			return nil, err
		}

		keyring.Add(cred)
	}

	return keyring, nil
}

type secretDataWrapper interface {
	Get(key string) (data []byte, existed bool)
}

type byteSecretData map[string][]byte

func (b byteSecretData) Get(key string) (data []byte, existed bool) {
	data, existed = b[key]
	return
}

type stringSecretData map[string]string

func (s stringSecretData) Get(key string) (data []byte, existed bool) {
	strings, existed := s[key]
	if existed {
		data = []byte(strings)
	}

	return
}

func parseDockerConfigFromSecretData(data secretDataWrapper) (DockerConfig, error) {
	if dockerConfigJSONBytes, existed := data.Get(corev1.DockerConfigJsonKey); existed {
		if len(dockerConfigJSONBytes) > 0 {
			dockerConfigJSON := DockerConfigJSON{}
			if err := json.Unmarshal(dockerConfigJSONBytes, &dockerConfigJSON); err != nil {
				return nil, err
			}

			return dockerConfigJSON.Auths, nil
		}
	}

	if dockercfgBytes, existed := data.Get(corev1.DockerConfigKey); existed {
		if len(dockercfgBytes) > 0 {
			dockercfg := DockerConfig{}
			if err := json.Unmarshal(dockercfgBytes, &dockercfg); err != nil {
				return nil, err
			}
			return dockercfg, nil
		}
	}

	return nil, nil
}

type persistentKeyringGetter interface {
	Get(context.Context) DockerKeyring
}

type keyringStore struct {
	persistentKeyringGetter
}

func (s keyringStore) GetDockerKeyring(ctx context.Context, secretData map[string]string) (keyring DockerKeyring, err error) {
	var preferredKeyring DockerKeyring
	if len(secretData) > 0 {
		preferredKeyring, err = makeDockerKeyringFromMap(secretData)
		if err != nil {
			return nil, err
		}
	}

	daemonKeyring := s.Get(ctx)
	if preferredKeyring != nil {
		return UnionDockerKeyring{preferredKeyring, daemonKeyring}, nil
	}

	return UnionDockerKeyring{daemonKeyring, NewDockerKeyring()}, err
}

type secretFetcher struct {
	Client       *kubernetes.Clientset
	nodePluginSA string
	Namespace    string
}

func (f secretFetcher) Fetch(ctx context.Context) ([]corev1.Secret, error) {
	sa, err := f.Client.CoreV1().ServiceAccounts(f.Namespace).Get(ctx, f.nodePluginSA, metav1.GetOptions{})
	if err != nil {
		klog.Errorf(`unable to fetch service account of the daemon pod "%s/%s": %s`, f.Namespace, f.nodePluginSA, err)
		return nil, err
	}

	secrets := make([]corev1.Secret, len(sa.ImagePullSecrets))
	klog.V(2).Infof(
		`got %d imagePullSecrets from the service account %s/%s`, len(sa.ImagePullSecrets), f.Namespace, f.nodePluginSA,
	)

	for i := range sa.ImagePullSecrets {
		s := &sa.ImagePullSecrets[i]
		secret, err := f.Client.CoreV1().Secrets(f.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
		if err != nil {
			klog.Errorf(`unable to fetch secret "%s/%s": %s`, f.Namespace, s.Name, err)
			continue
		}

		secrets[i] = *secret
	}

	return secrets, nil
}

func (s secretFetcher) Get(ctx context.Context) DockerKeyring {
	secrets, _ := s.Fetch(ctx)
	keyring, _ := makeDockerKeyringFromSecrets(secrets)
	return keyring
}

func createSecretFetcher(nodePluginSA string) *secretFetcher {
	config, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("unable to get cluster config: %s", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatalf("unable to get cluster client: %s", err)
	}

	curNamespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		klog.Fatalf("unable to fetch the current namespace from the sa volume: %q", err.Error())
	}

	return &secretFetcher{
		Client:       clientset,
		nodePluginSA: nodePluginSA,
		Namespace:    string(curNamespace),
	}
}

func createFetcherOrDie(nodePluginSA string) Store {
	return keyringStore{
		persistentKeyringGetter: createSecretFetcher(nodePluginSA),
	}
}

type secretWOCache struct {
	daemonKeyring DockerKeyring
}

func (s secretWOCache) Get(_ context.Context) DockerKeyring {
	return s.daemonKeyring
}

func createCacheOrDie(nodePluginSA string) Store {
	fetcher := createSecretFetcher(nodePluginSA)
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	var keyring DockerKeyring
	secrets, _ := fetcher.Fetch(ctx)
	keyring, _ = makeDockerKeyringFromSecrets(secrets)
	return keyringStore{
		persistentKeyringGetter: secretWOCache{
			daemonKeyring: keyring,
		},
	}
}

// createEnhancedKeyring creates a keyring that combines K8s secrets with built-in providers
func createEnhancedKeyring(ctx context.Context, baseKeyring DockerKeyring) DockerKeyring {
	// Create a keyring for built-in providers (AWS ECR, etc.)
	providerKeyring := &providerDockerKeyring{
		providers: make([]DockerConfigProvider, 0),
	}

	// Add all registered providers to the provider keyring
	providersMutex.Lock()
	for name, factory := range providers {
		provider := factory()
		if provider != nil && provider.Enabled() {
			klog.Infof("Using credential provider: %s", name)
			providerKeyring.providers = append(providerKeyring.providers, provider)
		}
	}
	providersMutex.Unlock()

	// Return a union keyring that tries the base keyring first, then the provider keyring
	return UnionDockerKeyring{baseKeyring, providerKeyring}
}

// createEnhancedCacheOrDie creates a store that combines K8s secrets with built-in providers and caches results
func createEnhancedCacheOrDie(nodePluginSA string) Store {
	fetcher := createSecretFetcher(nodePluginSA)
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	// Get base keyring from k8s secrets
	baseSecrets, _ := fetcher.Fetch(ctx)
	baseKeyring, _ := makeDockerKeyringFromSecrets(baseSecrets)

	// Create enhanced keyring with provider support
	enhancedKeyring := createEnhancedKeyring(ctx, baseKeyring)

	// Wrap in a store
	return keyringStore{
		persistentKeyringGetter: secretWOCache{
			daemonKeyring: enhancedKeyring,
		},
	}
}

// createEnhancedFetcherOrDie creates a store that combines K8s secrets with built-in providers
func createEnhancedFetcherOrDie(nodePluginSA string) Store {
	return &enhancedFetcherStore{
		secretFetcher: createSecretFetcher(nodePluginSA),
	}
}

// enhancedFetcherStore is a Store that combines secrets with built-in providers
type enhancedFetcherStore struct {
	secretFetcher *secretFetcher
}

// GetDockerKeyring returns a keyring combining secrets and built-in providers
func (s *enhancedFetcherStore) GetDockerKeyring(ctx context.Context, secretData map[string]string) (DockerKeyring, error) {
	var preferredKeyring DockerKeyring
	if len(secretData) > 0 {
		var err error
		preferredKeyring, err = makeDockerKeyringFromMap(secretData)
		if err != nil {
			return nil, err
		}
	}

	// Get base keyring from k8s secrets
	baseKeyring := s.secretFetcher.Get(ctx)

	// Create enhanced keyring with provider support
	enhancedKeyring := createEnhancedKeyring(ctx, baseKeyring)

	// Combine with preferred keyring if provided
	if preferredKeyring != nil {
		return UnionDockerKeyring{preferredKeyring, enhancedKeyring}, nil
	}

	return enhancedKeyring, nil
}

// providerDockerKeyring is a DockerKeyring implementation that uses credential providers
type providerDockerKeyring struct {
	providers []DockerConfigProvider
}

// Lookup implements DockerKeyring
func (dk *providerDockerKeyring) Lookup(image string) ([]AuthConfig, bool) {
	// Try each provider
	for _, provider := range dk.providers {
		dockerConfig := provider.Provide(image)
		if len(dockerConfig) > 0 {
			var authConfigs []AuthConfig

			// Convert each entry in the DockerConfig to an AuthConfig
			for registry, entry := range dockerConfig {
				authConfigs = append(authConfigs, AuthConfig{
					Username: entry.Username,
					Password: entry.Password,
					Auth:     entry.Auth,
				})
				klog.V(4).Infof("Found credentials for %s using provider", registry)
			}

			return authConfigs, len(authConfigs) > 0
		}
	}

	return nil, false
}

// CreateStoreOrDie creates a credential store for container registry authentication.
// The credentials are fetched from the ServiceAccount of the driver pod.
func CreateStoreOrDie(pluginConfigFile, pluginBinDir, nodePluginSA string, enableCache bool) Store {
	// Support for dynamic plugin registration (if configured)
	if len(pluginConfigFile) > 0 && len(pluginBinDir) > 0 {
		klog.Infof("Registering credential provider plugins using config %s and binary dir %s", pluginConfigFile, pluginBinDir)
		if err := RegisterCredentialProviderPlugins(pluginConfigFile, pluginBinDir); err != nil {
			klog.Errorf("Failed to register credential provider plugins: %v", err)
		}
	}

	// Create a store with SA secrets plus built-in providers like ECR
	if enableCache {
		return createEnhancedCacheOrDie(nodePluginSA)
	} else {
		return createEnhancedFetcherOrDie(nodePluginSA)
	}
}
