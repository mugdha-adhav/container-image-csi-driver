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
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
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

// Note: Built-in cloud providers (ECR, ACR, GCR) have been removed
// Only Kubernetes secrets and external credential provider plugins are supported now

// pluginDockerKeyring is a DockerKeyring implementation that uses credential provider plugins
type pluginDockerKeyring struct{}

// Lookup implements DockerKeyring
func (dk *pluginDockerKeyring) Lookup(image string) ([]*cri.AuthConfig, bool) {
	auth, err := GetCredentialFromPlugin(image)
	if err != nil {
		klog.Warningf("Error getting credentials from plugin for image %s: %v", image, err)
		return nil, false
	}

	if auth != nil {
		klog.V(2).Infof("Found credentials for image %s using credential provider plugin", image)
		return []*cri.AuthConfig{auth}, true
	}

	return nil, false
}

// createPluginBasedKeyring creates a new keyring that uses credential provider plugins
func createPluginBasedKeyring() DockerKeyring {
	return &pluginDockerKeyring{}
}

// combinedKeyringStore combines Kubernetes secrets with plugin-based credentials
type combinedKeyringStore struct {
	secretKeyring persistentKeyringGetter
}

// GetDockerKeyring combines Kubernetes secrets with plugin-based credentials
func (s combinedKeyringStore) GetDockerKeyring(ctx context.Context, secretData map[string]string) (keyring DockerKeyring, err error) {
	var preferredKeyring DockerKeyring
	if len(secretData) > 0 {
		preferredKeyring, err = makeDockerKeyringFromMap(secretData)
		if err != nil {
			return nil, err
		}
	}

	secretKeyring := s.secretKeyring.Get(ctx)
	pluginKeyring := createPluginBasedKeyring()

	// Create a union keyring that checks:
	// 1. Preferred keyring (from volume context)
	// 2. Kubernetes secrets (from service account)
	// 3. Credential provider plugins
	combinedKeyring := UnionDockerKeyring{secretKeyring, pluginKeyring}

	if preferredKeyring != nil {
		return UnionDockerKeyring{preferredKeyring, combinedKeyring}, nil
	}

	return combinedKeyring, nil
}

// createCombinedStoreOrDie creates a store that combines K8s secrets with plugins
func createCombinedStoreOrDie(nodePluginSA string) Store {
	// Get base keyring getter from k8s secrets
	secretFetcher := createSecretFetcher(nodePluginSA)

	// Wrap in a combined store
	return combinedKeyringStore{
		secretKeyring: secretFetcher,
	}
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

		// Use combined store with plugin support
		return createCombinedStoreOrDie(nodePluginSA)
	}

	// If no plugin config is provided, fall back to just Kubernetes secrets
	if enableCache {
		return createCacheOrDie(nodePluginSA)
	} else {
		return createFetcherOrDie(nodePluginSA)
	}
}
