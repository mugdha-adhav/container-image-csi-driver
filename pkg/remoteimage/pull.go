package remoteimage

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/warm-metal/container-image-csi-driver/pkg/metrics"
	"github.com/warm-metal/container-image-csi-driver/pkg/secret"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog/v2"
)

type Puller interface {
	Pull(context.Context) error
	ImageWithTag() string
	ImageWithoutTag() string
	ImageSize(context.Context) (int, error)
}

func NewPuller(imageSvc cri.ImageServiceClient, image reference.Named,
	keyring secret.DockerKeyring) Puller {
	return &puller{
		imageSvc: imageSvc,
		image:    image,
		keyring:  keyring,
	}
}

type puller struct {
	imageSvc cri.ImageServiceClient
	image    reference.Named
	keyring  secret.DockerKeyring
}

func (p puller) ImageWithTag() string {
	return p.image.String()
}

func (p puller) ImageWithoutTag() string {
	return p.image.Name()
}

// Returns the compressed size of the image that was pulled in bytes
// see https://github.com/containerd/containerd/issues/9261
func (p puller) ImageSize(ctx context.Context) (size int, err error) {
	defer func() {
		if err != nil {
			klog.Errorf("%s", err.Error())
			metrics.OperationErrorsCount.WithLabelValues("size-error").Inc()
		}
	}()
	imageSpec := &cri.ImageSpec{Image: p.ImageWithTag()}
	if imageStatusResponse, err := p.imageSvc.ImageStatus(ctx, &cri.ImageStatusRequest{
		Image: imageSpec,
	}); err != nil {
		size = 0
		err = fmt.Errorf("remoteimage.ImageSize(): call returned an error: %s", err.Error())
		return size, err
	} else if imageStatusResponse == nil {
		size = 0
		err = fmt.Errorf("remoteimage.ImageSize(): imageStatusResponse is nil")
		return size, err
	} else if imageStatusResponse.Image == nil {
		size = 0
		err = fmt.Errorf("remoteimage.ImageSize(): imageStatusResponse.Image is nil")
		return size, err
	} else {
		size = imageStatusResponse.Image.Size()
		err = nil
		return size, err
	}
}

// formatRegistryAuth formats authentication config for all registry types
func formatRegistryAuth(registryDomain string, authConfig secret.AuthConfig) *cri.AuthConfig {
	klog.V(2).Infof("Formatting auth for registry: %s", registryDomain)
	klog.V(2).Infof("Input auth - Username: %s, Auth field present: %v, Password length: %d",
		authConfig.Username, authConfig.Auth != "", len(authConfig.Password))

	// DEBUG: Print full auth details
	if len(authConfig.Password) > 0 {
		klog.V(2).Infof("DEBUG: Input auth password full value: '%s'", authConfig.Password)
		// Check if password looks like base64
		if decodedPwd, err := base64.StdEncoding.DecodeString(authConfig.Password); err == nil {
			klog.V(2).Infof("DEBUG: Password is valid base64, decoded value: '%s'", string(decodedPwd))
		} else {
			klog.V(2).Infof("DEBUG: Password is NOT valid base64: %v", err)
		}
	}

	if authConfig.Auth != "" {
		klog.V(2).Infof("DEBUG: Input auth.Auth full value: '%s'", authConfig.Auth)
		if decodedAuth, err := base64.StdEncoding.DecodeString(authConfig.Auth); err == nil {
			klog.V(2).Infof("DEBUG: Auth is valid base64, decoded value: '%s'", string(decodedAuth))
		} else {
			klog.V(2).Infof("DEBUG: Auth is NOT valid base64: %v", err)
		}
	}

	// Create initial auth config structure
	auth := &cri.AuthConfig{
		ServerAddress: registryDomain,
		// Don't set Password/Username yet - we'll handle them differently based on registry type
		RegistryToken: authConfig.RegistryToken,
	}

	// If auth was already provided by the credential provider, use it directly
	if authConfig.Auth != "" {
		klog.V(2).Infof("Using provided auth field, length: %d", len(authConfig.Auth))
		auth.Auth = authConfig.Auth
		auth.Username = authConfig.Username
		auth.Password = authConfig.Password
		klog.V(2).Infof("DEBUG: Using existing Auth directly: '%s'", auth.Auth)
		return auth
	}

	// Special handling for ECR
	isECR := strings.Contains(registryDomain, ".dkr.ecr.") &&
		strings.Contains(registryDomain, ".amazonaws.com") &&
		authConfig.Username == "AWS"

	// Set username across all registry types
	auth.Username = authConfig.Username

	if isECR {
		klog.V(2).Infof("DEBUG: Handling ECR credentials for %s", registryDomain)

		// For ECR, try to decode the token if it's base64 encoded
		decodedToken, err := base64.StdEncoding.DecodeString(authConfig.Password)
		if err == nil {
			// Successfully decoded - try setting both options
			klog.V(2).Infof("DEBUG: Successfully decoded ECR token as base64, full decoded value: '%s'", string(decodedToken))

			// OPTION 1: Use the raw token in Auth field (containerd might expect it this way)
			// Note: raw tokens in the ECR case are JSON structures
			rawAuthJSON := fmt.Sprintf("%s:%s", auth.Username, string(decodedToken))
			encodedAuthJSON := base64.StdEncoding.EncodeToString([]byte(rawAuthJSON))
			auth.Auth = encodedAuthJSON
			auth.Password = string(decodedToken)

			klog.V(2).Infof("DEBUG: OPTION 1 - Using decoded token - Username: '%s', Password: '%s'",
				auth.Username, auth.Password)
			klog.V(2).Infof("DEBUG: OPTION 1 - Created Auth field from decoded token: '%s'", auth.Auth)
			klog.V(2).Infof("DEBUG: OPTION 1 - Decoded Auth would be: 'AWS:%s'", auth.Password)
		} else {
			// If decoding fails, use original token
			klog.V(2).Infof("DEBUG: ECR token is not base64 encoded: %v", err)
			klog.V(2).Infof("DEBUG: Using original token directly: '%s'", authConfig.Password)

			// OPTION 2: Use the raw token as-is
			auth.Password = authConfig.Password
			rawAuth := fmt.Sprintf("%s:%s", auth.Username, auth.Password)
			auth.Auth = base64.StdEncoding.EncodeToString([]byte(rawAuth))

			klog.V(2).Infof("DEBUG: OPTION 2 - Using original token - Auth: '%s'", auth.Auth)
			klog.V(2).Infof("DEBUG: OPTION 2 - Decoded Auth would be: '%s:%s'", auth.Username, auth.Password)
		}
	} else {
		// Standard Docker registry auth
		auth.Password = authConfig.Password

		// Create standard base64(username:password) auth string
		rawAuth := fmt.Sprintf("%s:%s", auth.Username, auth.Password)
		auth.Auth = base64.StdEncoding.EncodeToString([]byte(rawAuth))
		klog.V(2).Infof("DEBUG: Standard registry - Auth: '%s'", auth.Auth)
		klog.V(2).Infof("DEBUG: Standard registry - Decoded Auth would be: '%s:%s'", auth.Username, auth.Password)
	}

	klog.V(2).Infof("Final auth config - ServerAddress: %s, Username: %s, Auth present: %v, Password length: %d",
		auth.ServerAddress, auth.Username, auth.Auth != "", len(auth.Password))
	klog.V(2).Infof("DEBUG: Final Auth field: '%s'", auth.Auth)
	klog.V(2).Infof("DEBUG: Final Password field: '%s'", auth.Password)

	return auth
}

// limitString returns a substring up to maxLen characters, used for safe logging
func limitString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// isBase64Like does a simple heuristic check if a string looks like base64
func isBase64Like(s string) bool {
	// Base64 strings consist of A-Z, a-z, 0-9, +, / characters and may end with padding =
	validChars := true
	for i, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			(c == '=' && i >= len(s)-2)) {
			validChars = false
			break
		}
	}

	// Base64 encoding length is always a multiple of 4 (padded with =)
	// Allow some leeway for encoding variations but generally it should be close to multiple of 4
	return validChars && (len(s)%4 <= 2) && len(s) > 8
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func (p puller) Pull(ctx context.Context) (err error) {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime).Seconds()
		// pull time metrics and logs
		klog.Infof("remoteimage.Pull(): pulled %s in %d milliseconds", p.ImageWithTag(), int(1000*elapsed))
		metrics.ImagePullTimeHist.WithLabelValues(metrics.BoolToString(err != nil)).Observe(elapsed)
		metrics.ImagePullTime.WithLabelValues(p.ImageWithTag(), metrics.BoolToString(err != nil)).Set(elapsed)
		if err != nil {
			metrics.OperationErrorsCount.WithLabelValues("pull-error").Inc()
		}
		go func() {
			//TODO: this is a hack to ensure data is cleared in a reasonable time frame (after scrape) and does not build up.
			time.Sleep(1 * time.Minute)
			metrics.ImagePullTime.DeleteLabelValues(p.ImageWithTag(), metrics.BoolToString(err != nil))
		}()
		// pull size metrics and logs
		if err == nil { // only size if pull was successful
			if size, err2 := p.ImageSize(ctx); err2 != nil {
				// log entries and error counts emitted inside ImageSize() method
			} else { // success
				klog.Infof("remoteimage.Pull(): pulled %s with size of %d bytes", p.ImageWithTag(), size)
				metrics.ImagePullSizeBytes.WithLabelValues(p.ImageWithTag()).Set(float64(size))
				go func() {
					//TODO: this is a hack to ensure data is cleared in a reasonable time frame (after scrape) and does not build up.
					time.Sleep(1 * time.Minute)
					metrics.ImagePullSizeBytes.DeleteLabelValues(p.ImageWithTag())
				}()
			}
		}
	}()

	repo := p.ImageWithoutTag()
	imageSpec := &cri.ImageSpec{Image: p.ImageWithTag()}
	authConfigs, withCredentials := p.keyring.Lookup(repo)

	if !withCredentials {
		_, err = p.imageSvc.PullImage(ctx, &cri.PullImageRequest{
			Image: imageSpec,
		})
		klog.V(2).Infof("remoteimage.Pull(no creds): pulling %s completed with err=%v", p.ImageWithTag(), err)
		return
	}

	var pullErrs []error
	for i, authConfig := range authConfigs {
		// Extract the registry domain from the image reference
		registryDomain := extractRegistryDomain(repo)
		klog.V(2).Infof("Attempting pull %d/%d for image %s", i+1, len(authConfigs), p.ImageWithTag())

		// Get properly formatted auth config for the registry type
		auth := formatRegistryAuth(registryDomain, authConfig)
		klog.V(2).Infof("Using auth - ServerAddress: %s, Username: %s, Auth present: %v, Password length: %d",
			auth.ServerAddress, auth.Username, auth.Auth != "", len(auth.Password))

		_, err = p.imageSvc.PullImage(ctx, &cri.PullImageRequest{
			Image: imageSpec,
			Auth:  auth,
		})

		if err == nil {
			klog.V(2).Infof("Successfully pulled image %s", p.ImageWithTag())
			return
		}
		klog.V(2).Infof("Pull attempt %d failed: %v", i+1, err)
		pullErrs = append(pullErrs, err)
	}

	err = utilerrors.NewAggregate(pullErrs)
	klog.V(2).Infof("remoteimage.Pull(): completed with errors, len(pullErrs)=%d, aggErr=%s", len(pullErrs), err.Error())
	return
}

// extractRegistryDomain properly extracts the registry domain from an image reference
// It handles special cases like Docker Hub's implicit registry format
func extractRegistryDomain(imageRef string) string {
	// Split the image reference by "/"
	parts := strings.Split(imageRef, "/")

	// Case 1: No slashes or single component - Docker Hub library image
	if len(parts) == 1 {
		return "docker.io"
	}

	// Case 2: If the first part contains "." or ":", it's likely a registry domain
	// Examples: localhost:5000, myregistry.azurecr.io, 123456789012.dkr.ecr.region.amazonaws.com
	if strings.ContainsAny(parts[0], ".:") {
		return parts[0]
	}

	// Case 3: Docker Hub with username (implicit registry)
	// Example: username/repository - the registry is docker.io
	return "docker.io"
}
