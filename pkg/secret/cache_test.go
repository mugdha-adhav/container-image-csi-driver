package secret

import (
	"testing"
)

func TestSplitImageName(t *testing.T) {
	testCases := []struct {
		name     string
		image    string
		expected string
	}{
		{
			name:     "ECR image",
			image:    "672327909798.dkr.ecr.us-east-1.amazonaws.com/warm-metal/ecr-test-image:1.0",
			expected: "672327909798.dkr.ecr.us-east-1.amazonaws.com",
		},
		{
			name:     "JFrog image",
			image:    "edge.jfrog.ais.acquia.io/devops-pipeline-dev/kaas-container-image-csi/hello-world:linux",
			expected: "edge.jfrog.ais.acquia.io",
		},
		{
			name:     "Docker Hub image",
			image:    "warmmetal/csi-image:v1.2.6",
			expected: "docker.io",
		},
		{
			name:     "Simple image",
			image:    "nginx:latest",
			expected: "docker.io",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitImageName(tc.image)
			if len(result) == 0 || result[0] != tc.expected {
				t.Errorf("Expected %s, got %v", tc.expected, result)
			}
		})
	}
}

func TestParseRepoURL(t *testing.T) {
	testCases := []struct {
		name           string
		image          string
		expectECR      bool
		expectedRegion string
	}{
		{
			name:           "Valid ECR URL",
			image:          "672327909798.dkr.ecr.us-east-1.amazonaws.com/warm-metal/ecr-test-image:1.0",
			expectECR:      true,
			expectedRegion: "us-east-1",
		},
		{
			name:      "Non-ECR URL",
			image:     "edge.jfrog.ais.acquia.io/devops-pipeline-dev/image:tag",
			expectECR: false,
		},
		{
			name:      "Docker Hub URL",
			image:     "docker.io/library/nginx:latest",
			expectECR: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseRepoURL(tc.image)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tc.expectECR {
				if result == nil {
					t.Error("Expected ECR URL but got nil")
					return
				}
				if result.region != tc.expectedRegion {
					t.Errorf("Expected region %s, got %s", tc.expectedRegion, result.region)
				}
			} else if !tc.expectECR && result != nil {
				t.Errorf("Expected non-ECR URL but got ECR result: %+v", result)
			}
		})
	}
}
