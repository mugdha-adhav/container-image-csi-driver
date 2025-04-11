package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

// Hard-coded constants for ECR authentication
const (
	// Replace with your actual ECR image
	ecrImageURL = "672327909798.dkr.ecr.us-east-1.amazonaws.com/warm-metal/ecr-test-image:1.0"

	// Replace with your actual ECR token - leave blank to auto-fetch
	ecrToken = "eyJwYXlsb2FkIjoiNHJ5UXNTWVRMc3Y0OUZFK2xEQXRub0NWNmxMMGdOZWFDS2VJT3U4ellYT1RrOTQ0MGpKTk1nR2E4c1dCUmRsVm90WUF1RFBLUnJWMmkrcEN1V2xtSlZkL2xrZmxJTGw0UU05R0VaUzJNWlFrNU1MR1dIUS9kNk5hMlVsblRudHpvREpBMzZ5Qlk0c0ZxcUJqUW5pc0hIMkNnT09vTWxzN09FWkRydjdiRDNlRm5FNi9MSG1iS21Wd21pc1VYUXRjOU5XYnNOcmVLTGxEMlVOSE5CQmg5dzJNQWJYVU5rL0gyN21yUXNteTgydUhCRHhwdEw0dlg1TmtMdGNUQ0E1UDJQQmhmdmdHK1Zjd3JQc0twOUtDZDZUVUhROU9FdlI3bjZ5RGtmVXBFYVppdnQramNiSllCSUpFTjNsWSt1dEZubW04WnA1QlBBeDdNcFNlYWZTTFhUc2JYNHF4bHdITXFGbEpvUkczbnhicGpxZTdGb1JqNWhNWEhGTHJoVVFDWERRSUdYd3FVR0IwVkg4Q3pRQkJBam1EaUxJZDNPQ1VXbDRPOEJBWi85SmtpczkxalAweTJZbGVETk9JZFM2QllkOWNKWWlTZEhmc3RhYXp5dUxVU0dOamhQS0tOT3A3a09Zb21jMDBDUkZGY3M0by8wamxDNGpVL0txVU5FM20zUXNvMWVHZFFVVDlhS2ZBcmZ0bE9rSkNFSG43ZnRuRWg0cmZGZmFLSkRGa3N6TnFpYjJmd0xTbllZaDlIWm9UWjJWZlpWK2JLM0IyTDF4QWFDMU53ekdqVHZUUy9KQVRVd1pPRU5SZHQ2S0hCOWhrSDlyQVRpdTdWS1JaWTlKN0hseGEzRWV4UlV6cGdFK1NZQVdUUDdpNkZoVDBKZFR6Rm93SHppNzd4Q1ZMNVA1MVBjQlVxNlYvb2d6UWk4YWtLRzJHWDlZV3kybU5oNzVZaUpOV0d6SThpOUVBYkNtQXEvOW1SNWErSEM4MHhFQUhRcVVYcXpOdWgyeXBkL2dVZElkKzFaZjhVelh1QWJDd1kzdmVTc1ZNbVYvclAyR2sxa3BUWnp3YmNqMWhBM3hINEJRaElDbFBWcEJnL203TjdBSkRpUk1HN3NRQjhNRnpRazc4NXlZajVEcmlOZ2JNbXRaRDdlN2duUUlIYWswMDBkb0U3TzgxWkFYMXo3cDJYMjc2MWJueW5aeFJWbXNuejdianBuZzhFb0JDMVptSGIvK1Y3Rk9wNHZkV3V4dnJkZ2tZZHFsdlQ4ZUc1VVVYN3E5dUlYZHF1aFdvNlZWdGI5U0tmcXFFaTdZaW1rWFJCa09kbG5uWnpTQllFdmtTNXBIWER6NG5mRDlabzRLTU1xcjRYN1NhWHBrZkM0bTB0ZEtGMkpDc3RXT1JQOEFiQ1planFJdHpMVVErQTJkdE96Z3JYZG93eSs2TUxRQmJaY2lJVmI4aVYycllsaFhzcktpMjBtNE52RTZhMHlEY1hHeTdqamUyY05qWHdzVCtGRXN2WTRERGJISEF4TVhuWWZqWTVGRFhOVWcwQ1RBTDlPczBCbnd1N3FxYmRNbjc0VEVnRWYyeXBZSndvZzFzWXFnM01SMmZoM1BmSXUxWDZ5cXdTcmR1THk1bldGSVg5QUx6eVlGdFNCY2srU3Rod1Vzb3ZlRkZxV2xXOEVxYzc1bEY5cms9IiwiZGF0YWtleSI6IkFRRUJBSGh3bTBZYUlTSmVSdEptNW4xRzZ1cWVla1h1b1hYUGU1VUZjZTlScTgvMTR3QUFBSDR3ZkFZSktvWklodmNOQVFjR29HOHdiUUlCQURCb0Jna3Foa2lHOXcwQkJ3RXdIZ1lKWUlaSUFXVURCQUV1TUJFRURJdVF1dHQ4d2VxT25UNVpSZ0lCRUlBNzFSRWdPU2xrY21XYU85Skp0UkVmMEVTZVVwWE93L2hlMWpMYlhrdFFLeTlId3AwMmZnVnBqOUlFblZIM0NNOTBORWluN1o1UG5GWkNOMDg9IiwidmVyc2lvbiI6IjIiLCJ0eXBlIjoiREFUQV9LRVkiLCJleHBpcmF0aW9uIjoxNzQ0Mzk2MjQyfQ=="
)

// Get ECR token using AWS CLI
func getECRToken(region string) (string, error) {
	cmd := exec.Command("aws", "ecr", "get-login-password", "--region", region)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get ECR token: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}

// Test ECR authentication by making a direct registry request
func testECRAuth(registryDomain string, token string) error {
	// Test different auth formats
	authFormats := []struct {
		name   string
		header string
	}{
		// {
		// 	name: "ECR Basic Auth",
		// 	header: fmt.Sprintf("Basic %s",
		// 		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("AWS:%s", token)))),
		// },
		// {
		// 	// Docker registry v2 format
		// 	name:   "Docker V2 Basic Auth",
		// 	header: fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(token))),
		// },
		{
			// Try username:password format
			name: "Username:Password Basic Auth",
			header: fmt.Sprintf("Basic %s",
				base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("username:%s", token)))),
		},
	}

	// Print token details for debugging
	fmt.Printf("\nToken first 10 chars: %s\n", token[:10])
	fmt.Printf("Token length: %d\n", len(token))

	for _, auth := range authFormats {
		fmt.Printf("\nTesting auth format: %s\n", auth.name)

		// Create HTTP request to ECR registry API
		url := fmt.Sprintf("https://%s/v2/", registryDomain)
		fmt.Printf("Making request to: %s\n", url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		// Add auth header
		req.Header.Set("Authorization", auth.header)

		// Make the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("❌ Request failed: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		fmt.Printf("Response status: %s\n", resp.Status)
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
			fmt.Printf("✓ Authentication successful with format: %s\n", auth.name)
			return nil
		} else {
			fmt.Printf("❌ Authentication failed with format: %s (Status: %d)\n", auth.name, resp.StatusCode)
		}
	}

	return fmt.Errorf("all authentication formats failed")
}

func main() {
	// Get the token
	token := ecrToken
	if token == "" {
		fmt.Println("No token provided in constants, fetching from AWS CLI...")
		// Extract region from image URL
		region := "us-east-1" // default
		if strings.Contains(ecrImageURL, ".dkr.ecr.") && strings.Contains(ecrImageURL, ".amazonaws.com") {
			parts := strings.Split(ecrImageURL, ".")
			for i, part := range parts {
				if part == "dkr" && i+2 < len(parts) {
					region = parts[i+2]
					break
				}
			}
		}

		fetchedToken, err := getECRToken(region)
		if err != nil {
			fmt.Printf("Error fetching ECR token: %v\n", err)
			fmt.Println("Please hard-code a valid token in the ecrToken constant.")
			return
		}
		token = fetchedToken
		fmt.Printf("Successfully fetched ECR token for region %s (length: %d characters)\n", region, len(token))
	}

	// Extract registry domain from image
	var registryDomain string
	parts := strings.Split(ecrImageURL, "/")
	if len(parts) > 0 {
		registryDomain = parts[0]
	}

	fmt.Printf("\nDebug info:\n")
	fmt.Printf("- Image: %s\n", ecrImageURL)
	fmt.Printf("- Registry: %s\n", registryDomain)
	fmt.Printf("- Token Length: %d characters\n", len(token))

	// Test ECR authentication
	err := testECRAuth(registryDomain, token)
	if err != nil {
		fmt.Printf("\nFinal result: Authentication failed: %v\n", err)
	} else {
		fmt.Printf("\nFinal result: Authentication successful!\n")
	}
}
