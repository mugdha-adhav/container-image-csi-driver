#!/bin/bash

# Debug script to test ECR authentication and image pulling

# Get AWS ECR authentication token
if [ -z "$ECR_TOKEN" ]; then
  if command -v aws &> /dev/null; then
    echo "AWS CLI found, getting token..."
    AWS_REGION=${AWS_REGION:-"us-east-1"}
    ECR_TOKEN=$(aws ecr get-login-password --region $AWS_REGION)
    if [ $? -ne 0 ]; then
      echo "Failed to get ECR token. Please provide it manually using the ECR_TOKEN environment variable."
      exit 1
    fi
  else
    echo "AWS CLI not found and ECR_TOKEN not set. Please provide token using the ECR_TOKEN environment variable."
    exit 1
  fi
fi

# ECR image to pull, default can be overridden with ECR_IMAGE env var
ECR_IMAGE=${ECR_IMAGE:-"672327909798.dkr.ecr.us-east-1.amazonaws.com/warm-metal/ecr-test-image:1.0"}

# Runtime endpoint, default can be overridden with RUNTIME_ENDPOINT env var
RUNTIME_ENDPOINT=${RUNTIME_ENDPOINT:-"unix:///run/containerd/containerd.sock"}

echo "Building debug tool..."
go build -o ecr-debug test/ecr-debug.go

echo "Running ECR debug tool..."
./ecr-debug --image="$ECR_IMAGE" --token="$ECR_TOKEN" --runtime-endpoint="$RUNTIME_ENDPOINT"