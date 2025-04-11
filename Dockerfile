FROM docker.io/library/golang:1.24.1-alpine3.21 as builder
RUN apk add --no-cache btrfs-progs-dev lvm2-dev make build-base
WORKDIR /go/src/container-image-csi-driver
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY pkg ./pkg
COPY Makefile ./
RUN make build
RUN make install-util

FROM scratch as install-util
COPY --from=builder /go/src/container-image-csi-driver/_output/warm-metal-csi-image-install /

FROM alpine:3.21.3
RUN apk add --no-cache btrfs-progs-dev lvm2-dev
WORKDIR /
COPY --from=builder /go/src/container-image-csi-driver/_output/csi-image-plugin /usr/bin/

# Create directory for credential provider
RUN mkdir -p /opt/image-credential-providers

# Copy the local ECR credential helper binary
COPY bin/docker-credential-ecr-login /opt/image-credential-providers/docker-credential-ecr-login
RUN chmod +x /opt/image-credential-providers/docker-credential-ecr-login

# Create credential provider configuration file
RUN echo '{ \
    "kind": "CredentialProviderConfig", \
    "apiVersion": "credentialprovider.kubelet.k8s.io/v1", \
    "providers": [ \
      { \
        "name": "docker-credential-ecr-login", \
        "apiVersion": "credentialprovider.kubelet.k8s.io/v1", \
        "args": [] \
      } \
    ] \
  }' > /opt/image-credential-providers/config.json

ENTRYPOINT ["csi-image-plugin"]
