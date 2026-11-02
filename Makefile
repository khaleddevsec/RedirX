# RedirX Makefile
# Production-grade build automation for Linux AMD64 and ARM64

BINARY_NAME=redirx
BUILD_DIR=bin
VERSION?=3.1.2
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

LDFLAGS=-s -w \
	-X redirx/pkg/version.Version=$(VERSION) \
	-X redirx/pkg/version.Commit=$(COMMIT) \
	-X redirx/pkg/version.BuildDate=$(BUILD_DATE)

.PHONY: all build clean test vet fmt build-linux-amd64 build-linux-arm64 build-all install

all: build-all test

build:
	@echo "==> Building $(BINARY_NAME)..."
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/redirx

build-linux-amd64:
	@echo "==> Building Linux AMD64 binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)_linux_amd64 ./cmd/redirx

build-linux-arm64:
	@echo "==> Building Linux ARM64 binary..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)_linux_arm64 ./cmd/redirx

build-all: build-linux-amd64 build-linux-arm64
	@echo "==> Release binaries built in $(BUILD_DIR)/"

test:
	@echo "==> Running test suite..."
	go test -v ./tests

test-race:
	@echo "==> Running test suite with race detector..."
	go test -race -v ./tests

vet:
	@echo "==> Running go vet..."
	go vet ./...

fmt:
	@echo "==> Formatting code..."
	go fmt ./...

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe

install:
	@echo "==> Installing $(BINARY_NAME) to GOBIN..."
	go install -ldflags "$(LDFLAGS)" ./cmd/redirx

