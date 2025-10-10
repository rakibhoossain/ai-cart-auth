.PHONY: help build run clean test install dev build-all docker-build docker-run

APP_NAME := ai-cart-auth
VERSION := 1.0.0
BUILD_DIR := build
DOCKER_IMAGE := $(APP_NAME):$(VERSION)

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application for current platform
	@echo "Building $(APP_NAME)..."
	@go build -ldflags="-s -w" -o $(BUILD_DIR)/$(APP_NAME) .
	@echo "✓ Build complete: $(BUILD_DIR)/$(APP_NAME)"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@chmod +x build.sh
	@./build.sh

run: ## Run the application
	@echo "Starting $(APP_NAME)..."
	@go run .

dev: ## Run with auto-reload (requires air: go install github.com/cosmtrek/air@latest)
	@echo "Starting development server with auto-reload..."
	@air

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Clean complete"

install: ## Install dependencies
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "✓ Dependencies installed"

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE) .
	@echo "✓ Docker image built: $(DOCKER_IMAGE)"

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✓ Code formatted"

lint: ## Run linter (requires golangci-lint)
	@echo "Running linter..."
	@golangci-lint run
	@echo "✓ Linting complete"

.DEFAULT_GOAL := help

