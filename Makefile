.PHONY: build test test-auth test-protocols web-build test-web-e2e test-prod-config release-bundle verify verify-prod clean generate migrate-up migrate-down docker-build lint run dev-init

BINARY := bin/sftpxy
CONFIG ?= $(shell if [ -f config.local.yaml ]; then echo config.local.yaml; elif [ -f config.yaml ]; then echo config.yaml; else echo config.yaml.example; fi)

# Build the application
build:
	@echo "Building SFTPxy..."
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/sftpxy
	@echo "Build complete: $(BINARY)"

# Run tests
test:
	@echo "Running tests..."
	go test -count=1 -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Run authentication-focused tests
test-auth:
	@echo "Running auth and HTTP auth tests..."
	go test ./internal/auth ./internal/protocols/httpd ./internal/config

# Run protocol regression tests
test-protocols:
	@echo "Running protocol regression tests..."
	go test -count=1 -v ./internal/protocols/ssh ./internal/protocols/ftp ./internal/protocols/webdav

# Build the web assets used by the HTTP server
web-build:
	@echo "Building web assets..."
	npm --prefix web run build

# Run browser E2E tests for WebAdmin and WebClient
test-web-e2e: build web-build
	@echo "Running web E2E tests..."
	npm --prefix web run test:e2e

# Run production configuration and deployment checks
test-prod-config: build web-build
	@echo "Running production validation tests..."
	go test ./cmd/sftpxy ./internal/config ./internal/storage/remotesftp ./deploy
	bash -n deploy/systemd/install.sh

# Build the Linux systemd release bundle
release-bundle: web-build
	@echo "Building release bundle..."
	bash deploy/package-release.sh

# Unified regression command
verify: build test-protocols test web-build
	@echo "Verification complete"

# Production-focused unified regression command
verify-prod: build test-protocols test web-build test-web-e2e test-prod-config
	@echo "Production verification complete"

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@PACKAGES=$$(go list ./tests/integration/... 2>/dev/null); \
	if [ -n "$$PACKAGES" ]; then \
		go test -v -tags=integration $$PACKAGES; \
	else \
		echo "Skipping integration tests: tests/integration not found"; \
	fi

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out
	@echo "Clean complete"

# Generate code (SQLC, oapi-codegen)
generate:
	@echo "Generating code..."
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "Skipping sqlc generate: sqlc not installed"; fi
	@if [ -f internal/api/openapi.yaml ] && command -v oapi-codegen >/dev/null 2>&1; then \
		mkdir -p internal/api/generated && \
		oapi-codegen -generate types,chi-server,spec -package generated internal/api/openapi.yaml > internal/api/generated/server.go; \
	else \
		echo "Skipping oapi-codegen: internal/api/openapi.yaml not found or oapi-codegen not installed"; \
	fi
	@echo "Code generation complete"

# Run database migrations up
migrate-up:
	@echo "Running migrations up..."
	@mkdir -p data
	goose -dir migrations/sqlite sqlite ./data/sftpxy.db up
	@echo "Migrations complete"

# Run database migrations down
migrate-down:
	@echo "Running migrations down..."
	@mkdir -p data
	goose -dir migrations/sqlite sqlite ./data/sftpxy.db down
	@echo "Migrations rollback complete"

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t sftpxy:latest .
	@echo "Docker build complete"

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run
	@echo "Lint complete"

# Run the application
run: build
	@mkdir -p data logs plugins
	@$(MAKE) web-build
	@echo "Starting SFTPxy with $(CONFIG)..."
	./$(BINARY) --config $(CONFIG)

# Initialize development environment
dev-init:
	@echo "Initializing development environment..."
	mkdir -p data logs plugins
	go mod download
	go mod tidy
	@echo "Development environment ready"
