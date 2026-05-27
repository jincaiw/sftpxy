.PHONY: build test clean generate migrate-up migrate-down docker-build lint

# Build the application
build:
	@echo "Building SFTPxy..."
	go build -o bin/sftpxy ./cmd/sftpxy
	@echo "Build complete: bin/sftpxy"

# Run tests
test:
	@echo "Running tests..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./tests/integration/...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf coverage.out
	rm -rf internal/models/*.go
	rm -rf internal/models/mysql/*.go
	@echo "Clean complete"

# Generate code (SQLC, oapi-codegen)
generate:
	@echo "Generating code..."
	sqlc generate
	oapi-codegen -generate types,chi-server,spec -package generated internal/api/openapi.yaml > internal/api/generated/server.go
	@echo "Code generation complete"

# Run database migrations up
migrate-up:
	@echo "Running migrations up..."
	goose -dir migrations/sqlite sqlite ./data/sftpxy.db up
	@echo "Migrations complete"

# Run database migrations down
migrate-down:
	@echo "Running migrations down..."
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
	@echo "Starting SFTPxy..."
	./bin/sftpxy --config config.yaml

# Initialize development environment
dev-init:
	@echo "Initializing development environment..."
	mkdir -p data keys plugins
	go mod download
	go mod tidy
	@echo "Development environment ready"
