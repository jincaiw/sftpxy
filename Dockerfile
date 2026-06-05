FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o sftpxy ./cmd/sftpxy

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/sftpxy /usr/local/bin/sftpxy

# Create directories
RUN mkdir -p /etc/sftpxy /var/log/sftpxy /data/sftpxy

EXPOSE 30082 30086 30080 30084 30088

VOLUME ["/etc/sftpxy", "/var/log/sftpxy", "/data/sftpxy"]

ENTRYPOINT ["sftpxy"]
CMD ["--config", "/etc/sftpxy/config.yaml"]
