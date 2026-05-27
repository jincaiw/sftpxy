#!/bin/bash
# SFTPxy Linux Installation Script
# This script installs SFTPxy as a systemd service

set -e

BINARY_PATH="/usr/local/bin/sftpxy"
CONFIG_DIR="/etc/sftpxy"
DATA_DIR="/var/lib/sftpxy"
LOG_DIR="/var/log/sftpxy"
SERVICE_FILE="/etc/systemd/system/sftpxy.service"

echo "=== SFTPxy Installation ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Create system user
if ! id -u sftpxy >/dev/null 2>&1; then
    echo "Creating sftpxy system user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin sftpxy
fi

# Create directories
echo "Creating directories..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown sftpxy:sftpxy "$DATA_DIR" "$LOG_DIR"
chmod 750 "$DATA_DIR" "$LOG_DIR"

# Install binary
if [ -f "./bin/sftpxy" ]; then
    echo "Installing binary..."
    cp ./bin/sftpxy "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    chown root:root "$BINARY_PATH"
else
    echo "Warning: Binary not found at ./bin/sftpxy"
    echo "Please build first with: make build"
    exit 1
fi

# Install config example
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo "Installing example configuration..."
    cp config.yaml.example "$CONFIG_DIR/config.yaml"
    chown sftpxy:sftpxy "$CONFIG_DIR/config.yaml"
    chmod 640 "$CONFIG_DIR/config.yaml"
fi

# Install systemd service
echo "Installing systemd service..."
cp deploy/systemd/sftpxy.service "$SERVICE_FILE"
systemctl daemon-reload

# Enable and start service
echo "Enabling and starting service..."
systemctl enable sftpxy
systemctl start sftpxy

echo ""
echo "=== Installation Complete ==="
echo "Service status: $(systemctl is-active sftpxy)"
echo "Config file: $CONFIG_DIR/config.yaml"
echo "Data directory: $DATA_DIR"
echo "Log directory: $LOG_DIR"
echo ""
echo "Useful commands:"
echo "  systemctl status sftpxy    - Check service status"
echo "  systemctl restart sftpxy   - Restart service"
echo "  journalctl -u sftpxy -f    - View logs"
echo "  systemctl stop sftpxy      - Stop service"
