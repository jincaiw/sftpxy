#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${VERSION:-0.1.1}"
TARGET_NAME="sftpxy-linux-amd64-systemd-v${VERSION}"
DIST_DIR="$ROOT_DIR/dist/release"
PACKAGE_DIR="$DIST_DIR/$TARGET_NAME"
ARCHIVE_PATH="$DIST_DIR/${TARGET_NAME}.tar.gz"
MANIFEST_PATH="$DIST_DIR/${TARGET_NAME}.manifest.txt"
SHA256_PATH="$ARCHIVE_PATH.sha256"

mkdir -p "$PACKAGE_DIR"
mkdir -p "$DIST_DIR"
rm -rf "$PACKAGE_DIR"
rm -f "$ARCHIVE_PATH" "$MANIFEST_PATH" "$SHA256_PATH"
mkdir -p "$PACKAGE_DIR"

echo "Building linux/amd64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "$PACKAGE_DIR/sftpxy" \
  ./cmd/sftpxy

cp config.yaml.example "$PACKAGE_DIR/config.yaml.example"
cp README.md "$PACKAGE_DIR/README.md"
cp README.zh-CN.md "$PACKAGE_DIR/README.zh-CN.md"
cp LICENSE "$PACKAGE_DIR/LICENSE"
cp -R deploy/systemd "$PACKAGE_DIR/systemd"
cp -R migrations "$PACKAGE_DIR/migrations"
cp -R docs/production "$PACKAGE_DIR/docs-production"
mkdir -p "$PACKAGE_DIR/web"
cp -R web/dist "$PACKAGE_DIR/web/dist"

cat > "$PACKAGE_DIR/RELEASE.txt" <<EOF
SFTPxy Release Bundle
Version: ${VERSION}
Target: Linux systemd single-node
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Included:
- sftpxy binary
- systemd install files
- database migrations
- built web assets
- production documentation
EOF

(
  cd "$DIST_DIR"
  tar czf "${TARGET_NAME}.tar.gz" "$TARGET_NAME"
)

(
  cd "$DIST_DIR"
  find "$TARGET_NAME" -type f | sort > "${TARGET_NAME}.manifest.txt"
  shasum -a 256 "${TARGET_NAME}.tar.gz" > "${TARGET_NAME}.tar.gz.sha256"
)

echo "Release archive: $ARCHIVE_PATH"
echo "Release manifest: $MANIFEST_PATH"
echo "Release checksum: $SHA256_PATH"
