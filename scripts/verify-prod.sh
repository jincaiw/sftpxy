#!/usr/bin/env bash
set -euo pipefail

version="${1:-$(tr -d '[:space:]' < VERSION)}"
features="nopgxregisterdefaulttypes,disable_grpc_modules"
commit="$(git describe --always --abbrev=8 --dirty)"
date_utc="$(date -u +%FT%TZ)"
ldflags="-s -w -X github.com/jincaiw/sftpxy/v2/internal/version.commit=${commit} -X github.com/jincaiw/sftpxy/v2/internal/version.date=${date_utc}"
export GOCACHE="${GOCACHE:-${PWD}/.gocache}"
mkdir -p "${GOCACHE}"

scripts/release-check.sh "${version}"

echo "==> gofmt check"
unformatted="$(gofmt -l main.go internal pkgs sdk tests 2>/dev/null || true)"
if [[ -n "${unformatted}" ]]; then
  echo "Go files need gofmt:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

echo "==> go vet"
go vet -tags "${features}" ./...

echo "==> test helpers"
(
  cd tests/eventsearcher
  go build -trimpath -ldflags "-s -w" -o eventsearcher
)
(
  cd tests/ipfilter
  go build -trimpath -ldflags "-s -w" -o ipfilter
)

echo "==> go test"
go test -tags "${features}" -p 1 -timeout 10m ./...

echo "==> production build"
mkdir -p build/verify
go build -trimpath -tags "${features}" -ldflags "${ldflags}" -o build/verify/SFTPxy .
build/verify/SFTPxy -v

echo "Production verification passed for v${version}"
