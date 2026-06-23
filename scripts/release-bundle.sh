#!/usr/bin/env bash
set -euo pipefail

version="${1:-$(tr -d '[:space:]' < VERSION)}"
tag="v${version}"
features="nopgxregisterdefaulttypes,disable_grpc_modules"
portable_features="${features},nosqlite"
commit="$(git describe --always --abbrev=8 --dirty)"
date_utc="$(date -u +%FT%TZ)"
ldflags="-s -w -X github.com/jincaiw/sftpxy/v2/internal/version.commit=${commit} -X github.com/jincaiw/sftpxy/v2/internal/version.date=${date_utc}"
release_dir="build/release/${tag}"
export GOCACHE="${GOCACHE:-${PWD}/.gocache}"
mkdir -p "${GOCACHE}"

scripts/release-check.sh "${version}"

rm -rf "${release_dir}"
mkdir -p "${release_dir}/native"

echo "==> native release bundle"
go build -trimpath -tags "${features}" -ldflags "${ldflags}" -o "${release_dir}/native/SFTPxy" .

stage_common() {
  local stage="$1"
  mkdir -p "${stage}/init"
  cp LICENSE NOTICE README.md README.zh-CN.md SFTPxy.json "${stage}/"
  cp -R templates static openapi "${stage}/"
  cp init/SFTPxy.service "${stage}/init/"
}

stage_common "${release_dir}/native"
(
  cd "${release_dir}/native"
  tar -czf "../SFTPxy_${tag}_$(go env GOOS)_$(go env GOARCH).tar.gz" .
)

build_cross() {
  local goos="$1"
  local goarch="$2"
  local ext="$3"
  local stage="${release_dir}/${goos}_${goarch}"
  local bin="SFTPxy${ext}"
  echo "==> ${goos}/${goarch} portable bundle"
  mkdir -p "${stage}"
  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" go build -trimpath -tags "${portable_features}" -ldflags "${ldflags}" -o "${stage}/${bin}" .
  stage_common "${stage}"
  if [[ "${goos}" == "windows" ]]; then
    (
      cd "${stage}"
      zip -qr "../SFTPxy_${tag}_${goos}_${goarch}.zip" .
    )
  else
    (
      cd "${stage}"
      tar -czf "../SFTPxy_${tag}_${goos}_${goarch}.tar.gz" .
    )
  fi
}

build_cross linux amd64 ""
build_cross linux arm64 ""
build_cross windows amd64 ".exe"

(
  cd "${release_dir}"
  shasum -a 256 SFTPxy_${tag}_* > SHA256SUMS
)

echo "Release dry-run bundles written to ${release_dir}"
