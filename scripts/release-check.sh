#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ -z "${version}" ]]; then
  echo "usage: scripts/release-check.sh <version>" >&2
  exit 2
fi

if [[ "${version}" == v* ]]; then
  echo "version must not include leading v: ${version}" >&2
  exit 1
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must use X.Y.Z format: ${version}" >&2
  exit 1
fi

if [[ ! -f VERSION ]]; then
  echo "missing VERSION file" >&2
  exit 1
fi

file_version="$(tr -d '[:space:]' < VERSION)"
if [[ "${file_version}" != "${version}" ]]; then
  echo "VERSION contains ${file_version}, expected ${version}" >&2
  exit 1
fi

go_version="$(sed -n 's/^[[:space:]]*version = "\([^"]*\)"/\1/p' internal/version/version.go)"
if [[ "${go_version}" != "${version}" ]]; then
  echo "internal/version/version.go contains ${go_version}, expected ${version}" >&2
  exit 1
fi

if ! rg -q "## v${version}" CHANGELOG.md; then
  echo "CHANGELOG.md is missing ## v${version}" >&2
  exit 1
fi

for path in README.md README.zh-CN.md LICENSE NOTICE SFTPxy.json init/SFTPxy.service; do
  if [[ ! -e "${path}" ]]; then
    echo "missing required release file: ${path}" >&2
    exit 1
  fi
done

for shot in docs/screenshots/webadmin-login.png docs/screenshots/webclient-login.png docs/screenshots/mobile-webadmin-login.png; do
  if [[ ! -s "${shot}" ]]; then
    echo "missing required screenshot: ${shot}" >&2
    exit 1
  fi
done

if ! rg -q '\[中文文档\]\(\./README\.zh-CN\.md\)' README.md; then
  echo "README.md must link to README.zh-CN.md at the top" >&2
  exit 1
fi

if ! rg -q '\[English\]\(\./README\.md\)' README.zh-CN.md; then
  echo "README.zh-CN.md must link back to README.md" >&2
  exit 1
fi

if git ls-files --error-unmatch SFTPxy.db SFTPxy.db-shm SFTPxy.db-wal >/dev/null 2>&1; then
  echo "runtime database files must not be tracked" >&2
  exit 1
fi

echo "Release metadata checks passed for v${version}"
