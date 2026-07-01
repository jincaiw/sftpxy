#!/usr/bin/env bash
set -euo pipefail

version="${1:-$(tr -d '[:space:]' < VERSION)}"
if [[ "${version}" == v* ]]; then
  version="${version#v}"
fi

if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: scripts/sync-version.sh <X.Y.Z>" >&2
  exit 2
fi

printf '%s\n' "${version}" > VERSION

python3 - <<'PY' "${version}"
from pathlib import Path
import re, sys
version = sys.argv[1]
root = Path('.')
# internal/version/version.go
p = root / 'internal/version/version.go'
s = p.read_text()
s = re.sub(r'version = "[^"]+"', f'version = "{version}"', s, count=1)
p.write_text(s)

# openapi/openapi.yaml
p = root / 'openapi/openapi.yaml'
s = p.read_text()
s = re.sub(r'^  version: .*$', f'  version: v{version}', s, count=1, flags=re.M)
p.write_text(s)

# README files
for path, label in [('README.md', 'Current release: `v{}`.'), ('README.zh-CN.md', '当前版本：`v{}`。')]:
    p = root / path
    s = p.read_text()
    s = re.sub(r'Current release: `v[^`]+`\.|当前版本：`v[^`]+`。', label.format(version), s, count=1)
    p.write_text(s)
PY

echo "Synchronized version to ${version}"