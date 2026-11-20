#!/usr/bin/env bash
# Verify that the published release artifacts are actually available.
#
# A release is not done when the tag is pushed: the GitHub Release, the Docker
# images on Docker Hub and GHCR, and the docs site all publish asynchronously.
# v0.2.10 once left a Docker tag missing while the release page looked complete,
# so check the registries directly instead of trusting the run list.
#
# Usage: scripts/check-artifacts.sh [version]
# Exit:  0 all present, 1 something missing, 3 network unavailable
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

version="${1:-$(tr -d '[:space:]' < VERSION)}"
missing=0
net_error=0

say()  { printf '  %-52s %s\n' "$1" "$2"; }
have() { say "$1" "OK"; }
miss() { say "$1" "MISSING"; missing=$((missing + 1)); }
neterr() { say "$1" "NETWORK/UNAVAILABLE"; net_error=$((net_error + 1)); }

echo "==> GitHub release v${version}"
gh_json="$(curl -sf --max-time 25 "https://api.github.com/repos/jincaiw/sftpxy/releases/tags/v${version}" 2>/dev/null)"
if [[ -z "${gh_json}" ]]; then
  neterr "api.github.com release v${version}"
else
  draft="$(printf '%s' "${gh_json}" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("draft"))' 2>/dev/null)"
  count="$(printf '%s' "${gh_json}" | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("assets",[])))' 2>/dev/null)"
  if [[ "${draft}" == "False" ]]; then have "release published (not draft)"; else miss "release is draft or unreadable"; fi
  if [[ "${count:-0}" -ge 10 ]]; then have "assets: ${count}"; else miss "assets: ${count:-0} (expected >= 10)"; fi
fi

# Check a manifest in a registry namespace. Args: registry host, repo, tag, token.
check_registry_tag() {
  local host="$1" repo="$2" tag="$3" token="$4"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 25 \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json' \
    "https://${host}/v2/${repo}/manifests/${tag}" 2>/dev/null)"
  case "${code}" in
    200) have "${host}/${repo}:${tag}" ;;
    401|403|404) miss "${host}/${repo}:${tag} (HTTP ${code})" ;;
    *)   neterr "${host}/${repo}:${tag} (HTTP ${code:-none})" ;;
  esac
}

# The Docker workflow derives these from the tag ref (which keeps its leading
# "v"), so the published minor/major tags are "v0.2" and "v0", not "0.2"/"0".
minor="v${version%.*}"
major="v${version%%.*}"

echo "==> Docker Hub qing1205/sftpxy"
dh_token="$(curl -sf --max-time 25 "https://auth.docker.io/token?service=registry.docker.io&scope=repository:qing1205/sftpxy:pull" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)"
if [[ -z "${dh_token}" ]]; then
  neterr "auth.docker.io token"
else
  for t in "v${version}" "${minor}" "${major}" latest; do
    check_registry_tag registry-1.docker.io qing1205/sftpxy "${t}" "${dh_token}"
  done
fi

echo "==> GHCR ghcr.io/jincaiw/sftpxy"
ghcr_token="$(curl -sf --max-time 25 "https://ghcr.io/token?scope=repository:jincaiw/sftpxy:pull" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)"
if [[ -z "${ghcr_token}" ]]; then
  neterr "ghcr.io token"
else
  for t in "v${version}" latest; do
    check_registry_tag ghcr.io jincaiw/sftpxy "${t}" "${ghcr_token}"
  done
fi

echo "==> Docs site"
docs_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 https://sftp.mujizi.com/ 2>/dev/null)"
case "${docs_code}" in
  200) have "https://sftp.mujizi.com/" ;;
  000|"") neterr "https://sftp.mujizi.com/" ;;
  *) miss "https://sftp.mujizi.com/ (HTTP ${docs_code})" ;;
esac

echo
if [[ "${net_error}" -gt 0 ]]; then
  echo "RESULT: ${net_error} check(s) could not reach the network, ${missing} missing. Retry when connectivity is back." >&2
  exit 3
fi
if [[ "${missing}" -gt 0 ]]; then
  echo "RESULT: ${missing} artifact(s) missing for v${version}." >&2
  exit 1
fi
echo "RESULT: all release artifacts present for v${version}."
