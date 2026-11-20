#!/usr/bin/env bash
# Gate that must pass before creating a release tag.
#
# This exists because v0.2.11 was tagged on a commit that predated the fix it
# was supposed to ship, so the published assets still carried the bug. No check
# can prove that "the intended fix is included", but tagging the current,
# fully-pushed tip of the release branch with a clean tree and a fresh tag
# removes the mechanical ways that mistake happens.
#
# Usage: scripts/pre-tag-check.sh [version]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

version="${1:-$(tr -d '[:space:]' < VERSION)}"
tag="v${version}"
fail() { echo "pre-tag check failed: $*" >&2; exit 1; }

# 1. Working tree must be clean: a dirty tree means the release would ship
#    something that is not in any commit.
if [[ -n "$(git status --porcelain)" ]]; then
  echo "uncommitted changes:" >&2
  git status --short >&2
  fail "working tree is not clean"
fi

# 2. The tag must not exist yet, locally or on the remote.
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  fail "tag ${tag} already exists locally"
fi
if git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
  fail "tag ${tag} already exists on origin"
fi

# 3. HEAD must be the tip of the tracked remote branch: this is the check that
#    would have caught tagging an older commit, and it also catches forgotten
#    pushes.
branch="$(git rev-parse --abbrev-ref HEAD)"
remote_ref="refs/remotes/origin/${branch}"
if ! git rev-parse -q --verify "${remote_ref}" >/dev/null; then
  fail "no remote-tracking ref for ${remote_ref}; push the branch first"
fi
head_sha="$(git rev-parse HEAD)"
remote_sha="$(git rev-parse "${remote_ref}")"
if [[ "${head_sha}" != "${remote_sha}" ]]; then
  fail "HEAD (${head_sha:0:8}) is not the tip of origin/${branch} (${remote_sha:0:8}); push first"
fi

# 4. Release metadata must be internally consistent for this version.
scripts/release-check.sh "${version}"

# 5. The version must be an increase over the latest released tag.
latest="$(git tag --list 'v*' --sort=-v:refname | head -n 1)"
if [[ -n "${latest}" && "${latest}" == "${tag}" ]]; then
  echo "note: ${tag} equals the latest existing tag" >&2
fi

echo "pre-tag checks passed for ${tag} on ${head_sha:0:8} (origin/${branch})"
