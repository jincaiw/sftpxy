#!/usr/bin/env bash
# Development helpers for building and running SFTPxy in Docker.
#
# The image is built from the repository Dockerfile, so it exercises the same
# build path as the release pipeline (build tags, ldflags, non-root user).
#
# Usage:
#   scripts/docker-dev.sh build [image-tag]   build the image (default: sftpxy:dev)
#   scripts/docker-dev.sh run   [image-tag]   run it on 31080/31081/31082
#   scripts/docker-dev.sh shell [image-tag]   open a shell in the image
#   scripts/docker-dev.sh test                run the suite in a container
#   scripts/docker-dev.sh stop                stop and remove the container
#   scripts/docker-dev.sh logs                follow the container logs
#
# Environment:
#   DOCKER_CONFIG    kept inside the repo by default so the build works in
#                    sandboxes where ~/.docker is not writable
#   GOPROXY          module proxy used during the build; defaults to a mirror
#                    because the default proxy often times out here
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export DOCKER_CONFIG="${DOCKER_CONFIG:-$PWD/.dockercfg}"
mkdir -p "$DOCKER_CONFIG"

IMAGE="${2:-sftpxy:dev}"
CONTAINER=sftpxy-dev
FEATURES=nopgxregisterdefaulttypes,disable_grpc_modules
GOPROXY_VALUE="${GOPROXY:-https://goproxy.cn,direct}"

cmd="${1:-}"
case "$cmd" in
  build)
    docker build \
      --build-arg GOPROXY="$GOPROXY_VALUE" \
      --build-arg COMMIT_SHA="$(git describe --always --abbrev=8 --dirty)" \
      --build-arg FEATURES="$FEATURES" \
      -t "$IMAGE" .
    ;;
  run)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    mkdir -p "$PWD/.dockerrun"
    docker run -d --name "$CONTAINER" \
      -p 31080:30080 -p 31081:30081 -p 31082:30082 \
      -v "$PWD/.dockerrun:/var/lib/SFTPxy" \
      "$IMAGE"
    echo "WebAdmin: http://127.0.0.1:31080/ (first visit creates the admin)"
    echo "WebClient: http://127.0.0.1:31081/"
    echo "SFTP:      sftp -P 31082 <user>@127.0.0.1"
    ;;
  shell)
    docker run --rm -it --entrypoint /bin/sh "$IMAGE"
    ;;
  test)
    # Run the suite in a throwaway container built from the same toolchain,
    # so results do not depend on the host Go installation.
    docker run --rm \
      -v "$PWD:/src" -w /src \
      -e GOPROXY="$GOPROXY_VALUE" -e GOSUMDB=off \
      -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomodcache \
      "golang:1.26.11-trixie" \
      sh -c 'go build ./... && go test -tags "'"$FEATURES"'" -p 1 -timeout 25m ./...'
    ;;
  stop)
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    echo "container removed"
    ;;
  logs)
    docker logs -f "$CONTAINER"
    ;;
  *)
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
