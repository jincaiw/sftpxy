FROM golang:1.26-trixie AS builder

ENV GOFLAGS="-mod=readonly"

RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace
WORKDIR /workspace

ARG GOPROXY

COPY go.mod go.sum ./
COPY sdk ./sdk
RUN go mod download && go mod verify

ARG COMMIT_SHA

# This ARG allows to disable some optional features and it might be useful if you build the image yourself.
# For example you can disable S3 and GCS support like this:
# --build-arg FEATURES=nos3,nogcs
ARG FEATURES

COPY . .

RUN set -xe && \
    export COMMIT_SHA=${COMMIT_SHA:-$(git describe --always --abbrev=8 --dirty)} && \
    go build $(if [ -n "${FEATURES}" ]; then echo "-tags ${FEATURES}"; fi) -trimpath -ldflags "-s -w -X github.com/jincaiw/sftpxy/v2/internal/version.commit=${COMMIT_SHA} -X github.com/jincaiw/sftpxy/v2/internal/version.date=`date -u +%FT%TZ`" -v -o SFTPxy

# Set to "true" to download the "official" plugins in /usr/local/bin
ARG DOWNLOAD_PLUGINS=false

RUN if [ "${DOWNLOAD_PLUGINS}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y curl && ./docker/scripts/download-plugins.sh; fi

FROM debian:trixie-slim

# Set to "true" to install jq
ARG INSTALL_OPTIONAL_PACKAGES=false

RUN apt-get update && apt-get -y upgrade && apt-get install --no-install-recommends -y ca-certificates media-types && rm -rf /var/lib/apt/lists/*

RUN if [ "${INSTALL_OPTIONAL_PACKAGES}" = "true" ]; then apt-get update && apt-get install --no-install-recommends -y jq && rm -rf /var/lib/apt/lists/*; fi

RUN mkdir -p /etc/SFTPxy /var/lib/SFTPxy /usr/share/SFTPxy /srv/SFTPxy/data /srv/SFTPxy/backups

RUN groupadd --system -g 1000 SFTPxy && \
    useradd --system --gid SFTPxy --no-create-home \
    --home-dir /var/lib/SFTPxy --shell /usr/sbin/nologin \
    --comment "SFTPxy user" --uid 1000 SFTPxy

COPY --from=builder /workspace/SFTPxy.json /etc/SFTPxy/SFTPxy.json
COPY --from=builder /workspace/templates /usr/share/SFTPxy/templates
COPY --from=builder /workspace/static /usr/share/SFTPxy/static
COPY --from=builder /workspace/openapi /usr/share/SFTPxy/openapi
COPY --from=builder /workspace/SFTPxy /usr/local/bin/SFTPxy-plugin-* /usr/local/bin/

# Log to the stdout so the logs will be available using docker logs
ENV SFTPXY_LOG_FILE_PATH=""

# Modify the default configuration file
RUN sed -i 's|"users_base_dir": "",|"users_base_dir": "/srv/SFTPxy/data",|' /etc/SFTPxy/SFTPxy.json && \
    sed -i 's|"backups"|"/srv/SFTPxy/backups"|' /etc/SFTPxy/SFTPxy.json && \
    sed -i 's|"templates_path": "templates"|"templates_path": "/usr/share/SFTPxy/templates"|' /etc/SFTPxy/SFTPxy.json && \
    sed -i 's|"static_files_path": "static"|"static_files_path": "/usr/share/SFTPxy/static"|' /etc/SFTPxy/SFTPxy.json && \
    sed -i 's|"openapi_path": "openapi"|"openapi_path": "/usr/share/SFTPxy/openapi"|' /etc/SFTPxy/SFTPxy.json

RUN chown -R SFTPxy:SFTPxy /etc/SFTPxy /srv/SFTPxy && chown SFTPxy:SFTPxy /var/lib/SFTPxy && chmod 700 /srv/SFTPxy/backups

WORKDIR /var/lib/SFTPxy
USER 1000:1000

EXPOSE 30080 30081 30082 30085-30088

CMD ["SFTPxy", "serve"]
