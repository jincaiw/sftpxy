#!/bin/bash

NFPM_VERSION=2.46.3
NFPM_ARCH=${NFPM_ARCH:-amd64}
if [ -z ${SFTPXY_VERSION} ]
then
  LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
  NUM_COMMITS_FROM_TAG=$(git rev-list ${LATEST_TAG}.. --count)
  VERSION=$(echo "${LATEST_TAG}" | awk -F. -v OFS=. '{$NF++;print}')-dev.${NUM_COMMITS_FROM_TAG}
else
  VERSION=${SFTPXY_VERSION}
fi

rm -rf dist
mkdir dist
echo -n ${VERSION} > dist/version
cd dist
BASE_DIR="../.."

if [ -f "${BASE_DIR}/output/bash_completion/SFTPxy" ]
then
  cp ${BASE_DIR}/output/bash_completion/SFTPxy SFTPxy-completion.bash
else
  $BASE_DIR/SFTPxy gen completion bash > SFTPxy-completion.bash
fi

if [ -d "${BASE_DIR}/output/man/man1" ]
then
  cp -r ${BASE_DIR}/output/man/man1 .
else
  $BASE_DIR/SFTPxy gen man -d man1
fi

if [ ! -f ${BASE_DIR}/SFTPxy ]
then
  cp ${BASE_DIR}/output/SFTPxy ${BASE_DIR}/SFTPxy
  chmod 755 ${BASE_DIR}/SFTPxy
fi

cp ${BASE_DIR}/SFTPxy.json .
sed -i "s|SFTPxy.db|/var/lib/SFTPxy/SFTPxy.db|" SFTPxy.json
sed -i "s|\"users_base_dir\": \"\",|\"users_base_dir\": \"/srv/SFTPxy/data\",|" SFTPxy.json
sed -i "s|\"backups\"|\"/srv/SFTPxy/backups\"|" SFTPxy.json
sed -i "s|\"certs\"|\"/var/lib/SFTPxy/certs\"|" SFTPxy.json
sed -i "s|\"templates_path\": \"templates\"|\"templates_path\": \"/usr/share/SFTPxy/templates\"|" SFTPxy.json
sed -i "s|\"static_files_path\": \"static\"|\"static_files_path\": \"/usr/share/SFTPxy/static\"|" SFTPxy.json
sed -i "s|\"openapi_path\": \"openapi\"|\"openapi_path\": \"/usr/share/SFTPxy/openapi\"|" SFTPxy.json

cat >nfpm.yaml <<EOF
name: "SFTPxy"
arch: "${NFPM_ARCH}"
platform: "linux"
version: ${VERSION}
release: 1
section: "net"
priority: "optional"
maintainer: "jincaiw <https://github.com/jincaiw>"
description: |
  Full-featured and highly configurable SFTP server
  SFTPxy has optional HTTP, FTP/S and WebDAV support.
  It can serve local filesystem, S3 (Compatible) Object Storage,
  Google Cloud Storage, Azure Blob Storage, SFTP.
vendor: "SFTPxy"
homepage: "https://github.com/jincaiw/sftpxy"
license: "MIT"
provides:
  - SFTPxy
contents:
  - src: "${BASE_DIR}/SFTPxy${BIN_SUFFIX}"
    dst: "/usr/bin/SFTPxy"

  - src: "./SFTPxy-completion.bash"
    dst: "/usr/share/bash-completion/completions/SFTPxy"

  - src: "./man1/*"
    dst: "/usr/share/man/man1/"

  - src: "${BASE_DIR}/init/SFTPxy.service"
    dst: "/lib/systemd/system/SFTPxy.service"

  - src: "${BASE_DIR}/templates/*"
    dst: "/usr/share/SFTPxy/templates"

  - src: "${BASE_DIR}/static/*"
    dst: "/usr/share/SFTPxy/static"

  - src: "${BASE_DIR}/openapi/*"
    dst: "/usr/share/SFTPxy/openapi"

  - src: "${BASE_DIR}/LICENSE"
    dst: "/usr/share/licenses/SFTPxy/LICENSE"

  - src: "${BASE_DIR}/NOTICE"
    dst: "/usr/share/licenses/SFTPxy/NOTICE"

  - src: "./SFTPxy.json"
    dst: "/etc/SFTPxy/SFTPxy.json"
    type: "config|noreplace"

  - dst: "/srv/SFTPxy"
    type: dir

  - dst: "/var/lib/SFTPxy"
    type: dir

  - dst: "/etc/SFTPxy/env.d"
    type: dir

overrides:
  deb:
    recommends:
      - bash-completion
      - mime-support
    scripts:
      postinstall: ../scripts/deb/postinstall.sh
      preremove: ../scripts/deb/preremove.sh
      postremove: ../scripts/deb/postremove.sh
  rpm:
    recommends:
      - bash-completion
      - mailcap
    scripts:
      postinstall: ../scripts/rpm/postinstall
      preremove: ../scripts/rpm/preremove
      postremove: ../scripts/rpm/postremove

rpm:
  compression: xz

deb:
  compression: xz

EOF

curl --retry 5 --retry-delay 2 --connect-timeout 10 -L -O \
  https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz
tar xvf nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz nfpm
chmod 755 nfpm
mkdir rpm
./nfpm -f nfpm.yaml pkg -p rpm -t rpm
mkdir deb
./nfpm -f nfpm.yaml pkg -p deb -t deb
