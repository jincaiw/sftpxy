# SFTPxy

[中文](README.zh-CN.md)

SFTPxy is an enterprise managed file transfer platform. It provides SFTP/SCP, FTP/FTPS, WebDAV, WebAdmin, WebClient, REST APIs, audit logs, Prometheus metrics, policy controls, and pluggable storage backends in one deployable service.

## Features

- Multi-protocol access: SFTP/SCP, FTP/FTPS, WebDAV, HTTP/WebAdmin/WebClient, and REST APIs.
- Storage backends: local filesystem, encrypted local filesystem, remote SFTP, and HTTPFs.
- Unified access control: file permissions, quotas, bandwidth limits, IP filters, and protocol policies.
- Authentication: password, SSH public key, TOTP MFA, OIDC, LDAP/AD, JWT bearer tokens, and API keys.
- Operations: JSON logs, audit records, active sessions, shares, event rules, hooks, backup/restore, and Prometheus metrics.
- Deployment: single Linux binary, Linux systemd service, Docker, Docker Compose, and Windows service wrapper.

## Quick Start

```bash
git clone https://github.com/jincaiw/sftpxy.git
cd sftpxy
make build
./bin/sftpxy --config config.yaml.example
```

The default ports are:

| Service | Port |
|---|---:|
| SSH/SFTP/SCP | 30082 |
| WebAdmin/API | 30088 |
| WebClient | 30080 |
| WebDAV | 30084 |
| FTP/FTPS | 30086 |

## Build From Source

```bash
go mod download
npm --prefix web install
make verify-prod
make release-bundle
```

The Linux release archive is written to:

```text
dist/release/sftpxy-linux-amd64-systemd-v0.1.1.tar.gz
```

## Linux Single-Binary Deployment

1. Build or download the Linux binary:

```bash
VERSION=0.1.1 make release-bundle
tar xzf dist/release/sftpxy-linux-amd64-systemd-v0.1.1.tar.gz -C /tmp
```

2. Install the binary and runtime assets:

```bash
sudo install -m 755 /tmp/sftpxy-linux-amd64-systemd-v0.1.1/sftpxy /usr/local/bin/sftpxy
sudo install -d -m 750 /etc/sftpxy /var/lib/sftpxy /var/log/sftpxy /usr/local/share/sftpxy
sudo cp /tmp/sftpxy-linux-amd64-systemd-v0.1.1/config.yaml.example /etc/sftpxy/config.yaml
sudo cp -R /tmp/sftpxy-linux-amd64-systemd-v0.1.1/migrations /usr/local/share/sftpxy/
sudo cp -R /tmp/sftpxy-linux-amd64-systemd-v0.1.1/web /usr/local/share/sftpxy/
```

3. Edit `/etc/sftpxy/config.yaml` for production:

```yaml
common:
  log_path: /var/log/sftpxy/sftpxy.log
ssh:
  host_keys:
    - /var/lib/sftpxy/keys/ssh_host_ed25519_key
httpd:
  static_path: /usr/local/share/sftpxy/web/dist
  template_path: /usr/local/share/sftpxy/web/dist
  session_secret: replace-with-a-random-hex-secret
data_provider:
  connection_string: /var/lib/sftpxy/sftpxy.db
```

4. Generate a persistent SSH host key and validate the config:

```bash
sudo /usr/local/bin/sftpxy generate-hostkey --output /var/lib/sftpxy/keys/ssh_host_ed25519_key
sudo /usr/local/bin/sftpxy validate-config --config /etc/sftpxy/config.yaml --strict-production
```

5. Run SFTPxy:

```bash
sudo /usr/local/bin/sftpxy --config /etc/sftpxy/config.yaml
```

6. Create the first administrator:

```bash
printf 'StrongPasswordHere' | sudo /usr/local/bin/sftpxy \
  bootstrap-admin \
  --config /etc/sftpxy/config.yaml \
  --username admin \
  --password-stdin
```

## Linux systemd Deployment

1. Build the release bundle:

```bash
VERSION=0.1.1 make release-bundle
tar xzf dist/release/sftpxy-linux-amd64-systemd-v0.1.1.tar.gz -C /tmp
cd /tmp/sftpxy-linux-amd64-systemd-v0.1.1
```

2. Install with the bundled script:

```bash
sudo SFTPXY_TLS_CERT_FILE=/path/to/sftpxy.crt \
  SFTPXY_TLS_KEY_FILE=/path/to/sftpxy.key \
  ./systemd/install.sh
```

3. Manage the service:

```bash
sudo systemctl status sftpxy
sudo systemctl restart sftpxy
sudo journalctl -u sftpxy -f
```

4. Smoke test:

```bash
curl -k https://127.0.0.1:30088/health
curl -k https://127.0.0.1:30088/status
curl -k https://127.0.0.1:30088/openapi
curl http://127.0.0.1:30088/metrics
```

## Docker

```bash
docker build -t sftpxy:latest .
docker compose up -d
```

## Development

```bash
make test
make test-protocols
make web-build
make verify-prod
```

## Documentation

- [Linux systemd deployment](docs/production/systemd.md)
- [Docker deployment](docs/production/docker.md)
- [Production configuration](docs/production/configuration.md)
- [Backup and restore](docs/production/backup-restore.md)
- [Release checklist](docs/production/release-checklist.md)
- [Release notes](docs/production/release-notes.md)

## License

SFTPxy is released under the [MIT License](LICENSE).
