# SFTPxy

[English](README.md)

SFTPxy 是一套企业级托管文件传输平台，将 SFTP/SCP、FTP/FTPS、WebDAV、WebAdmin、WebClient、REST API、审计日志、Prometheus 指标、统一策略控制和多种存储后端整合在一个可部署服务中。

## 核心特性

- 多协议访问：SFTP/SCP、FTP/FTPS、WebDAV、HTTP/WebAdmin/WebClient、REST API。
- 多存储后端：本地文件系统、加密本地文件系统、远端 SFTP、HTTPFs。
- 统一访问控制：文件权限、配额、带宽限制、IP 过滤和协议策略。
- 多认证方式：密码、SSH 公钥、TOTP MFA、OIDC、LDAP/AD、JWT Bearer、API Key。
- 运维能力：JSON 日志、审计记录、活动会话、分享链接、事件规则、Hooks、备份恢复、Prometheus 指标。
- 部署方式：Linux 单文件、Linux systemd、Docker、Docker Compose、Windows 服务包装器。

## 快速开始

```bash
git clone https://github.com/jincaiw/sftpxy.git
cd sftpxy
make build
./bin/sftpxy --config config.yaml.example
```

默认端口：

| 服务 | 端口 |
|---|---:|
| SSH/SFTP/SCP | 30082 |
| WebAdmin/API | 30088 |
| WebClient | 30080 |
| WebDAV | 30084 |
| FTP/FTPS | 30086 |

## 从源码构建

```bash
go mod download
npm --prefix web install
make verify-prod
make release-bundle
```

Linux 发布包输出到：

```text
dist/release/sftpxy-linux-amd64-systemd-v0.1.0.tar.gz
```

## Linux 单文件部署

1. 构建或下载 Linux 二进制：

```bash
VERSION=0.1.0 make release-bundle
tar xzf dist/release/sftpxy-linux-amd64-systemd-v0.1.0.tar.gz -C /tmp
```

2. 安装二进制和运行资源：

```bash
sudo install -m 755 /tmp/sftpxy-linux-amd64-systemd-v0.1.0/sftpxy /usr/local/bin/sftpxy
sudo install -d -m 750 /etc/sftpxy /var/lib/sftpxy /var/log/sftpxy /usr/local/share/sftpxy
sudo cp /tmp/sftpxy-linux-amd64-systemd-v0.1.0/config.yaml.example /etc/sftpxy/config.yaml
sudo cp -R /tmp/sftpxy-linux-amd64-systemd-v0.1.0/migrations /usr/local/share/sftpxy/
sudo cp -R /tmp/sftpxy-linux-amd64-systemd-v0.1.0/web /usr/local/share/sftpxy/
```

3. 修改 `/etc/sftpxy/config.yaml`：

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

4. 生成持久化 SSH host key 并校验配置：

```bash
sudo /usr/local/bin/sftpxy generate-hostkey --output /var/lib/sftpxy/keys/ssh_host_ed25519_key
sudo /usr/local/bin/sftpxy validate-config --config /etc/sftpxy/config.yaml --strict-production
```

5. 启动服务：

```bash
sudo /usr/local/bin/sftpxy --config /etc/sftpxy/config.yaml
```

6. 创建首个管理员：

```bash
printf 'StrongPasswordHere' | sudo /usr/local/bin/sftpxy \
  bootstrap-admin \
  --config /etc/sftpxy/config.yaml \
  --username admin \
  --password-stdin
```

## Linux systemd 服务部署

1. 构建发布包：

```bash
VERSION=0.1.0 make release-bundle
tar xzf dist/release/sftpxy-linux-amd64-systemd-v0.1.0.tar.gz -C /tmp
cd /tmp/sftpxy-linux-amd64-systemd-v0.1.0
```

2. 使用发布包内安装脚本：

```bash
sudo SFTPXY_TLS_CERT_FILE=/path/to/sftpxy.crt \
  SFTPXY_TLS_KEY_FILE=/path/to/sftpxy.key \
  ./systemd/install.sh
```

3. 管理服务：

```bash
sudo systemctl status sftpxy
sudo systemctl restart sftpxy
sudo journalctl -u sftpxy -f
```

4. 冒烟验证：

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

## 开发

```bash
make test
make test-protocols
make web-build
make verify-prod
```

## 文档

- [Linux systemd 部署](docs/production/systemd.md)
- [Docker 部署](docs/production/docker.md)
- [生产配置说明](docs/production/configuration.md)
- [备份恢复](docs/production/backup-restore.md)
- [发布清单](docs/production/release-checklist.md)
- [发布说明](docs/production/release-notes.md)

## 开源协议

SFTPxy 使用 [MIT License](LICENSE) 开源。
