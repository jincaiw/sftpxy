# SFTPxy

[English](./README.md)

[![CI Status](https://github.com/jincaiw/sftpxy/workflows/CI/badge.svg)](https://github.com/jincaiw/sftpxy/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

SFTPxy 是一个面向生产环境的文件传输服务，支持 SFTP、WebAdmin、WebClient、FTP/S、WebDAV、REST API 和可插拔存储后端。它适合部署在私有基础设施中，可以通过单文件二进制、systemd 服务或 Docker 容器稳定运行。

默认服务端口：

| 服务 | URL 或端口 |
| --- | --- |
| WebAdmin 和 REST/OpenAPI | `http://localhost:30080/` |
| WebClient | `http://localhost:30081/` |
| SFTP | `30082` |
| FTP 被动端口范围 | `30085-30088` |

Web 界面默认使用中文（`zh-CN`）。英文可以在语言选择器中切换。

## 演示

![WebAdmin login](docs/screenshots/webadmin-login.png)

![WebClient login](docs/screenshots/webclient-login.png)

![Mobile WebAdmin login](docs/screenshots/mobile-webadmin-login.png)

## 快速开始

从 [GitHub Releases](https://github.com/jincaiw/sftpxy/releases) 下载最新版本，解压对应平台的归档文件，然后启动服务：

```bash
./SFTPxy serve -c .
```

首次本地运行时，可以创建默认管理员：

```bash
SFTPXY_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1 \
SFTPXY_DEFAULT_ADMIN_USERNAME=admin \
SFTPXY_DEFAULT_ADMIN_PASSWORD='change-this-password' \
SFTPXY_COMMON__SECRET_MIN_ENTROPY=0 \
./SFTPxy serve -c .
```

打开 `http://localhost:30080/` 登录，然后在生产使用前修改启动时创建的临时凭据。

## Linux 单文件部署

下面的目录结构将可执行文件、配置、状态和用户数据分开管理：

```bash
sudo install -d -m 0755 /etc/SFTPxy /usr/local/bin /srv/SFTPxy/data
sudo install -d -m 0750 /var/lib/SFTPxy /var/log/SFTPxy

sudo install -m 0755 SFTPxy /usr/local/bin/SFTPxy
sudo cp SFTPxy.json /etc/SFTPxy/SFTPxy.json
sudo cp -R templates static openapi /etc/SFTPxy/
```

首次启动时创建管理员账号：

```bash
sudo SFTPXY_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1 \
  SFTPXY_DEFAULT_ADMIN_USERNAME=admin \
  SFTPXY_DEFAULT_ADMIN_PASSWORD='replace-with-a-strong-password' \
  SFTPXY_COMMON__SECRET_MIN_ENTROPY=0 \
  /usr/local/bin/SFTPxy serve -c /etc/SFTPxy
```

首次登录后，停止临时前台进程，并改用 systemd 运行 SFTPxy。

## systemd 部署

创建专用系统账号：

```bash
sudo useradd --system --home /var/lib/SFTPxy --shell /usr/sbin/nologin SFTPxy
sudo chown -R SFTPxy:SFTPxy /var/lib/SFTPxy /srv/SFTPxy /var/log/SFTPxy
sudo chown -R root:SFTPxy /etc/SFTPxy
sudo chmod 0750 /etc/SFTPxy
```

安装服务：

```bash
sudo cp init/SFTPxy.service /etc/systemd/system/SFTPxy.service
sudo tee /etc/SFTPxy/SFTPxy.env >/dev/null <<'EOF'
SFTPXY_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1
SFTPXY_DEFAULT_ADMIN_USERNAME=admin
SFTPXY_DEFAULT_ADMIN_PASSWORD=replace-with-a-strong-password
SFTPXY_COMMON__SECRET_MIN_ENTROPY=0
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now SFTPxy
sudo systemctl status SFTPxy
```

默认管理员创建完成并设置正式密码后，删除 `/etc/SFTPxy/SFTPxy.env` 中的启动变量并重启：

```bash
sudo sed -i '/CREATE_DEFAULT_ADMIN/d;/DEFAULT_ADMIN_/d;/SECRET_MIN_ENTROPY/d' /etc/SFTPxy/SFTPxy.env
sudo systemctl restart SFTPxy
```

## Docker 部署

Docker 镜像发布在 `qing1205/sftpxy`。

```bash
docker run -d --name sftpxy \
  -p 30080:30080 \
  -p 30081:30081 \
  -p 30082:30082 \
  -p 30085-30088:30085-30088 \
  -e SFTPXY_DATA_PROVIDER__CREATE_DEFAULT_ADMIN=1 \
  -e SFTPXY_DEFAULT_ADMIN_USERNAME=admin \
  -e SFTPXY_DEFAULT_ADMIN_PASSWORD='replace-with-a-strong-password' \
  -e SFTPXY_COMMON__SECRET_MIN_ENTROPY=0 \
  -v sftpxy-config:/etc/SFTPxy \
  -v sftpxy-data:/srv/SFTPxy \
  qing1205/sftpxy:v0.2.1
```

Docker Compose：

```yaml
services:
  sftpxy:
    image: qing1205/sftpxy:v0.2.1
    container_name: sftpxy
    restart: unless-stopped
    ports:
      - "30080:30080"
      - "30081:30081"
      - "30082:30082"
      - "30085-30088:30085-30088"
    environment:
      SFTPXY_DATA_PROVIDER__CREATE_DEFAULT_ADMIN: "1"
      SFTPXY_DEFAULT_ADMIN_USERNAME: admin
      SFTPXY_DEFAULT_ADMIN_PASSWORD: replace-with-a-strong-password
      SFTPXY_COMMON__SECRET_MIN_ENTROPY: "0"
    volumes:
      - sftpxy-config:/etc/SFTPxy
      - sftpxy-data:/srv/SFTPxy

volumes:
  sftpxy-config:
  sftpxy-data:
```

## 发布产物

`v0.2.1` 发布包含：

- Linux 安装包和便携归档。
- Windows 安装程序和便携归档。
- 包含 vendored 依赖的源码归档。
- Docker 镜像 `qing1205/sftpxy:v0.2.1` 和 `qing1205/sftpxy:latest`。

## 标准发布流程

SFTPxy 使用语义化版本，Git 标签格式为 `vX.Y.Z`。发布版本写在 `VERSION` 文件中，不带前缀 `v`，并且必须与 `internal/version/version.go` 保持一致。

打标签前先运行本地发布门禁：

```bash
make release-dry-run VERSION=0.2.1
```

本地流程通过且工作树干净后，创建并推送发布标签：

```bash
make release-tag VERSION=0.2.1
make release-push VERSION=0.2.1
```

推送标签会触发 GitHub release workflow 和 Docker workflow。完整发布检查清单见 [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md)。

## 配置说明

- WebAdmin 和 REST/OpenAPI 使用 `30080`。
- WebClient 使用 `30081`。
- SFTP 使用 `30082`。
- 启用 FTP 时，建议使用 `30085-30088` 作为被动端口范围。
- 密钥和密码等敏感配置优先放在 `/etc/SFTPxy/SFTPxy.env` 或 Docker 环境变量中。
- 不要提交本地数据库、日志、运行时密钥、发布包或私有配置覆盖文件。

## 许可证

SFTPxy 使用 [MIT License](./LICENSE) 授权。
