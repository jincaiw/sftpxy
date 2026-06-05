# SFTPxy Linux systemd 单机部署

## 目标

本文档对应当前仓库支持的生产交付形态：

- Linux
- systemd
- SQLite 单机
- 服务内 TLS 证书
- SFTP/SCP、HTTP/WebAdmin/WebClient/REST、FTP/FTPS、WebDAV 均可配置启用

## 目录约定

- 二进制：`/usr/local/bin/sftpxy`
- 配置：`/etc/sftpxy/config.yaml`
- 证书：`/etc/sftpxy/certs/`
- 数据：`/var/lib/sftpxy/`
- SSH Host Key：`/var/lib/sftpxy/keys/ssh_host_ed25519_key`
- 日志：`/var/log/sftpxy/sftpxy.log`
- 运行资源：`/usr/local/share/sftpxy/`

## 前置要求

- 目标主机已安装 `systemd`
- 已构建二进制：`make build`
- 已构建前端资源：`make web-build`
- 已准备 TLS 证书和私钥

推荐先执行：

```bash
make verify-prod
```

## 安装步骤

1. 准备 TLS 证书文件

```bash
export SFTPXY_TLS_CERT_FILE=/path/to/sftpxy.crt
export SFTPXY_TLS_KEY_FILE=/path/to/sftpxy.key
```

2. 执行安装脚本

```bash
sudo ./deploy/systemd/install.sh
```

安装脚本会自动完成：

- 安装 `sftpxy` 二进制
- 安装 `migrations` 与 `web/dist`
- 复制 TLS 证书到 `/etc/sftpxy/certs/`
- 生成持久化 SSH host key
- 生成随机 `session_secret`
- 生成 systemd 配置
- 运行 `sftpxy validate-config --strict-production`
- 启用并启动 `sftpxy.service`

## 初始化管理员

安装成功后，使用下述命令创建首个管理员：

```bash
printf 'StrongPasswordHere' | sudo /usr/local/bin/sftpxy \
  bootstrap-admin \
  --config /etc/sftpxy/config.yaml \
  --username admin \
  --password-stdin
```

## 常用运维命令

```bash
sudo systemctl status sftpxy
sudo systemctl restart sftpxy
sudo systemctl stop sftpxy
sudo journalctl -u sftpxy -f
```

## 首次上线后检查

```bash
curl -k https://127.0.0.1:30088/health
curl -k https://127.0.0.1:30088/status
curl -k https://127.0.0.1:30088/openapi
curl http://127.0.0.1:30088/metrics
```

同时验证：

- `sftp` 可使用密码和 SSH 公钥登录
- `https://<host>:30088/admin` 可登录管理端
- `https://<host>:30080/client` 可登录客户端
- FTPS 与 WebDAV TLS 端口可访问

## 常见故障

- `validate-config --strict-production` 失败
  - 检查 `session_secret`
  - 检查 `ssh.host_keys`
  - 检查 `httpd/ftp/webdav` 的证书路径
  - 检查 `cors_origins`
- HTTP 启动失败
  - 确认 `web/dist/index.html` 已安装到 `/usr/local/share/sftpxy/web/dist`
- SFTP 指纹变化
  - 确认 `/var/lib/sftpxy/keys/ssh_host_ed25519_key` 未被替换
- FTPS 数据通道失败
  - 检查 `passive_port_start/end`
  - 检查防火墙是否放通被动端口范围
  - 检查 `nat_external_address`
