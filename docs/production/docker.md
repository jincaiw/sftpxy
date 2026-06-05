# SFTPxy Linux Docker 单机部署

## 目标

本文档对应当前仓库支持的生产交付形态：

- Linux
- Docker
- SQLite 单机
- 服务内 TLS 证书
- SFTP/SCP、HTTP/WebAdmin/WebClient/REST、FTP/FTPS、WebDAV 均可配置启用

## 目录约定

推荐使用以下宿主机目录：

- 配置：`/srv/sftpxy/config/config.yaml`
- 证书：`/srv/sftpxy/certs/`
- 数据：`/srv/sftpxy/data/`
- 日志：`/srv/sftpxy/logs/`
- 前端资源：`/srv/sftpxy/web/dist/`

容器内目录约定：

- 镜像：`sftpxy:latest`
- 配置：`/etc/sftpxy/config.yaml`
- 证书：`/etc/sftpxy/certs/`
- 数据：`/var/lib/sftpxy/`
- SSH Host Key：`/var/lib/sftpxy/keys/ssh_host_ed25519_key`
- 日志：`/var/log/sftpxy/sftpxy.log`
- 前端资源：`/opt/sftpxy/web/dist/`

## 前置要求

- 目标主机已安装 Docker Engine
- 已构建前端资源：`make web-build`
- 已准备 TLS 证书和私钥
- 若启用 FTPS，被动端口范围已预留并可映射

推荐先执行：

```bash
make verify-prod
```

## 安装步骤

1. 准备宿主机目录与前端资源

```bash
sudo mkdir -p /srv/sftpxy/config /srv/sftpxy/certs /srv/sftpxy/data /srv/sftpxy/logs /srv/sftpxy/web
sudo cp config.yaml.example /srv/sftpxy/config/config.yaml
sudo cp -R web/dist /srv/sftpxy/web/
```

`/srv/sftpxy/config/config.yaml` 至少需要调整：

- `common.log_path: /var/log/sftpxy/sftpxy.log`
- `ssh.host_keys: [/var/lib/sftpxy/keys/ssh_host_ed25519_key]`
- `httpd.static_path: /opt/sftpxy/web/dist`
- `httpd.template_path: /opt/sftpxy/web/dist`
- `data_provider.connection_string: /var/lib/sftpxy/sftpxy.db`

2. 安装 TLS 证书文件

```bash
sudo install -m 600 /path/to/sftpxy.crt /srv/sftpxy/certs/sftpxy.crt
sudo install -m 600 /path/to/sftpxy.key /srv/sftpxy/certs/sftpxy.key
```

3. 构建镜像

```bash
docker build -t sftpxy:latest .
```

4. 生成持久化 SSH host key

```bash
docker run --rm \
  -v /srv/sftpxy/data:/var/lib/sftpxy \
  sftpxy:latest \
  generate-hostkey \
  --output /var/lib/sftpxy/keys/ssh_host_ed25519_key
```

5. 生成随机 `session_secret`

```bash
openssl rand -hex 32
```

将输出结果写入 `/srv/sftpxy/config/config.yaml` 的 `httpd.session_secret`。

6. 运行严格生产校验

```bash
docker run --rm \
  -v /srv/sftpxy/config/config.yaml:/etc/sftpxy/config.yaml:ro \
  -v /srv/sftpxy/certs:/etc/sftpxy/certs:ro \
  -v /srv/sftpxy/data:/var/lib/sftpxy \
  -v /srv/sftpxy/logs:/var/log/sftpxy \
  -v /srv/sftpxy/web/dist:/opt/sftpxy/web/dist:ro \
  sftpxy:latest \
  validate-config \
  --config /etc/sftpxy/config.yaml \
  --strict-production
```

7. 启动容器

```bash
docker run -d \
  --name sftpxy \
  --restart unless-stopped \
  -p 30082:30082 \
  -p 30088:30088 \
  -p 30084:30084 \
  -p 30080:30080 \
  -p 30086:30086 \
  -p 30100-30199:30100-30199 \
  -v /srv/sftpxy/config/config.yaml:/etc/sftpxy/config.yaml:ro \
  -v /srv/sftpxy/certs:/etc/sftpxy/certs:ro \
  -v /srv/sftpxy/data:/var/lib/sftpxy \
  -v /srv/sftpxy/logs:/var/log/sftpxy \
  -v /srv/sftpxy/web/dist:/opt/sftpxy/web/dist:ro \
  sftpxy:latest
```

如果未启用 FTP/FTPS 或 WebDAV，可删除对应的端口映射。

## 初始化管理员

容器启动成功后，使用下述命令创建首个管理员：

```bash
printf 'StrongPasswordHere' | docker exec -i sftpxy \
  /usr/local/bin/sftpxy \
  bootstrap-admin \
  --config /etc/sftpxy/config.yaml \
  --username admin \
  --password-stdin
```

## 常用运维命令

```bash
docker ps --filter name=sftpxy
docker logs -f sftpxy
docker restart sftpxy
docker stop sftpxy
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' sftpxy
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
  - 检查 `httpd.static_path` 与 `httpd.template_path`
  - 检查 `cors_origins`
- HTTP 启动失败
  - 确认 `web/dist/index.html` 已挂载到 `/opt/sftpxy/web/dist`
- SQLite 或 SSH host key 未持久化
  - 确认 `/srv/sftpxy/data` 已作为持久目录挂载
- FTPS 数据通道失败
  - 检查 `passive_port_start/end`
  - 检查宿主机和容器的被动端口映射
  - 检查 `nat_external_address`
