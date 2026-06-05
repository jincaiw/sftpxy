# SFTPxy 发布与回滚清单

## 发布前

- 执行 `make verify-prod`
- 确认 `deploy/systemd/install.sh` 与 `deploy/systemd/sftpxy.service` 已随版本更新
- 确认 TLS 证书与私钥可用
- 确认 `config.yaml` 中：
  - `session_secret` 已替换
  - `cors_origins` 为显式域名
  - `ssh.host_keys` 为持久化密钥
  - 若启用 FTPS，`passive_port_start/end` 与 `nat_external_address` 已核对
- 完成冷备或至少数据库与密钥备份

## 发布步骤

1. 在目标机准备新二进制与前端资源
2. 备份 `/etc/sftpxy` 与 `/var/lib/sftpxy`
3. 执行：

```bash
sudo ./deploy/systemd/install.sh
```

4. 初始化或确认管理员账号
5. 验证：

```bash
sudo systemctl status sftpxy
curl -k https://127.0.0.1:30088/health
curl -k https://127.0.0.1:30088/status
curl -k https://127.0.0.1:30088/openapi
curl http://127.0.0.1:30088/metrics
```

## 上线后检查

- Admin 登录正常
- Client 登录正常
- SFTP 文件上传下载正常
- FTPS 文件上传下载正常
- WebDAV 目录读写正常
- 审计日志有记录
- systemd 自动重启策略正常

## 回滚条件

出现以下任一情况应回滚：

- 服务无法启动
- 管理端/客户端无法登录
- SFTP/FTPS/WebDAV 任一核心协议不可用
- 数据库迁移异常
- 审计日志或关键指标缺失

## 回滚步骤

1. 停止服务

```bash
sudo systemctl stop sftpxy
```

2. 恢复备份的配置、数据库、密钥、证书

3. 恢复上一版本二进制和前端资源

4. 启动服务并复查：

```bash
sudo systemctl start sftpxy
sudo systemctl status sftpxy
```

## 发布证据留存

建议保存：

- `make verify-prod` 输出
- `systemctl status sftpxy`
- `/health`、`/status`、`/openapi`、`/metrics` 响应
- 管理端和客户端登录截图
