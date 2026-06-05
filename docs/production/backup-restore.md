# SFTPxy SQLite 备份恢复

## 备份范围

单机生产版至少要备份以下内容：

- 数据库：`/var/lib/sftpxy/sftpxy.db`
- SSH Host Key：`/var/lib/sftpxy/keys/ssh_host_ed25519_key`
- KMS Key：`/var/lib/sftpxy/keys/kms.key`
- TLS 证书：`/etc/sftpxy/certs/`
- 主配置：`/etc/sftpxy/config.yaml`
- 如需审计保留：`/var/log/sftpxy/`

## 冷备流程

```bash
sudo systemctl stop sftpxy
sudo tar czf sftpxy-backup-$(date +%F-%H%M%S).tar.gz \
  /etc/sftpxy \
  /var/lib/sftpxy \
  /var/log/sftpxy
sudo systemctl start sftpxy
```

适用：

- 升级前完整备份
- 短暂停机窗口可接受

## SQLite 在线备份

若要在服务运行中获取数据库一致性备份，推荐先复制完整数据目录或使用系统快照。最小方案：

```bash
sudo install -d -m 750 /var/backups/sftpxy
sudo cp /var/lib/sftpxy/sftpxy.db /var/backups/sftpxy/sftpxy.db.$(date +%F-%H%M%S)
```

说明：

- 当前交付基线主要保证单机可恢复
- 如需更严格的一致性快照，建议结合文件系统快照能力

## 恢复流程

1. 停服务

```bash
sudo systemctl stop sftpxy
```

2. 恢复配置和数据

```bash
sudo tar xzf sftpxy-backup-<timestamp>.tar.gz -C /
sudo chown -R sftpxy:sftpxy /var/lib/sftpxy /var/log/sftpxy
sudo chown -R root:sftpxy /etc/sftpxy
```

3. 启动并验证

```bash
sudo systemctl start sftpxy
sudo systemctl status sftpxy
curl -k https://127.0.0.1:30088/health
```

## 恢复后验证

至少检查：

- `sftp` 登录成功
- `https://<host>:30088/admin` 登录成功
- `https://<host>:30080/client` 能浏览文件
- FTPS/WebDAV 端口可访问
- `/health`、`/status`、`/openapi`、`/metrics` 正常

## 演练建议

每次发布前至少完成一次：

- 冷备恢复演练
- 管理员登录验证
- WebClient 文件读写验证
- SFTP 文件传输验证
