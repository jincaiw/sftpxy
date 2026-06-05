# SFTPxy 发布说明

## 版本范围

当前发布包面向以下交付范围：

- Linux
- systemd
- SQLite 单机
- 服务内 TLS
- SFTP/SCP、HTTP/WebAdmin/WebClient/REST、FTP/FTPS、WebDAV

## 本次交付完成项

- 补齐生产初始化命令：
  - `bootstrap-admin`
  - `generate-hostkey`
  - `validate-config --strict-production`
- systemd 安装脚本改为生产默认安全：
  - 强制提供 TLS 证书
  - 生成持久化 SSH host key
  - 生成随机 `session_secret`
  - 执行严格生产校验
- 协议层生产边界收口：
  - HTTP 启动前检查静态资源和 TLS 配置
  - SSH 明确区分临时/持久化 host key
  - FTP 校验被动端口范围和 NAT 地址
  - WebDAV 校验 `base_path`
  - 远程 SFTP 存储强制主机密钥校验
- 补齐生产文档：
  - systemd 部署
  - 生产配置
  - 备份恢复
  - 发布与回滚
- 补齐生产验收命令：
  - `make test-prod-config`
  - `make verify-prod`

## 验证结果

本次发布前已通过：

- `make test-prod-config`
- `make verify-prod`

其中 `verify-prod` 覆盖：

- Go 构建
- Go 全量测试
- 协议回归测试
- 前端构建
- Playwright 网页自动化测试
- 生产配置与部署脚本校验

## 发布包内容

通过以下命令生成发布包：

```bash
make release-bundle
```

生成产物位于：

- `dist/release/sftpxy-linux-amd64-systemd-v0.1.0.tar.gz`
- `dist/release/sftpxy-linux-amd64-systemd-v0.1.0.manifest.txt`

发布包中包含：

- `sftpxy` 二进制
- `config.yaml.example`
- `deploy/systemd` 安装文件
- `migrations`
- `web/dist`
- `docs/production`

## 上线建议

- 先执行 [release-checklist.md](release-checklist.md)
- 按 [systemd.md](systemd.md) 在目标机安装
- 按 [backup-restore.md](backup-restore.md) 先完成备份
