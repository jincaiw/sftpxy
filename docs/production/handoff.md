# SFTPxy 最终交付手册

## 交付结论

当前仓库已经完成本轮约定交付范围，可按 Linux + systemd + SQLite 单机或 Linux + Docker + SQLite 单机模式发布上线。

本次交付覆盖：

- SFTP/SCP
- HTTP / REST API
- WebAdmin
- WebClient
- FTP/FTPS
- WebDAV
- Linux systemd 安装与运行
- Linux Docker 安装与运行
- 生产配置校验、发布文档、发布包

已完成验证：

- `make verify-prod`
- `make test-prod-config`
- `make release-bundle`

## 推荐提交说明

建议使用一条汇总型提交说明：

```text
feat: deliver production-ready single-node systemd release for SFTPxy
```

如需拆分变更说明，可在提交正文中概括：

```text
- finish web admin/client feature closure and browser E2E coverage
- add production CLI bootstrap and strict config validation
- harden systemd deployment, protocol startup checks, and remote sftp host verification
- add production docs, release checklist, and release bundle packaging
```

## 关键变更分组

### 运行与生产 CLI

- `cmd/sftpxy/main.go`
- `cmd/sftpxy/main_test.go`
- `internal/config/validation.go`
- `internal/config/validation_test.go`

本组完成：

- `bootstrap-admin`
- `generate-hostkey`
- `validate-config --strict-production`
- 单机生产配置安全校验

### 协议与安全收口

- `internal/protocols/httpd/server.go`
- `internal/protocols/ssh/server.go`
- `internal/protocols/ftp/server.go`
- `internal/protocols/ftp/server_test.go`
- `internal/protocols/webdav/server.go`
- `internal/protocols/webdav/server_test.go`
- `internal/storage/remotesftp/remotesftp.go`
- `internal/storage/remotesftp/remotesftp_test.go`

本组完成：

- HTTP 静态资源与 TLS 启动前检查
- SSH 持久化 host key 提示与生产校验
- FTP/FTPS 端口、NAT、显式 TLS 边界校验
- WebDAV `base_path` 校验
- Remote SFTP 主机密钥强校验

### Web 功能闭环与自动化

- `web/src/views/admin/Login.vue`
- `web/src/views/admin/Layout.vue`
- `web/src/views/admin/Users.vue`
- `web/src/views/client/Login.vue`
- `web/src/views/client/Layout.vue`
- `web/src/views/client/FileBrowser.vue`
- `web/src/views/client/Profile.vue`
- `web/playwright.config.mjs`
- `web/tests/e2e/admin.spec.ts`
- `web/tests/e2e/client.spec.ts`
- `tests/e2e/start-e2e.sh`
- `tests/e2e/seed.go`

本组完成：

- WebAdmin / WebClient 主流程修复
- 稳定 `data-testid` 选择器
- Playwright 端到端回归
- 隔离端口 `7080` 的可重复 E2E 环境

### 部署、文档与发布产物

- `Makefile`
- `config.yaml.example`
- `deploy/systemd/install.sh`
- `deploy/systemd/sftpxy.service`
- `deploy/package-release.sh`
- `docs/production/docker.md`
- `docs/production/systemd.md`
- `docs/production/configuration.md`
- `docs/production/backup-restore.md`
- `docs/production/release-checklist.md`
- `docs/production/release-notes.md`

本组完成：

- 统一生产验证命令
- systemd 安装脚本加固
- Docker / systemd 生产文档更新
- 发布清单、发布说明、备份恢复文档
- Linux systemd 发布包生成

## 已生成交付产物

发布包与清单位于：

- `dist/release/sftpxy-linux-amd64-systemd-v0.1.0.tar.gz`
- `dist/release/sftpxy-linux-amd64-systemd-v0.1.0.manifest.txt`
- `dist/release/sftpxy-linux-amd64-systemd-v0.1.0/RELEASE.txt`

发布包内包含：

- `sftpxy` 二进制
- `config.yaml.example`
- `deploy/systemd`
- `migrations`
- `web/dist`
- `docs/production`

## 推荐交付顺序

1. 执行 `make verify-prod`
2. 执行 `make release-bundle`
3. 提交代码并附带本轮发布说明
4. 将 `dist/release/*.tar.gz` 与 `*.manifest.txt` 交付到目标环境
5. 按 `docs/production/systemd.md` 或 `docs/production/docker.md` 执行安装
6. 按 `docs/production/release-checklist.md` 做上线前复核

## 上线后最小验收

建议至少复验以下内容：

- `https://<host>:30088/health`
- `https://<host>:30088/status`
- `https://<host>:30088/openapi`
- `http://<host>:30088/metrics`
- Admin 登录、用户管理、退出登录
- Client 登录、文件上传下载、分享、修改资料、退出登录
- SFTP/FTPS/WebDAV 至少各完成一次真实访问

## 本轮非目标

当前交付不包含以下范围：

- 多节点或分布式部署
- MySQL 生产化方案
- 复杂外部认证体系
- 高可用编排与云原生部署模板
- 自动签发证书流程

## 交付给接手人的入口

优先阅读：

- `docs/production/handoff.md`
- `docs/production/release-notes.md`
- `docs/production/release-checklist.md`
- `docs/production/docker.md`
- `docs/production/systemd.md`
- `docs/production/configuration.md`
- `docs/production/backup-restore.md`
