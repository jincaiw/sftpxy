# SFTPxy 最终交付说明与变更清单

## 交付结论

本轮工作已完成既定目标，当前仓库可以作为本次认证、安全、回归与交付收尾版本交付。

本次交付覆盖：

- 存储路径安全修复
- 分享授权与计数语义修复
- HTTP 登录、MFA、JWT 会话撤销修复
- LDAP / OIDC 认证链路修复
- OIDC 回跳安全修复
- Admin 持久化会话模型补齐
- 前端登录与 MFA 关闭流程适配
- 数据库迁移补齐
- 综合回归、真实服务编排验证、生产配置验证、发布打包验证

## 本次完成的核心问题

### 1. 存储与文件访问安全

- 修复本地存储路径逃逸与 sibling-prefix escape
- 修复 symlink escape 风险
- 修复加密文件系统 `../` 路径穿越
- 修复 Remote SFTP 前缀逃逸

对应文件：

- `internal/storage/pathutil.go`
- `internal/storage/local/local.go`
- `internal/storage/encrypted/encrypted.go`
- `internal/storage/remotesftp/remotesftp.go`
- `internal/storage/local/local_test.go`
- `internal/storage/encrypted/encrypted_test.go`
- `internal/storage/remotesftp/remotesftp_test.go`

### 2. 分享链路安全

- 修复分享创建时未重新校验下载/上传策略的问题
- 修复分享下载时未重新校验分享所有者权限的问题
- 修复分享访问校验阶段提前增加下载/上传次数的问题

对应文件：

- `internal/protocols/httpd/api_handlers.go`
- `internal/shares/share_manager.go`
- `internal/shares/share_manager_test.go`

### 3. HTTP 登录、MFA 与 JWT 会话撤销

- 修复用户 HTTP 登录仅校验 MFA 非空、未真实校验 TOTP 的问题
- 为管理员 HTTP 登录补齐 MFA 校验
- 修复 refresh 后旧 JWT 仍可继续使用的问题
- 修复主动断开会话后旧 JWT 仍可访问的问题
- 修复禁用用户或管理员后旧 token 未即时失效的问题
- 修复 `password_changed_at` 为空时密码过期逻辑失效的问题
- 修复强制改密时复杂策略缺失导致弱密码可通过的问题
- 修复恢复码不可用问题，并实现一次性消费

对应文件：

- `internal/protocols/httpd/server.go`
- `internal/protocols/httpd/api_new_handlers.go`
- `internal/protocols/httpd/server_test.go`
- `migrations/sqlite/007_mfa_recovery_codes.sql`
- `migrations/mysql/007_mfa_recovery_codes.sql`

### 4. LDAP / OIDC 链路修复

- 修复 LDAP 登录绕过本地 MFA 的问题
- 修复 OIDC `roleHint` 可触发 admin 提权的问题
- 修复 LDAP / OIDC 自动建用户时 home dir 路径穿越风险
- 修复 OIDC 缺少 `UserInfoURL` 时无法从 `id_token` 提取 claims 的问题
- 修复 OIDC callback 将 token 暴露在 query 中的问题，改为 URL fragment 回跳

对应文件：

- `internal/protocols/httpd/server.go`
- `internal/auth/oidc.go`
- `internal/auth/oidc_test.go`
- `web/src/views/admin/Login.vue`
- `web/src/views/client/Login.vue`

### 5. Admin 持久化会话与连接视图统一

- 为 admin 引入 `admin_sessions` 持久化会话表
- 补齐 admin 登录、refresh、会话失效、统一撤销能力
- `/api/v1/connections` 统一展示 `sessions` 与 `admin_sessions`
- 管理端断开连接逻辑支持 user/admin 两类主体

对应文件：

- `internal/protocols/httpd/server.go`
- `internal/protocols/httpd/api_new_handlers.go`
- `internal/protocols/httpd/server_test.go`
- `migrations/sqlite/008_admin_sessions.sql`
- `migrations/mysql/008_admin_sessions.sql`
- `web/src/api/client.ts`

### 6. 联邦用户 MFA 关闭流程

- 修复 LDAP / OIDC 用户没有本地密码时无法关闭 MFA 的问题
- 关闭 MFA 时允许使用当前密码，或当前 MFA code / recovery code 进行确认
- 前端文案与交互已同步适配联邦账号场景

对应文件：

- `internal/protocols/httpd/api_new_handlers.go`
- `internal/protocols/httpd/server_test.go`
- `web/src/views/client/Profile.vue`

### 7. 测试脚本与回归体系修复

- 修复 `tests/api-comprehensive-test.sh` 中虚拟目录更新和数据保留策略的误报
- 修复 `tests/protocol-comprehensive-test.sh` 中 SFTP / SSH 探测脆弱实现
- 修复 `TestUserFileAPIContract` 对 `/connections` 的旧语义断言

对应文件：

- `tests/api-comprehensive-test.sh`
- `tests/protocol-comprehensive-test.sh`
- `internal/protocols/httpd/server_test.go`

## 数据库变更

本次新增数据库迁移如下：

- `migrations/sqlite/007_mfa_recovery_codes.sql`
- `migrations/mysql/007_mfa_recovery_codes.sql`
- `migrations/sqlite/008_admin_sessions.sql`
- `migrations/mysql/008_admin_sessions.sql`

用途如下：

- 为 `users` 增加 `mfa_recovery_codes`
- 新增 `admin_sessions`，支撑管理员会话持久化、连接展示与统一撤销

## 前端变更

本次前端主要变更如下：

- `web/src/views/admin/Login.vue`
- `web/src/views/client/Login.vue`
- `web/src/views/client/Profile.vue`
- `web/src/api/client.ts`

交付结果如下：

- Admin / Client 登录页支持优先从 URL fragment 读取 OIDC 登录结果
- Client 个人中心支持联邦用户使用 MFA code / recovery code 关闭 MFA
- 连接对象新增 `principal` 字段，兼容 user/admin 连接展示

## 主要回归验证结果

### Go 回归

已通过：

- `go test ./internal/protocols/httpd -count=1`
- `go test ./... -count=1`

### 真实服务编排验证

已通过：

- `bash tests/protocol-comprehensive-test.sh`
- `bash tests/api-comprehensive-test.sh`
- `node tests/ui-comprehensive-test.js`
- `npm --prefix web run test:e2e`

### 生产与交付验证

已通过：

- `make build`
- `npm --prefix web run build`
- `make test-prod-config`
- `bash deploy/package-release.sh`

### 性能 / 并发 / 长稳验证

已完成一轮补充验证，结论如下：

- HTTP 突发压测稳定，`/health`、`/status`、`/api/v1/profile` 在当前单机 e2e 环境下均为 `0` 失败
- FTP 并发传输验证通过，`10` worker、`60` 次回环成功率 `100%`
- WebDAV 并发传输验证通过，`12` worker、`96` 次回环成功率 `100%`
- 压测前后 goroutine、活动连接、堆内存未出现明显泄漏迹象
- SFTP 压测结果在当前本机 `sftp` 命令行认证方式下不稳定，结论记为 `inconclusive`，不作为服务端失败定论

## 当前交付物

当前已生成发布产物：

- `dist/release/sftpxy-linux-amd64-systemd-v0.1.1.tar.gz`
- `dist/release/sftpxy-linux-amd64-systemd-v0.1.1.manifest.txt`
- `dist/release/sftpxy-linux-amd64-systemd-v0.1.1.tar.gz.sha256`

## 建议上线前再确认

- 执行 `docs/production/release-checklist.md`
- 确认目标环境 TLS 证书、SSH host key、`session_secret` 和备份策略
- 应用新增数据库迁移 `007` 与 `008`
- 重点复验：
  - Admin 登录 / refresh / logout
  - Client 登录 / 文件上传下载 / 分享
  - MFA 开启、关闭、恢复码登录
  - OIDC 登录回跳
  - `/api/v1/connections` 与会话撤销

## 剩余风险与后续建议

本次仍有以下已知非阻断项：

- 前端构建存在 chunk 体积告警，属于包体优化问题，不影响当前功能交付
- 当前仓库缺少专业压测工具链，HTTP 长稳与 SFTP 压测的高置信度结论仍建议后续用 `wrk` / `vegeta` / `k6` 或稳定 SFTP 客户端补测
- `SSH/SFTP`、`FTP` 的部分连接上限和超时配置在实现层仍有继续加强空间
- telemetry 中虽有 profiling 配置字段，但尚未真正接入 `pprof`

## 本次变更文件清单

已修改：

- `internal/auth/oidc.go`
- `internal/protocols/httpd/api_handlers.go`
- `internal/protocols/httpd/api_new_handlers.go`
- `internal/protocols/httpd/server.go`
- `internal/protocols/httpd/server_test.go`
- `internal/shares/share_manager.go`
- `internal/shares/share_manager_test.go`
- `internal/storage/encrypted/encrypted.go`
- `internal/storage/local/local.go`
- `internal/storage/remotesftp/remotesftp.go`
- `internal/storage/remotesftp/remotesftp_test.go`
- `tests/api-comprehensive-test.sh`
- `tests/protocol-comprehensive-test.sh`
- `web/src/api/client.ts`
- `web/src/views/admin/Login.vue`
- `web/src/views/client/Login.vue`
- `web/src/views/client/Profile.vue`

已新增：

- `internal/auth/oidc_test.go`
- `internal/storage/encrypted/encrypted_test.go`
- `internal/storage/local/local_test.go`
- `internal/storage/pathutil.go`
- `migrations/mysql/007_mfa_recovery_codes.sql`
- `migrations/mysql/008_admin_sessions.sql`
- `migrations/sqlite/007_mfa_recovery_codes.sql`
- `migrations/sqlite/008_admin_sessions.sql`

## 建议阅读顺序

建议接手人优先阅读：

- `docs/production/final-delivery-auth-hardening.md`
- `docs/production/release-checklist.md`
- `docs/production/handoff.md`
- `docs/production/release-notes.md`
