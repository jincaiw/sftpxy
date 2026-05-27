# SFTPxy 产品需求文档

# 1. 项目概述

## 1.1 产品名称

SFTPxy

## 1.2 产品定位

SFTPxy 是一套企业级、安全、可配置、可审计、可扩展的托管文件传输平台。

它不是单一 SFTP 服务，而是将多协议文件传输、本地与远端文件存储、Web 管理、Web 文件客户端、REST API、虚拟目录、权限控制、配额限速、事件管理、外部认证、审计日志、Prometheus 指标、插件扩展等能力整合到一个统一系统中。

## 1.3 核心价值

1. 统一管理企业文件传输账户。
2. 统一提供 SFTP、SCP、FTP/S、WebDAV、HTTP/S 文件访问能力。
3. 统一对接本地文件系统、加密本地文件系统、远端 SFTP 存储与 HTTPFs。
4. 统一实现权限、配额、审计、限速、安全认证。
5. 统一通过 WebAdmin、WebClient 和 REST API 进行管理与集成。
6. 支持事件驱动自动化处理文件传输业务。
7. 支持 Docker、Linux、Windows、SQLite 默认部署与 MySQL 生产部署方式。
8. 支持面向企业文件交换、合作伙伴文件协作和托管文件传输场景。

## 1.4 典型使用场景

| 场景 | 说明 |
|---|---|
| 企业 SFTP 文件交换 | 为内部系统、外部客户、合作伙伴提供安全文件交换 |
| 安全文件分享 | 通过 WebClient 创建带密码、过期时间、IP 限制的分享链接 |
| 多租户文件管理 | 不同管理员只管理授权范围内的用户和资源 |
| 自动化文件处理 | 上传、下载、删除、重命名等事件触发 HTTP Hook、命令、邮件等动作 |
| 合规审计 | 记录登录、传输、命令、API、失败连接、安全事件 |
| 轻量私有云文件传输 | 单机、Docker、SQLite 快速部署 |

---

# 2. 产品范围与边界

## 2.1 支持范围

系统必须支持以下核心能力：

1. SFTP 文件传输。
2. SCP 文件传输。
3. FTP / FTPS 文件传输。
4. HTTP / HTTPS 文件访问。
5. WebDAV 文件访问。
6. WebAdmin 管理端。
7. WebClient 文件客户端。
8. REST API。
9. OpenAPI 3 Schema。
10. 本地文件系统。
11. 加密本地文件系统。
12. 远端 SFTP 存储。
13. HTTPFs。
14. 虚拟目录。
15. 用户、管理员、组、角色管理。
16. 权限、配额、限速、IP 过滤。
17. MFA、OIDC、LDAP / AD 插件认证。
18. Event Manager。
19. Hooks。
20. JSON 结构化日志。
21. Prometheus Metrics。
22. SQLite 数据提供器。
23. MySQL 8.0+ 数据提供器。
24. Docker、Linux systemd、Windows 服务部署。

## 2.2 不支持范围

系统不支持以下能力：

1. 不支持对象存储对接。
2. 不支持 S3、GCS、Azure Blob。
3. 不支持对象存储协议网关。
4. 不支持将对象存储通过 SFTP、FTP、WebDAV 或 HTTP 暴露。
5. 不支持 PostgreSQL。
6. 不支持 CockroachDB。
7. 不支持 Bolt 数据库。
8. 不支持 Memory Provider 作为产品数据库。
9. 不支持 SQLite 和 MySQL 8.0+ 之外的其他产品数据库。
10. 不支持反向代理作为产品内置能力。
11. 不支持 IMAP 邮件附件采集。
12. 不支持 PGP。
13. 不支持 Antivirus。
14. 不支持 DLP via ICAP。
15. 不支持高可用集群作为本版本产品能力。
16. 不支持高级文档协同编辑作为本版本产品能力。
17. 不支持 Kubernetes 作为本版本内置部署能力。
18. 不支持 Terraform Provider 作为本版本产品能力。

## 2.3 整体交付原则

系统交付必须满足以下原则：

1. 所有功能统一开发。
2. 所有功能统一联调。
3. 所有功能统一验收。
4. 产品以完整版本整体交付。
5. 不按分期方式拆分交付。
6. 不以部分功能完成作为最终交付结果。
7. 不将核心功能拆分为未交付功能。
8. 整体验收必须覆盖协议服务、用户权限、WebAdmin、WebClient、REST API、存储、事件、日志、指标、部署和安全能力。

---

# 3. 用户角色与权限模型

## 3.1 超级管理员

超级管理员拥有系统全部管理权限。

职责包括：

1. 初始化系统。
2. 创建管理员。
3. 配置协议服务。
4. 配置数据提供器。
5. 配置存储后端。
6. 管理用户、组、角色、文件夹。
7. 查看连接、日志、指标。
8. 配置安全策略。
9. 配置事件规则。
10. 执行备份、恢复、升级、迁移。

## 3.2 受限管理员

受限管理员只能管理授权范围内的资源。

适用场景：

1. 多租户。
2. 多部门。
3. 运维分权。
4. 合作伙伴账号管理。
5. 客户自助账号管理。

受限方式包括：

1. 基于角色限制。
2. 基于组限制。
3. 基于用户归属限制。
4. 基于文件夹归属限制。
5. 基于权限项限制。

## 3.3 普通用户

普通用户通过协议或 WebClient 使用文件服务。

可配置限制：

1. 可用协议。
2. 登录认证方式。
3. 主目录。
4. 虚拟目录。
5. 文件权限。
6. 文件过滤。
7. 配额。
8. 带宽。
9. 总传输量。
10. 并发会话。
11. IP 允许/拒绝。
12. MFA。
13. 公钥管理权限。
14. 分享链接权限。

## 3.4 外部系统

外部系统通过以下方式集成：

1. REST API。
2. API Key。
3. JWT。
4. OpenAPI Client。
5. HTTP Hooks。
6. 外部认证接口。
7. 动态用户创建接口。
8. Event Manager。
9. 插件系统。

---

# 4. 总体架构

## 4.1 架构模式

系统采用模块化单体架构。

系统架构必须满足以下要求：

1. 后端核心能力由一个主服务进程承载。
2. 协议服务、HTTP 服务、事件管理、日志审计和指标监控共用同一套用户、权限、配置和数据模型。
3. 各功能模块在代码层面保持清晰边界。
4. 系统不拆分为独立微服务。
5. 系统不依赖 Kubernetes、服务网格或分布式注册中心。
6. 系统支持单二进制部署。
7. 系统支持通过配置启用或禁用不同协议服务。
8. 系统支持 SQLite 单机部署。
9. 系统支持 MySQL 8.0+ 生产部署。

## 4.2 功能架构

```text
客户端层
├── SFTP / SCP Client
├── FTP / FTPS Client
├── WebDAV Client
├── Browser WebAdmin
├── Browser WebClient
└── External System / API Client

接入层
├── SSH / SFTP / SCP Server
├── FTP / FTPS Server
├── WebDAV Server
├── HTTP Server
├── REST API
└── Telemetry Server

认证与会话层
├── Password Auth
├── Public Key Auth
├── SSH Certificate Auth
├── MFA / TOTP
├── OIDC
├── LDAP / AD Plugin
├── API Key / JWT
└── Session Management

业务能力层
├── 用户管理
├── 管理员管理
├── 组管理
├── 角色管理
├── 统一策略控制
├── 权限控制
├── 配额控制
├── 限速控制
├── 分享管理
├── 虚拟目录
├── Event Manager
└── Hooks

存储适配层
├── Local Filesystem
├── Encrypted Local Filesystem
├── Remote SFTP
└── HTTPFs

数据持久层
├── SQLite（默认）
└── MySQL 8.0+

运维观测层
├── JSON Logs
├── Audit Logs
├── Prometheus Metrics
├── Health Check
├── Backup / Restore
└── Config Management
```

## 4.3 系统模块划分

系统必须划分为以下核心模块：

1. 协议服务模块。
2. 用户与权限模块。
3. 统一策略控制模块。
4. 存储适配模块。
5. WebAdmin 模块。
6. WebClient 模块。
7. REST API 模块。
8. 事件管理模块。
9. Hooks 模块。
10. 日志审计模块。
11. 指标监控模块。
12. 数据提供器模块。
13. 配置管理模块。
14. 插件管理模块。
15. 备份恢复模块。

## 4.4 技术实现约束

系统技术实现必须满足以下约束：

1. 后端语言采用 Go。
2. 后端架构采用模块化单体架构。
3. HTTP 路由采用 Chi。
4. API 采用 REST + OpenAPI 3。
5. OpenAPI 代码生成采用 oapi-codegen。
6. 数据库迁移采用 Goose。
7. 数据访问采用 SQLC。
8. 系统所有数据库访问必须通过 SQLC 生成的类型安全代码或经过封装的 Repository 接口完成。
9. 系统不采用 GORM 作为核心数据访问层。
10. SQLite 与 MySQL 8.0+ 必须分别提供迁移脚本、查询 SQL 和集成测试。
11. 配置管理采用 Viper。
12. 日志组件采用 Zap。
13. 指标组件采用 Prometheus client_golang。
14. 数据库默认使用 SQLite。
15. 数据库支持 MySQL 8.0+。
16. 系统不支持 SQLite 和 MySQL 8.0+ 之外的其他产品数据库。
17. 存储支持本地文件系统、加密本地文件系统、远端 SFTP 和 HTTPFs。
18. 日志采用 JSON 结构化日志。
19. 部署支持单二进制、Docker、Docker Compose、Linux systemd 和 Windows 服务。
20. 前端框架采用 Vue 3。
21. 前端语言采用 TypeScript。
22. 前端 UI 组件库采用 Naive UI。
23. 前端构建工具采用 Vite。
24. 前端状态管理采用 Pinia。
25. 前端路由采用 Vue Router。
26. 前端图表采用 ECharts。

## 4.5 统一策略控制模块

系统必须提供统一策略控制模块。所有协议服务、WebClient 和 REST API 必须调用统一策略控制模块。

统一策略控制模块必须集中判断以下策略：

1. 用户状态。
2. 管理员状态。
3. 协议启用状态。
4. 认证方式。
5. IP 允许列表。
6. IP 拒绝列表。
7. 文件权限。
8. 虚拟目录权限。
9. 配额。
10. 带宽限速。
11. 总传输量限制。
12. 文件过滤。
13. 分享权限。
14. WebClient 权限。
15. API 权限。
16. 管理员管理范围。

统一策略控制模块必须保证 SFTP、SCP、FTP/FTPS、WebDAV、WebClient 和 REST API 的权限判断结果一致。

---

# 5. 配置体系需求

系统必须提供独立配置管理模块。配置管理模块应支持配置文件、环境变量、命令行参数、配置校验、敏感信息脱敏和配置变更提示。

## 5.1 配置文件格式

系统应支持：

1. JSON。
2. TOML。
3. YAML。
4. envfile。
5. 环境变量覆盖配置。
6. 命令行参数指定配置路径。
7. 默认配置文件。
8. 配置项校验。
9. 敏感配置脱敏展示。
10. 配置变更后是否需要重启应明确说明。

## 5.2 Common 配置

应支持：

1. 服务实例名称。
2. 日志级别。
3. 日志输出路径。
4. 临时目录。
5. 文件上传临时处理策略。
6. 插件加载路径。
7. 全局超时时间。
8. 全局安全策略。
9. 全局路径设置。
10. 运行时参数。

## 5.3 SSH / SFTP / SCP 配置

应支持：

1. 监听地址。
2. 监听端口。
3. Host Key 配置。
4. 密码认证开关。
5. 公钥认证开关。
6. SSH 证书认证。
7. Keyboard Interactive。
8. 允许算法。
9. 禁用算法。
10. 最大连接数。
11. 登录超时。
12. 空闲超时。
13. SCP 启用/禁用。
14. SFTP 子系统参数。
15. Banner。
16. SSH 命令控制。
17. Git over SSH 支持。

## 5.4 FTP / FTPS 配置

应支持：

1. FTP 监听地址。
2. FTP 监听端口。
3. FTPS 显式 TLS。
4. TLS 证书配置。
5. 是否强制控制通道 TLS。
6. 是否强制数据通道 TLS。
7. Passive 端口范围。
8. NAT 外部地址。
9. 最大连接数。
10. 登录超时。
11. 空闲超时。
12. 文件名编码。
13. 被动模式与主动模式配置。

## 5.5 WebDAV 配置

应支持：

1. WebDAV 启用/禁用。
2. 监听地址。
3. 监听端口。
4. 基础路径。
5. HTTPS 配置。
6. 双向 TLS。
7. CORS。
8. 上传限制。
9. 下载限制。
10. 认证方式。
11. WebDAV 客户端兼容性配置。

## 5.6 HTTPD 配置

HTTPD 负责 WebAdmin、WebClient、REST API、OpenAPI、分享链接等 HTTP 能力。

应支持：

1. HTTPD 启用/禁用。
2. 监听地址。
3. 监听端口。
4. HTTPS 配置。
5. 双向 TLS。
6. WebAdmin 启用/禁用。
7. WebClient 启用/禁用。
8. REST API 启用/禁用。
9. OpenAPI 启用/禁用。
10. 静态资源路径。
11. 模板路径。
12. CORS。
13. CSRF。
14. Cookie 安全策略。
15. 客户端真实 IP 获取方式。
16. 登录 Session 配置。
17. API Token 有效期。
18. 分享链接访问路径。
19. Web UI 国际化设置。

## 5.7 Data Provider 配置

系统默认使用 SQLite，同时支持 MySQL 8.0+；其他数据库不纳入产品范围。

应支持：

1. SQLite 默认数据提供器。
2. MySQL 8.0+ 数据提供器。
3. 数据库连接字符串。
4. SSL 模式。
5. 连接池。
6. 超时时间。
7. 数据库迁移开关。
8. 数据结构初始化。
9. 数据结构升级。
10. 数据结构降级。
11. Provider 健康检查。
12. 数据导入导出。

## 5.8 Telemetry 配置

应支持独立 Telemetry Server。

功能包括：

1. 是否启用 Telemetry。
2. 监听地址。
3. 监听端口。
4. `/metrics` Prometheus 指标。
5. 健康检查接口。
6. 运行时指标。
7. Data Provider 可用性指标。
8. 访问控制。
9. TLS 配置。
10. 是否暴露 Profiling。

## 5.9 HTTP Clients 配置

用于外部 HTTP Hook、外部认证、HTTPFs、OIDC、插件等场景。

应支持：

1. 默认超时时间。
2. HTTP Client 出站网络配置。
3. TLS 校验。
4. 客户端证书。
5. 重试策略。
6. 最大连接数。
7. Keepalive。
8. 请求头配置。
9. 认证配置。
10. 失败处理策略。

## 5.10 Commands 配置

用于外部命令执行。

应支持：

1. 命令白名单。
2. 命令执行超时时间。
3. 环境变量传递。
4. 工作目录。
5. 权限隔离。
6. stdout/stderr 记录。
7. 失败处理。
8. 安全提示。
9. 是否允许事件规则调用。
10. 是否允许认证 Hook 调用。

## 5.11 KMS 配置

系统应支持密钥管理服务，用于保护敏感配置和存储凭据。

应支持：

1. 本地密钥。
2. 密钥文件。
3. Secret 加密。
4. 存储后端凭据加密。
5. 数据静态加密密钥。
6. 密钥轮换。
7. 密钥丢失提示。
8. KMS 配置校验。
9. 加密失败告警。
10. 启动时密钥加载检查。

## 5.12 MFA 配置

应支持：

1. TOTP。
2. Issuer 名称。
3. 备用恢复码。
4. 管理员 MFA。
5. 用户 MFA。
6. 强制 MFA。
7. 按角色强制 MFA。
8. 按协议限制 MFA。
9. WebAdmin / WebClient MFA。
10. 与 OIDC 的关系。

## 5.13 SMTP 配置

用于邮件通知、事件通知、分享链接通知等。

应支持：

1. SMTP Host。
2. SMTP Port。
3. 用户名。
4. 密码。
5. 发件人。
6. TLS / STARTTLS。
7. 邮件模板。
8. 测试邮件。
9. 发送失败日志。
10. 事件管理邮件动作。

## 5.14 Plugins 配置

应支持插件加载与扩展。

插件可用于：

1. LDAP / AD。
2. Geo-IP。
3. 自定义认证。
4. 自定义策略。
5. 外部身份源。
6. 审计扩展。
7. 安全过滤。
8. 文件处理扩展。

---

# 6. 协议服务需求

## 6.1 SFTP

系统必须支持 SFTP。

功能要求：

1. 密码认证。
2. 公钥认证。
3. 多公钥。
4. SSH 用户证书。
5. Keyboard Interactive。
6. 多步骤认证。
7. 按用户启用/禁用协议。
8. 按用户限制认证方式。
9. chroot 到用户根目录。
10. 虚拟目录挂载。
11. 文件上传。
12. 文件下载。
13. 删除。
14. 重命名。
15. 创建目录。
16. 删除目录。
17. chmod。
18. chown。
19. chtimes。
20. symlink。
21. truncate。
22. copy。
23. SSH 命令记录。
24. Git over SSH。
25. 空闲连接断开。
26. 会话限制。
27. 传输日志。
28. 失败登录日志。

## 6.2 SCP

系统应支持 SCP 文件传输。

要求：

1. 上传文件。
2. 下载文件。
3. 按用户协议开关控制。
4. 受相同权限、配额、限速约束。
5. 记录传输日志。
6. 支持 SSH 认证体系。

## 6.3 FTP / FTPS

系统应支持 FTP 和 FTPS。

要求：

1. FTP 明文模式可配置。
2. FTPS 显式 TLS。
3. 控制通道强制 TLS。
4. 数据通道强制 TLS。
5. Passive 端口范围。
6. NAT 地址配置。
7. 用户权限控制。
8. 配额控制。
9. 带宽限制。
10. 文件过滤。
11. 传输日志。
12. 失败连接日志。

## 6.4 WebDAV

系统应支持 WebDAV。

要求：

1. WebDAV 文件浏览。
2. 上传。
3. 下载。
4. 删除。
5. 重命名。
6. 创建目录。
7. HTTPS。
8. 双向 TLS。
9. 同一套用户权限体系。
10. 同一套配额和限速体系。
11. 支持虚拟目录。
12. 记录 HTTP 日志与文件操作日志。

## 6.5 HTTP / HTTPS 文件访问

HTTPD 应提供：

1. WebAdmin。
2. WebClient。
3. REST API。
4. OpenAPI。
5. 分享链接访问。
6. 文件下载。
7. 文件上传。
8. 凭据管理。
9. MFA 管理。
10. 公钥管理。

---

# 7. 存储后端需求

## 7.1 本地文件系统

要求：

1. 支持用户主目录。
2. 支持 chroot 隔离。
3. 支持文件权限映射。
4. 支持配额统计。
5. 支持大文件上传。
6. 支持临时文件。
7. 支持原子替换策略。
8. 支持审计日志。

## 7.2 加密本地文件系统

要求：

1. 静态数据加密。
2. 每用户或每目录加密策略。
3. 密钥管理。
4. 上传时加密。
5. 下载时解密。
6. 禁止明文落盘配置。
7. 密钥丢失提示。
8. 加密存储验收。

## 7.3 远端 SFTP 存储

要求：

1. 远端地址。
2. 端口。
3. 用户名。
4. 密码或私钥。
5. Host Key 校验。
6. 路径前缀。
7. 上传下载。
8. 删除重命名。
9. 超时控制。
10. 错误重试。
11. 虚拟目录挂载。

## 7.4 HTTPFs

HTTPFs 用于通过外部 HTTP API 实现自定义文件系统。

要求：

1. HTTP API 认证。
2. 文件列表。
3. 文件读取。
4. 文件写入。
5. 文件删除。
6. 文件重命名。
7. 目录创建。
8. 目录删除。
9. 元数据获取。
10. 错误码映射。
11. 超时和重试。
12. TLS 配置。

## 7.5 存储边界要求

系统存储边界必须满足以下要求：

1. 本地文件系统为默认存储后端。
2. 加密本地文件系统为本地存储增强能力。
3. 远端 SFTP 存储仅作为文件存储后端。
4. HTTPFs 仅用于对接自定义 HTTP 文件系统接口。
5. 虚拟目录仅允许挂载产品支持范围内的文件系统。
6. 系统不支持 S3、GCS、Azure Blob 或其他对象存储协议。
7. 系统不支持对象存储协议转换。
8. 系统不支持对象存储桶管理。
9. 系统不支持对象存储生命周期管理。

## 7.6 存储一致性需求

系统应对非本地存储提供以下一致性处理能力：

1. 系统应处理大文件上传失败后的临时文件清理。
2. 系统应处理覆盖写入时的并发控制。
3. 系统应处理删除、重命名、目录创建等操作失败后的状态恢复。
4. 系统应支持配额统计修正。
5. 系统应记录存储操作失败日志。
6. 系统应提供存储后端健康检查。
7. 系统应处理文件时间语义差异。
8. 系统应处理元数据差异。

---

# 8. 用户、组、角色、管理员需求

## 8.1 用户管理

用户字段至少包括：

| 字段 | 说明 |
|---|---|
| username | 用户名 |
| status | 启用/禁用 |
| password | 密码哈希 |
| public_keys | SSH 公钥列表 |
| home_dir | 主目录 |
| filesystem | 文件系统配置 |
| permissions | 权限配置 |
| filters | 文件过滤 |
| quotas | 配额 |
| bandwidth_limits | 带宽限制 |
| transfer_limits | 总传输量限制 |
| max_sessions | 最大会话 |
| allowed_protocols | 允许协议 |
| denied_protocols | 禁止协议 |
| ip_filters | IP 限制 |
| groups | 所属组 |
| role | 所属角色 |
| mfa | MFA 配置 |
| expiration_date | 过期时间 |
| description | 描述 |
| created_at | 创建时间 |
| updated_at | 更新时间 |

## 8.2 用户操作

应支持：

1. 新增用户。
2. 修改用户。
3. 删除用户。
4. 禁用用户。
5. 启用用户。
6. 批量导入用户。
7. 批量导出用户。
8. 查询用户。
9. 重置密码。
10. 管理公钥。
11. 管理 MFA。
12. 配额扫描。
13. 配额重算。
14. 查看用户连接。
15. 强制断开用户连接。
16. 查看用户审计日志。

## 8.3 管理员管理

管理员字段包括：

1. 用户名。
2. 密码哈希。
3. 状态。
4. 权限列表。
5. 角色。
6. MFA。
7. 登录历史。
8. 创建时间。
9. 更新时间。

管理员操作包括：

1. 创建管理员。
2. 修改管理员。
3. 删除管理员。
4. 禁用管理员。
5. 启用管理员。
6. 分配权限。
7. 分配角色。
8. 重置密码。
9. 配置 MFA。
10. 审计管理员操作。

## 8.4 组管理

组用于复用用户配置。

应支持：

1. 创建组。
2. 修改组。
3. 删除组。
4. 将用户加入组。
5. 从组移除用户。
6. 配置组级文件系统。
7. 配置组级权限。
8. 配置组级配额。
9. 配置组级协议限制。
10. 配置组级过滤规则。
11. 用户字段覆盖组字段。
12. 多组优先级处理。

## 8.5 角色管理

角色用于管理权限范围。

应支持：

1. 创建角色。
2. 修改角色。
3. 删除角色。
4. 管理员绑定角色。
5. 用户绑定角色。
6. 限制管理员可管理用户。
7. 限制管理员可管理文件夹。
8. 限制管理员可管理组。
9. 限制管理员可查看日志范围。
10. 限制管理员 API 权限。

---

# 9. 虚拟目录需求

## 9.1 基础能力

虚拟目录用于把任意支持的存储后端挂载到用户可见路径。

应支持：

1. 本地文件夹挂载。
2. 远端 SFTP 挂载。
3. HTTPFs 挂载。
4. 加密本地存储挂载。
5. 多个虚拟目录挂载到同一用户。
6. 不同用户挂载同一共享目录。
7. 同一用户不同路径挂载不同后端。

## 9.2 私有虚拟目录

要求：

1. 仅单个用户可见。
2. 可单独配置权限。
3. 可单独配置配额。
4. 可单独配置存储后端。
5. 删除用户时可选择是否删除关联目录。

## 9.3 共享虚拟目录

要求：

1. 多用户共享。
2. 多用户权限不同。
3. 多用户配额不同。
4. 可按组共享。
5. 可按角色共享。
6. 记录共享目录审计日志。

## 9.4 权限继承

虚拟目录权限应支持：

1. 用户权限继承。
2. 目录独立权限覆盖。
3. 只读目录。
4. 只写目录。
5. 禁止删除。
6. 禁止重命名。
7. 禁止列目录。
8. 禁止创建目录。
9. 禁止修改属性。

---

# 10. 权限、过滤、配额、限速需求

## 10.1 文件权限

权限项包括：

1. list。
2. download。
3. upload。
4. overwrite。
5. delete。
6. rename。
7. create_dirs。
8. create_symlinks。
9. chmod。
10. chown。
11. chtimes。
12. truncate。
13. copy。
14. stat。
15. share。
16. zip_download。

## 10.2 目录权限

要求：

1. 支持按路径配置权限。
2. 支持默认权限。
3. 支持子路径覆盖。
4. 支持虚拟目录独立权限。
5. 支持按协议区分权限。
6. 支持权限冲突规则。

## 10.3 文件过滤

应支持：

1. 允许文件名模式。
2. 拒绝文件名模式。
3. 隐藏文件名模式。
4. 允许扩展名。
5. 拒绝扩展名。
6. 限制最大文件大小。
7. 限制最小文件大小。
8. 限制上传文件名。
9. 限制下载文件名。
10. shell-like pattern。

## 10.4 配额

应支持：

1. 用户容量配额。
2. 用户文件数量配额。
3. 虚拟目录配额。
4. 共享目录按用户配额。
5. 配额统计。
6. 配额重算。
7. 配额超限拒绝上传。
8. 配额告警。
9. 配额扫描任务。

## 10.5 带宽限制

应支持：

1. 上传限速。
2. 下载限速。
3. 按用户限速。
4. 按组限速。
5. 按协议限速。
6. 按客户端 IP 覆盖限速。
7. 按时间段限速。
8. 限速日志。

## 10.6 总传输量限制

应支持：

1. 总上传量限制。
2. 总下载量限制。
3. 上传 + 下载总量限制。
4. 按日重置。
5. 按月重置。
6. 按用户重置。
7. 达到限制后拒绝传输。
8. 管理员手动重置。

---

# 11. 认证与安全需求

## 11.1 密码认证

要求：

1. 密码安全哈希。
2. 禁止明文保存。
3. 密码复杂度策略。
4. 密码过期策略。
5. 密码重置。
6. 密码登录开关。
7. 外部密码校验 Hook。
8. 登录失败记录。

## 11.2 SSH 公钥认证

要求：

1. 每用户多个公钥。
2. 公钥增删改查。
3. 公钥格式校验。
4. WebClient 自助管理公钥。
5. 管理员禁用用户自助公钥管理。
6. 公钥登录日志。

## 11.3 SSH 用户证书

要求：

1. 用户证书认证。
2. CA 公钥配置。
3. 证书有效期校验。
4. 证书 principal 校验。
5. 证书撤销机制。
6. 证书登录审计。

## 11.4 Keyboard Interactive

要求：

1. 支持交互式认证。
2. 可用于 MFA。
3. 可用于自定义认证流程。
4. 支持外部认证系统。
5. 支持多步骤认证。

## 11.5 多步骤认证

要求：

1. 公钥 + 密码。
2. 密码 + TOTP。
3. 公钥 + TOTP。
4. 外部认证 + 本地认证。
5. Partial Authentication 状态处理。

## 11.6 TOTP MFA

要求：

1. 管理员 MFA。
2. 用户 MFA。
3. WebAdmin MFA。
4. WebClient MFA。
5. TOTP 二维码。
6. 恢复码。
7. 重置 MFA。
8. 强制 MFA。
9. MFA 登录日志。
10. MFA 失败限制。

## 11.7 OIDC

要求：

1. WebAdmin OIDC。
2. WebClient OIDC。
3. Provider 配置。
4. Client ID。
5. Client Secret。
6. Redirect URI。
7. 用户映射。
8. 角色映射。
9. 管理员映射。
10. 退出登录。
11. 与 Keycloak 等 IdP 集成。

## 11.8 LDAP / Active Directory

要求：

1. 插件方式支持。
2. LDAP Server 配置。
3. Bind DN。
4. 用户搜索。
5. 组搜索。
6. 用户属性映射。
7. 组属性映射。
8. 登录认证。
9. 失败日志。
10. 与本地用户策略合并。

## 11.9 外部认证

要求：

1. 外部程序认证。
2. HTTP API 认证。
3. 认证请求参数。
4. 认证响应格式。
5. 超时控制。
6. 失败处理。
7. 动态用户创建。
8. 动态用户修改。
9. 外部认证日志。

## 11.10 IP 过滤

要求：

1. 全局允许列表。
2. 全局拒绝列表。
3. 用户级允许列表。
4. 用户级拒绝列表。
5. CIDR 支持。
6. IPv4 / IPv6。
7. 协议级 IP 控制。
8. IP 过滤日志。

## 11.11 TLS 与双向 TLS

要求：

1. HTTPS。
2. FTPS。
3. WebDAV over HTTPS。
4. REST API HTTPS。
5. WebAdmin HTTPS。
6. WebClient HTTPS。
7. 客户端证书认证。
8. 证书链校验。
9. TLS 版本配置。
10. Cipher Suite 配置。

## 11.12 Defender 防暴力破解

要求：

1. 登录失败统计。
2. 自动加入 blocklist。
3. 自动解封。
4. 手动解封。
5. 按协议统计。
6. 与限流联动。
7. 封禁日志。
8. 封禁指标。

## 11.13 Geo-IP 过滤

要求：

1. 插件方式支持。
2. 国家/地区允许。
3. 国家/地区拒绝。
4. 登录前检查。
5. 审计日志。
6. 误封处理。

---

# 12. WebAdmin 需求

## 12.1 基础能力

WebAdmin 应支持：

1. 管理员登录。
2. 首次初始化管理员。
3. HTTPS。
4. 双向 TLS。
5. MFA。
6. OIDC。
7. 权限控制。
8. 受限管理员。
9. 国际化。
10. 主题与 UI 配置。

## 12.2 页面清单

| 页面 | 功能 |
|---|---|
| 登录页 | 管理员登录、MFA、OIDC |
| 初始化页 | 首次创建管理员 |
| 仪表盘 | 服务状态、连接、传输、告警、指标 |
| 用户管理 | 用户 CRUD、权限、协议、认证、配额 |
| 用户详情 | 用户存储、虚拟目录、连接、日志、MFA |
| 管理员管理 | 管理员 CRUD、权限、角色、MFA |
| 组管理 | 组 CRUD、组策略、用户绑定 |
| 角色管理 | 角色 CRUD、受限管理员范围 |
| 文件夹管理 | 虚拟目录、共享目录、存储配置 |
| 连接管理 | 活跃连接、强制断开 |
| 分享管理 | 分享链接列表、状态、撤销 |
| 事件规则 | 事件规则、动作、计划任务 |
| 事件历史 | 执行记录、失败记录、重试 |
| Hooks 配置 | 外部认证、命令、HTTP Hook |
| 安全策略 | MFA、IP 过滤、Defender、限流 |
| 日志审计 | App、Transfer、Command、HTTP、Failed connection |
| 指标监控 | Prometheus 指标、健康检查 |
| 配置管理 | 协议、HTTPD、Telemetry、SMTP、KMS、Plugins |
| 备份恢复 | 导出、导入、恢复 |
| OpenAPI | Swagger UI、Schema 下载、接口调试 |

## 12.3 管理端验收

1. 超级管理员可访问所有页面。
2. 受限管理员只能访问授权页面。
3. 非授权操作必须被拒绝。
4. 管理操作必须记录审计日志。
5. 管理端支持 HTTPS。
6. 启用 MFA 后登录必须二次验证。
7. 启用 OIDC 后可通过身份提供商登录。
8. 管理员首次初始化流程可用。

---

# 13. WebClient 需求

## 13.1 基础能力

WebClient 面向普通用户。

应支持：

1. 用户登录。
2. MFA。
3. OIDC。
4. 文件浏览。
5. 文件上传。
6. 文件下载。
7. ZIP 批量下载。
8. 删除文件。
9. 重命名。
10. 创建目录。
11. 删除目录。
12. 分享链接。
13. 修改密码。
14. 管理公钥。
15. 配置 MFA。
16. 查看个人配额。
17. 查看个人连接。
18. 多语言界面。

## 13.2 WebClient 启用控制

系统应支持：

1. 全局启用 WebClient。
2. 全局禁用 WebClient。
3. 按用户禁用 HTTP 协议。
4. 按用户禁用 WebClient。
5. 按权限禁用公钥自助管理。
6. 按权限禁用分享链接。
7. 按权限禁用上传/下载/删除等操作。

## 13.3 分享链接

分享链接应支持：

1. 文件分享。
2. 文件夹分享。
3. 下载分享。
4. 上传分享。
5. 下载次数限制。
6. 上传次数限制。
7. 过期时间。
8. 密码保护。
9. 来源 IP 限制。
10. 管理员查看分享。
11. 用户撤销分享。
12. 分享访问日志。
13. 分享安全审计。

---

# 14. REST API 与 OpenAPI 需求

## 14.1 API 认证

REST API 应支持：

1. JWT。
2. API Key。
3. HTTPS。
4. 可选客户端证书。
5. 管理员 Token。
6. 用户 Token。
7. Token 过期时间。
8. Token 刷新。
9. API 权限控制。
10. API 调用审计。

## 14.2 管理员 API

| API 类别 | 需求 |
|---|---|
| Auth | 登录、刷新、退出、MFA |
| Admins | 管理员 CRUD、权限、MFA |
| Users | 用户 CRUD、状态、权限、存储、配额 |
| Groups | 组 CRUD、组策略 |
| Roles | 角色 CRUD、受限范围 |
| Folders | 虚拟目录 CRUD、挂载配置 |
| Connections | 活跃连接查询、强制断开 |
| Shares | 分享链接查询、撤销 |
| Event Rules | 规则 CRUD、动作绑定 |
| Event Actions | 动作 CRUD、命令、HTTP、邮件 |
| Event History | 执行记录、错误记录 |
| Quota | 扫描、重算、查询 |
| Backup | 数据导出 |
| Restore | 数据导入 |
| Data Retention | 本地文件系统、加密本地文件系统、远端 SFTP 与 HTTPFs 的数据保留策略 |
| Status | 系统状态 |
| Health | 健康检查 |
| Metrics | 指标入口 |
| Defender | Blocklist 查询、解封 |
| Logs | 日志查询或日志配置 |
| Config | 配置读取、部分配置变更 |

## 14.3 用户 API

| API 类别 | 需求 |
|---|---|
| Profile | 查看个人信息 |
| Credentials | 修改密码、公钥、MFA |
| Files | 列表、上传、下载、删除、重命名、创建目录 |
| Shares | 创建、修改、删除分享 |
| Quota | 查看配额 |
| Sessions | 查看个人连接 |
| Logout | 退出登录 |

## 14.4 OpenAPI

系统必须提供 OpenAPI 3 Schema。

要求：

1. Schema 文件必须纳入项目文件。
2. 可通过 `/openapi` 访问。
3. 支持 Swagger UI。
4. 支持替换 OpenAPI 渲染器。
5. 支持 OpenAPI Generator 生成客户端。
6. 支持 swagger-codegen 生成客户端。
7. Schema 应描述 request、response、error、security scheme。
8. API 变更必须同步更新 Schema。
9. API 文档可用于自动化测试。

---

# 15. Event Manager 需求

## 15.1 基础概念

Event Manager 用于根据服务器事件或计划任务执行自定义工作流。

核心对象：

1. Event Rule。
2. Event Action。
3. Trigger。
4. Conditions。
5. Schedule。
6. Execution History。

## 15.2 触发类型

应支持：

1. 文件上传前。
2. 文件上传后。
3. 文件下载前。
4. 文件下载后。
5. 删除前。
6. 删除后。
7. 重命名。
8. 创建目录。
9. 删除目录。
10. SSH Command。
11. 用户新增。
12. 用户更新。
13. 用户删除。
14. 连接建立后。
15. 登录后。
16. 断开连接后。
17. 定时计划任务。

## 15.3 条件

应支持按以下条件判断：

1. 用户名。
2. 用户组。
3. 角色。
4. 协议。
5. 客户端 IP。
6. 文件路径。
7. 文件名。
8. 文件大小。
9. 文件扩展名。
10. 存储后端。
11. 操作结果。
12. 时间范围。
13. 自定义变量。
14. 占位符。

## 15.4 动作类型

应支持：

1. HTTP Notification。
2. Command Execution。
3. Email Notification。
4. 文件删除。
5. 文件移动。
6. 文件复制。
7. 数据保留。
8. 配额扫描。
9. 外部系统回调。
10. 自定义脚本。

## 15.5 执行管理

要求：

1. 执行历史记录。
2. 失败状态记录。
3. 错误日志。
4. 超时控制。
5. 重试策略。
6. 并发控制。
7. 同一实例内任务并发控制。
8. 计划任务冲突处理。
9. 动作参数脱敏。
10. 执行结果指标。

---

# 16. Hooks 与外部集成需求

## 16.1 外部认证 Hook

要求：

1. 支持外部程序。
2. 支持 HTTP API。
3. 支持用户密码认证。
4. 支持动态返回用户配置。
5. 支持失败原因。
6. 支持超时。
7. 支持缓存。
8. 支持审计日志。

## 16.2 动态用户 Hook

要求：

1. 登录时创建用户。
2. 登录时更新用户。
3. 动态设置存储后端。
4. 动态设置权限。
5. 动态设置配额。
6. 动态设置协议。
7. 动态设置组和角色。
8. 动态用户失败处理。

## 16.3 文件事件 Hook

要求：

1. pre-upload。
2. upload。
3. pre-download。
4. download。
5. pre-delete。
6. delete。
7. rename。
8. mkdir。
9. rmdir。
10. 传递文件元数据。
11. 传递用户信息。
12. 传递协议和 IP。
13. 支持 HTTP 和命令方式。

## 16.4 连接 Hook

要求：

1. post-connect。
2. post-login。
3. post-disconnect。
4. 记录连接 ID。
5. 记录协议。
6. 记录客户端地址。
7. 记录认证方式。
8. 支持失败处理。

---

# 17. 日志与审计需求

## 17.1 日志类型

系统应输出结构化 JSON 日志。

日志类型包括：

1. App logs。
2. Transfer logs。
3. Command logs。
4. HTTP logs。
5. Connection failed logs。
6. Event Manager logs。
7. Hook logs。
8. Defender logs。
9. Data provider logs。
10. Storage backend logs。

## 17.2 Transfer Logs

应记录：

1. 操作类型：Upload / Download。
2. 用户名。
3. 协议。
4. 连接 ID。
5. 本地地址。
6. 远端地址。
7. 文件路径。
8. 文件大小。
9. 传输字节数。
10. 开始时间。
11. 结束时间。
12. 耗时。
13. 成功/失败。
14. 错误信息。
15. FTP active/passive 模式。

## 17.3 Command Logs

应记录：

1. Rename。
2. Rmdir。
3. Mkdir。
4. Symlink。
5. Remove。
6. Chmod。
7. Chown。
8. Chtimes。
9. Truncate。
10. Copy。
11. SSHCommand。
12. 用户名。
13. 协议。
14. 路径。
15. 结果。
16. 错误信息。

## 17.4 HTTP Logs

应记录：

1. 请求方法。
2. 请求路径。
3. 状态码。
4. 用户。
5. IP。
6. User-Agent。
7. 响应耗时。
8. 请求大小。
9. 响应大小。
10. API Key / JWT 认证方式。
11. 错误信息。

## 17.5 审计查询

系统应支持按以下条件查询或对接外部日志系统：

1. 时间范围。
2. 用户。
3. 管理员。
4. IP。
5. 协议。
6. 操作类型。
7. 文件路径。
8. 状态。
9. 错误码。
10. 连接 ID。
11. 事件规则 ID。
12. 存储后端类型。

## 17.6 统一审计事件模型

系统必须统一记录以下审计事件：

1. 登录成功。
2. 登录失败。
3. MFA 成功。
4. MFA 失败。
5. 文件上传。
6. 文件下载。
7. 文件删除。
8. 文件重命名。
9. 目录创建。
10. 目录删除。
11. 分享创建。
12. 分享修改。
13. 分享撤销。
14. 分享访问。
15. 管理员新增用户。
16. 管理员修改用户。
17. 管理员删除用户。
18. 管理员修改权限。
19. API 调用。
20. Event Action 执行。
21. Hook 调用。
22. Defender 封禁。
23. Defender 解封。
24. 配置变更。
25. 数据备份。
26. 数据恢复。

审计事件字段必须包括：

| 字段 | 说明 |
|---|---|
| event_id | 审计事件 ID |
| event_type | 审计事件类型 |
| actor_type | 操作者类型 |
| actor_name | 操作者名称 |
| target_type | 目标对象类型 |
| target_id | 目标对象 ID |
| protocol | 访问协议 |
| client_ip | 客户端 IP |
| result | 执行结果 |
| error_message | 错误信息 |
| created_at | 事件时间 |

---

# 18. Metrics 与可观测性需求

## 18.1 Telemetry Server

系统应支持独立 Telemetry Server 暴露监控能力。

要求：

1. 可启用/禁用。
2. 独立监听端口。
3. 暴露 `/metrics`。
4. 支持 Prometheus 抓取。
5. 支持健康检查。
6. 支持访问限制。
7. 支持 TLS。
8. 支持运行时诊断。

## 18.2 Prometheus 指标

应包括：

1. 上传总数。
2. 下载总数。
3. 上传字节数。
4. 下载字节数。
5. 传输错误数。
6. SSH 命令数。
7. SSH 命令错误数。
8. 活跃连接数。
9. 认证成功数。
10. 认证失败数。
11. 按认证方式统计登录。
12. HTTP 请求数。
13. HTTP 状态码统计。
14. Data Provider 可用性。
15. Event Manager 执行次数。
16. Event Manager 失败次数。
17. Defender 封禁数量。
18. Go runtime GC 指标。
19. goroutines 数量。
20. OS threads 数量。
21. 进程 CPU。
22. 进程内存。
23. 文件描述符。
24. 进程启动时间。

## 18.3 告警规则需求

系统应支持通过 Prometheus 指标对接外部告警系统，并至少提供以下指标条件：

1. Data Provider 不可用。
2. 登录失败次数异常。
3. 活跃连接数异常。
4. 传输失败次数异常。
5. 磁盘空间不足。
6. 配额超限。
7. 事件执行失败。
8. Hook 超时。
9. Defender 封禁数量异常。
10. 进程重启。

---

# 19. 数据提供器管理需求

## 19.1 支持类型

SQLite 为默认数据库，适用于单机部署、轻量部署和快速验证场景。MySQL 8.0+ 为可选数据库，适用于生产部署和多用户管理场景。系统不支持 PostgreSQL、CockroachDB、Bolt、Memory Provider 或其他数据库作为产品数据提供器。

系统应支持：

1. SQLite。
2. MySQL 8.0+。

## 19.2 数据库实现约束

数据库实现必须满足以下要求：

1. SQLite 与 MySQL 8.0+ 使用同一套业务模型。
2. 数据库迁移采用 Goose。
3. 数据访问采用 SQLC。
4. 系统所有数据库访问必须通过 SQLC 生成的类型安全代码或经过封装的 Repository 接口完成。
5. SQLite 与 MySQL 8.0+ 必须分别提供迁移脚本。
6. SQLite 与 MySQL 8.0+ 必须分别提供 SQLC 查询 SQL。
7. SQLite 与 MySQL 8.0+ 必须分别提供集成测试。
8. 所有数据库字段必须优先使用 SQLite 与 MySQL 8.0+ 兼容的数据类型。
9. 时间字段统一使用 UTC 时间。
10. 主键策略必须统一。
11. JSON 配置字段必须明确 SQLite 与 MySQL 8.0+ 的存储方式。
12. 索引设计必须覆盖用户查询、权限查询、连接查询、日志查询、事件查询、分享查询和虚拟目录查询。
13. 数据库初始化、升级、降级、备份和恢复必须同时支持 SQLite 与 MySQL 8.0+。
14. 不允许引入 PostgreSQL、CockroachDB、Bolt、Memory Provider 或其他数据库实现。
15. 不允许使用 GORM AutoMigrate 生成或修改产品数据库结构。
16. 不允许通过未封装的临时 SQL 直接绕过 Repository 接口访问业务数据。

## 19.3 初始化

要求：

1. SQLite 可自动创建数据库文件。
2. MySQL 8.0+ 需预先创建数据库并配置账号权限。
3. 系统启动时检查数据结构。
4. 可通过初始化命令完成数据结构创建。
5. 可禁用自动初始化。
6. 初始化失败应输出明确错误。
7. 初始化操作应记录日志。

## 19.4 升级

要求：

1. 检测 schema 版本。
2. 自动执行升级迁移。
3. 支持手动升级。
4. 升级前提示备份。
5. 升级失败可追踪。
6. 升级过程记录日志。

## 19.5 降级

要求：

1. 支持按文档降级。
2. 支持数据库版本回滚命令。
3. 降级前必须备份。
4. 降级失败可恢复。
5. 记录降级日志。

## 19.6 备份与恢复

要求：

1. 导出 JSON dump。
2. 导入 JSON dump。
3. 备份用户。
4. 备份管理员。
5. 备份组。
6. 备份角色。
7. 备份文件夹。
8. 备份事件规则。
9. 备份分享链接。
10. 恢复冲突处理。
11. 恢复前校验。
12. 恢复后校验。

---

# 20. 插件系统需求

## 20.1 插件用途

插件应支持扩展：

1. LDAP / AD。
2. Geo-IP。
3. 外部认证。
4. 安全策略。
5. 文件过滤。
6. 审计扩展。
7. 产品范围内的文件系统扩展。
8. 身份源扩展。

插件系统不支持对象存储插件。

## 20.2 插件管理

要求：

1. 插件路径配置。
2. 插件启用/禁用。
3. 插件版本。
4. 插件参数。
5. 插件日志。
6. 插件健康状态。
7. 插件失败处理。
8. 插件安全限制。

---

# 21. 部署与运维需求

## 21.1 部署方式

应支持：

1. 单二进制部署。
2. Linux systemd。
3. Docker。
4. Docker Compose。
5. Windows Installer。
6. 私有化部署。

## 21.2 Docker

要求：

1. 标准镜像。
2. Alpine 镜像。
3. Distroless 镜像。
4. 配置文件挂载。
5. 数据目录挂载。
6. 日志目录挂载。
7. 环境变量配置。
8. 健康检查。

## 21.3 Linux systemd

要求：

1. systemd unit。
2. 指定运行用户。
3. 指定配置路径。
4. 自动重启。
5. 日志输出。
6. 开机自启。
7. 安全限制。
8. 升级流程。

## 21.4 Windows

要求：

1. Windows 安装包。
2. 服务安装。
3. 服务启动/停止。
4. 配置文件路径。
5. 日志路径。
6. 升级卸载。
7. 权限提示。

---

# 22. 数据对象设计

## 22.1 User

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 用户 ID |
| username | string | 用户名 |
| status | enum | 状态 |
| password_hash | string | 密码哈希 |
| public_keys | array | 公钥 |
| home_dir | string | 主目录 |
| filesystem | object | 文件系统配置 |
| virtual_folders | array | 虚拟目录 |
| permissions | object | 权限 |
| filters | object | 文件过滤 |
| quotas | object | 配额 |
| bandwidth_limits | object | 带宽限制 |
| transfer_limits | object | 流量限制 |
| max_sessions | integer | 最大会话 |
| allowed_protocols | array | 允许协议 |
| denied_protocols | array | 禁止协议 |
| ip_filters | object | IP 过滤 |
| mfa | object | MFA |
| groups | array | 用户组 |
| role | string | 角色 |
| expiration_date | datetime | 过期时间 |
| created_at | datetime | 创建时间 |
| updated_at | datetime | 更新时间 |

## 22.2 Admin

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 管理员 ID |
| username | string | 管理员用户名 |
| password_hash | string | 密码哈希 |
| status | enum | 状态 |
| permissions | array | 权限 |
| role | string | 角色 |
| mfa | object | MFA |
| filters | object | 管理范围 |
| last_login_at | datetime | 最后登录时间 |
| created_at | datetime | 创建时间 |

## 22.3 Group

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 组 ID |
| name | string | 组名 |
| description | string | 描述 |
| settings | object | 组配置 |
| user_settings | object | 用户继承配置 |
| created_at | datetime | 创建时间 |
| updated_at | datetime | 更新时间 |

## 22.4 Role

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 角色 ID |
| name | string | 角色名 |
| description | string | 描述 |
| permissions | array | 权限 |
| scope | object | 范围 |
| created_at | datetime | 创建时间 |

## 22.5 Virtual Folder

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 文件夹 ID |
| name | string | 名称 |
| mapped_path | string | 实际路径 |
| mount_path | string | 挂载路径 |
| filesystem | object | 文件系统 |
| quota | object | 配额 |
| permissions | object | 权限 |
| users | array | 关联用户 |
| groups | array | 关联组 |

## 22.6 Share

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 分享 ID |
| owner | string | 所属用户 |
| path | string | 路径 |
| scope | enum | 文件/目录/上传 |
| password_hash | string | 分享密码 |
| max_downloads | integer | 下载次数 |
| max_uploads | integer | 上传次数 |
| allowed_ips | array | 允许 IP |
| expires_at | datetime | 过期时间 |
| created_at | datetime | 创建时间 |
| last_use_at | datetime | 最近使用时间 |

## 22.7 Event Rule

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 规则 ID |
| name | string | 名称 |
| trigger | object | 触发器 |
| conditions | object | 条件 |
| actions | array | 动作 |
| schedule | string | 定时计划 |
| enabled | boolean | 是否启用 |
| created_at | datetime | 创建时间 |

## 22.8 Event Action

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string/int | 动作 ID |
| name | string | 名称 |
| type | enum | HTTP/Command/Email/File/DataRetention |
| config | object | 动作配置 |
| timeout | integer | 超时 |
| retry | object | 重试 |
| enabled | boolean | 是否启用 |

---

# 23. 验收标准

## 23.0 整体验收原则

系统验收必须满足以下原则：

1. 所有需求章节中的功能必须全部完成后进入验收。
2. 验收不按分期方式拆分。
3. 验收不接受核心功能缺失。
4. 协议、Web、API、存储、安全、事件、日志、指标和部署必须统一联调。
5. 同一用户、权限、配额、限速、认证策略必须在 SFTP、SCP、FTP/FTPS、WebDAV、WebClient 和 REST API 中保持一致。
6. SQLite 与 MySQL 8.0+ 均必须完成安装、初始化、迁移、备份和恢复测试。
7. Linux systemd、Docker、Docker Compose 和 Windows 服务均必须完成部署验证。
8. 所有验收用例必须形成测试记录。
9. 产品验收通过后才能作为完整版本交付。

## 23.1 协议验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| A-001 | SFTP 登录 | 用户可通过密码、公钥登录 |
| A-002 | SFTP 文件操作 | 上传、下载、删除、重命名、建目录正常 |
| A-003 | SCP | SCP 上传下载正常 |
| A-004 | FTP | FTP 登录与文件传输正常 |
| A-005 | FTPS | 控制通道和数据通道 TLS 生效 |
| A-006 | WebDAV | WebDAV 客户端可操作文件 |
| A-007 | HTTP WebClient | 浏览器可管理文件 |
| A-008 | 协议限制 | 被禁用协议无法登录 |

## 23.2 安全验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| B-001 | 密码哈希 | 数据库无明文密码 |
| B-002 | 公钥认证 | 公钥登录成功，错误公钥失败 |
| B-003 | MFA | 启用后必须二次验证 |
| B-004 | OIDC | 可通过身份提供商登录 |
| B-005 | IP 过滤 | 非允许 IP 无法登录 |
| B-006 | Defender | 多次失败后自动封禁 |
| B-007 | TLS | HTTPS/FTPS/WebDAV HTTPS 可用 |
| B-008 | 双向 TLS | 客户端证书校验生效 |

## 23.3 存储验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| C-001 | 本地存储 | 文件正确写入本地目录 |
| C-002 | 加密本地存储 | 静态文件加密存储 |
| C-003 | 远端 SFTP | 文件正确转发到远端 |
| C-004 | HTTPFs | 外部 HTTP 文件系统可用 |
| C-005 | 虚拟目录 | 多后端可挂载同一用户不同路径 |

## 23.4 Web 验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| D-001 | WebAdmin 初始化 | 无管理员时可创建首个管理员 |
| D-002 | 用户管理 | 可创建、修改、删除、禁用用户 |
| D-003 | 组角色管理 | 可管理组、角色与受限管理员 |
| D-004 | WebClient | 用户可浏览、上传、下载文件 |
| D-005 | 分享链接 | 可创建带密码、过期、次数限制的分享 |
| D-006 | 公钥管理 | 用户可按权限自助管理公钥 |
| D-007 | MFA 管理 | 用户可配置 TOTP |

## 23.5 API 验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| E-001 | JWT | API 可通过 JWT 调用 |
| E-002 | API Key | API Key 调用成功 |
| E-003 | OpenAPI | `/openapi` 可查看 Schema |
| E-004 | 用户 API | 可通过 API 管理用户 |
| E-005 | 连接 API | 可查询和关闭活跃连接 |
| E-006 | 事件 API | 可管理事件规则和动作 |
| E-007 | 备份恢复 | 可导出导入数据 |

## 23.6 可观测性验收

| 编号 | 验收项 | 验收标准 |
|---|---|---|
| F-001 | JSON 日志 | 日志为结构化 JSON |
| F-002 | Transfer 日志 | 上传下载记录完整 |
| F-003 | Command 日志 | 删除、重命名、mkdir 等记录完整 |
| F-004 | HTTP 日志 | API 和 Web 请求记录完整 |
| F-005 | Metrics | Prometheus 可抓取指标 |
| F-006 | 健康检查 | 可判断服务运行状态 |

