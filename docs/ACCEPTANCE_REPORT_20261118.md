# SFTPxy 生产级交付验收报告

- **验收日期**：2026-11-18
- **被测版本**：v0.2.9（源码 HEAD `21af5ce` + 本次修复）
- **验收环境**：macOS / darwin-arm64，Go 1.26.11，SQLite 33→34，全新安装
- **验收依据**：实际代码审计 + 实际运行结果（非静态推测）
- **结论**：**PASS**（发现并修复 3 项高危缺陷 + 18 个可达漏洞；5 项受环境限制未完全验证，已在 §6 明确标注）

---

## 1. 问题清单与分级

| # | 级别 | 类别 | 问题 | 状态 |
| --- | --- | --- | --- | --- |
| 1 | **P0 高危** | 可靠性 | SFTP 客户端 SSH 握手无超时，对端接受 TCP 后不发 banner 会**永久挂起** | ✅ 已修复 |
| 2 | **P1 高** | 并发安全 | `service.Service.Error` 被多个 goroutine 无锁写、无锁读（数据竞争） | ✅ 已修复 |
| 3 | **P1 高** | 安全/依赖 | govulncheck 报告 **18 个可达漏洞**（标准库 14 + x/net、x/crypto、grpc、otel-sdk） | ✅ 已修复 |
| 4 | **P2 中** | 发布一致性 | `VERSION`/openapi/README 仍为 0.2.8，`version.go` 为 0.2.9，发布校验脚本失败 | ✅ 已修复 |
| 5 | **P2 中** | 工程卫生 | 工具缓存目录 `.tools/`、`.lintcache/` 未纳入 `.gitignore` | ✅ 已修复 |
| 6 | **P3 低** | 部署 | Docker 构建镜像使用浮动 tag `golang:1.26-*`，与 CI 固定的 Go 版本不一致 | ✅ 已修复 |
| 7 | **P1 高** | 并发安全 | 引入 `Service` 的 mutex 后，Windows 代码按值复制 `Service`（`go vet` 报 copylocks）——**由本次修复 2.2 引入的回归，已发现并修复** | ✅ 已修复 |
| 8 | 观察项 | 测试 | `internal/vfs`、`internal/dataprovider`、`internal/service` 等 10 个包无测试 | ⚠️ 部分补充 |

---

## 2. 修复记录

### 2.1 【P0】SFTP 客户端 SSH 握手永久挂起

- **文件**：`internal/vfs/sftpfs.go`
- **根因**：`ssh.Dial` 内部只用 `config.Timeout` 约束 **TCP 建连**（`net.DialTimeout`），随后 `NewClientConn` → `readVersion` 在无 deadline 的连接上阻塞。服务端已用 `SetDeadline` 防护（`internal/sftpd/server.go:647`），客户端没有。
- **影响**：任何 SFTP 虚拟文件夹指向一个"能建连但不发 SSH banner"的对端（半开端口、被防火墙吞包、异常服务）时，该连接及其调用方永久阻塞，并长期占用连接缓存槽位，最终拖垮整个进程。
- **证据（修复前）**：对端 accept 后静默，`ssh.Dial` 在 15s 测试超时后仍未返回：
  ```
  panic: test timed out after 15s
      running tests: TestScratchOldSSHDialTimeout (15s)
  ```
- **修复**：新增 `dialSSH()`，用 `net.Dialer` 建连 → `conn.SetDeadline(now+timeout)` → `ssh.NewClientConn` → 握手成功后清除 deadline（避免影响长连接会话）。
- **证据（修复后）**：
  ```
  === RUN   TestDialSSHHandshakeTimeout
  --- PASS: TestDialSSHHandshakeTimeout (0.50s)
  === RUN   TestDialSSHConnectionRefused
  --- PASS: TestDialSSHConnectionRefused (0.00s)
  ```

### 2.2 【P1】service.Error 数据竞争

- **文件**：`internal/service/service.go`、`service_windows.go`、`internal/cmd/serve.go`、`internal/cmd/portable.go`
- **根因**：`startServices()` 为每个服务器启动 goroutine，失败时直接写 `s.Error = err`；`Wait()` 返回后主流程与 Windows 服务 `handleExit` 无同步读取该字段。
- **修复**：增加 `errorMu sync.Mutex`，提供 `setError()`（保留**首个**错误，保证退出时报告根因）与 `GetError()`；所有读写改为经由此接口。
- **证据**：
  ```
  === RUN   TestSetErrorIsRaceFree   --- PASS
  === RUN   TestSetErrorKeepsFirstError --- PASS
  === RUN   TestGetErrorNilWhenNoFailure --- PASS
  ```

### 2.3 【P1】依赖漏洞治理

- **工具链**：`go 1.26.6` → `go 1.26.11`（覆盖 GO-2026-6859/6809/6617/6613/6612/6611/6610/6609/6608/6607/6605/6603/6600/6599 共 14 个标准库漏洞）
- **模块升级**：`golang.org/x/net` v0.57.0→v0.62.0、`golang.org/x/crypto` v0.55.0→v0.58.1-0.20261009181718、`google.golang.org/grpc` v1.82.1→v1.83.2、`go.opentelemetry.io/otel/sdk` v1.44.0→v1.45.0、`github.com/klauspost/compress` v1.18.7→v1.20.2
- **同步更新**：`.github/workflows/{codeql,development,release}.yml`、`Dockerfile`、`Dockerfile.alpine`、`Dockerfile.distroless`
- **证据（修复前）**：
  ```
  Your code is affected by 18 vulnerabilities from 3 modules and the Go standard library.
  ```
- **证据（修复后）**：
  ```
  No vulnerabilities found.
  Your code is affected by 0 vulnerabilities.
  This scan also found 0 vulnerabilities in packages you import and 1
  vulnerability in modules you require, but your code doesn't appear to call these.
  ```
  （唯一残留为 `x/crypto/openpgp` 的"包已废弃"提示，本项目**未导入**该包，非可达风险。）

### 2.4 【P2】版本元数据不一致

- 执行 `scripts/sync-version.sh 0.2.9`，同步 `VERSION`、`openapi/openapi.yaml`、`README.md`、`README.zh-CN.md`。
- **证据**：
  ```
  $ bash scripts/release-check.sh 0.2.9
  Release metadata checks passed for v0.2.9
  ```

### 2.5 【P2】工程卫生

- `.gitignore` 增加 `.lintcache/`、`.tools/`、`.tools12611/`。

### 2.6 【P1】Windows 服务按值复制 Service（copylocks 回归）

- **文件**：`internal/service/service_windows.go`、`internal/cmd/{install,start,stop,status,reload,rotatelogs,uninstall}_windows.go`
- **根因**：为修复 2.2 的数据竞争给 `Service` 加了 `sync.Mutex`，但 `WindowsService.Service` 是**值类型**字段，7 处调用点按值复制含锁结构体。`go vet` 明确报错：
  ```
  internal/cmd/install_windows.go:40:14: literal copies lock value from s: ...Service contains sync.Mutex
  internal/cmd/start_windows.go:40:14:   literal copies lock value from s: ...Service contains sync.Mutex
  ```
  复制锁会导致**两个 Service 实例各持一把锁**，互相不互斥，数据竞争依然存在。
- **修复**：`WindowsService.Service` 改为 `*Service`，7 处调用点改为传指针。
- **证据（修复后）**：
  ```
  === GOOS=windows GOARCH=amd64 vet ===   exit=0
  === GOOS=linux   GOARCH=amd64 vet ===   exit=0
  === GOOS=linux   GOARCH=arm64 vet ===   exit=0
  === GOOS=darwin  GOARCH=arm64 vet ===   exit=0
  WINDOWS_BUILD_OK / LINUX_BUILD_OK / LINUX_ARM64_BUILD_OK
  ```

### 2.7 【P3】Docker 构建镜像版本对齐

- `golang:1.26-trixie` → `golang:1.26.11-trixie`（alpine/distroless 同步），确保镜像内工具链与 CI 一致、不再引入已知标准库漏洞。

---

## 3. 测试证据

### 3.1 构建与静态分析

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 构建 | `go build ./...` | ✅ exit 0 |
| 静态检查 | `go vet ./...` | ✅ exit 0 |
| 格式 | `gofmt -l main.go internal pkgs sdk tests` | ✅ 无输出 |
| Lint | `golangci-lint run ./...`（v2.15.0，18 个 linter） | ✅ **0 issues** |
| 漏洞 | `govulncheck ./...` | ✅ **0 可达漏洞** |
| 跨平台 vet | `GOOS={windows,linux,darwin} GOARCH=... go vet ./...` | ✅ 4 个目标全部 exit 0 |
| 跨平台构建 | windows/amd64、linux/amd64、linux/arm64、darwin/arm64 | ✅ 全部成功 |
| 模块一致性 | `go mod tidy` 重复执行 | ✅ 幂等（go.mod/go.sum 稳定） |

### 3.2 单元 / 集成测试

`go test -tags "nopgxregisterdefaulttypes,disable_grpc_modules" -p 1 ./...`

| 包 | 结果 |
| --- | --- |
| internal/command | ok 0.57s |
| internal/common | ok 73.5s |
| internal/config | ok 0.92s |
| internal/ftpd | ok 20.0s |
| internal/httpd | ok 57.8s |
| internal/jwt | ok 1.15s |
| internal/mfa | ok 0.63s |
| internal/plugin | ok 0.77s |
| internal/service | ok 1.20s |
| internal/sftpd | ok 52.3s |
| internal/telemetry | ok 0.90s |
| internal/version | ok 0.51s |
| internal/vfs | ok 1.21s |
| internal/webdavd | ok 25.1s |
| sdk/* | ok（全部） |

### 3.3 竞态检测

`go test -race -p 1 ./...` → **13 个包全部 ok，0 个 DATA RACE 告警**（总耗时约 19 分钟）。

### 3.4 发布流水线

`bash scripts/verify-prod.sh 0.2.9` → **Production verification passed for v0.2.9**
（含 release-check、gofmt、vet、测试辅助程序构建、全量测试、sdk 测试、生产构建）

### 3.5 端到端功能验收（真实进程 + 真实客户端）

全新 SQLite 实例，端口 31180(HTTP)/31182(SFTP)/31184(WebDAV)/31185(FTP)。

| 模块 | 用例 | 结果 |
| --- | --- | --- |
| 安装 | 首次访问 302 → `/web/admin/setup`；带 CSRF 创建管理员 | ✅ |
| WebAdmin | 登录/登出；status、users、folders、groups、roles、connections、events、defender、configs、maintenance 全部 200 | ✅ |
| WebClient | 登录；files、shares、profile、mfa 全部 200；目录 JSON 正确返回 subdir/hello.txt | ✅ |
| REST API | token、users CRUD、folders、groups、roles、quotas、apikeys、iplists、eventactions、eventrules、dumpdata/loaddata | ✅ |
| SFTP | 公钥认证、ls/pwd、put/get（内容校验一致）、mkdir/rename/rmdir/rm | ✅ |
| SSH 命令 | 白名单内 `pwd`/`sha256sum`/`cd` 正常；白名单外 `rm -rf /` 被拒 | ✅ |
| scp | 上传成功，内容一致 | ✅ |
| FTP | LIST/GET/PUT/回读一致；错误密码 530 | ✅ |
| WebDAV | PROPFIND 207、GET 200、PUT 201、回读一致；未认证 401 | ✅ |
| 备份/恢复 | dumpdata 导出 12 个 section；loaddata mode=0 恢复后**无重复数据** | ✅ |
| 事件系统 | 创建 retention 动作与 schedule 规则；引用不存在动作返回 400 校验错误 | ✅ |

### 3.6 安全专项验证

| 攻击面 | 载荷 | 结果 |
| --- | --- | --- |
| HTTP 路径穿越 | `?path=/../../../../etc/passwd` | ✅ 404，无内容泄露 |
| HTTP 路径穿越（编码） | `%2F..%2F..%2F..%2Fetc%2Fpasswd` | ✅ 404 |
| SFTP 符号链接逃逸 | `data/testuser/etclink -> /etc`，`get /etclink/passwd` | ✅ 拒绝（not found） |
| HTTP 符号链接逃逸 | `?path=/etclink/passwd` | ✅ 403 permission denied |
| WebDAV 路径穿越 | `GET /../../../../etc/passwd` (--path-as-is) | ✅ 404 |
| CSRF | 无 token 提交 setup/login | ✅ 被拒（需 `_form_token`） |
| SQL 注入 | 审计：表名为常量、prefix 仅允许 `[a-zA-Z0-9_]`、值全部走占位符 | ✅ 无注入面 |
| 配额越权 | quota_size=20B 时上传 100KB | ✅ 413 "denying write due to space limit" |
| 并发 | 10 路并发下载同一文件 | ✅ 全部 200 |
| 暴力破解 | 20 次错误密码后正确登录 | ✅ 仍可正常登录（defender 默认关闭，符合文档） |

---

## 4. 架构与代码质量评估

| 维度 | 评估 |
| --- | --- |
| 分层 | `internal/{cmd,service,config,dataprovider,vfs,sftpd,ftpd,httpd,webdavd,plugin}` 职责清晰，协议层与存储层通过 `vfs.Fs` 接口解耦 |
| 配置 | viper + `env.d` 环境文件，默认值集中在 `config.go`，支持 SIGHUP 热重载 |
| 并发 | 全局配置已用 `ConfigLock/ConfigRLock` 保护；数据提供者配置为原子快照；本次补齐 `service.Error` |
| 数据一致性 | 事务封装统一走 `sqlCommonExecuteTx`（CockroachDB 走 `crdb.ExecuteTx` 自动重试），失败路径均 `Rollback` |
| 资源管理 | `defer Close()` 覆盖良好；SFTP 连接缓存有 30s 空闲回收 + 1m 定时清理 |
| 错误处理 | 使用 `I18nError`/`ValidationError` 分类映射 HTTP 状态码；224 处显式 `nolint:errcheck` 均附理由 |
| 可观测性 | 结构化日志（zerolog）+ Prometheus 指标 + 可选 OpenTelemetry |

---

## 5. 部署与运维评估

| 项目 | 评估 |
| --- | --- |
| 二进制 | 单文件，`-trimpath -ldflags "-s -w"`，版本信息可注入，`SFTPxy -v` 正常 |
| Docker | 3 种变体（debian / alpine / distroless），均以 UID 1000 非 root 运行，日志输出 stdout |
| systemd | `NoNewPrivileges`、`ProtectSystem`、`PrivateTmp`、`RestrictAddressFamilies`、`CAP_NET_BIND_SERVICE` 最小权限 |
| 打包 | DEB postinst 创建系统用户、`chmod 640` 配置、`setcap` 绑定特权端口 |
| CI | quality（lint+govulncheck）、test-deploy（ubuntu+macos）、多架构发布、CodeQL |
| 发布脚本 | `release-check` / `verify-prod` / `release-bundle` 齐备，本次全部实际执行通过 |
| 升级 | 数据库 schema 33→34 自动迁移验证通过；备份/恢复无重复数据 |

---

## 6. 未验证项（明确标注）

| 项目 | 原因 | 风险 |
| --- | --- | --- |
| Windows 服务**运行时**行为 | 当前环境为 macOS，无法运行 Windows 服务控制管理器 | 低（`GOOS=windows go build` + `go vet ./...` 全部通过，copylocks 回归已修复） |
| Docker 镜像构建与运行 | 未在本环境执行 `docker build`（镜像拉取受网络限制） | 低（仅修改 FROM tag，未改构建逻辑） |
| MySQL / PostgreSQL / CockroachDB 数据提供者 | 无可用数据库实例，测试套件默认 SQLite | 中（SQL 层共用代码已审计，但未做真实库回归） |
| 浏览器端 JS 交互（WebAdmin/WebClient 动态行为） | 本环境无浏览器自动化 | 中（HTTP 层页面渲染与 API 已验证，前端 JS 未执行） |
| ACME / Let's Encrypt 证书签发 | 需公网域名与 80/443 端口 | 低（代码路径审计通过，未实测） |
| OIDC / OAuth2 第三方登录 | 需外部 IdP | 低（单元测试覆盖） |
| 大文件 / 高并发压测 | 未执行压力测试 | 中（建议上线前补充） |

---

## 7. 验收结论

### **PASS**

**判定依据**：
1. 构建、vet、gofmt、golangci-lint（0 issues）、govulncheck（0 漏洞）全部通过
2. 13 个包单元/集成测试全部通过；`-race` 全量通过且无数据竞争
3. `scripts/verify-prod.sh` 生产验证通过
4. 端到端实测覆盖 REST / SFTP / FTP / WebDAV / WebAdmin / WebClient / SSH 命令 / 备份恢复，全部通过
5. 安全专项（路径穿越、符号链接逃逸、CSRF、SQL 注入、配额、命令白名单）全部有效
6. 本次发现并修复 **3 个高危缺陷**（P0 永久挂起、P1 数据竞争、P1 由前次修复引入的 copylocks 回归）+ **18 个可达依赖漏洞**
7. 跨平台构建与 vet（windows / linux-amd64 / linux-arm64 / darwin-arm64）全部通过

**遗留建议（不阻塞交付）**：
- 为 `internal/vfs`、`internal/dataprovider`、`internal/service` 补充测试（本次已为关键修复补充 5 个用例）
- 上线前在真实 MySQL/PostgreSQL 与浏览器环境补充一轮回归
- 建议将 `govulncheck` 与 `golangci-lint` 版本固定，避免 `@latest` 带来的构建不确定性
