# SFTPxy v0.2.11 全功能测试报告

- **测试日期**：2026-11-19
- **被测版本**：SFTPxy 0.2.11（commit `4cc823a`）
- **测试环境**：macOS / darwin-arm64，Go 1.26.11 构建，SQLite schema 34，全新实例
- **测试方式**：**Agent 循环 + Computer Use 浏览器模拟人工操作**，辅以 REST API 与协议客户端验证
- **管理员账号**：`admin`（本次测试使用）
- **结论**：**PASS**（5 个功能域全部通过，1 个缺陷已在测试前修复并验证）

---

## 1. 测试方法说明

本次采用「Agent 循环 + Computer Use」方式：由 Agent 通过 macOS 无障碍树（AX）读取真实浏览器渲染结果，模拟人工完成登录、页面导航、表单填写与点击，逐页采集页面标题、可见元素与错误信息。

与纯 HTTP 状态码检查相比，这种方式能发现：
- CSS/JS 加载失败导致的页面异常（本次修复的样式缺陷正是此类）
- 前端渲染错误、空白页、组件缺失
- 中文本地化问题

关键操作路径：`cua.getState` 读取 AX 树 → 提取元素 ID → `cua.setValue` 填表 → `cua.click` 点击 → `cua.screenshot` 截图留证。

---

## 2. 测试结果总览

| # | 功能域 | 用例数 | 通过 | 失败 | 结论 |
| --- | --- | --- | --- | --- | --- |
| 1 | WebAdmin 界面（14 页面） | 14 | 14 | 0 | ✅ PASS |
| 2 | WebClient 界面（5 页面） | 5 | 5 | 0 | ✅ PASS |
| 3 | REST API | 25 | 25 | 0 | ✅ PASS |
| 4 | SFTP 协议 | 7 | 7 | 0 | ✅ PASS |
| 5 | FTP 协议 | 4 | 4 | 0 | ✅ PASS |
| 6 | WebDAV 协议 | 4 | 4 | 0 | ✅ PASS |
| 7 | SSH 命令白名单 | 3 | 3 | 0 | ✅ PASS |
| 8 | 事件管理器 | 73 | 73 | 0 | ✅ PASS（见专项报告） |
| 9 | 安全专项 | 6 | 6 | 0 | ✅ PASS |
| **合计** | | **141** | **141** | **0** | |

---

## 3. WebAdmin 界面测试（Computer Use 实测）

登录方式：浏览器打开 `/web/admin/login`，通过 AX 树定位输入框填入 `admin` / 密码，点击「登录」按钮，成功跳转至用户管理页。

| # | 页面 | 路径 | 页面标题 | 渲染 | 错误 |
| --- | --- | --- | --- | --- | --- |
| 1 | 服务器状态 | `/web/admin/status` | 服务器状态 | ✅ 完整 | 无 |
| 2 | 用户 | `/web/admin/users` | 用户 | ✅ 完整，显示 testuser | 无 |
| 3 | 虚拟文件夹 | `/web/admin/folders` | 虚拟文件夹 | ✅ 完整 | 无 |
| 4 | 组 | `/web/admin/groups` | 组 | ✅ 完整 | 无 |
| 5 | 角色 | `/web/admin/roles` | 角色 | ✅ 完整 | 无 |
| 6 | 活动连接 | `/web/admin/connections` | 活动连接 | ✅ 完整 | 无 |
| 7 | 日志 | `/web/admin/events` | 日志 | ✅ 完整 | 无 |
| 8 | 规则 | `/web/admin/eventrules` | 规则 | ✅ 完整，21 条 | 无 |
| 9 | 操作 | `/web/admin/eventactions` | 操作 | ✅ 完整，17 条 | 无 |
| 10 | 自动屏蔽列表 | `/web/admin/defender` | 自动屏蔽列表 | ✅ 完整 | 无 |
| 11 | 配置 | `/web/admin/configs` | 配置 | ✅ 完整 | 无 |
| 12 | 维护 | `/web/admin/maintenance` | 维护 | ✅ 完整 | 无 |
| 13 | IP 列表 | `/web/admin/ip-lists` | IP 列表 | ✅ 完整 | 无 |
| 14 | 个人资料 | `/web/admin/profile` | 个人资料 | ✅ 完整 | 无 |

**界面质量确认**：
- Logo 正确渲染为图片（`/static/img/logo.png`）
- 样式表完整加载（`style.bundle.css` + `plugins.bundle.css`）
- 中文本地化完整
- 左侧导航菜单可展开（事件管理器、IP 管理器、服务器管理）
- 页脚版本号正确显示 `SFTPxy 0.2.11 v0.2.11-2-g70729c79-dirty`

---

## 4. WebClient 界面测试（Computer Use 实测）

登录方式：以 `testuser` 登录 `/web/client/login`。

| # | 页面 | 路径 | 页面标题 | 渲染 | 错误 |
| --- | --- | --- | --- | --- | --- |
| 1 | 文件 | `/web/client/files` | 文件 | ✅ 完整，列出 hello.txt (13 Bytes) | 无 |
| 2 | 分享 | `/web/client/shares` | 分享 | ✅ 完整 | 无 |
| 3 | 个人资料 | `/web/client/profile` | 个人资料 | ✅ 完整 | 无 |
| 4 | 两步验证 | `/web/client/mfa` | 两步验证 | ✅ 完整 | 无 |
| 5 | 修改密码 | `/web/client/changepwd` | 修改密码 | ✅ 完整 | 无 |

**界面元素确认**：搜索框、新文件夹按钮、上传文件按钮、面包屑导航（首页）、文件列表（名称/大小/最近修改）、分页控件均正常渲染。

---

## 5. REST API 测试

| # | 接口 | 方法 | 结果 |
| --- | --- | --- | --- |
| 1 | `/api/v2/token` | GET (Basic) | ✅ 200，返回 JWT |
| 2 | `/api/v2/user/token` | GET (Basic) | ✅ 200 |
| 3 | `/api/v2/users` | GET | ✅ 200 |
| 4 | `/api/v2/users` | POST | ✅ 201 |
| 5 | `/api/v2/users/{u}` | PUT | ✅ 200 |
| 6 | `/api/v2/folders` | GET/POST | ✅ 200/201 |
| 7 | `/api/v2/groups` | POST | ✅ 201 |
| 8 | `/api/v2/roles` | POST | ✅ 201 |
| 9 | `/api/v2/quotas/users/{u}/usage` | PUT | ✅ 200 |
| 10 | `/api/v2/apikeys` | POST | ✅ 201，返回一次性 key |
| 11 | `/api/v2/iplists/{type}` | GET/POST | ✅ 200/201 |
| 12 | `/api/v2/iplists/{type}/{ip}` | DELETE | ✅ 200 |
| 13 | `/api/v2/dumpdata` | GET | ✅ 200，导出 12 个 section |
| 14 | `/api/v2/dumpdata?output-file=` | GET | ✅ 200，写入 backups 目录 |
| 15 | `/api/v2/loaddata` | POST | ✅ 200，恢复后无重复 |
| 16 | `/api/v2/eventactions` | CRUD | ✅ 全通过 |
| 17 | `/api/v2/eventrules` | CRUD | ✅ 全通过 |
| 18 | `/api/v2/eventrules/run/{name}` | POST | ✅ 202 |
| 19 | `/api/v2/events/fs` | GET | ✅ 501（需插件，预期） |
| 20 | `/api/v2/connections` | GET | ✅ 200 |
| 21 | `/api/v2/user/files` | GET/POST | ✅ 200/201 |
| 22 | `/api/v2/user/dirs` | GET/POST | ✅ 200/201 |
| 23 | `/openapi/` | GET | ✅ 200 |
| 24 | 未认证访问受保护接口 | GET | ✅ 401 |
| 25 | 错误凭据 | GET | ✅ 401 |

**备份恢复专项**：`dumpdata` 导出含 `admins / api_keys / configs / event_actions / event_rules / folders / groups / ip_lists / roles / shares / users / version` 共 12 个 section；`loaddata` 恢复后用户数与动作数均无重复。

---

## 6. 协议测试

### 6.1 SFTP（端口 30082）

| # | 用例 | 结果 |
| --- | --- | --- |
| 1 | 公钥认证登录 | ✅ |
| 2 | `ls` / `pwd` | ✅ |
| 3 | `put` 上传 | ✅ |
| 4 | `get` 下载，内容校验一致 | ✅ |
| 5 | `mkdir` / `rename` / `rmdir` | ✅ |
| 6 | `rm` 删除 | ✅ |
| 7 | 服务端 banner | ✅ `SSH-2.0-SFTPxy_0.2.11` |

### 6.2 FTP（端口 30083）

| # | 用例 | 结果 |
| --- | --- | --- |
| 1 | 目录列表 | ✅ 226 |
| 2 | 文件下载，内容一致 | ✅ 226 |
| 3 | 文件上传 + 回读 | ✅ 226 |
| 4 | 错误密码 | ✅ 530 |

### 6.3 WebDAV（端口 30084）

| # | 用例 | 结果 |
| --- | --- | --- |
| 1 | `PROPFIND` Depth:1 | ✅ 207，返回文件列表 |
| 2 | `GET` 文件，内容一致 | ✅ 200 |
| 3 | `PUT` 上传 + 回读 | ✅ 201/200 |
| 4 | 未认证访问 | ✅ 401 |

### 6.4 SSH 命令白名单

| # | 命令 | 期望 | 结果 |
| --- | --- | --- | --- |
| 1 | `pwd` | 允许 | ✅ 返回 `/` |
| 2 | `sha256sum /hello.txt` | 允许 | ✅ 返回正确哈希 |
| 3 | `cat /etc/passwd` | 拒绝 | ✅ `exec request failed on channel 0` |

---

## 7. 安全专项测试

| # | 攻击面 | 载荷 | 结果 |
| --- | --- | --- | --- |
| 1 | HTTP 路径穿越 | `?path=/../../../../etc/passwd` | ✅ 404，无泄露 |
| 2 | HTTP 路径穿越（编码） | `%2F..%2F..%2F..%2Fetc%2Fpasswd` | ✅ 404 |
| 3 | WebDAV 路径穿越 | `GET /../../../../etc/passwd` | ✅ 404 |
| 4 | SFTP 符号链接逃逸 | `etclink -> /etc`，`get /etclink/passwd` | ✅ 拒绝 |
| 5 | HTTP 符号链接逃逸 | `?path=/etclink/passwd` | ✅ 403 |
| 6 | 配额越权 | quota=20B 时上传 100KB | ✅ 413 `denying write due to space limit` |

---

## 8. 本次修复验证

测试开始前，项目存在 **Web 页面全部丢失样式** 的缺陷（详见 `docs/ACCEPTANCE_REPORT_20261118.md` 之后的修复记录）。

| 检查项 | 修复前 | 修复后 |
| --- | --- | --- |
| 30080 `style.bundle.css` 出现次数 | 0 | **1** |
| 30080 `plugins.bundle.css` 出现次数 | 0 | **1** |
| 30081 `style.bundle.css` 出现次数 | 0 | **1** |
| favicon 路径 | `/static`（截断） | `/static/favicon.png` |
| logo 路径 | `/static`（截断） | `/static/img/logo.png` |
| 浏览器实测 | 无样式、Logo 为 alt 文本 | **完整渲染，Logo 为图片** |

**根因**：`Conf.Initialize` 用 `for _, binding := range c.Bindings` 校验 binding，`binding` 是副本，`(*Binding).check()` 的指针接收者修改（含 `DefaultCSS`）落在副本上丢失。
**修复**：抽取 `(*Conf).checkBindings()` 并改为索引遍历。提交 `4cc823a`。

---

## 9. 未测试项（明确标注）

| 项目 | 原因 | 影响 |
| --- | --- | --- |
| 计划任务定时触发 | 需等待到点执行，本次仅验证规则创建与 cron 校验 | 中，建议补测 |
| 邮箱动作端到端送达 | 实例未配置 SMTP | 低，已确认动作被调用 |
| 事件日志检索 | 需 eventsearcher 插件 | 低，501 为文档化预期 |
| OIDC / OAuth2 登录 | 需外部 IdP | 低 |
| ACME 证书签发 | 需公网域名与 80/443 | 低 |
| 大文件 / 高并发压测 | 未执行 | 中，建议上线前补充 |
| MySQL / PostgreSQL / CockroachDB | 本实例为 SQLite（CI 中已覆盖） | 低 |
| 两步验证（TOTP）实际绑定 | 需认证器 App | 低 |

---

## 10. 结论

### **PASS**

**判定依据**：

1. **141 个用例全部通过，0 失败**。
2. WebAdmin 14 个页面、WebClient 5 个页面经 **Computer Use 真实浏览器操作**验证，渲染完整、无错误、中文本地化正确。
3. 事件管理器 **73 个专项用例全部通过**，覆盖全部 14 种动作类型、7 种触发器、6 类条件过滤、按需执行、失败动作、执行顺序、校验负例，并通过服务日志与文件系统副作用验证了**真实触发链路**。
4. 四种访问协议（SFTP / FTP / WebDAV / REST）功能完整，SSH 命令白名单有效。
5. 安全专项 6 项全部有效，路径穿越、符号链接逃逸、配额越权均被正确拦截。
6. 测试前发现的样式缺陷已修复并验证。

**建议后续**：补测计划任务实际定时触发、配置 SMTP 后复测邮箱送达、配置 eventsearcher 插件后验证日志检索、上线前做一轮压力测试。

**专项报告**：详见 [事件管理器专项测试报告](./EVENT_MANAGER_TEST_REPORT_20261119.md)
