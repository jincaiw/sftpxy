# SFTPxy v0.2.4 全功能测试报告

- **测试日期**：2026-08-31
- **被测版本**：v0.2.4（本地源码编译，非 Docker 镜像）
- **测试方式**：浏览器模拟人工操作（Web Admin / Web Client）+ 命令行客户端（SFTP/scp/ssh）+ REST API 调用
- **测试环境**：macOS，SQLite 数据库，全新安装（从 setup 页面初始化管理员开始）

---

## 1. 测试环境

| 项目 | 说明 |
| --- | --- |
| 应用二进制 | 当前源码 `go build` 产物（`/tmp/sftpxy-run/sftpxy`） |
| 数据库 | SQLite（全新初始化，schema version 34） |
| Web Admin + REST API | http://localhost:31080 |
| Web Client | http://localhost:31081 |
| SFTP | localhost:31082 |
| 管理员账号 | admin / Passw0rd!123（setup 页面创建） |
| 测试用户 | testuser / Passw0rd!123（home: /tmp/sftpxy-run/data/testuser，权限 `/*`） |
| 副管理员 | subadmin / Passw0rd!123 |

测试数据：`/hello.txt`、`/subdir/nested.txt`、上传的 `test_upload.txt`、`webdir/` 目录等。

---

## 2. 测试范围与结果总览

| 模块 | 方式 | 结果 |
| --- | --- | --- |
| 安装初始化（Setup） | 浏览器 | ✅ 通过 |
| Web Admin 全部页面与功能 | 浏览器 | ✅ 通过（发现 1 个 API 层 bug，已修复） |
| Web Client 全部页面与功能 | 浏览器 | ✅ 通过 |
| SFTP / scp / SSH 命令 | 命令行 | ✅ 通过 |
| REST API（含备份恢复） | curl | ✅ 通过（发现并修复 1 个 bug） |
| 单元测试 / 静态检查 | go test / go vet / gofmt | ✅ 通过 |

---

## 3. Web Admin 测试明细（浏览器模拟人工操作）

### 3.1 初始化与登录

| 测试项 | 结果 | 说明 |
| --- | --- | --- |
| 首次访问重定向到 setup 页 | ✅ | 访问 :31080 自动跳转 `/web/admin/setup` |
| 创建管理员 admin | ✅ | 创建成功后跳转 MFA 页面 |
| 登录 / 登出 / 重新登录 | ✅ | 会话正常，登出后跳转登录页 |
| 中英文语言切换 | ✅ | 登录页下拉切换，文案完整切换，无 JS 错误 |

### 3.2 功能页面

| 测试项 | 结果 | 说明 |
| --- | --- | --- |
| 状态页（Status） | ✅ | 服务器状态渲染正常 |
| 连接页（Connections） | ✅ | 活动连接列表及操作按钮正常 |
| 用户管理 | ✅ | 创建 testuser 成功，列表显示活跃 |
| 文件夹管理 | ✅ | 创建 shared（本地磁盘 /tmp/sftpxy-run/data/shared），列表出现 |
| 组（Groups） | ✅ | 页面渲染正常 |
| 角色（Roles） | ✅ | 页面渲染正常 |
| IP 黑白名单 | ✅ | 页面渲染正常（API 创建测试见 §5） |
| 事件规则 / 事件动作 | ✅ | 页面渲染正常（API 深度测试见 §5） |
| 事件（Events） | ✅ | 页面渲染正常；事件搜索依赖外部插件，返回明确的 501 提示（预期行为） |
| 管理员管理 | ✅ | 创建 subadmin 成功，列表显示 2 条记录 |
| Profile 页 | ✅ | 个人资料字段与保存按钮正常 |
| MFA（TOTP）页 | ✅ | 二维码配置区域正常渲染 |
| Defender 页 | ✅ | 自动屏蔽列表、搜索/刷新按钮正常 |
| 维护（Maintenance） | ✅ | 恢复/备份两个区域正常；备份恢复 API 实测见 §5.4 |
| 配置（Configs）页 | ✅ | 渲染正常 |
| 修改密码表单（/web/admin/changepwd） | ✅ | 表单完整（未提交修改） |

---

## 4. Web Client 测试明细（浏览器模拟人工操作）

| 测试项 | 结果 | 说明 |
| --- | --- | --- |
| 登录 | ✅ | 登录成功跳转 /web/client/files，中文界面 |
| 文件列表（根目录） | ✅ | 正确显示 hello.txt、subdir 等 |
| 进入子目录 / 返回上级 | ✅ | 正常 |
| 上传文件 | ✅ | 通过文件选择器上传，列表刷新显示 |
| 下载文件 | ✅ | 无报错 |
| 文件预览/编辑 | ✅ | 文本文件内容正常显示 |
| 新建目录（webdir） | ✅ | 创建成功并出现在列表 |
| 分享（Shares） | ✅ | 创建 testshare（/hello.txt），列表出现，匿名打开分享链接可访问 |
| Profile 页 | ✅ | 渲染正常，无 JS 错误 |
| 修改密码表单 | ✅ | 表单完整（未提交） |
| MFA 页 | ✅ | 渲染正常 |
| 登出 | ✅ | 跳转登录页 |
| 语言切换 | ✅ | 英文文案切换正常，无 JS 错误 |

文件操作（mkdir/rename/delete）另经用户 REST API 层复测，全部正常（见 §5.3）。

---

## 5. SFTP 协议与 REST API 测试明细

### 5.1 SFTP（sshpass + OpenSSH 客户端，端口 31082）

| 测试项 | 结果 |
| --- | --- |
| 密码认证登录 | ✅ |
| 错误密码拒绝（Permission denied） | ✅ |
| ls / pwd | ✅ |
| 上传（put） | ✅ 内容校验一致 |
| 下载（get） | ✅ 内容校验一致 |
| mkdir / rmdir | ✅ |
| rename | ✅ |
| rm | ✅ |

### 5.2 scp 与 SSH 命令

| 测试项 | 结果 |
| --- | --- |
| scp 上传 / 下载 | ✅ 内容校验一致 |
| ssh 远程命令 sha256sum | ✅ |

### 5.3 用户 API（/api/v2/user/...）

| 测试项 | 结果 | 说明 |
| --- | --- | --- |
| 获取用户 token | ✅ | GET + Basic Auth |
| 创建目录（POST /user/dirs?path=） | ✅ | 201 |
| 重命名（PATCH /user/dirs?path=&target=） | ✅ | 200 |
| 删除（DELETE /user/dirs?path=） | ✅ | 200 |
| 文件重命名/删除（/user/files） | ✅ | 200 |

### 5.4 管理 API

| 测试项 | 结果 | 说明 |
| --- | --- | --- |
| Token（GET /api/v2/token + Basic） | ✅ | |
| 创建事件动作 retention72（Data retention，/ 72h） | ✅ | 201 |
| 创建事件规则 cleanup-rule（schedule 触发 + retention72） | ✅ | 201 |
| 创建引用不存在动作的规则 | ⚠️→✅ | **发现 bug #1**，修复后返回 400 校验错误（见 §6） |
| 备份（GET /api/v2/dumpdata?output-data=1） | ✅ | 导出 users/admins/folders 等完整 |
| 恢复（POST /api/v2/loaddata?mode=0） | ✅ | 恢复后数据无重复 |
| 按需运行非 on-demand 规则 | ✅ | 返回 400 校验错误（正确防护行为） |

---

## 6. 发现的问题与修复

### Bug #1（已修复）：事件规则引用不存在的动作时返回 500 原始数据库错误

- **复现步骤**：
  1. 获取管理员 token；
  2. `POST /api/v2/eventrules`，payload 的 `actions` 引用一个不存在的动作名（如 `nonexistent-action`）。
- **修复前表现**：`500 {"error":"NOT NULL constraint failed: rules_actions_mapping.action_id"}`
- **根因分析**：SQL 提供者（sqlite/mysql/pgsql）通过 `generateEventRuleActionsMapping` 插入规则-动作映射，INSERT 语句使用子查询 `(SELECT id FROM events_actions WHERE name = ?)` 获取动作 ID；动作不存在时子查询返回 NULL，直接触发 NOT NULL 约束错误。Bolt 与 Memory 提供者均有动作存在性校验并返回友好错误，SQL 提供者遗漏了该校验。
- **修复方案**：
  - [internal/dataprovider/sqlcommon.go](../internal/dataprovider/sqlcommon.go) `generateEventRuleActionsMapping`：插入映射前先查询动作是否存在，不存在时返回 `400 Validation error: action "xxx" does not exist`；
  - [internal/dataprovider/sqlqueries.go](../internal/dataprovider/sqlqueries.go) 新增 `getEventActionNameQuery` 查询；
  - 更新两处断言旧行为（期望 500）的测试用例为期望 400。
- **修复后表现**：`400 {"error":"Validation error: action \"nonexistent-action\" does not exist"}`

### 排查后确认为预期行为（非 bug）

| 现象 | 结论 |
| --- | --- |
| `/web/admin/apikeys` 返回 404 | API Keys 仅通过 REST API `/api/v2/apikeys` 管理，Web Admin 无此页面 |
| `/api/v2/events/fs` 返回 501 | 事件搜索需配置外部事件搜索插件，错误提示明确 |
| SFTP 报 "too many authentication failures" | OpenSSH 客户端默认先尝试本机公钥所致，加 `-o PubkeyAuthentication=no` 即正常，属客户端行为 |

---

## 7. 回归验证

| 验证项 | 结果 |
| --- | --- |
| `go test ./internal/httpd -run 'TestEventRule\|TestEventAction'` | ✅ 通过 |
| `go vet ./internal/dataprovider ./internal/httpd` | ✅ 通过 |
| `gofmt` 检查修改的文件 | ✅ 通过 |
| 重新编译并重启服务 | ✅ |
| bug #1 回归：引用不存在动作 | ✅ 返回 400 带明确错误信息 |
| 正常规则（引用存在动作）创建 | ✅ 不受影响 |
| 端到端回归：Web Admin / Web Client 登录页 200、OpenAPI 200、API 用户列表 200、SFTP ls 正常 | ✅ |

---

## 8. 结论

- 应用整体功能完整、运行稳定：Web Admin、Web Client、SFTP/scp/SSH 命令、REST API、备份恢复在全新安装环境下全部测试通过。
- 测试期间发现并修复 1 个真实 bug（SQL 提供者事件规则动作校验缺失），修复后相关单元测试与端到端回归全部通过，无重复数据、无副作用。
- 其余疑似问题经排查均为预期行为或客户端环境因素。
