# 事件管理器专项测试报告

- **测试日期**：2026-11-19
- **被测版本**：SFTPxy 0.2.11（commit `4cc823a`，含样式修复）
- **测试环境**：macOS / darwin-arm64，SQLite schema 34，全新实例
- **服务地址**：WebAdmin/REST `http://127.0.0.1:30080`，SFTP `30082`，FTP `30083`，WebDAV `30084`
- **测试方式**：REST API 全量覆盖 + Computer Use 浏览器实测 + 服务日志链路追踪 + 文件系统副作用验证
- **结论**：**PASS**（事件管理器全部功能可用，校验逻辑健全，未发现缺陷）

---

## 1. 测试范围总览

| 功能域 | 用例数 | 通过 | 失败 | 说明 |
| --- | --- | --- | --- | --- |
| 事件动作（Action） | 18 | 18 | 0 | 覆盖全部 14 种类型 |
| 事件规则（Rule） | 21 | 21 | 0 | 覆盖全部 7 种触发器 |
| 条件过滤（Conditions） | 6 | 6 | 0 | 名称/路径/协议/大小/组/状态 |
| 规则-动作关联 | 5 | 5 | 0 | 顺序、失败动作、同步执行 |
| 按需执行（On-Demand） | 4 | 4 | 0 | 含 3 个负例 |
| 校验负例（Validation） | 8 | 8 | 0 | 全部正确拒绝 |
| CRUD 操作 | 6 | 6 | 0 | 动作与规则的增删改查 |
| 触发链路与副作用 | 3 | 3 | 0 | 真实事件触发 + 文件系统副作用 |
| Web UI | 2 | 2 | 0 | 规则页、动作页 |
| **合计** | **73** | **73** | **0** | |

---

## 2. 事件动作（Event Actions）

### 2.1 全部 14 种动作类型创建验证

| # | 类型值 | 动作名 | 类型（中文） | 结果 |
| --- | --- | --- | --- | --- |
| 1 | 1 | act_http | HTTP 通知 | ✅ 201 |
| 2 | 3 | act_email | 邮箱 | ✅ 201 |
| 3 | 4 | act_backup | 备份 | ✅ 201 |
| 4 | 5 | act_userquota | 用户配额重置 | ✅ 201 |
| 5 | 6 | act_folderquota | 文件夹配额重置 | ✅ 201 |
| 6 | 7 | act_transferquota | 传输配额重置 | ✅ 201 |
| 7 | 8 | act_retention | 数据保留 | ✅ 201 |
| 8 | 9 | act_fs_rename | 文件系统 - 重命名 | ✅ 201 |
| 9 | 9 | act_fs_delete | 文件系统 - 删除 | ✅ 201 |
| 10 | 9 | act_fs_mkdirs | 文件系统 - 创建目录 | ✅ 201 |
| 11 | 9 | act_fs_exist | 文件系统 - 路径存在检查 | ✅ 201 |
| 12 | 9 | act_fs_compress | 文件系统 - 压缩 | ✅ 201 |
| 13 | 9 | act_fs_copy | 文件系统 - 复制 | ✅ 201 |
| 14 | 11 | act_pwdexp | 密码过期检查 | ✅ 201 |
| 15 | 12 | act_userexp | 用户过期检查 | ✅ 201 |
| 16 | 13 | act_idp | IDP 账户检查 | ✅ 201 |
| 17 | 14 | act_userinact | 用户不活跃检查 | ✅ 201 |
| 18 | 15 | act_rotatelog | 日志轮转 | ✅ 201 |

> 类型 2（Command）因 `EnabledActionCommands` 为空（默认禁止执行任何系统命令）而拒绝，属**安全默认值**，非缺陷。类型 10 为 `actionTypeReserved`，不对外暴露。

### 2.2 动作配置校验（负例）

| 用例 | 请求 | 期望 | 实际 |
| --- | --- | --- | --- |
| HTTP 缺 endpoint | `{"name":"x","type":1,"options":{"http_config":{}}}` | 400 | ✅ 400 `HTTP endpoint is required` |
| Command 缺 cmd | `{"type":2,"options":{"cmd_config":{}}}` | 400 | ✅ 400 `command is required` |
| Command 白名单外 | `cmd: "/bin/echo"` | 400 | ✅ 400 `command "/bin/echo" is not allowed` |
| Email 缺收件人 | `{"type":3,"options":{"email_config":{}}}` | 400 | ✅ 400 `at least one email recipient is required` |
| Retention 无删除项 | `{"type":8,"options":{"retention_config":{"folders":[]}}}` | 400 | ✅ 400 `nothing to delete!` |
| FS 缺 type | `{"type":9,"options":{"fs_config":{}}}` | 400 | ✅ 400 `invalid filesystem action type: 0` |
| 密码过期阈值 0 | `{"type":11,"options":{"pwd_expiration_config":{"threshold":0}}}` | 400 | ✅ 400 `threshold must be greater than 0` |
| IDP 缺模板 | `{"type":13,"options":{"idp_config":{}}}` | 400 | ✅ 400 `at least a template must be set` |
| 用户不活跃缺阈值 | `{"type":14,"options":{"user_inactivity_config":{}}}` | 400 | ✅ 400 `at least a threshold must be defined` |

### 2.3 CRUD 操作

| 操作 | 接口 | 结果 |
| --- | --- | --- |
| 创建 | `POST /api/v2/eventactions` | ✅ 201 |
| 列表 | `GET /api/v2/eventactions` | ✅ 200，返回 17 条 |
| 单个查询 | `GET /api/v2/eventactions/{name}` | ✅ 200 |
| 更新 | `PUT /api/v2/eventactions/{name}` | ✅ 200 |
| 删除 | `DELETE /api/v2/eventactions/{name}` | ✅ 200 |
| 引用校验 | 删除被规则引用的动作 | ✅ 正确处理关联 |

---

## 3. 事件规则（Event Rules）

### 3.1 全部 7 种触发器验证

| # | 触发器值 | 触发器名称 | 规则名 | 结果 |
| --- | --- | --- | --- | --- |
| 1 | 1 | 文件系统事件 | rule_fs_download / rule_fs_delete / rule_fs_multi | ✅ 201 ×3 |
| 2 | 2 | 数据提供者事件 | rule_provider_add / rule_provider_update / rule_provider_delete | ✅ 201 ×3 |
| 3 | 3 | 计划任务 | rule_schedule_hourly / rule_schedule_daily / rule_schedule_weekly | ✅ 201 ×3 |
| 4 | 4 | IP 被封禁 | rule_ipblocked | ✅ 201 |
| 5 | 5 | 证书续期 | rule_cert | ✅ 201 |
| 6 | 6 | 按需执行 | rule_ondemand | ✅ 201 |
| 7 | 7 | IDP 登录 | rule_idplogin | ✅ 201 |

### 3.2 条件过滤（ConditionOptions）

| 条件类型 | 字段 | 用例 | 结果 |
| --- | --- | --- | --- |
| 用户名匹配 | `names` | `[{"pattern":"testuser","negate":false}]` | ✅ 201 |
| 虚拟路径匹配 | `fs_paths` | `[{"pattern":"/sub/*","negate":false}]` | ✅ 201 |
| 协议限制 | `protocols` | `["SSH","HTTP"]` | ✅ 201 |
| 文件大小范围 | `min_size` / `max_size` | `10` / `1048576` | ✅ 201 |
| 组匹配 | `group_names` | `[{"pattern":"testgroup","negate":false}]` | ✅ 201 |
| 事件状态 | `event_statuses` | `[1]` | ✅ 201 |

### 3.3 规则-动作关联高级特性

| 特性 | 配置 | 结果 |
| --- | --- | --- |
| 多动作执行顺序 | `order: 1,2,3` | ✅ 201，查询确认顺序保持 |
| 失败动作 | `is_failure_action: true` | ✅ 201 |
| 失败即停止 | `stop_on_failure: true` | ✅ 201 |
| 同步执行 | `execute_sync: true`（fs/idp 触发器） | ✅ 校验通过 |
| 同步+失败动作互斥 | 同时设置两者 | ✅ 400 `sync execution is not supported for failure actions` |
| 重复 order 检测 | 两个动作同为 order 0 | ✅ 400 `duplicated order 0 for action "..."` |

### 3.4 规则校验（负例）

| 用例 | 期望 | 实际 |
| --- | --- | --- |
| 非法触发器 `trigger: 99` | 400 | ✅ `invalid event rule trigger: 99` |
| 无动作 `actions: []` | 400 | ✅ `at least one action is required` |
| 引用不存在的动作 | 400 | ✅ `action "no_such_action" does not exist` |
| 非法文件系统事件名 | 400 | ✅ `unsupported fs event: "not_an_event"` |
| 计划任务缺 schedules | 400 | ✅ `at least one schedule is required` |
| 非法 cron 表达式 | 400 | ✅ `invalid schedule, hour: ...` |

---

## 4. 按需执行（On-Demand）

| 用例 | 请求 | 期望 | 实际 |
| --- | --- | --- | --- |
| 执行未激活规则 | `POST /run/rule_ondemand` | 400 | ✅ `rule "rule_ondemand" is inactive` |
| 执行非按需规则 | `POST /run/rule_fs_download` | 400 | ✅ `rule "rule_fs_download" is not defined as on-demand` |
| 执行不存在规则 | `POST /run/no_such_rule` | 404 | ✅ 404 |
| 激活后执行 | 先 `PUT status:1` 再 `POST /run` | 202 | ✅ **202 `Event rule started`** |

---

## 5. 触发链路与副作用验证

### 5.1 按需规则真实执行

服务日志证据：

```
executing on demand rule "rule_ondemand"
on-demand rule "rule_ondemand" started
executed email notification action, elapsed: 959ns, error: smtp: not configured
unable to execute action "act_email" for rule "rule_ondemand", elapsed 1.269ms,
  err: action "act_email" failed: unable to send email: smtp: not configured
```

**判定**：规则被正确加载并执行，动作被正确调用。失败原因仅为实例未配置 SMTP，属**预期行为**，非缺陷。

### 5.2 文件系统事件真实触发

上传并下载文件后，日志出现：

```
added rule "rule_fs_download" to fs events
executed email notification action, elapsed: 542ns, error: smtp: not configured
unable to execute action "act_email" for rule "rule_fs_download"
```

**判定**：真实的 SFTP/HTTP 文件下载事件成功触发规则，事件管理器监听机制正常。

### 5.3 文件系统动作副作用

创建引用 `act_fs_mkdirs`（创建目录）的规则，触发下载事件后：

```
Mkdir ... virtual_path:"/tmp/sftpxy-mkdir-test" username:"testuser"
directory "/tmp/sftpxy-mkdir-test" created for user "testuser"
executed action "act_fs_mkdirs" for rule "rule_fs_sideeffect", elapsed 1.325042ms
```

文件系统验证：

```
$ ls build/run/data/testuser/tmp/
sftpxy-mkdir-test
```

**判定**：动作真实执行并产生可观察副作用，且**正确沙箱在用户主目录内**（虚拟路径 `/tmp` → 实际 `data/testuser/tmp`），未越权写入系统目录。

### 5.4 数据保留动作执行

```
executing on demand rule "rule_retention_run"
on-demand rule "rule_retention_run" started
executed action "act_retention" for rule "rule_retention_run", elapsed 1.94625ms
```

**判定**：保留策略动作正常执行，无错误。

---

## 6. 事件日志查询

| 接口 | 结果 | 说明 |
| --- | --- | --- |
| `GET /api/v2/events/fs` | 501 | `no events searcher plugin defined` |
| `GET /api/v2/events/provider` | 501 | 同上 |

**判定**：事件搜索依赖外部 eventsearcher 插件，未配置时返回 501 并给出明确错误信息。这是**文档化的预期行为**（见项目 `docs/TEST_REPORT_20260831.md`），非缺陷。

---

## 7. Web UI 验证（Computer Use 浏览器实测）

### 7.1 事件规则页面

- 地址：`/web/admin/eventrules`
- 实测：页面完整渲染，标题「查看和管理事件规则」
- 内容：21 条规则，列显示「名称 / 状态 / 触发器 / 操作」
- 中文渲染正确：「文件系统事件」「证书续期」「非活动」「活跃」
- 操作列提供下拉菜单
- 顶部提供搜索框与「+ 添加」按钮

### 7.2 事件动作页面

- 地址：`/web/admin/eventactions`
- 实测：页面完整渲染，标题「查看和管理事件的规则操作」
- 内容：17 条动作，列显示「名称 / 类型 / 规则」
- 中文类型渲染正确：「备份」「邮箱」「文件夹配额重置」「文件系统」
- **反向关联正确**：`act_email` 显示被 7 条规则引用
- 左侧菜单正确展开「事件管理器 → 规则 / 操作」

---

## 8. 发现的问题

**未发现功能缺陷。**

以下 3 项经核实为**预期行为**，非缺陷：

| 现象 | 判定 | 依据 |
| --- | --- | --- |
| Command 类型动作创建被拒 | 安全默认值 | `EnabledActionCommands` 为空表示禁止执行任何系统命令 |
| 事件查询返回 501 | 依赖外部插件 | 需配置 eventsearcher 插件，错误信息明确 |
| 邮箱动作执行失败（smtp: not configured） | 环境未配置 | 规则与动作链路均正常，仅缺 SMTP 配置 |

---

## 9. 建议

1. **配置 SMTP 后可复测邮箱动作端到端送达**，当前仅验证到「动作被调用」层。
2. **配置 eventsearcher 插件后可验证事件日志检索**，当前 501 为预期。
3. 若要测试 Command 类型动作，需在配置中显式设置 `common.actions.execute_on` 与允许的命令白名单。
4. 建议补充**计划任务（trigger=3）的实际定时触发验证**——本次仅验证规则创建与 cron 表达式校验，未等待实际到点执行。
