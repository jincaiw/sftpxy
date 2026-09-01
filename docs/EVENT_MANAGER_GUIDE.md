# SFTPxy 事件管理器使用教程

本文介绍 SFTPxy WebAdmin 中“事件管理器”的使用方法。

入口：

```text
http://127.0.0.1:30080/web/admin/eventrules
```

事件管理器用于实现：

> 当某类事件发生时，根据规则条件匹配，然后自动执行一个或多个动作。

---

## 1. 核心概念

事件管理器主要由两部分组成：

### 1.1 Event Actions：事件动作

事件动作表示“要做什么”。

例如：

- 发送 HTTP webhook
- 发送邮件
- 执行本地命令
- 执行备份
- 重置用户配额
- 压缩文件
- 复制文件
- 删除文件
- 做数据保留检查

### 1.2 Event Rules：事件规则

事件规则表示“什么时候做”。

例如：

- 用户上传文件后
- 用户删除文件前
- 每天凌晨 2 点
- IP 被封禁时
- 用户通过 OIDC 登录时

一个事件规则可以绑定多个事件动作。

---

## 2. 支持的触发器

| 触发器 | 说明 |
|---|---|
| Filesystem event | 文件事件 |
| Provider event | 用户、组、管理员、分享等对象变更事件 |
| Schedule | 定时任务 |
| IP blocked | IP 被封禁事件 |
| Certificate renewal | 证书续期事件 |
| On demand | 手动触发 |
| Identity Provider login | OIDC / IDP 登录事件 |

---

## 3. 支持的文件事件

| 事件 | 说明 |
|---|---|
| `upload` | 上传完成后触发 |
| `download` | 下载完成后触发 |
| `delete` | 删除完成后触发 |
| `rename` | 重命名完成后触发 |
| `mkdir` | 创建目录后触发 |
| `rmdir` | 删除目录后触发 |
| `copy` | 复制文件后触发 |
| `ssh_cmd` | 执行 SSH 命令时触发 |
| `pre-upload` | 上传前触发 |
| `pre-download` | 下载前触发 |
| `pre-delete` | 删除前触发 |
| `first-upload` | 用户首次上传时触发 |
| `first-download` | 用户首次下载时触发 |

---

## 4. 支持的动作类型

| 动作 | 用途 |
|---|---|
| HTTP | 调用 webhook 或外部接口 |
| Command | 执行本地命令 |
| Email | 发送邮件 |
| Backup | 执行备份 |
| User quota reset | 重置用户配额 |
| Folder quota reset | 重置文件夹配额 |
| Transfer quota reset | 重置传输配额 |
| Data retention check | 数据保留/过期清理 |
| Filesystem | 文件系统操作 |
| Password expiration check | 密码过期检查 |
| User expiration check | 用户过期检查 |
| Identity Provider account check | IDP 登录后创建/更新账号 |
| User inactivity check | 用户不活跃检查 |
| Rotate log file | 轮转日志 |

---

## 5. 使用流程

推荐按以下顺序配置：

```text
先创建 Event Action
再创建 Event Rule
最后把 Action 绑定到 Rule
```

登录 WebAdmin：

```text
http://127.0.0.1:30080/web/admin/login
```

进入：

```text
Event Manager / Event Rules
```

或直接访问：

```text
http://127.0.0.1:30080/web/admin/eventrules
```

---

## 6. 示例一：上传文件后调用 Webhook

### 适用场景

- 用户上传文件后通知业务系统
- 上传文件后通知飞书、钉钉、企业微信
- 上传文件后触发后续处理流程

### 创建 HTTP Action

动作类型选择：

```text
HTTP
```

配置示例：

```text
Name: notify-upload
Endpoint: https://example.com/webhook
Method: POST
Timeout: 10
Headers:
  Content-Type: application/json
Body:
  {
    "event": "upload",
    "username": "{{.Name}}",
    "path": "{{.VirtualPath}}",
    "size": "{{.FileSize}}"
  }
```

### 创建 Event Rule

```text
Trigger: Filesystem event
Event: upload
Action: notify-upload
Status: Enabled
```

效果：用户上传文件后，SFTPxy 自动向 webhook 地址发送 HTTP 请求。

---

## 7. 示例二：每天凌晨自动备份

### 创建 Backup Action

```text
Action type: Backup
Name: daily-backup
```

### 创建 Schedule Rule

```text
Trigger: Schedule
Hour: 2
Day of month: *
Month: *
Day of week: *
Action: daily-backup
```

表示每天凌晨 2 点执行备份。

---

## 8. 示例三：定期清理过期文件

### 创建 Data Retention Action

```text
Action type: Data retention check
Folder: /tmp
Retention: 7 days
```

### 创建 Schedule Rule

```text
Trigger: Schedule
Hour: 3
Day of month: *
Month: *
Day of week: *
Action: cleanup-expired-files
```

---

## 9. 示例四：上传后自动复制文件

### 创建 Filesystem Action

```text
Action type: Filesystem
Filesystem action type: Copy
Source: /incoming/{{.ObjectName}}
Target: /archive/{{.ObjectName}}
```

### 创建 Rule

```text
Trigger: Filesystem event
Event: upload
Condition path: /incoming/*
Action: copy-to-archive
```

注意：需要避免复制目标再次触发同一规则，造成递归执行。

---

## 10. 示例五：删除前拦截

### 创建 HTTP Action

```text
Action type: HTTP
Endpoint: https://example.com/delete-check
Method: POST
Body:
{
  "username": "{{.Name}}",
  "path": "{{.VirtualPath}}",
  "event": "pre-delete"
}
```

### 创建 Rule

```text
Trigger: Filesystem event
Event: pre-delete
Action: check-before-delete
```

注意：`pre-delete` 是前置事件，会影响用户删除操作。外部接口必须响应快、稳定，并返回明确结果。

---

## 11. 示例六：IP 被封禁后告警

### 前提

需要启用 Defender。

### 创建规则

```text
Trigger: IP blocked
Action: security-alert
```

动作可以选择：

- HTTP
- Email

---

## 12. 条件过滤

事件规则支持按条件过滤。

| 条件 | 用途 |
|---|---|
| Names | 用户名或对象名 |
| Group names | 用户组 |
| Role names | 角色 |
| FS paths | 文件路径 |
| Protocols | 协议 |
| Provider objects | Provider 对象类型 |
| Min size | 最小文件大小 |
| Max size | 最大文件大小 |
| Event statuses | 事件状态 |

示例：只匹配某个目录：

```text
FS paths:
/incoming/*
```

示例：只匹配某个用户：

```text
Names:
alice
```

示例：只匹配 SFTP 上传：

```text
Protocols:
SFTP
```

---

## 13. 动作执行顺序

一个规则可以绑定多个动作。

| 配置 | 说明 |
|---|---|
| Order | 执行顺序 |
| Execute sync | 是否同步执行 |
| Stop on failure | 失败后是否停止后续动作 |
| Is failure action | 是否作为失败处理动作 |

建议：

- 通知类动作异步执行
- 前置校验类动作同步执行
- 关键流程设置 `stop on failure`

---

## 14. 当前环境注意事项

当前本地环境中：

| 功能 | 状态 |
|---|---|
| SFTP | 已启用 |
| WebAdmin | 已启用 |
| WebClient | 已启用 |
| FTP | 未启用 |
| WebDAV | 未启用 |
| SMTP | 未配置 |
| Command allowlist | 未配置 |
| Event rules | 暂无 |
| Event actions | 暂无 |

因此当前最适合先测试：

1. 上传后 HTTP webhook
2. 定时 Backup
3. Filesystem copy / compress

暂不建议直接测试：

- Email，除非先配置 SMTP
- Command，除非先配置 `enabled_commands`
- IP blocked，除非先启用 Defender

---

## 15. Command 动作安全配置

Command 动作默认不会随便执行任意命令，需要在配置中显式允许命令。

示例：

```json
{
  "common": {
    "event_manager": {
      "enabled_commands": [
        "/usr/local/bin/scan-file",
        "/usr/local/bin/sync-file"
      ]
    }
  }
}
```

建议：

- 只允许固定脚本
- 使用绝对路径
- 不允许用户可写目录下的脚本
- 脚本内部做参数校验
- 设置合理 timeout

---

## 16. SMTP 配置建议

如果要使用 Email 动作，需要配置 SMTP。

典型配置包括：

```text
SMTP Host
SMTP Port
From
User
Password
Encryption
Templates path
```

未配置 SMTP 时，Email 动作无法正常发送邮件。

---

## 17. 推荐落地路线

### 第一阶段：基础自动化

- 上传后 webhook
- 定时备份
- 定时数据清理

### 第二阶段：文件流转

- 上传后复制
- 上传后压缩
- 上传后移动目录

### 第三阶段：安全治理

- 删除前校验
- 上传前安全检查
- IP blocked 告警

### 第四阶段：企业集成

- OIDC 登录自动建号
- 审计日志推送
- 外部审批系统集成

---

## 18. 常见问题

### Q1：为什么 Email 动作不生效？

通常是 SMTP 未配置或配置错误。

### Q2：为什么 Command 动作不执行？

通常是命令未加入 allowlist。

需要配置：

```json
"enabled_commands": [
  "/absolute/path/to/script"
]
```

### Q3：为什么 FTP / WebDAV 没有事件？

当前 FTP 和 WebDAV 未启用。需要先在配置中启用对应服务。

### Q4：为什么规则创建了但不触发？

检查：

- 规则是否启用
- 触发器是否选对
- 事件类型是否选对
- 条件是否过窄
- 动作是否绑定
- 服务是否重载或已重新加载规则

### Q5：前置事件会不会影响用户操作？

会。

例如：

- `pre-upload`
- `pre-download`
- `pre-delete`

这些事件适合做校验，不适合做耗时任务。

---

## 19. 总结

SFTPxy 事件管理器可以实现：

- 文件事件自动化
- Webhook 集成
- 邮件通知
- 定时任务
- 自动备份
- 数据保留清理
- 配额重置
- 文件归档
- 安全告警
- IDP 登录自动建号
- 本地脚本扩展

建议先从低风险场景开始：

```text
上传后 webhook → 定时备份 → 数据清理 → 文件归档 → 安全治理
```
