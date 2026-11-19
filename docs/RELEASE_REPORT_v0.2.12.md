# v0.2.12 深度测试与验收报告

- **日期**：2026-11-19
- **版本**：v0.2.12（commit `bdba313`）
- **环境**：macOS darwin-arm64 / Go 1.26.11 / SQLite schema 34 / Docker 29.8.2
- **结论**：**PASS**，已发布

---

## 1. 关键发现（本次验收的主要价值）

**v0.2.11 的发布产物不包含样式修复。**

核对发现 v0.2.11 tag 指向 `fd8ba6f`，而样式修复提交 `4cc823a` 在其之后：

```
$ git show v0.2.11:internal/httpd/httpd.go | grep -c checkBindings
0        # 修复不在 v0.2.11 中
$ grep -c checkBindings internal/httpd/httpd.go
3        # 修复在 HEAD 中
```

这意味着 v0.2.11 的 13 个发布资产（含 Docker 镜像）**仍存在 Web 页面无样式缺陷**。本次因此发布 v0.2.12 携带该修复。

---

## 2. 静态检查

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| 构建 | `go build ./...` | ✅ |
| 静态分析 | `go vet ./...` | ✅ |
| 格式 | `gofmt -l` | ✅ 无输出 |
| Lint | `golangci-lint run ./...` | ✅ **0 issues** |
| 漏洞 | `govulncheck ./...` | ✅ **No vulnerabilities found** |
| 跨平台 | `GOOS=windows go vet ./...` | ✅ |
| 发布元数据 | `release-check.sh 0.2.12` | ✅ |

## 3. 测试

| 范围 | 结果 |
| --- | --- |
| `go test ./...`（14 个包） | ✅ 全部 ok |
| `go test -race`（httpd/service/vfs/common） | ✅ 全部 ok，**无 DATA RACE** |
| `scripts/verify-prod.sh 0.2.12` | ✅ **Production verification passed** |

## 4. Docker 深度测试

| 检查 | 结果 |
| --- | --- |
| 镜像构建（仓库 Dockerfile） | ✅ 225,430,297 B |
| 镜像元数据 | ✅ `User=1000:1000`、`WorkDir=/var/lib/SFTPxy`、7 个 EXPOSE |
| 版本注入 | ✅ `SFTPxy 0.2.12-...` |
| 非 root 运行 | ✅ `uid=1000(SFTPxy)` |
| WebAdmin / SFTP | ✅ 302 → setup；`SSH-2.0-SFTPxy_0.2.12` |
| 数据持久化 | ✅ 写入宿主 `.dockerrun/`；**重启容器后** token 仍 200；**删除重建容器后** token 仍 200 |

## 5. 功能测试

**WebAdmin（14 页，Computer Use 真实浏览器）**：status / users / folders / groups / roles / connections / events / eventrules / eventactions / defender / configs / maintenance / ip-lists / profile —— 全部渲染正常、中文标题正确、无错误横幅。

**REST API**：users / folders / groups / roles / eventactions / eventrules / connections 均 200；user token + dirs + files 均 200。

**协议**：SFTP banner 正常；FTP LIST 226；WebDAV PROPFIND 207。

**事件管理器回归**：17 个动作、23 条规则（无重复），按需执行返回 202。

## 6. 安全专项

| 攻击面 | 载荷 | 结果 |
| --- | --- | --- |
| 路径穿越（原始） | `/../../../../etc/passwd` | ✅ 404，无泄露 |
| 路径穿越（编码） | `%2F..%2F..%2Fetc%2Fpasswd` | ✅ 404 |
| WebDAV 穿越 | `--path-as-is` | ✅ 404 |
| 无 token | — | ✅ 401 |
| 伪造 token | `Bearer bogus` | ✅ 401 |
| 错误密码 | `admin:wrong` | ✅ 401 |
| 配额越权 | 30B 配额上传 200KB | ✅ 413 `denying write due to space limit` |

## 7. 发布结果

**GitHub Release**：https://github.com/jincaiw/sftpxy/releases/tag/v0.2.12
状态：已发布（非草稿），**13 个资产**：

| 平台 | 资产 |
| --- | --- |
| Linux | `.rpm`(x86_64)、`.deb`(amd64)、bundle、x86_64 tar.xz |
| macOS | arm64/x86_64 的 `.dmg` 与 `.tar.xz` |
| Windows | x86/x86_64/arm64 `.exe`、portable `.zip` |
| 源码 | `src_with_deps.tar.xz` |

**流水线**：Release ✅ success、CodeQL ✅ success、Docker（v0.2.12 多架构构建中）。

**发布产物验证**：从 v0.2.12 源码重新构建并运行，setup 页面正确输出两条样式表 `<link>` 与完整 favicon 路径，确认修复已包含。

## 8. 未完成项

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| Docker 镜像推送 DockerHub | 进行中 | 多架构构建耗时较长，未等到完成 |
| 计划任务定时触发实测 | 未执行 | 需等待到点，本次仅验证规则创建与 cron 校验 |
| 邮箱动作端到端送达 | 未执行 | 实例未配置 SMTP |
| 事件日志检索 | 未执行 | 依赖 eventsearcher 插件，501 为预期 |
| 压力测试 | 未执行 | 未定义验收标准 |

## 9. 遗留建议

1. 发布流程应在 tag 前校验「目标提交是否包含待发布修复」——本次 v0.2.11 的问题正源于此。可在 `release-check.sh` 中增加一条断言。
2. DockerHub 镜像发布后应回查 tag 可拉取，避免像 v0.2.10 那样 tag 存在但资产缺失。
