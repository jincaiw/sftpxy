# 发布门禁与遗留测试项 专项报告

- **日期**：2026-11-20
- **基线版本**：v0.2.12（发布产物）
- **目的**：处理 v0.2.12 验收后遗留的三项事项

---

## 事项 2：发布流程断言（已完成）

### 根因复核

```
$ git show v0.2.11:internal/httpd/httpd.go | grep -c checkBindings
0     # 修复不在 v0.2.11
```

v0.2.11 的 tag 指向 `fd8ba6f`，早于样式修复提交 `4cc823a`。原
`release-check.sh` 只校验元数据一致性，不校验 tag 目标是否为最新提交。

### 新增

- `scripts/pre-tag-check.sh`：发布前门禁
  1. 工作区必须干净
  2. Tag 不得已存在（本地或远端）
  3. **HEAD 必须是 `origin/<branch>` 的最新提交**（拦住「在旧提交上打 tag」）
  4. 发布元数据一致（复用 `release-check.sh`）
- `scripts/verify-prod.sh`：构建后断言二进制上报的**版本**与**构建 commit** 与本次一致
- `make release-tag` 改为调用 `pre-tag-check.sh`
- `docs/RELEASE_SOP.md`、`docs/RELEASE_CHECKLIST.md` 更新为「先 push 再 gate 再打 tag」

### 验证（临时 git 仓库，离线）

| 用例 | 预期 | 实际 |
| --- | --- | --- |
| 干净 + HEAD==origin | 通过 | ✅ 通过 |
| 工作区脏 | 失败 | ✅ 失败 |
| 有未推送提交 | 失败 | ✅ 失败 |
| Tag 已存在 | 失败 | ✅ 失败 |
| 元数据版本不符 | 失败 | ✅ 失败 |

`verify-prod.sh` 的产物断言用同 ldflags 构建实测：版本与 commit 均匹配；错误 commit 能被检出。

提交：`77aef33`

---

## 事项 1：Docker 镜像核查（已完成）

### 结论：v0.2.12 镜像已发布，可拉取可运行

之前的 404 是构建未完成 + 网络抖动。新增 `scripts/check-artifacts.sh` 直接查注册表：

```
==> GitHub release v0.2.12
  release published (not draft)                        OK
  assets: 13                                           OK
==> Docker Hub qing1205/sftpxy
  ...:v0.2.12  OK    ...:v0.2  OK    ...:v0  OK    ...:latest  OK
==> GHCR ghcr.io/jincaiw/sftpxy
  ...:v0.2.12  OK    ...:latest  OK
==> Docs site
  https://sftp.mujizi.com/                             OK
RESULT: all release artifacts present for v0.2.12.
```

> 注意：minor/major tag 带 `v` 前缀（`v0.2`、`v0`），因为流水线从 tag ref 推导。
> 脚本初版误判为 `0.2`/`0`，已修正。

### 拉取并实跑

- 拉取成功，digest `sha256:9ae69a5d...`，`User=1000:1000`，arm64/linux
- 版本串 `SFTPxy 0.2.12-bdba3130-...`，**commit 与 v0.2.12 tag 一致**
- 容器启动后：setup 页 200 且含 `style.bundle.css`（样式修复生效）、favicon 正确、SFTP banner `SSH-2.0-SFTPxy_0.2.12`

脚本同时区分「网络不可达（退出 3）」与「产物缺失（退出 1）」，避免误判。
提交：`6ae7bf1`、`213b402`

---

## 事项 3：遗留测试项

### 3b 邮箱端到端送达 —— 通过

自写无认证 SMTP 接收器（127.0.0.1:33998），配置 `smtp.host/port/from`，
触发按需规则 `rule_ondemand`（使用 `act_email`）。接收器捕获到完整邮件：

```
Subject: SFTPxy event test
User-Agent: SFTPxy 0.2.12
From: <sftpgo@test.local>
To: <ops@example.com>
Content-Type: text/plain; charset=UTF-8

event manager email delivery test
```

结论：动作真正执行并完成 SMTP 投递（此前仅验证到「动作被调用」）。

### 3c 事件日志检索 —— 通过

构建 `tests/eventsearcher` 插件（12.5 MB），以 `plugins` 配置加载，插件进程已启动。

| 接口 | 修复前 | 加载插件后 |
| --- | --- | --- |
| `GET /api/v2/events/fs` | 501 | ✅ 200，返回结构化事件 |
| `GET /api/v2/events/provider` | 501 | ✅ 200 |
| `GET /api/v2/events/logs` | 501 | ✅ 200 |

结论：501 确系「未配置插件」所致，接入插件后检索链路完全可用。

### 3d 压力测试 —— 通过

新增 `scripts/loadtest.py`（零第三方依赖）。基线（localhost，0.2.12）：

| 场景 | 请求/并发 | 吞吐 | p95 | 错误率 | 判定 |
| --- | --- | --- | --- | --- | --- |
| Web 登录页 | 300 / 30 | 9,624 rps | 7.1 ms | 0% | PASS |
| REST `/api/v2/version` | 300 / 30 | 15,283 rps | 3.8 ms | 0% | PASS |
| REST `/api/v2/version` | 3000 / 100 | 19,536 rps | 7.3 ms | 0% | PASS |

验收标准（本次自定）：错误率 0%，p95 < 1000 ms。三轮均满足。

> 说明：这是本地回环 smoke 级负载，不代表生产容量规划；未覆盖 SFTP 大批量传输与长连接场景。

### 3a 计划任务定时触发 —— 见下节

调度器为 robfig/cron 标准 5 段，分钟位固定 0（`0 <hour> <dom> <month> <dow>`），
且运行实例未配置 TZ（`UseLocalTime()==false`）→ 使用 **UTC**。因此只能整点触发。

已注册规则 `sched_trigger_test`，cron `0 9 * * *`（09:00 UTC = 17:00 CST），
动作为 HTTP GET 到本地监听器 127.0.0.1:33999，实际等待到点。

**注册日志**：

```
schedule for rule "sched_trigger_test" added, id: 1, cron string "0 9 * * *", active scheduling rules: 1
```

**到点执行日志**：

```
17:00:00.003 executing scheduled rule "sched_trigger_test"
17:00:00.039 http notification sent, endpoint: http://127.0.0.1:33999/hit, elapsed: 16.858833ms, status code: 200
17:00:00.040 executed action "sched_probe_http" for rule "sched_trigger_test", elapsed 19.607959ms
17:00:00.040 execution for scheduled rule "sched_trigger_test" finished
```

**监听器记录**：

```
2026-11-20T17:00:00.037726 /hit
```

结论：计划任务在整点精确触发（偏差 < 40ms），动作执行成功并产生外部可观测副作用。**通过**。
