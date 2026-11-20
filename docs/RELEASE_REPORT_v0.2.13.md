# v0.2.13 发布报告

- **发布日期**：2026-11-20
- **Tag**：`v0.2.13` → commit `fa543d9`
- **结论**：**已发布，全部产物验证通过**

## 本版内容

自 v0.2.12 起累积的发布工程改进（无 Go 业务代码变更）：

- `scripts/pre-tag-check.sh`：发布前门禁（干净树 / HEAD==origin / tag 未存在 / 元数据一致）
- `scripts/check-artifacts.sh` + `make check-artifacts`：核查 Release、Docker Hub、GHCR、文档站
- `scripts/loadtest.py`：零依赖 HTTP 压测
- `scripts/verify-prod.sh`：新增产物版本与 commit 断言
- `make release-tag` 复用门禁；SOP / Checklist 同步更新

## 发布前校验

| 检查 | 结果 |
| --- | --- |
| `scripts/release-check.sh 0.2.13` | ✅ |
| `scripts/verify-prod.sh 0.2.13` | ✅ Production verification passed |
| `scripts/pre-tag-check.sh 0.2.13` | ✅ 通过（新门禁首次用于真实发布） |

## 发布产物

| 渠道 | 结果 |
| --- | --- |
| GitHub Release | ✅ published（非 draft），**13 个资产** |
| Docker Hub `qing1205/sftpxy` | ✅ `v0.2.13` / `v0.2` / `v0` / `latest` |
| GHCR `ghcr.io/jincaiw/sftpxy` | ✅ `v0.2.13` / `latest` |
| 文档站 | ✅ 200 |

Docker 镜像实拉验证：digest `sha256:63209232...`，`User=1000:1000`，arm64，
版本串 `SFTPxy 0.2.13-fa543d92` —— **commit 与 tag 一致**；容器启动后 setup 页 200
且含样式表，SFTP banner `SSH-2.0-SFTPxy_0.2.13`。

> 说明：Docker Hub API 在发布期间对本次核查多次返回 000（网络抖动），
> 但 `docker pull` 与 manifest 查询均确认镜像存在，故判定为已发布。

## 流水线

Release ✅ success、Docker ✅ success、CodeQL ✅ success。
