# Release Checklist

SFTPxy 标准发布清单。

简版操作卡见 `docs/RELEASE_CARD.md`。

## 发布原则

- 先做版本同步，再做校验，再提交和打 Tag
- 先通过本地 dry-run，再触发线上发布
- 以 `make release-dry-run` 的结果作为最终本地验收依据

## 1. 版本准备

1. 确认发布版本 `X.Y.Z`
2. 执行 `make sync-version VERSION=X.Y.Z`
3. 检查并更新 `CHANGELOG.md`
4. 确认 `README.md` / `README.zh-CN.md` 中版本提示正确
5. 确认 `openapi/openapi.yaml` 版本正确
6. 确认 `internal/version/version.go` 版本正确
7. 确认 `VERSION` 仅包含裸版本号

验收标准：`scripts/release-check.sh X.Y.Z` 能通过。

## 2. 发布前校验

1. `make ci VERSION=X.Y.Z`
2. `make release-dry-run VERSION=X.Y.Z`
3. `scripts/release-check.sh X.Y.Z`
4. `scripts/verify-prod.sh X.Y.Z`
5. `docker build --build-arg DOWNLOAD_PLUGINS=false --build-arg INSTALL_OPTIONAL_PACKAGES=false -t sftpxy:test .`
6. `git status --short` 为空

验收标准：CI、dry-run、生产验证、Docker 构建都通过。

## 3. 提交与打 Tag

1. `git add -A`
2. `git commit -m "chore: release vX.Y.Z"`
3. 创建并推送 `vX.Y.Z` Tag
4. `git push origin master refs/tags/vX.Y.Z`

验收标准：仓库主分支和 Tag 已同步到远端。

## 4. GitHub Release

1. 等待 `Release` workflow 自动触发
2. 检查 Linux / Windows / macOS / source 资产
3. 检查 checksums 是否生成
4. 检查 Release 是否为 published 而非 draft
5. 检查资产名与 `vX.Y.Z` 一致

验收标准：GitHub Release 页面可正常下载全部资产。

## 5. DockerHub 发布

1. 等待 `Docker` workflow 自动触发
2. 检查镜像 `qing1205/sftpxy:vX.Y.Z`
3. 检查 `latest` 是否更新
4. 检查 `major` / `minor` tag 是否更新
5. 确认 `linux/amd64` 和 `linux/arm64` 均已发布

验收标准：DockerHub 镜像可拉取并正常启动。

## 6. 发布后确认

1. 打开 GitHub Release 页面确认链接正常
2. 拉取一次 Docker 镜像确认可启动
3. 确认文档站点可访问
4. 如有需要，同步公告或变更说明

验收标准：外部下载、镜像拉取、文档访问均正常。

## 7. 常用命令

```bash
make sync-version VERSION=X.Y.Z
make ci VERSION=X.Y.Z
make release-dry-run VERSION=X.Y.Z
scripts/release-check.sh X.Y.Z
scripts/verify-prod.sh X.Y.Z
git push origin master refs/tags/vX.Y.Z
```

## 8. 发布顺序速查

1. 选版本号
2. 同步版本
3. 本地校验
4. 提交并打 Tag
5. 等待 GitHub Release
6. 等待 DockerHub 发布
7. 最终验收
