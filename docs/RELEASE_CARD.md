# Release Card

SFTPxy 发布人操作卡（简版）。

## 一次性流程

1. 选定版本 `X.Y.Z`
2. 执行版本同步：`make sync-version VERSION=X.Y.Z`
3. 先做本地校验：`make ci VERSION=X.Y.Z`
4. 做发布 dry-run：`make release-dry-run VERSION=X.Y.Z`
5. 确认工作区干净：`git status --short`
6. 提交发布变更：`git commit -m "chore: release vX.Y.Z"`
7. 打 Tag 并推送：`git tag -a vX.Y.Z -m "SFTPxy vX.Y.Z" && git push origin master refs/tags/vX.Y.Z`
8. 等待 GitHub Release 自动生成
9. 等待 DockerHub 镜像自动发布
10. 最终确认下载、镜像、文档都可用

## 最少执行命令

```bash
make sync-version VERSION=X.Y.Z
make ci VERSION=X.Y.Z
make release-dry-run VERSION=X.Y.Z
scripts/verify-prod.sh X.Y.Z
git status --short
git push origin master refs/tags/vX.Y.Z
```

## 发布结果验收

- GitHub Release 有完整资产
- DockerHub 有 `vX.Y.Z` 和 `latest`
- 文档站点可访问
- `scripts/verify-prod.sh X.Y.Z` 通过
