# SFTPxy 标准发布 SOP

## 1. 版本同步

```bash
make sync-version VERSION=X.Y.Z
```

检查：
- `VERSION`
- `internal/version/version.go`
- `openapi/openapi.yaml`
- `README.md`
- `README.zh-CN.md`
- `CHANGELOG.md`

## 2. 本地校验

```bash
make ci VERSION=X.Y.Z
make release-dry-run VERSION=X.Y.Z
scripts/verify-prod.sh X.Y.Z
docker build --build-arg DOWNLOAD_PLUGINS=false --build-arg INSTALL_OPTIONAL_PACKAGES=false -t sftpxy:test .
```

## 3. 提交并打 Tag

先提交，把提交推到远端，再跑发布门禁，最后才打 Tag：

```bash
git add -A
git commit -m "chore: release vX.Y.Z"
git push origin master

# 门禁：工作区干净、HEAD 是 origin 的最新提交、Tag 尚未存在、发布元数据一致
scripts/pre-tag-check.sh X.Y.Z

git tag -a vX.Y.Z -m "SFTPxy vX.Y.Z"
git push origin refs/tags/vX.Y.Z
```

> 为什么要先 push 再打 Tag：v0.2.11 的 Tag 打在了样式修复之前的旧提交上，
> 导致发布的资产仍带缺陷。`pre-tag-check.sh` 校验 Tag 目标的提交就是
> `origin` 分支的最新提交，从而拦住「在旧提交上打 Tag」这类错误。

## 4. GitHub Release

- 自动触发 `release.yml`
- 上传 Linux / Windows / macOS / source 资产
- 自动转为正式发布（非 Draft）

## 5. DockerHub 发布

- 自动触发 `docker.yml`
- 发布 `qing1205/sftpxy:vX.Y.Z`
- 更新 `latest` / `major` / `minor`

## 6. Pages 部署

- 自动触发 `pages.yml`
- 更新 `sftp.mujizi.com`

## 7. 最终验收

- GitHub Release 可下载
- Docker 镜像可拉取
- 文档站可访问
- `git status --short` 为空
