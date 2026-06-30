# Release Checklist

Use this checklist for every public SFTPxy release.

## Version

- [ ] `VERSION` contains the release version without the leading `v`.
- [ ] `internal/version/version.go` matches `VERSION`.
- [ ] `CHANGELOG.md` has an entry for the release tag.
- [ ] The tag uses `vX.Y.Z`.
- [ ] The release commit is on `master`.

## Documentation

- [ ] `README.md` is the default English README.
- [ ] `README.md` links to `README.zh-CN.md` at the top.
- [ ] `README.zh-CN.md` links back to `README.md`.
- [ ] GitHub Pages docs include bilingual downloads, Linux, Windows, macOS, Docker, configuration, and user manual pages.
- [ ] GitHub Pages static HTML pages exist for all docs sections.
- [ ] Linux DEB/RPM, Windows EXE, and macOS DMG install steps are documented.
- [ ] GitHub Pages uses the custom domain `sftp.mujizi.com`.
- [ ] Linux single-binary deployment is documented.
- [ ] systemd deployment is documented.
- [ ] Docker deployment is documented.
- [ ] At least three demo screenshots are present under `docs/screenshots/`.

## Local Gates

- [ ] `make verify-prod VERSION=X.Y.Z` passes.
- [ ] `make release-bundle VERSION=X.Y.Z` generates local dry-run artifacts.
- [ ] `make docker-build VERSION=X.Y.Z` passes when Docker is available.
- [ ] `make release-dry-run VERSION=X.Y.Z` passes before tagging.

## GitHub Release

- [ ] `git status --short` is clean before tagging.
- [ ] `make release-tag VERSION=X.Y.Z` creates `vX.Y.Z`.
- [ ] `git push origin master refs/tags/vX.Y.Z` succeeds.
- [ ] GitHub Actions release workflow completes.
- [ ] Release assets include Linux, Windows, macOS DMG, source, and checksums.
- [ ] GitHub Release is published, not left as an unintended draft.

## Docker

- [ ] Docker workflow completes for `vX.Y.Z`.
- [ ] Docker Hub has `qing1205/sftpxy:vX.Y.Z`.
- [ ] Docker Hub has `qing1205/sftpxy:latest`.
- [ ] Published images include `linux/amd64` and `linux/arm64`.

## Hygiene

- [ ] Runtime databases, logs, keys, build artifacts, and local env files are ignored.
- [ ] No private credentials are present in tracked files.
- [ ] Remote branches and tags only expose intentional release history.
