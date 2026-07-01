VERSION ?= $(shell cat VERSION)

.PHONY: help ci lint vulncheck sync-version version-check verify-prod release-check release-bundle docker-build release-dry-run release-tag release-push clean-release

help:
	@echo "SFTPxy release targets"
	@echo "  make version-check VERSION=$(VERSION)"
	@echo "  make ci VERSION=$(VERSION)"
	@echo "  make lint"
	@echo "  make vulncheck"
	@echo "  make sync-version VERSION=$(VERSION)"
	@echo "  make verify-prod VERSION=$(VERSION)"
	@echo "  make release-bundle VERSION=$(VERSION)"
	@echo "  make docker-build VERSION=$(VERSION)"
	@echo "  make release-dry-run VERSION=$(VERSION)"
	@echo "  make release-tag VERSION=$(VERSION)"
	@echo "  make release-push VERSION=$(VERSION)"

version-check:
	@scripts/release-check.sh "$(VERSION)"

release-check: version-check

ci: lint vulncheck verify-prod
	@echo "CI checks completed for v$(VERSION)"

sync-version:
	@scripts/sync-version.sh "$(VERSION)"

lint:
	@golangci-lint run ./...

vulncheck:
	@govulncheck ./...

verify-prod:
	@scripts/verify-prod.sh "$(VERSION)"

release-bundle:
	@scripts/release-bundle.sh "$(VERSION)"

docker-build:
	@docker build \
		--build-arg COMMIT_SHA=$$(git describe --always --abbrev=8 --dirty) \
		--build-arg FEATURES=nopgxregisterdefaulttypes,disable_grpc_modules,unixcrypt \
		-t qing1205/sftpxy:v$(VERSION)-local .

release-dry-run: release-check verify-prod release-bundle
	@echo "Release dry run completed for v$(VERSION)"

release-tag: release-check
	@if [ -n "$$(git status --short)" ]; then \
		echo "Refusing to tag: working tree is not clean"; \
		git status --short; \
		exit 1; \
	fi
	@git tag -a "v$(VERSION)" -m "SFTPxy v$(VERSION)"
	@echo "Created tag v$(VERSION)"

release-push:
	@if ! git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		echo "Missing tag v$(VERSION). Run: make release-tag VERSION=$(VERSION)"; \
		exit 1; \
	fi
	@git push origin master "refs/tags/v$(VERSION)"

clean-release:
	@rm -rf build/release
