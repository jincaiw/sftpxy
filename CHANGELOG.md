# Changelog

All notable SFTPxy release changes are tracked here.

## v0.2.5 - 2026-08-31

- Return a 400 validation error instead of a raw 500 database error when an event rule references a non-existent action (SQL providers).
- Add an integration test for the scheduled data retention cleanup covering the 72-hour mtime boundary and subdirectory recursion.
- Add the release SOP, event manager guide, 3-day retention guide, and the full-stack QA test report.

## v0.2.4 - 2026-08-27

- Update the Go toolchain used by development and release workflows to Go 1.26.6.
- Update gRPC and Go module dependencies to address reachable security advisories.
- Verify the server, SDK, plugins, WebAdmin, WebClient, SFTP, FTP/S, WebDAV, REST API, and production build paths.

## v0.2.3 - 2026-07-01

- Remove the remaining visible migration-brand residues from the release notes.
- Add release-oriented tests for version sync and plugin handshake compatibility.
- Finish the lint and vulnerability checks in CI and the local release gate.

## v0.2.2 - 2026-06-30

- Simplify the default English README and keep the Chinese README linked at the top.
- Publish a bilingual static GitHub Pages documentation site at `https://sftp.mujizi.com/`.
- Add easy install portals and platform guides for Linux, Windows, macOS, and Docker.
- Point release packages, Windows installer, and Chocolatey metadata to the new documentation site.

## v0.2.1 - 2026-06-23

- Make WebAdmin and REST/OpenAPI available from `http://localhost:30080/`.
- Make WebClient available from `http://localhost:30081/`.
- Keep the web UI default language as Chinese.
- Publish release artifacts and Docker images under the SFTPxy project name.

## v0.2.0 - 2026-06-22

- Establish the SFTPxy release baseline after the migration.
- Publish MIT-licensed release artifacts.
- Document Linux single-binary, systemd, and Docker deployment paths.
