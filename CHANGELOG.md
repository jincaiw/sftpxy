# Changelog

All notable SFTPxy release changes are tracked here.

## v0.2.7 - 2026-09-01

- Fix flaky transfers checker tests: the periodic background transfer check scheduled by the test setup could still be in flight while a test invoked its own synchronous check, which was then skipped by the "previous check still running" guard. Stopping the event scheduler in the affected tests and waiting for running jobs on scheduler shutdown makes the checks deterministic.
- Fix a data race in the HTTPD server: the package-level configuration values (e.g. the token validation mode) were written after the HTTP servers were already started, so concurrently served requests could read them without synchronization. The values are now set before the servers start.

## v0.2.6 - 2026-09-01

- Return a 400 validation error when an event rule references a non-existent action for Bolt and memory data providers, aligning their behavior with the SQL providers.
- Update golang.org/x/crypto to v0.55.0 to fix the GO-2026-6303 ssh vulnerability reported by govulncheck.
- Fix a flaky TestInitialization in the HTTPD tests: the second WebClient binding from the default config leaked a listener on port 30081 and made subsequent assertions race against bind errors.
- Increase the schema creation and migration timeout to 5 minutes so a cold CockroachDB instance can finish the initial DDL instead of failing at the previous 60 seconds deadline.
- Fix the Windows CI job failing at the "Initialize data provider" step when no previous SFTPxy.db file exists to remove.
- Fix flaky CI test failures ("bind: address already in use") by moving the test server listening ports out of the Linux ephemeral port range (32768-60999): outbound connections from earlier test packages could land on those ports and their TIME_WAIT sockets blocked the next listener bind.

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
