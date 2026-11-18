# Changelog

All notable SFTPxy release changes are tracked here.

## v0.2.11 - 2026-11-19

- Use the `macos-latest` runner for the macOS release job: the pinned
  `macos-14` label is no longer provisioned and the job was cancelled before
  running any step ("The configuration 'macos-14-arm64-us-default' is not
  supported"), which skipped the whole release job.

## v0.2.10 - 2026-11-19

- Fix a hang in the SFTP filesystem backend: `ssh.Dial` applies the configured
  timeout only to the TCP connection, so a peer that accepted the connection and
  never sent its SSH version banner blocked the handshake forever. The client
  now sets a deadline on the raw connection for the whole handshake and clears
  it once the session is established, so a stalled server fails with an error
  instead of hanging the filesystem and its callers.

- Fix a data race on `service.Service.Error`: the error field was written by
  the goroutines started for each configured server and read by the shutdown
  path without synchronization. It is now protected by a mutex, exposed via
  `setError`/`GetError`, and the first failure is preserved so the root cause
  is the one reported on exit. `WindowsService.Service` is now a pointer so the
  struct is never copied after first use.

- Raise the Go toolchain to 1.26.11 to pick up the standard library security
  fixes for `net/http`, `crypto/x509`, `crypto/tls`, `net/textproto` and
  `html/template`, and update `golang.org/x/net`, `golang.org/x/crypto`,
  `google.golang.org/grpc`, `go.opentelemetry.io/otel/sdk` and
  `github.com/klauspost/compress` to versions without known advisories.
  `govulncheck` now reports no vulnerabilities.

- Synchronize the release metadata: `VERSION`, `openapi/openapi.yaml` and both
  README files still advertised v0.2.8 while `internal/version/version.go`
  reported 0.2.9, which made `scripts/release-check.sh` fail.

- Add regression tests for the SSH handshake timeout and the service error
  synchronization.

## v0.2.9 - 2026-09-02

- Fix the long-standing read/write races on the shared `common.Config`: the global configuration is now protected by an RWMutex exposed via `ConfigLock`/`ConfigRLock` helpers, and every reader in the sftpd, ftpd, webdavd, httpd and dataprovider packages reads it under the lock. The full test suite now passes with the `-race` detector enabled.

- Eliminate data races uncovered by the race detector: the data provider configuration is now an atomically swapped immutable snapshot; the provider log sender and SQL table names are accessed atomically; the plugin manager is a stable singleton with atomic state flags; the protocol action handler is stored in an atomic pointer.

- Fix concurrency bugs in the connection keep-alive timer, in `util.RemoveDuplicates` (now a pure function), and in the HTTP client (each retryable client gets its own cloned TLS config instead of sharing one).

- Store the certificate managers of the httpd, ftpd and webdavd services in atomic pointers so tests re-initializing a server never race with certificate reloads and TLS handshakes.

- Fix race-detector-only test failures: read the SFTP host key fingerprints from the server status instead of the by-value test config, make the rate limiter tests use a long enough period so no token is refilled mid-test, and give the share usage test a share lifetime that outlives the slowed-down bcrypt check.

## v0.2.8 - 2026-09-01

- Fix a flaky TestInitialization in the HTTPD tests: the second default WebClient binding on port 30081 was reintroduced when the test re-fetched the configuration copy, leaked a listener, and then raced with the expected validation errors.

- Validate all HTTPD bindings before starting any server: previously, when a later binding failed validation the servers for the earlier bindings were already running and leaked their listeners.

## v0.2.7 - 2026-09-01

- Fix flaky transfers checker tests: the periodic background transfer check scheduled by the test setup could still be in flight while a test invoked its own synchronous check, which was then skipped by the "previous check still running" guard. Stopping the event scheduler in the affected tests and waiting for running jobs on scheduler shutdown makes the checks deterministic.

- Fix a data race in the HTTPD server: the package-level configuration values (e.g. the token validation mode) were written after the HTTP servers were already started, so concurrently served requests could read them without synchronization. The values are now set before the servers start.

## v0.2.6 - 2026-09-01

- Return a 400 validation error when an event rule references a non-existent action for Bolt and memory data providers, aligning their behavior with the SQL providers.

- Update golang.org/x/crypto to v0.55.0 to fix the GO-2026-6303 ssh vulnerability reported by govulncheck.

- Fix a flaky TestInitialization in the HTTPD tests: the second WebClient binding from the default config leaked a listener on port 30081 and made subsequent assertions race against bind errors.

- Increase the schema creation and migration timeout to 5 minutes so a cold CockroachDB instance can finish the initial DDL instead of failing at the previous 60 seconds deadline.

- Fix the Windows CI job failing at the "Initialize data provider" step when no previous SFTPxy.db file exists to remove.

- Fix flaky CI test failures ("bind: address already in use") by moving the test server listening ports out of the Linux ephemeral port range (32768-60999): outbound connections from earlier test packages could land on those ports and their TIME\_WAIT sockets blocked the next listener bind.

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

