package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jincaiw/sftpxy/internal/audit"
	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/database"
	"github.com/jincaiw/sftpxy/internal/defender"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/logger"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/protocols/ftp"
	"github.com/jincaiw/sftpxy/internal/protocols/httpd"
	sshd "github.com/jincaiw/sftpxy/internal/protocols/ssh"
	"github.com/jincaiw/sftpxy/internal/protocols/webdav"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/shares"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var version = "0.1.1"

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	if err := execute(args, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func execute(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "bootstrap-admin":
			return runBootstrapAdminCommand(args[1:], stdout, stderr)
		case "generate-hostkey":
			return runGenerateHostKeyCommand(args[1:], stdout, stderr)
		case "validate-config":
			return runValidateConfigCommand(args[1:], stdout, stderr)
		}
	}

	return runServerCommand(args, stdout, stderr)
}

func runServerCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sftpxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to configuration file (auto-detects config.local.yaml, config.yaml, config.yaml.example when omitted)")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, resolvedConfigPath, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := prepareRuntimePaths(cfg); err != nil {
		return fmt.Errorf("failed to prepare runtime paths: %w", err)
	}

	log, err := logger.NewLogger(cfg.Common)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Sync()

	log.Info("Starting SFTPxy", zap.String("version", version))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	db, err := database.NewDB(cfg.DataProvider)
	if err != nil {
		log.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer db.Close()

	if err := db.HealthCheck(ctx); err != nil {
		log.Warn("Database health check failed", zap.Error(err))
	} else {
		log.Info("Database connected", zap.String("driver", db.Driver()))
	}

	// Run database migrations if auto_migrate is enabled
	if cfg.DataProvider.AutoMigrate {
		log.Info("Running database migrations...")
		if err := runMigrations(db, cfg.DataProvider); err != nil {
			log.Fatal("Database migration failed", zap.Error(err))
		} else {
			log.Info("Database migrations completed")
		}
	}

	// Repositories
	userRepo := repository.NewUserRepository(db)
	adminRepo := repository.NewAdminRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	shareRepo := repository.NewShareRepository(db)
	eventRepo := repository.NewEventRepository(db)

	// Defender (anti-brute force)
	defenderCfg := defender.DefaultConfig()
	defenderService := defender.NewDefender(defenderCfg, log, auditRepo)

	// HookManager
	hookManager := hooks.NewHookManager(log)
	if cfg.Hooks.Auth.Type != "" {
		hookManager.SetAuthHook(hooks.NewAuthHook(&hooks.AuthHook{
			Type:     hooks.HookType(cfg.Hooks.Auth.Type),
			Endpoint: cfg.Hooks.Auth.Endpoint,
			Command:  cfg.Hooks.Auth.Command,
			Timeout:  cfg.Hooks.Auth.Timeout,
			CacheTTL: cfg.Hooks.Auth.CacheTTL,
		}, log))
	}
	if cfg.Hooks.DynamicUser.Type != "" {
		hookManager.SetDynamicUserHook(hooks.NewDynamicUserHook(hooks.DynamicUserHook{
			Type:     hooks.HookType(cfg.Hooks.DynamicUser.Type),
			Endpoint: cfg.Hooks.DynamicUser.Endpoint,
			Command:  cfg.Hooks.DynamicUser.Command,
			Timeout:  cfg.Hooks.DynamicUser.Timeout,
		}, log))
	}
	for _, feCfg := range cfg.Hooks.FileEvents {
		hookManager.AddFileEventHook(hooks.NewFileEventHook(hooks.FileEventHook{
			Event:    hooks.FileEvent(feCfg.Event),
			Type:     hooks.HookType(feCfg.Type),
			Endpoint: feCfg.Endpoint,
			Command:  feCfg.Command,
			Timeout:  feCfg.Timeout,
		}, log))
	}
	for _, connCfg := range cfg.Hooks.Connection {
		hookManager.AddConnectionHook(hooks.NewConnectionHook(hooks.ConnectionHook{
			Event:    hooks.ConnectionEvent(connCfg.Event),
			Type:     hooks.HookType(connCfg.Type),
			Endpoint: connCfg.Endpoint,
			Command:  connCfg.Command,
			Timeout:  connCfg.Timeout,
		}, log))
	}

	// Auth & Policy
	authService := auth.NewAuthenticationServiceWithHooks(userRepo, adminRepo, hookManager)
	authService.SetDefender(defenderService)
	policyEngine := policy.NewPolicyEngine(userRepo)

	// Password Policy
	passwordPolicy := auth.NewPasswordPolicy(cfg.Auth.PasswordPolicy)

	// Audit Recorder
	auditRecorder := audit.NewAuditRecorder(auditRepo, log)

	// Metrics Collector
	metricsCollector := metrics.NewCollector(cfg.Telemetry, log)
	telemetryRunning := false
	if err := metricsCollector.Start(ctx); err != nil {
		log.Warn("Failed to start metrics collector", zap.Error(err))
	} else {
		telemetryRunning = cfg.Telemetry.Enabled
	}

	defenderService.SetMetricsCollector(metricsCollector)
	defenderService.SetAuditRecorder(auditRecorder)

	// Share Manager
	shareManager := shares.NewManagerWithDependencies(shareRepo, userRepo, auditRepo, metricsCollector, log)

	// Event Manager
	commandTimeout := 30 * time.Second
	if cfg.Commands.Timeout > 0 {
		commandTimeout = time.Duration(cfg.Commands.Timeout) * time.Second
	}
	eventManager := events.NewManagerWithOptions(log, cfg.Commands.Whitelist, eventRepo, metricsCollector, commandTimeout)
	defer eventManager.Shutdown(ctx)

	// SSH/SFTP Server
	sshServer := sshd.NewServer(cfg.SSH, log, authService, policyEngine, userRepo, auditRepo, sessionRepo)
	sshServer.SetAuthConfig(cfg.Auth)
	sshServer.SetPasswordPolicy(passwordPolicy)
	sshServer.SetHookManager(hookManager)
	sshServer.SetAuditRecorder(auditRecorder)
	sshServer.SetDefender(defenderService)
	if err := sshServer.Start(ctx); err != nil {
		log.Fatal("Failed to start SSH server", zap.Error(err))
	}

	// FTP Server
	ftpServer := ftp.NewServer(cfg.FTP, log, authService, policyEngine, userRepo, auditRepo, sessionRepo)
	if err := ftpServer.Start(ctx); err != nil {
		log.Fatal("Failed to start FTP server", zap.Error(err))
	}

	// WebDAV Server
	webdavServer := webdav.NewServer(cfg.WebDAV, log, authService, policyEngine, userRepo, auditRepo, sessionRepo)
	if err := webdavServer.Start(ctx); err != nil {
		log.Fatal("Failed to start WebDAV server", zap.Error(err))
	}

	// HTTP Server (WebAdmin/WebClient/API)
	httpServer := httpd.NewServerWithDependencies(cfg.HTTPD, log, httpd.ServerDependencies{
		DB:               db.DB,
		UserRepo:         userRepo,
		PolicyEngine:     policyEngine,
		ShareManager:     shareManager,
		AuditRepo:        auditRepo,
		EventManager:     eventManager,
		MetricsCollector: metricsCollector,
		FullConfig:       cfg,
		ConfigPath:       resolvedConfigPath,
		ProtocolEnabled: map[string]bool{
			"ssh":    cfg.SSH.Enabled,
			"ftp":    cfg.FTP.Enabled,
			"webdav": cfg.WebDAV.Enabled,
			"http":   cfg.HTTPD.Enabled,
		},
		TelemetryEnabled: telemetryRunning,
	})
	if err := httpServer.Start(ctx); err != nil {
		log.Fatal("Failed to start HTTP server", zap.Error(err))
	}
	httpServer.SetProtocolStatuses(map[string]bool{
		"ssh":    cfg.SSH.Enabled,
		"ftp":    cfg.FTP.Enabled,
		"webdav": cfg.WebDAV.Enabled,
		"http":   cfg.HTTPD.Enabled,
	})

	log.Info("SFTPxy is running",
		zap.Bool("ssh", cfg.SSH.Enabled),
		zap.Bool("ftp", cfg.FTP.Enabled),
		zap.Bool("webdav", cfg.WebDAV.Enabled),
		zap.Bool("http", cfg.HTTPD.Enabled),
		zap.Bool("telemetry", cfg.Telemetry.Enabled),
	)

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Info("Shutting down", zap.String("signal", sig.String()))
	case <-ctx.Done():
		log.Info("Context cancelled")
	}

	// Graceful shutdown
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	sshServer.Shutdown(shutdownCtx)
	ftpServer.Shutdown(shutdownCtx)
	webdavServer.Shutdown(shutdownCtx)
	httpServer.Shutdown(shutdownCtx)
	metricsCollector.Shutdown(shutdownCtx)

	log.Info("SFTPxy stopped")
	fmt.Fprintln(stdout, "SFTPxy stopped")
	return nil
}

func runBootstrapAdminCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to configuration file")
	username := flags.String("username", "", "administrator username")
	passwordStdin := flags.Bool("password-stdin", false, "read administrator password from stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*username) == "" {
		return errors.New("bootstrap-admin requires --username")
	}
	if !*passwordStdin {
		return errors.New("bootstrap-admin requires --password-stdin")
	}

	password, err := readPasswordFromReader(os.Stdin)
	if password == "" {
		return errors.New("administrator password must not be empty")
	}

	cfg, _, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if err := prepareRuntimePaths(cfg); err != nil {
		return fmt.Errorf("failed to prepare runtime paths: %w", err)
	}

	if err := bootstrapAdmin(cfg, strings.TrimSpace(*username), password); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Administrator %q created successfully\n", strings.TrimSpace(*username))
	return nil
}

func bootstrapAdmin(cfg *config.Config, username, password string) error {
	db, err := database.NewDB(cfg.DataProvider)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	if cfg.DataProvider.AutoMigrate {
		if err := runMigrations(db, cfg.DataProvider); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var existingID int64
	err = db.QueryRowContext(ctx, "SELECT id FROM admins WHERE username = ? LIMIT 1", username).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("administrator %q already exists", username)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to check existing administrator: %w", err)
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash administrator password: %w", err)
	}

	adminRepo := repository.NewAdminRepository(db)
	admin := &repository.Admin{
		Username:     username,
		PasswordHash: passwordHash,
		Status:       "active",
		Permissions:  json.RawMessage(`[]`),
		Filters:      json.RawMessage(`{}`),
	}
	if _, err := adminRepo.Create(ctx, admin); err != nil {
		return fmt.Errorf("failed to create administrator: %w", err)
	}

	return nil
}

func runGenerateHostKeyCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("generate-hostkey", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "path to write the SSH host key")
	force := flags.Bool("force", false, "overwrite existing host key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("generate-hostkey requires --output")
	}
	if err := generateHostKeyFile(strings.TrimSpace(*output), *force); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "SSH host key written to %s\n", *output)
	return nil
}

func runValidateConfigCommand(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "path to configuration file")
	strictProduction := flags.Bool("strict-production", false, "enable production-grade validation checks")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if err := validateConfigFile(*configPath, *strictProduction); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Configuration is valid")
	return nil
}

func generateHostKeyFile(outputPath string, force bool) error {
	if outputPath == "" {
		return errors.New("host key output path must not be empty")
	}
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			return fmt.Errorf("host key file already exists: %s", outputPath)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to stat host key output path: %w", err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return fmt.Errorf("failed to create host key directory: %w", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 host key: %w", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal host key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
	if pemBytes == nil {
		return errors.New("failed to encode host key to PEM")
	}

	if err := os.WriteFile(outputPath, pemBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write host key: %w", err)
	}
	if _, err := gossh.ParsePrivateKey(pemBytes); err != nil {
		return fmt.Errorf("generated host key could not be parsed: %w", err)
	}
	return nil
}

func readPasswordFromReader(reader io.Reader) (string, error) {
	passwordBytes, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read password from stdin: %w", err)
	}
	return strings.TrimSpace(string(passwordBytes)), nil
}

func validateConfigFile(configPath string, strictProduction bool) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	if strictProduction {
		if err := cfg.ValidateForProduction(); err != nil {
			return err
		}
	}
	return nil
}

// runMigrations runs database migrations
func runMigrations(db *database.DB, cfg config.DataProviderConfig) error {
	migrationDir, err := resolveMigrationDir(cfg.Driver)
	if err != nil {
		return err
	}

	if err := ensureMigrationTable(db.DB); err != nil {
		return err
	}

	// Read and execute migration files
	files, err := os.ReadDir(migrationDir)
	if err != nil {
		return fmt.Errorf("failed to read migration directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if len(name) < 4 || name[len(name)-4:] != ".sql" {
			continue
		}

		filePath := filepath.Join(migrationDir, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to read migration file %s: %w", filePath, err)
		}

		applied, err := migrationApplied(db.DB, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		// Remove goose directives and comments
		sqlContent := removeGooseDirectives(string(content))

		if sqlContent == "" {
			if err := recordMigration(db.DB, name); err != nil {
				return err
			}
			continue
		}

		for _, statement := range splitSQLStatements(sqlContent) {
			if _, err := db.Exec(statement); err != nil && !isIgnorableMigrationError(cfg.Driver, statement, err) {
				return fmt.Errorf("failed to execute migration %s: %w", file.Name(), err)
			}
		}

		if err := recordMigration(db.DB, name); err != nil {
			return err
		}
	}

	return nil
}

// removeGooseDirectives removes goose directives and non-SQL comments from migration content
func removeGooseDirectives(content string) string {
	lines := strings.Split(content, "\n")
	hasGooseDirective := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "-- +goose") {
			hasGooseDirective = true
			break
		}
	}

	if !hasGooseDirective {
		var result []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "--") {
				continue
			}
			result = append(result, trimmed)
		}
		return strings.Join(result, "\n")
	}

	var result []string
	inUpSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "-- +goose") {
			if strings.Contains(trimmed, "Up") {
				inUpSection = true
			} else if strings.Contains(trimmed, "Down") {
				inUpSection = false
			}
			continue
		}

		if inUpSection && strings.HasPrefix(trimmed, "--") {
			continue
		}

		if inUpSection {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

func prepareRuntimePaths(cfg *config.Config) error {
	paths := []string{
		cfg.Common.TempDir,
		cfg.Common.PluginPath,
		filepath.Dir(cfg.Common.LogPath),
	}

	if sqlitePath := sqlitePathFromDSN(cfg.DataProvider.ConnectionString); cfg.DataProvider.Driver == "sqlite" && sqlitePath != "" {
		paths = append(paths, filepath.Dir(sqlitePath))
	}

	for _, path := range paths {
		if path == "" || path == "." {
			continue
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", path, err)
		}
	}

	return nil
}

func resolveMigrationDir(driver string) (string, error) {
	var subdir string
	switch driver {
	case "sqlite":
		subdir = filepath.Join("migrations", "sqlite")
	case "mysql":
		subdir = filepath.Join("migrations", "mysql")
	default:
		return "", fmt.Errorf("unsupported driver: %s", driver)
	}

	executablePath, _ := os.Executable()
	candidates := []string{
		subdir,
		filepath.Join("..", subdir),
		filepath.Join("..", "..", subdir),
		filepath.Join(filepath.Dir(executablePath), "..", subdir),
		filepath.Join(filepath.Dir(executablePath), subdir),
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("failed to locate migration directory for %s", driver)
}

func ensureMigrationTable(db *sql.DB) error {
	const statement = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version VARCHAR(255) PRIMARY KEY,
	applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)`
	_, err := db.Exec(statement)
	if err != nil {
		return fmt.Errorf("failed to ensure schema_migrations table: %w", err)
	}
	return nil
}

func migrationApplied(db *sql.DB, version string) (bool, error) {
	var existing string
	err := db.QueryRow("SELECT version FROM schema_migrations WHERE version = ?", version).Scan(&existing)
	if err == nil {
		return true, nil
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	return false, fmt.Errorf("failed to query schema_migrations: %w", err)
}

func recordMigration(db *sql.DB, version string) error {
	if _, err := db.Exec("INSERT INTO schema_migrations(version) VALUES (?)", version); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", version, err)
	}
	return nil
}

func splitSQLStatements(content string) []string {
	parts := strings.Split(content, ";")
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		statement := strings.TrimSpace(part)
		if statement == "" {
			continue
		}
		statements = append(statements, statement)
	}
	return statements
}

func isIgnorableMigrationError(driver, statement string, err error) bool {
	message := strings.ToLower(err.Error())
	statement = strings.ToLower(strings.TrimSpace(statement))

	isCreateObject := strings.HasPrefix(statement, "create table") ||
		strings.HasPrefix(statement, "create index") ||
		strings.HasPrefix(statement, "create unique index")
	switch driver {
	case "sqlite":
		if isCreateObject && strings.Contains(message, "already exists") {
			return true
		}
		return strings.HasPrefix(statement, "alter table") &&
			strings.Contains(statement, " add column") &&
			strings.Contains(message, "duplicate column name")
	case "mysql":
		if isCreateObject && (strings.Contains(message, "already exists") ||
			strings.Contains(message, "duplicate key name")) {
			return true
		}
		return strings.HasPrefix(statement, "alter table") &&
			strings.Contains(statement, " add column") &&
			(strings.Contains(message, "duplicate column") ||
				strings.Contains(message, "duplicate column name"))
	default:
		return false
	}
}

func sqlitePathFromDSN(dsn string) string {
	base := dsn
	if idx := strings.Index(base, "?"); idx >= 0 {
		base = base[:idx]
	}
	base = strings.TrimPrefix(base, "file:")
	base = strings.TrimSpace(base)
	if base == "" || base == ":memory:" || strings.Contains(base, "mode=memory") {
		return ""
	}
	return filepath.Clean(base)
}
