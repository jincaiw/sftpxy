package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/database"
)

func TestRunMigrationsIsIdempotent(t *testing.T) {
	t.Parallel()

	cfg := sqliteTestConfig(t)
	db := openTestDB(t, cfg)

	if err := runMigrations(db, cfg); err != nil {
		t.Fatalf("first migration run failed: %v", err)
	}
	if err := runMigrations(db, cfg); err != nil {
		t.Fatalf("second migration run failed: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", "001_initial_schema.sql").Scan(&count); err != nil {
		t.Fatalf("query migration record failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one migration record, got %d", count)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", "002_add_user_email.sql").Scan(&count); err != nil {
		t.Fatalf("query second migration record failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one second migration record, got %d", count)
	}
}

func TestRunMigrationsBackfillsExistingSchemaWithoutVersionRow(t *testing.T) {
	t.Parallel()

	cfg := sqliteTestConfig(t)
	db := openTestDB(t, cfg)

	if err := runMigrations(db, cfg); err != nil {
		t.Fatalf("initial migration run failed: %v", err)
	}
	if _, err := db.Exec("DELETE FROM schema_migrations"); err != nil {
		t.Fatalf("delete migration record failed: %v", err)
	}

	if err := runMigrations(db, cfg); err != nil {
		t.Fatalf("migration rerun against existing schema failed: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", "001_initial_schema.sql").Scan(&count); err != nil {
		t.Fatalf("query migration record failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected migration record to be recreated once, got %d", count)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version = ?", "002_add_user_email.sql").Scan(&count); err != nil {
		t.Fatalf("query second migration record failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected second migration record to be recreated once, got %d", count)
	}
}

func openTestDB(t *testing.T, cfg config.DataProviderConfig) *database.DB {
	t.Helper()

	db, err := database.NewDB(cfg)
	if err != nil {
		t.Fatalf("open test db failed: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func sqliteTestConfig(t *testing.T) config.DataProviderConfig {
	t.Helper()

	return config.DataProviderConfig{
		Driver:           "sqlite",
		ConnectionString: filepath.Join(t.TempDir(), "sftpxy-test.db"),
	}
}

func TestGenerateHostKeyFileCreatesParseableKey(t *testing.T) {
	t.Parallel()

	outputPath := filepath.Join(t.TempDir(), "keys", "ssh_host_ed25519_key")
	if err := generateHostKeyFile(outputPath, false); err != nil {
		t.Fatalf("generateHostKeyFile failed: %v", err)
	}

	keyBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read generated host key failed: %v", err)
	}
	if !strings.Contains(string(keyBytes), "PRIVATE KEY") {
		t.Fatalf("generated key does not look like a PEM private key: %q", string(keyBytes))
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("generated key stat failed: %v", err)
	}
}

func TestBootstrapAdminCreatesAdministrator(t *testing.T) {
	t.Parallel()

	cfg := productionReadyConfig(t)
	if err := prepareRuntimePaths(cfg); err != nil {
		t.Fatalf("prepareRuntimePaths failed: %v", err)
	}

	if err := bootstrapAdmin(cfg, "prod-admin", "super-secret-password"); err != nil {
		t.Fatalf("bootstrapAdmin failed: %v", err)
	}

	db := openTestDB(t, cfg.DataProvider)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM admins WHERE username = ?", "prod-admin").Scan(&status); err != nil {
		t.Fatalf("query bootstrapped admin failed: %v", err)
	}
	if status != "active" {
		t.Fatalf("bootstrapped admin status = %q, want %q", status, "active")
	}

	if err := bootstrapAdmin(cfg, "prod-admin", "another-password"); err == nil {
		t.Fatal("expected duplicate bootstrap admin attempt to fail")
	}
}

func TestValidateConfigFileStrictProduction(t *testing.T) {
	t.Parallel()

	cfg := productionReadyConfig(t)
	configPath := writeConfigFile(t, cfg)
	if err := validateConfigFile(configPath, true); err != nil {
		t.Fatalf("validateConfigFile strict production failed: %v", err)
	}
}

func productionReadyConfig(t *testing.T) *config.Config {
	t.Helper()

	rootDir := t.TempDir()
	staticDir := filepath.Join(rootDir, "web", "dist")
	templateDir := filepath.Join(rootDir, "web", "templates")
	pluginDir := filepath.Join(rootDir, "plugins")
	tempDir := filepath.Join(rootDir, "tmp")
	keysDir := filepath.Join(rootDir, "keys")
	logDir := filepath.Join(rootDir, "logs")
	dataDir := filepath.Join(rootDir, "data")
	for _, dir := range []string{staticDir, templateDir, pluginDir, tempDir, keysDir, logDir, dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s failed: %v", dir, err)
		}
	}

	hostKeyPath := filepath.Join(keysDir, "ssh_host_ed25519_key")
	if err := generateHostKeyFile(hostKeyPath, false); err != nil {
		t.Fatalf("generateHostKeyFile failed: %v", err)
	}
	certFile, keyFile := writeTLSKeyPair(t, filepath.Join(keysDir, "tls"))

	return &config.Config{
		Common: config.CommonConfig{
			ServiceName:   "sftpxy",
			LogLevel:      "info",
			LogPath:       filepath.Join(logDir, "sftpxy.log"),
			TempDir:       tempDir,
			PluginPath:    pluginDir,
			GlobalTimeout: 300,
		},
		SSH: config.SSHConfig{
			Enabled:        true,
			ListenAddress:  "127.0.0.1",
			ListenPort:     30082,
			HostKeys:       []string{hostKeyPath},
			PasswordAuth:   true,
			PublicKeyAuth:  true,
			MaxConnections: 100,
			LoginTimeout:   60,
			IdleTimeout:    300,
			SCPEnabled:     true,
		},
		FTP: config.FTPConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1",
			ListenPort:       30086,
			ExplicitTLS:      true,
			TLSCertFile:      certFile,
			TLSKeyFile:       keyFile,
			ForceControlTLS:  true,
			ForceDataTLS:     true,
			PassivePortStart: 30100,
			PassivePortEnd:   30110,
			MaxConnections:   50,
			LoginTimeout:     60,
			IdleTimeout:      300,
		},
		WebDAV: config.WebDAVConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    30084,
			BasePath:      "/",
			TLSCertFile:   certFile,
			TLSKeyFile:    keyFile,
		},
		HTTPD: config.HTTPDConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1",
			ListenPort:       30088,
			TLSCertFile:      certFile,
			TLSKeyFile:       keyFile,
			WebAdminEnabled:  true,
			WebClientEnabled: true,
			RESTAPIEnabled:   true,
			OpenAPIEnabled:   true,
			StaticPath:       staticDir,
			TemplatePath:     templateDir,
			SessionSecret:    "this-is-a-production-grade-session-secret",
			TokenExpiry:      3600,
			CORSOrigins:      []string{"https://files.example.com"},
		},
		DataProvider: config.DataProviderConfig{
			Driver:           "sqlite",
			ConnectionString: filepath.Join(dataDir, "sftpxy.db"),
			MaxOpenConns:     25,
			MaxIdleConns:     5,
			ConnMaxLifetime:  300,
			AutoMigrate:      true,
		},
		Telemetry: config.TelemetryConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    0,
		},
		HTTPClients: config.HTTPClientsConfig{
			DefaultTimeout: 30,
			TLSVerify:      true,
			MaxConnections: 100,
		},
		Commands: config.CommandsConfig{
			Whitelist: []string{"/usr/local/bin/sftpxy-hook"},
			Timeout:   30,
		},
		KMS: config.KMSConfig{
			Type:    "local",
			KeyPath: filepath.Join(keysDir, "kms.key"),
		},
		MFA: config.MFAConfig{
			Enabled: false,
			Issuer:  "SFTPxy",
		},
		Plugins: config.PluginsConfig{
			Directory: pluginDir,
		},
	}
}

func writeConfigFile(t *testing.T, cfg *config.Config) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := strings.Join([]string{
		"common:",
		"  service_name: \"sftpxy\"",
		"  log_level: \"info\"",
		"  log_path: \"" + cfg.Common.LogPath + "\"",
		"  temp_dir: \"" + cfg.Common.TempDir + "\"",
		"  plugin_path: \"" + cfg.Common.PluginPath + "\"",
		"ssh:",
		"  enabled: true",
		"  listen_address: \"127.0.0.1\"",
		"  listen_port: 30082",
		"  host_keys:",
		"    - \"" + cfg.SSH.HostKeys[0] + "\"",
		"  password_auth: true",
		"  public_key_auth: true",
		"ftp:",
		"  enabled: true",
		"  listen_address: \"127.0.0.1\"",
		"  listen_port: 30086",
		"  explicit_tls: true",
		"  tls_cert_file: \"" + cfg.FTP.TLSCertFile + "\"",
		"  tls_key_file: \"" + cfg.FTP.TLSKeyFile + "\"",
		"  force_control_tls: true",
		"  force_data_tls: true",
		"  passive_port_start: 30100",
		"  passive_port_end: 30110",
		"webdav:",
		"  enabled: true",
		"  listen_address: \"127.0.0.1\"",
		"  listen_port: 30084",
		"  base_path: \"/\"",
		"  tls_cert_file: \"" + cfg.WebDAV.TLSCertFile + "\"",
		"  tls_key_file: \"" + cfg.WebDAV.TLSKeyFile + "\"",
		"httpd:",
		"  enabled: true",
		"  listen_address: \"127.0.0.1\"",
		"  listen_port: 30088",
		"  tls_cert_file: \"" + cfg.HTTPD.TLSCertFile + "\"",
		"  tls_key_file: \"" + cfg.HTTPD.TLSKeyFile + "\"",
		"  webadmin_enabled: true",
		"  webclient_enabled: true",
		"  rest_api_enabled: true",
		"  openapi_enabled: true",
		"  static_path: \"" + cfg.HTTPD.StaticPath + "\"",
		"  template_path: \"" + cfg.HTTPD.TemplatePath + "\"",
		"  session_secret: \"" + cfg.HTTPD.SessionSecret + "\"",
		"  token_expiry: 3600",
		"  cors_origins:",
		"    - \"https://files.example.com\"",
		"data_provider:",
		"  driver: \"sqlite\"",
		"  connection_string: \"" + cfg.DataProvider.ConnectionString + "\"",
		"  auto_migrate: true",
		"kms:",
		"  type: \"local\"",
		"  key_path: \"" + cfg.KMS.KeyPath + "\"",
	}, "\n")
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config file failed: %v", err)
	}
	return configPath
}

func writeTLSKeyPair(t *testing.T, prefix string) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create certificate failed: %v", err)
	}

	certPath := prefix + ".crt"
	keyPath := prefix + ".key"
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o644); err != nil {
		t.Fatalf("write certificate failed: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key failed: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("write private key failed: %v", err)
	}
	return certPath, keyPath
}

func TestReadPasswordFromReaderTrimsWhitespace(t *testing.T) {
	t.Parallel()

	password, err := readPasswordFromReader(strings.NewReader("super-secret\n"))
	if err != nil {
		t.Fatalf("readPasswordFromReader failed: %v", err)
	}
	if password != "super-secret" {
		t.Fatalf("password = %q, want %q", password, "super-secret")
	}
}

func TestBootstrapAdminRequiresMigrations(t *testing.T) {
	t.Parallel()

	cfg := productionReadyConfig(t)
	cfg.DataProvider.AutoMigrate = false
	if err := prepareRuntimePaths(cfg); err != nil {
		t.Fatalf("prepareRuntimePaths failed: %v", err)
	}

	err := bootstrapAdmin(cfg, "prod-admin", "super-secret-password")
	if err == nil {
		t.Fatal("expected bootstrapAdmin without migrations to fail")
	}
	if !strings.Contains(err.Error(), "no such table") && !strings.Contains(err.Error(), "no such table: admins") {
		t.Fatalf("bootstrapAdmin error = %v, want missing table error", err)
	}
}

func TestValidateConfigFileStrictProductionRejectsPlaceholderSecret(t *testing.T) {
	t.Parallel()

	cfg := productionReadyConfig(t)
	cfg.HTTPD.SessionSecret = "change-this-to-a-random-secret"
	configPath := writeConfigFile(t, cfg)

	err := validateConfigFile(configPath, true)
	if err == nil {
		t.Fatal("expected validateConfigFile strict production to fail")
	}
	if !strings.Contains(err.Error(), "session_secret") {
		t.Fatalf("validateConfigFile error = %v, want session_secret validation failure", err)
	}
}

func TestOpenTestDBUsesSQLite(t *testing.T) {
	t.Parallel()

	db := openTestDB(t, sqliteTestConfig(t))
	if db.Driver() != "sqlite" {
		t.Fatalf("db.Driver() = %q, want %q", db.Driver(), "sqlite")
	}
}

func TestBootstrapAdminCreatesSingleRow(t *testing.T) {
	t.Parallel()

	cfg := productionReadyConfig(t)
	if err := prepareRuntimePaths(cfg); err != nil {
		t.Fatalf("prepareRuntimePaths failed: %v", err)
	}
	if err := bootstrapAdmin(cfg, "prod-admin", "super-secret-password"); err != nil {
		t.Fatalf("bootstrapAdmin failed: %v", err)
	}

	db := openTestDB(t, cfg.DataProvider)
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM admins WHERE username = ?", "prod-admin").Scan(&count); err != nil {
		t.Fatalf("count admin rows failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin row count = %d, want %d", count, 1)
	}
}
