package config

import (
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
)

func TestValidateForProductionAcceptsSecureSingleNodeConfig(t *testing.T) {
	t.Parallel()

	cfg := productionValidationConfig(t)
	if err := cfg.ValidateForProduction(); err != nil {
		t.Fatalf("ValidateForProduction failed: %v", err)
	}
}

func TestValidateForProductionRejectsWildcardCORS(t *testing.T) {
	t.Parallel()

	cfg := productionValidationConfig(t)
	cfg.HTTPD.CORSOrigins = []string{"*"}

	err := cfg.ValidateForProduction()
	if err == nil {
		t.Fatal("expected wildcard cors validation to fail")
	}
	if !strings.Contains(err.Error(), "cors_origins") {
		t.Fatalf("ValidateForProduction error = %v, want cors_origins failure", err)
	}
}

func TestValidateForProductionRejectsMissingHostKey(t *testing.T) {
	t.Parallel()

	cfg := productionValidationConfig(t)
	cfg.SSH.HostKeys = nil

	err := cfg.ValidateForProduction()
	if err == nil {
		t.Fatal("expected missing host key validation to fail")
	}
	if !strings.Contains(err.Error(), "ssh.host_keys") {
		t.Fatalf("ValidateForProduction error = %v, want ssh.host_keys failure", err)
	}
}

func TestValidateForProductionRejectsPlainFTP(t *testing.T) {
	t.Parallel()

	cfg := productionValidationConfig(t)
	cfg.FTP.ExplicitTLS = false

	err := cfg.ValidateForProduction()
	if err == nil {
		t.Fatal("expected plain FTP validation to fail")
	}
	if !strings.Contains(err.Error(), "ftp.explicit_tls") {
		t.Fatalf("ValidateForProduction error = %v, want ftp.explicit_tls failure", err)
	}
}

func productionValidationConfig(t *testing.T) *Config {
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
	writeEd25519PrivateKey(t, hostKeyPath)
	certPath, keyPath := writeTLSPair(t, filepath.Join(keysDir, "tls"))

	return &Config{
		Common: CommonConfig{
			ServiceName: "sftpxy",
			LogLevel:    "info",
			LogPath:     filepath.Join(logDir, "sftpxy.log"),
			TempDir:     tempDir,
			PluginPath:  pluginDir,
		},
		SSH: SSHConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    30082,
			HostKeys:      []string{hostKeyPath},
			PasswordAuth:  true,
			PublicKeyAuth: true,
			SCPEnabled:    true,
		},
		FTP: FTPConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1",
			ListenPort:       30086,
			ExplicitTLS:      true,
			TLSCertFile:      certPath,
			TLSKeyFile:       keyPath,
			ForceControlTLS:  true,
			ForceDataTLS:     true,
			PassivePortStart: 30100,
			PassivePortEnd:   30110,
		},
		WebDAV: WebDAVConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    30084,
			BasePath:      "/",
			TLSCertFile:   certPath,
			TLSKeyFile:    keyPath,
		},
		HTTPD: HTTPDConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1",
			ListenPort:       30088,
			TLSCertFile:      certPath,
			TLSKeyFile:       keyPath,
			WebAdminEnabled:  true,
			WebClientEnabled: true,
			RESTAPIEnabled:   true,
			OpenAPIEnabled:   true,
			StaticPath:       staticDir,
			TemplatePath:     templateDir,
			SessionSecret:    "this-is-a-production-grade-session-secret",
			CORSOrigins:      []string{"https://files.example.com"},
		},
		DataProvider: DataProviderConfig{
			Driver:           "sqlite",
			ConnectionString: filepath.Join(dataDir, "sftpxy.db"),
			AutoMigrate:      true,
		},
		KMS: KMSConfig{
			Type:    "local",
			KeyPath: filepath.Join(keysDir, "kms.key"),
		},
	}
}

func writeEd25519PrivateKey(t *testing.T, outputPath string) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key failed: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal host key failed: %v", err)
	}
	if err := os.WriteFile(outputPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("write host key failed: %v", err)
	}
}

func writeTLSPair(t *testing.T, prefix string) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate tls keypair failed: %v", err)
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
		t.Fatalf("create tls certificate failed: %v", err)
	}

	certPath := prefix + ".crt"
	keyPath := prefix + ".key"
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), 0o644); err != nil {
		t.Fatalf("write certificate failed: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal tls key failed: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("write tls key failed: %v", err)
	}
	return certPath, keyPath
}
