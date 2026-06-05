package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

var insecureSessionSecrets = map[string]struct{}{
	"":                               {},
	"change-this-to-a-random-secret": {},
	"e2e-test-secret":                {},
}

// ValidateForProduction validates that the configuration is safe for a single-node production deployment.
func (c *Config) ValidateForProduction() error {
	var validationErrors []string

	if c.SSH.Enabled {
		if len(c.SSH.HostKeys) == 0 {
			validationErrors = append(validationErrors, "ssh.host_keys must be configured for production")
		}
		for _, hostKey := range c.SSH.HostKeys {
			hostKey = strings.TrimSpace(hostKey)
			if hostKey == "" {
				validationErrors = append(validationErrors, "ssh.host_keys must not contain empty entries")
				continue
			}
			if err := ensureReadableFile(hostKey); err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("ssh host key %q is invalid: %v", hostKey, err))
				continue
			}
			keyBytes, err := os.ReadFile(hostKey)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("ssh host key %q read failed: %v", hostKey, err))
				continue
			}
			if _, err := gossh.ParsePrivateKey(keyBytes); err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("ssh host key %q parse failed: %v", hostKey, err))
			}
		}
	}

	if c.HTTPD.Enabled {
		if err := ensureTLSConfigured("httpd", c.HTTPD.TLSCertFile, c.HTTPD.TLSKeyFile); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
		if err := ensureSecureSessionSecret(c.HTTPD.SessionSecret); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("httpd.session_secret %v", err))
		}
		if err := ensureRestrictedCORS(c.HTTPD.CORSOrigins); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("httpd.cors_origins %v", err))
		}
		if err := ensureDirectoryExists("httpd.static_path", c.HTTPD.StaticPath); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
		if err := ensureDirectoryExists("httpd.template_path", c.HTTPD.TemplatePath); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
	}

	if c.FTP.Enabled {
		if !c.FTP.ExplicitTLS {
			validationErrors = append(validationErrors, "ftp.explicit_tls must be enabled for production")
		}
		if !c.FTP.ForceControlTLS {
			validationErrors = append(validationErrors, "ftp.force_control_tls must be enabled for production")
		}
		if !c.FTP.ForceDataTLS {
			validationErrors = append(validationErrors, "ftp.force_data_tls must be enabled for production")
		}
		if err := ensureTLSConfigured("ftp", c.FTP.TLSCertFile, c.FTP.TLSKeyFile); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
		if c.FTP.PassivePortStart <= 0 || c.FTP.PassivePortEnd <= 0 {
			validationErrors = append(validationErrors, "ftp passive port range must be configured for production")
		} else if c.FTP.PassivePortEnd < c.FTP.PassivePortStart {
			validationErrors = append(validationErrors, "ftp passive port end must be greater than or equal to ftp passive port start")
		}
	}

	if c.WebDAV.Enabled {
		if err := ensureTLSConfigured("webdav", c.WebDAV.TLSCertFile, c.WebDAV.TLSKeyFile); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
		if c.WebDAV.ClientCert {
			validationErrors = append(validationErrors, "webdav.client_cert is not supported in the current production scope")
		}
		if !strings.HasPrefix(c.WebDAV.BasePath, "/") {
			validationErrors = append(validationErrors, "webdav.base_path must start with '/'")
		}
	}

	if err := ensurePathWritable("common.log_path", c.Common.LogPath, false); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	if err := ensurePathWritable("common.temp_dir", c.Common.TempDir, true); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	if err := ensurePathWritable("common.plugin_path", c.Common.PluginPath, true); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}
	if err := ensurePathWritable("kms.key_path", c.KMS.KeyPath, false); err != nil {
		validationErrors = append(validationErrors, err.Error())
	}

	switch c.DataProvider.Driver {
	case "sqlite":
		sqlitePath := sqliteFilePath(c.DataProvider.ConnectionString)
		if sqlitePath == "" {
			validationErrors = append(validationErrors, "data_provider.connection_string must point to a persistent sqlite database file in production")
		} else if err := ensurePathWritable("data_provider.connection_string", sqlitePath, false); err != nil {
			validationErrors = append(validationErrors, err.Error())
		}
	case "mysql":
		validationErrors = append(validationErrors, "mysql is outside the approved production scope for this delivery")
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("production configuration validation failed: %s", strings.Join(validationErrors, "; "))
	}

	return nil
}

func ensureTLSConfigured(component, certFile, keyFile string) error {
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("%s tls_cert_file and tls_key_file must both be configured", component)
	}
	if err := ensureReadableFile(certFile); err != nil {
		return fmt.Errorf("%s tls_cert_file is invalid: %w", component, err)
	}
	if err := ensureReadableFile(keyFile); err != nil {
		return fmt.Errorf("%s tls_key_file is invalid: %w", component, err)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("%s tls certificate/key pair failed to load: %w", component, err)
	}
	return nil
}

func ensureSecureSessionSecret(secret string) error {
	trimmed := strings.TrimSpace(secret)
	if _, insecure := insecureSessionSecrets[trimmed]; insecure {
		return errors.New("must be changed from the default placeholder")
	}
	if len(trimmed) < 32 {
		return errors.New("must be at least 32 characters long")
	}
	return nil
}

func ensureRestrictedCORS(origins []string) error {
	if len(origins) == 0 {
		return errors.New("must contain at least one explicit origin")
	}
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			return errors.New("must not contain empty origins")
		}
		if origin == "*" {
			return errors.New("must not contain wildcard '*'")
		}
	}
	return nil
}

func ensureReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	return file.Close()
}

func ensureDirectoryExists(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s %q is invalid: %w", name, path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s %q must be a directory", name, path)
	}
	return nil
}

func ensurePathWritable(name, path string, isDir bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%s must be configured", name)
	}

	targetDir := path
	if !isDir {
		targetDir = filepath.Dir(path)
	}
	if targetDir == "" {
		targetDir = "."
	}

	info, err := os.Stat(targetDir)
	if err != nil {
		return fmt.Errorf("%s parent directory %q is invalid: %w", name, targetDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s parent %q must be a directory", name, targetDir)
	}

	probe, err := os.CreateTemp(targetDir, ".sftpxy-validate-*")
	if err != nil {
		return fmt.Errorf("%s parent directory %q is not writable: %w", name, targetDir, err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return fmt.Errorf("%s parent directory %q temp file close failed: %w", name, targetDir, err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("%s parent directory %q cleanup failed: %w", name, targetDir, err)
	}

	if isDir {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return fmt.Errorf("%s %q must be a directory", name, path)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s %q is invalid: %w", name, path, err)
		}
	}

	return nil
}

func sqliteFilePath(dsn string) string {
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
