package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

// Load loads configuration from file, environment variables, and defaults
func Load(configPath string) (*Config, string, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigName("config")
	v.SetConfigType("yaml")

	resolvedPath := configPath
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		if defaultConfig := findDefaultConfigFile(); defaultConfig != "" {
			v.SetConfigFile(defaultConfig)
			resolvedPath = defaultConfig
		}
	}

	v.SetEnvPrefix("SFTPXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, "", fmt.Errorf("error reading config file: %w", err)
		}
	} else {
		resolvedPath = v.ConfigFileUsed()
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, "", fmt.Errorf("error unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}

	return &cfg, resolvedPath, nil
}

func Save(configPath string, cfg *Config) error {
	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("error marshaling config to JSON: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(jsonData, &raw); err != nil {
		return fmt.Errorf("error unmarshaling config JSON: %w", err)
	}

	data, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("error marshaling config to YAML: %w", err)
	}

	dir := filepath.Dir(configPath)
	tmpFile, err := os.CreateTemp(dir, "config-*.yaml")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("error writing temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("error closing temp file: %w", err)
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("error renaming temp file: %w", err)
	}

	return nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Common defaults
	v.SetDefault("common.service_name", "sftpxy")
	v.SetDefault("common.log_level", "info")
	v.SetDefault("common.log_path", "./logs/sftpxy.log")
	v.SetDefault("common.temp_dir", "./data/tmp")
	v.SetDefault("common.plugin_path", "./plugins")

	// SSH defaults
	v.SetDefault("ssh.enabled", true)
	v.SetDefault("ssh.listen_address", "0.0.0.0")
	v.SetDefault("ssh.listen_port", 30082)
	v.SetDefault("ssh.password_auth", true)
	v.SetDefault("ssh.public_key_auth", true)
	v.SetDefault("ssh.max_connections", 100)
	v.SetDefault("ssh.login_timeout", 60)
	v.SetDefault("ssh.idle_timeout", 300)
	v.SetDefault("ssh.scp_enabled", true)

	// FTP defaults
	v.SetDefault("ftp.enabled", false)
	v.SetDefault("ftp.listen_address", "0.0.0.0")
	v.SetDefault("ftp.listen_port", 30086)
	v.SetDefault("ftp.explicit_tls", false)
	v.SetDefault("ftp.passive_port_start", 30100)
	v.SetDefault("ftp.passive_port_end", 30199)
	v.SetDefault("ftp.max_connections", 50)

	// WebDAV defaults
	v.SetDefault("webdav.enabled", false)
	v.SetDefault("webdav.listen_address", "0.0.0.0")
	v.SetDefault("webdav.listen_port", 30084)

	// HTTPD defaults
	v.SetDefault("httpd.enabled", true)
	v.SetDefault("httpd.listen_address", "0.0.0.0")
	v.SetDefault("httpd.listen_port", 30088)
	v.SetDefault("httpd.client_listen_port", 30080)
	v.SetDefault("httpd.webadmin_enabled", true)
	v.SetDefault("httpd.webclient_enabled", true)
	v.SetDefault("httpd.rest_api_enabled", true)
	v.SetDefault("httpd.openapi_enabled", true)
	v.SetDefault("httpd.static_path", "./web/dist")
	v.SetDefault("httpd.template_path", "./web/dist")
	v.SetDefault("httpd.token_expiry", 3600)
	v.SetDefault("httpd.jwt.enabled", true)
	v.SetDefault("httpd.jwt.issuer", "sftpxy")
	v.SetDefault("httpd.jwt.audience", "sftpxy-api")
	v.SetDefault("httpd.jwt.expiry_seconds", 3600)
	v.SetDefault("httpd.oidc.provider_name", "default")
	v.SetDefault("httpd.oidc.scopes", []string{"openid", "profile", "email"})
	v.SetDefault("httpd.oidc.username_field", "preferred_username")
	v.SetDefault("httpd.oidc.email_field", "email")
	v.SetDefault("httpd.ldap.user_filter", "(&(objectClass=person)(uid=%s))")
	v.SetDefault("httpd.ldap.username_attribute", "uid")

	// Data Provider defaults
	v.SetDefault("data_provider.driver", "sqlite")
	v.SetDefault("data_provider.connection_string", "./data/sftpxy.db")
	v.SetDefault("data_provider.max_open_conns", 25)
	v.SetDefault("data_provider.max_idle_conns", 5)
	v.SetDefault("data_provider.conn_max_lifetime", 300)
	v.SetDefault("data_provider.auto_migrate", true)

	// Telemetry defaults
	v.SetDefault("telemetry.enabled", true)
	v.SetDefault("telemetry.listen_address", "0.0.0.0")
	v.SetDefault("telemetry.listen_port", 0)

	// HTTP Clients defaults
	v.SetDefault("http_clients.default_timeout", 30)
	v.SetDefault("http_clients.tls_verify", true)
	v.SetDefault("http_clients.max_connections", 100)

	// Commands defaults
	v.SetDefault("commands.timeout", 30)

	// KMS defaults
	v.SetDefault("kms.type", "local")

	// MFA defaults
	v.SetDefault("mfa.enabled", false)
	v.SetDefault("mfa.issuer", "SFTPxy")

	// SMTP defaults
	v.SetDefault("smtp.port", 587)
	v.SetDefault("smtp.use_tls", true)
}

func findDefaultConfigFile() string {
	candidates := []string{
		"config.local.yaml",
		"config.yaml",
		"config.yaml.example",
		"/etc/sftpxy/config.yaml",
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return ""
}
