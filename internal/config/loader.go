package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Load loads configuration from file, environment variables, and defaults
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure Viper
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// Add config paths
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("/etc/sftpxy")
	}

	// Environment variable support
	v.SetEnvPrefix("SFTPXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, using defaults and env vars
	}

	// Unmarshal into Config struct
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Common defaults
	v.SetDefault("common.service_name", "sftpxy")
	v.SetDefault("common.log_level", "info")
	v.SetDefault("common.temp_dir", "/tmp/sftpxy")

	// SSH defaults
	v.SetDefault("ssh.enabled", true)
	v.SetDefault("ssh.listen_address", "0.0.0.0")
	v.SetDefault("ssh.listen_port", 2022)
	v.SetDefault("ssh.password_auth", true)
	v.SetDefault("ssh.public_key_auth", true)
	v.SetDefault("ssh.max_connections", 100)
	v.SetDefault("ssh.login_timeout", 60)
	v.SetDefault("ssh.idle_timeout", 300)
	v.SetDefault("ssh.scp_enabled", true)

	// FTP defaults
	v.SetDefault("ftp.enabled", false)
	v.SetDefault("ftp.listen_address", "0.0.0.0")
	v.SetDefault("ftp.listen_port", 2121)
	v.SetDefault("ftp.explicit_tls", false)
	v.SetDefault("ftp.passive_port_start", 21000)
	v.SetDefault("ftp.passive_port_end", 21999)
	v.SetDefault("ftp.max_connections", 50)

	// WebDAV defaults
	v.SetDefault("webdav.enabled", false)
	v.SetDefault("webdav.listen_address", "0.0.0.0")
	v.SetDefault("webdav.listen_port", 8081)

	// HTTPD defaults
	v.SetDefault("httpd.enabled", true)
	v.SetDefault("httpd.listen_address", "0.0.0.0")
	v.SetDefault("httpd.listen_port", 8080)
	v.SetDefault("httpd.webadmin_enabled", true)
	v.SetDefault("httpd.webclient_enabled", true)
	v.SetDefault("httpd.rest_api_enabled", true)
	v.SetDefault("httpd.openapi_enabled", true)
	v.SetDefault("httpd.token_expiry", 3600)

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
	v.SetDefault("telemetry.listen_port", 9090)

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
