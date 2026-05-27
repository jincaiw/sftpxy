package config

import (
	"fmt"
	"strings"
)

// Config is the root configuration structure
type Config struct {
	Common       CommonConfig       `mapstructure:"common"`
	SSH          SSHConfig          `mapstructure:"ssh"`
	FTP          FTPConfig          `mapstructure:"ftp"`
	WebDAV       WebDAVConfig       `mapstructure:"webdav"`
	HTTPD        HTTPDConfig        `mapstructure:"httpd"`
	DataProvider DataProviderConfig `mapstructure:"data_provider"`
	Telemetry    TelemetryConfig    `mapstructure:"telemetry"`
	HTTPClients  HTTPClientsConfig  `mapstructure:"http_clients"`
	Commands     CommandsConfig     `mapstructure:"commands"`
	KMS          KMSConfig          `mapstructure:"kms"`
	MFA          MFAConfig          `mapstructure:"mfa"`
	SMTP         SMTPConfig         `mapstructure:"smtp"`
	Plugins      PluginsConfig      `mapstructure:"plugins"`
}

// CommonConfig contains common settings
type CommonConfig struct {
	ServiceName   string `mapstructure:"service_name"`
	LogLevel      string `mapstructure:"log_level"`
	LogPath       string `mapstructure:"log_path"`
	TempDir       string `mapstructure:"temp_dir"`
	PluginPath    string `mapstructure:"plugin_path"`
	GlobalTimeout int    `mapstructure:"global_timeout"`
}

// SSHConfig contains SSH/SFTP/SCP server configuration
type SSHConfig struct {
	Enabled            bool     `mapstructure:"enabled"`
	ListenAddress      string   `mapstructure:"listen_address"`
	ListenPort         int      `mapstructure:"listen_port"`
	HostKeys           []string `mapstructure:"host_keys"`
	PasswordAuth       bool     `mapstructure:"password_auth"`
	PublicKeyAuth      bool     `mapstructure:"public_key_auth"`
	CertificateAuth    bool     `mapstructure:"certificate_auth"`
	MaxConnections     int      `mapstructure:"max_connections"`
	LoginTimeout       int      `mapstructure:"login_timeout"`
	IdleTimeout        int      `mapstructure:"idle_timeout"`
	SCPEnabled         bool     `mapstructure:"scp_enabled"`
	Banner             string   `mapstructure:"banner"`
	AllowedAlgorithms  []string `mapstructure:"allowed_algorithms"`
	DisabledAlgorithms []string `mapstructure:"disabled_algorithms"`
}

// FTPConfig contains FTP/FTPS server configuration
type FTPConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	ListenAddress      string `mapstructure:"listen_address"`
	ListenPort         int    `mapstructure:"listen_port"`
	ExplicitTLS        bool   `mapstructure:"explicit_tls"`
	TLSCertFile        string `mapstructure:"tls_cert_file"`
	TLSKeyFile         string `mapstructure:"tls_key_file"`
	ForceControlTLS    bool   `mapstructure:"force_control_tls"`
	ForceDataTLS       bool   `mapstructure:"force_data_tls"`
	PassivePortStart   int    `mapstructure:"passive_port_start"`
	PassivePortEnd     int    `mapstructure:"passive_port_end"`
	NATExternalAddress string `mapstructure:"nat_external_address"`
	MaxConnections     int    `mapstructure:"max_connections"`
	LoginTimeout       int    `mapstructure:"login_timeout"`
	IdleTimeout        int    `mapstructure:"idle_timeout"`
}

// WebDAVConfig contains WebDAV server configuration
type WebDAVConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	ListenAddress string `mapstructure:"listen_address"`
	ListenPort    int    `mapstructure:"listen_port"`
	BasePath      string `mapstructure:"base_path"`
	TLSCertFile   string `mapstructure:"tls_cert_file"`
	TLSKeyFile    string `mapstructure:"tls_key_file"`
	ClientCert    bool   `mapstructure:"client_cert"`
}

// HTTPDConfig contains HTTP server configuration for WebAdmin, WebClient, REST API
type HTTPDConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	ListenAddress    string   `mapstructure:"listen_address"`
	ListenPort       int      `mapstructure:"listen_port"`
	TLSCertFile      string   `mapstructure:"tls_cert_file"`
	TLSKeyFile       string   `mapstructure:"tls_key_file"`
	ClientCert       bool     `mapstructure:"client_cert"`
	WebAdminEnabled  bool     `mapstructure:"webadmin_enabled"`
	WebClientEnabled bool     `mapstructure:"webclient_enabled"`
	RESTAPIEnabled   bool     `mapstructure:"rest_api_enabled"`
	OpenAPIEnabled   bool     `mapstructure:"openapi_enabled"`
	StaticPath       string   `mapstructure:"static_path"`
	TemplatePath     string   `mapstructure:"template_path"`
	SessionSecret    string   `mapstructure:"session_secret"`
	TokenExpiry      int      `mapstructure:"token_expiry"`
	CORSOrigins      []string `mapstructure:"cors_origins"`
}

// DataProviderConfig contains database configuration
type DataProviderConfig struct {
	Driver           string `mapstructure:"driver"` // sqlite or mysql
	ConnectionString string `mapstructure:"connection_string"`
	SSLMode          string `mapstructure:"ssl_mode"`
	MaxOpenConns     int    `mapstructure:"max_open_conns"`
	MaxIdleConns     int    `mapstructure:"max_idle_conns"`
	ConnMaxLifetime  int    `mapstructure:"conn_max_lifetime"`
	AutoMigrate      bool   `mapstructure:"auto_migrate"`
}

// TelemetryConfig contains telemetry server configuration
type TelemetryConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	ListenAddress   string `mapstructure:"listen_address"`
	ListenPort      int    `mapstructure:"listen_port"`
	TLSCertFile     string `mapstructure:"tls_cert_file"`
	TLSKeyFile      string `mapstructure:"tls_key_file"`
	EnableProfiling bool   `mapstructure:"enable_profiling"`
}

// HTTPClientsConfig contains HTTP client configuration
type HTTPClientsConfig struct {
	DefaultTimeout int  `mapstructure:"default_timeout"`
	TLSVerify      bool `mapstructure:"tls_verify"`
	MaxConnections int  `mapstructure:"max_connections"`
}

// CommandsConfig contains command execution configuration
type CommandsConfig struct {
	Whitelist []string `mapstructure:"whitelist"`
	Timeout   int      `mapstructure:"timeout"`
}

// KMSConfig contains Key Management Service configuration
type KMSConfig struct {
	Type    string `mapstructure:"type"` // local, file
	KeyPath string `mapstructure:"key_path"`
}

// MFAConfig contains Multi-Factor Authentication configuration
type MFAConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	Issuer         string `mapstructure:"issuer"`
	ForceForAdmins bool   `mapstructure:"force_for_admins"`
	ForceForUsers  bool   `mapstructure:"force_for_users"`
}

// SMTPConfig contains SMTP configuration for email notifications
type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	UseTLS   bool   `mapstructure:"use_tls"`
}

// PluginsConfig contains plugin configuration
type PluginsConfig struct {
	Path    string          `mapstructure:"path"`
	Enabled map[string]bool `mapstructure:"enabled"`
}

// MaskSensitive masks sensitive fields for logging
func (c *Config) MaskSensitive() Config {
	masked := *c
	if masked.DataProvider.ConnectionString != "" {
		masked.DataProvider.ConnectionString = "***"
	}
	if masked.SMTP.Password != "" {
		masked.SMTP.Password = "***"
	}
	if masked.HTTPD.SessionSecret != "" {
		masked.HTTPD.SessionSecret = "***"
	}
	return masked
}

// Validate validates the configuration
func (c *Config) Validate() error {
	var errors []string

	// Validate common config
	if c.Common.LogLevel == "" {
		c.Common.LogLevel = "info"
	}
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[strings.ToLower(c.Common.LogLevel)] {
		errors = append(errors, fmt.Sprintf("invalid log level: %s", c.Common.LogLevel))
	}

	// Validate data provider
	if c.DataProvider.Driver != "sqlite" && c.DataProvider.Driver != "mysql" {
		errors = append(errors, "data provider driver must be 'sqlite' or 'mysql'")
	}

	// Validate SSH config
	if c.SSH.Enabled {
		if c.SSH.ListenPort <= 0 || c.SSH.ListenPort > 65535 {
			errors = append(errors, "SSH listen port must be between 1 and 65535")
		}
	}

	// Validate FTP config
	if c.FTP.Enabled {
		if c.FTP.ListenPort <= 0 || c.FTP.ListenPort > 65535 {
			errors = append(errors, "FTP listen port must be between 1 and 65535")
		}
	}

	// Validate HTTPD config
	if c.HTTPD.Enabled {
		if c.HTTPD.ListenPort <= 0 || c.HTTPD.ListenPort > 65535 {
			errors = append(errors, "HTTPD listen port must be between 1 and 65535")
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}
