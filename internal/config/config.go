package config

import (
	"fmt"
	"strings"
	"time"
)

type Config struct {
	Common       CommonConfig       `mapstructure:"common" json:"common"`
	SSH          SSHConfig          `mapstructure:"ssh" json:"ssh"`
	FTP          FTPConfig          `mapstructure:"ftp" json:"ftp"`
	WebDAV       WebDAVConfig       `mapstructure:"webdav" json:"webdav"`
	HTTPD        HTTPDConfig        `mapstructure:"httpd" json:"httpd"`
	DataProvider DataProviderConfig `mapstructure:"data_provider" json:"data_provider"`
	Telemetry    TelemetryConfig    `mapstructure:"telemetry" json:"telemetry"`
	HTTPClients  HTTPClientsConfig  `mapstructure:"http_clients" json:"http_clients"`
	Commands     CommandsConfig     `mapstructure:"commands" json:"commands"`
	KMS          KMSConfig          `mapstructure:"kms" json:"kms"`
	MFA          MFAConfig          `mapstructure:"mfa" json:"mfa"`
	SMTP         SMTPConfig         `mapstructure:"smtp" json:"smtp"`
	Plugins      PluginsConfig      `mapstructure:"plugins" json:"plugins"`
	Auth         AuthConfig         `mapstructure:"auth" json:"auth"`
	Defender     DefenderConfig     `mapstructure:"defender" json:"defender"`
	Hooks        HooksConfig        `mapstructure:"hooks" json:"hooks"`
}

type CommonConfig struct {
	ServiceName   string `mapstructure:"service_name" json:"service_name"`
	LogLevel      string `mapstructure:"log_level" json:"log_level"`
	LogPath       string `mapstructure:"log_path" json:"log_path"`
	TempDir       string `mapstructure:"temp_dir" json:"temp_dir"`
	PluginPath    string `mapstructure:"plugin_path" json:"plugin_path"`
	GlobalTimeout int    `mapstructure:"global_timeout" json:"global_timeout"`
}

type SSHConfig struct {
	Enabled            bool     `mapstructure:"enabled" json:"enabled"`
	ListenAddress      string   `mapstructure:"listen_address" json:"listen_address"`
	ListenPort         int      `mapstructure:"listen_port" json:"listen_port"`
	HostKeys           []string `mapstructure:"host_keys" json:"host_keys"`
	PasswordAuth       bool     `mapstructure:"password_auth" json:"password_auth"`
	PublicKeyAuth      bool     `mapstructure:"public_key_auth" json:"public_key_auth"`
	CertificateAuth    bool     `mapstructure:"certificate_auth" json:"certificate_auth"`
	MaxConnections     int      `mapstructure:"max_connections" json:"max_connections"`
	LoginTimeout       int      `mapstructure:"login_timeout" json:"login_timeout"`
	IdleTimeout        int      `mapstructure:"idle_timeout" json:"idle_timeout"`
	SCPEnabled         bool     `mapstructure:"scp_enabled" json:"scp_enabled"`
	Banner             string   `mapstructure:"banner" json:"banner"`
	AllowedAlgorithms  []string `mapstructure:"allowed_algorithms" json:"allowed_algorithms"`
	DisabledAlgorithms []string `mapstructure:"disabled_algorithms" json:"disabled_algorithms"`
	CAKeys             []string `mapstructure:"ca_keys" json:"ca_keys"`
	CertPrincipals     bool     `mapstructure:"cert_principals" json:"cert_principals"`
}

type FTPConfig struct {
	Enabled            bool   `mapstructure:"enabled" json:"enabled"`
	ListenAddress      string `mapstructure:"listen_address" json:"listen_address"`
	ListenPort         int    `mapstructure:"listen_port" json:"listen_port"`
	ExplicitTLS        bool   `mapstructure:"explicit_tls" json:"explicit_tls"`
	TLSCertFile        string `mapstructure:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile         string `mapstructure:"tls_key_file" json:"tls_key_file"`
	ForceControlTLS    bool   `mapstructure:"force_control_tls" json:"force_control_tls"`
	ForceDataTLS       bool   `mapstructure:"force_data_tls" json:"force_data_tls"`
	PassivePortStart   int    `mapstructure:"passive_port_start" json:"passive_port_start"`
	PassivePortEnd     int    `mapstructure:"passive_port_end" json:"passive_port_end"`
	NATExternalAddress string `mapstructure:"nat_external_address" json:"nat_external_address"`
	MaxConnections     int    `mapstructure:"max_connections" json:"max_connections"`
	LoginTimeout       int    `mapstructure:"login_timeout" json:"login_timeout"`
	IdleTimeout        int    `mapstructure:"idle_timeout" json:"idle_timeout"`
}

type WebDAVConfig struct {
	Enabled       bool   `mapstructure:"enabled" json:"enabled"`
	ListenAddress string `mapstructure:"listen_address" json:"listen_address"`
	ListenPort    int    `mapstructure:"listen_port" json:"listen_port"`
	BasePath      string `mapstructure:"base_path" json:"base_path"`
	TLSCertFile   string `mapstructure:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile    string `mapstructure:"tls_key_file" json:"tls_key_file"`
	ClientCert    bool   `mapstructure:"client_cert" json:"client_cert"`
}

type HTTPDConfig struct {
	Enabled          bool           `mapstructure:"enabled" json:"enabled"`
	ListenAddress    string         `mapstructure:"listen_address" json:"listen_address"`
	ListenPort       int            `mapstructure:"listen_port" json:"listen_port"`
	ClientListenPort int            `mapstructure:"client_listen_port" json:"client_listen_port"`
	TLSCertFile      string         `mapstructure:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile       string         `mapstructure:"tls_key_file" json:"tls_key_file"`
	ClientCert       bool           `mapstructure:"client_cert" json:"client_cert"`
	WebAdminEnabled  bool           `mapstructure:"webadmin_enabled" json:"webadmin_enabled"`
	WebClientEnabled bool           `mapstructure:"webclient_enabled" json:"webclient_enabled"`
	RESTAPIEnabled   bool           `mapstructure:"rest_api_enabled" json:"rest_api_enabled"`
	OpenAPIEnabled   bool           `mapstructure:"openapi_enabled" json:"openapi_enabled"`
	StaticPath       string         `mapstructure:"static_path" json:"static_path"`
	TemplatePath     string         `mapstructure:"template_path" json:"template_path"`
	SessionSecret    string         `mapstructure:"session_secret" json:"session_secret"`
	TokenExpiry      int            `mapstructure:"token_expiry" json:"token_expiry"`
	RequestTimeout   time.Duration  `mapstructure:"request_timeout" json:"request_timeout"`
	CORSOrigins      []string       `mapstructure:"cors_origins" json:"cors_origins"`
	JWT              JWTConfig      `mapstructure:"jwt" json:"jwt"`
	APIKeys          []APIKeyConfig `mapstructure:"api_keys" json:"api_keys"`
	OIDC             OIDCConfig     `mapstructure:"oidc" json:"oidc"`
	LDAP             LDAPConfig     `mapstructure:"ldap" json:"ldap"`
}

type JWTConfig struct {
	Enabled       bool   `mapstructure:"enabled" json:"enabled"`
	Secret        string `mapstructure:"secret" json:"secret"`
	Issuer        string `mapstructure:"issuer" json:"issuer"`
	Audience      string `mapstructure:"audience" json:"audience"`
	ExpirySeconds int    `mapstructure:"expiry_seconds" json:"expiry_seconds"`
}

type APIKeyConfig struct {
	Key         string   `mapstructure:"key" json:"key"`
	Subject     string   `mapstructure:"subject" json:"subject"`
	Role        string   `mapstructure:"role" json:"role"`
	Scopes      []string `mapstructure:"scopes" json:"scopes"`
	Description string   `mapstructure:"description" json:"description"`
	Enabled     bool     `mapstructure:"enabled" json:"enabled"`
}

type OIDCConfig struct {
	Enabled            bool              `mapstructure:"enabled" json:"enabled"`
	ProviderName       string            `mapstructure:"provider_name" json:"provider_name"`
	ClientID           string            `mapstructure:"client_id" json:"client_id"`
	ClientSecret       string            `mapstructure:"client_secret" json:"client_secret"`
	IssuerURL          string            `mapstructure:"issuer_url" json:"issuer_url"`
	AuthURL            string            `mapstructure:"auth_url" json:"auth_url"`
	TokenURL           string            `mapstructure:"token_url" json:"token_url"`
	UserInfoURL        string            `mapstructure:"user_info_url" json:"user_info_url"`
	RedirectURL        string            `mapstructure:"redirect_url" json:"redirect_url"`
	Scopes             []string          `mapstructure:"scopes" json:"scopes"`
	UsernameField      string            `mapstructure:"username_field" json:"username_field"`
	EmailField         string            `mapstructure:"email_field" json:"email_field"`
	RoleField          string            `mapstructure:"role_field" json:"role_field"`
	RoleMappings       map[string]string `mapstructure:"role_mappings" json:"role_mappings"`
	AllowAdmin         bool              `mapstructure:"allow_admin" json:"allow_admin"`
	AllowUser          bool              `mapstructure:"allow_user" json:"allow_user"`
	AutoCreateUsers    bool              `mapstructure:"auto_create_users" json:"auto_create_users"`
	UserHomeBaseDir    string            `mapstructure:"user_home_base_dir" json:"user_home_base_dir"`
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify"`
}

type LDAPConfig struct {
	Enabled            bool   `mapstructure:"enabled" json:"enabled"`
	URL                string `mapstructure:"url" json:"url"`
	BindDN             string `mapstructure:"bind_dn" json:"bind_dn"`
	BindPassword       string `mapstructure:"bind_password" json:"bind_password"`
	BaseDN             string `mapstructure:"base_dn" json:"base_dn"`
	UserFilter         string `mapstructure:"user_filter" json:"user_filter"`
	UsernameAttribute  string `mapstructure:"username_attribute" json:"username_attribute"`
	AdminGroupCN       string `mapstructure:"admin_group_cn" json:"admin_group_cn"`
	AllowAdmin         bool   `mapstructure:"allow_admin" json:"allow_admin"`
	AllowUser          bool   `mapstructure:"allow_user" json:"allow_user"`
	AutoCreateUsers    bool   `mapstructure:"auto_create_users" json:"auto_create_users"`
	UserHomeBaseDir    string `mapstructure:"user_home_base_dir" json:"user_home_base_dir"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" json:"insecure_skip_verify"`
}

type DataProviderConfig struct {
	Driver           string `mapstructure:"driver" json:"driver"`
	ConnectionString string `mapstructure:"connection_string" json:"connection_string"`
	SSLMode          string `mapstructure:"ssl_mode" json:"ssl_mode"`
	MaxOpenConns     int    `mapstructure:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns     int    `mapstructure:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime  int    `mapstructure:"conn_max_lifetime" json:"conn_max_lifetime"`
	AutoMigrate      bool   `mapstructure:"auto_migrate" json:"auto_migrate"`
}

type TelemetryConfig struct {
	Enabled         bool   `mapstructure:"enabled" json:"enabled"`
	ListenAddress   string `mapstructure:"listen_address" json:"listen_address"`
	ListenPort      int    `mapstructure:"listen_port" json:"listen_port"`
	TLSCertFile     string `mapstructure:"tls_cert_file" json:"tls_cert_file"`
	TLSKeyFile      string `mapstructure:"tls_key_file" json:"tls_key_file"`
	EnableProfiling bool   `mapstructure:"enable_profiling" json:"enable_profiling"`
}

type HTTPClientsConfig struct {
	DefaultTimeout int  `mapstructure:"default_timeout" json:"default_timeout"`
	TLSVerify      bool `mapstructure:"tls_verify" json:"tls_verify"`
	MaxConnections int  `mapstructure:"max_connections" json:"max_connections"`
}

type CommandsConfig struct {
	Whitelist []string `mapstructure:"whitelist" json:"whitelist"`
	Timeout   int      `mapstructure:"timeout" json:"timeout"`
}

type KMSConfig struct {
	Type    string `mapstructure:"type" json:"type"`
	KeyPath string `mapstructure:"key_path" json:"key_path"`
}

type MFAConfig struct {
	Enabled        bool   `mapstructure:"enabled" json:"enabled"`
	Issuer         string `mapstructure:"issuer" json:"issuer"`
	ForceForAdmins bool   `mapstructure:"force_for_admins" json:"force_for_admins"`
	ForceForUsers  bool   `mapstructure:"force_for_users" json:"force_for_users"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host" json:"host"`
	Port     int    `mapstructure:"port" json:"port"`
	Username string `mapstructure:"username" json:"username"`
	Password string `mapstructure:"password" json:"password"`
	From     string `mapstructure:"from" json:"from"`
	UseTLS   bool   `mapstructure:"use_tls" json:"use_tls"`
}

type PluginsConfig struct {
	Directory  string                 `mapstructure:"directory" json:"directory"`
	Enabled    []string               `mapstructure:"enabled" json:"enabled"`
	Disabled   []string               `mapstructure:"disabled" json:"disabled"`
	Configs    map[string]interface{} `mapstructure:"configs" json:"configs"`
	Path       string                 `mapstructure:"path" json:"path"`
	EnabledMap map[string]bool        `mapstructure:"enabled_map" json:"enabled_map"`
}

type AuthConfig struct {
	IPFilter            IPFilterConfig       `mapstructure:"ip_filter" json:"ip_filter"`
	PasswordPolicy      PasswordPolicyConfig `mapstructure:"password_policy" json:"password_policy"`
	PasswordExpiresDays int                  `mapstructure:"password_expires_days" json:"password_expires_days"`
	GeoIP               GeoIPConfig          `mapstructure:"geoip" json:"geoip"`
	MultiStepAuth       MultiStepAuthConfig  `mapstructure:"multistep_auth" json:"multistep_auth"`
}

type IPFilterConfig struct {
	AllowList []string `mapstructure:"allow_list" json:"allow_list"`
	DenyList  []string `mapstructure:"deny_list" json:"deny_list"`
}

type PasswordPolicyConfig struct {
	MinLength        int  `mapstructure:"min_length" json:"min_length"`
	RequireUppercase bool `mapstructure:"require_uppercase" json:"require_uppercase"`
	RequireLowercase bool `mapstructure:"require_lowercase" json:"require_lowercase"`
	RequireDigit     bool `mapstructure:"require_digit" json:"require_digit"`
	RequireSpecial   bool `mapstructure:"require_special" json:"require_special"`
	DisallowUsername bool `mapstructure:"disallow_username" json:"disallow_username"`
}

type GeoIPConfig struct {
	Enabled          bool     `mapstructure:"enabled" json:"enabled"`
	DBPath           string   `mapstructure:"db_path" json:"db_path"`
	AllowedCountries []string `mapstructure:"allowed_countries" json:"allowed_countries"`
	DeniedCountries  []string `mapstructure:"denied_countries" json:"denied_countries"`
}

type MultiStepAuthConfig struct {
	Enabled         bool     `mapstructure:"enabled" json:"enabled"`
	RequiredMethods []string `mapstructure:"required_methods" json:"required_methods"`
	TTLSeconds      int      `mapstructure:"ttl_seconds" json:"ttl_seconds"`
}

type HooksConfig struct {
	Auth        HooksAuthConfig         `mapstructure:"auth" json:"auth"`
	DynamicUser HooksDynamicUserConfig  `mapstructure:"dynamic_user" json:"dynamic_user"`
	FileEvents  []HooksFileEventConfig  `mapstructure:"file_events" json:"file_events"`
	Connection  []HooksConnectionConfig `mapstructure:"connection" json:"connection"`
}

type HooksAuthConfig struct {
	Type     string        `mapstructure:"type" json:"type"`
	Endpoint string        `mapstructure:"endpoint" json:"endpoint"`
	Command  string        `mapstructure:"command" json:"command"`
	Timeout  time.Duration `mapstructure:"timeout" json:"timeout"`
	CacheTTL time.Duration `mapstructure:"cache_ttl" json:"cache_ttl"`
}

type HooksDynamicUserConfig struct {
	Type     string        `mapstructure:"type" json:"type"`
	Endpoint string        `mapstructure:"endpoint" json:"endpoint"`
	Command  string        `mapstructure:"command" json:"command"`
	Timeout  time.Duration `mapstructure:"timeout" json:"timeout"`
}

type HooksFileEventConfig struct {
	Event    string        `mapstructure:"event" json:"event"`
	Type     string        `mapstructure:"type" json:"type"`
	Endpoint string        `mapstructure:"endpoint" json:"endpoint"`
	Command  string        `mapstructure:"command" json:"command"`
	Timeout  time.Duration `mapstructure:"timeout" json:"timeout"`
}

type HooksConnectionConfig struct {
	Event    string        `mapstructure:"event" json:"event"`
	Type     string        `mapstructure:"type" json:"type"`
	Endpoint string        `mapstructure:"endpoint" json:"endpoint"`
	Command  string        `mapstructure:"command" json:"command"`
	Timeout  time.Duration `mapstructure:"timeout" json:"timeout"`
}

type DefenderConfig struct {
	MaxFailures       int      `mapstructure:"max_failures" json:"max_failures"`
	BanDuration       int      `mapstructure:"ban_duration" json:"ban_duration"`
	ObservationWindow int      `mapstructure:"observation_window" json:"observation_window"`
	Whitelist         []string `mapstructure:"whitelist" json:"whitelist"`
}

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
	if masked.HTTPD.JWT.Secret != "" {
		masked.HTTPD.JWT.Secret = "***"
	}
	if masked.HTTPD.OIDC.ClientSecret != "" {
		masked.HTTPD.OIDC.ClientSecret = "***"
	}
	if masked.HTTPD.LDAP.BindPassword != "" {
		masked.HTTPD.LDAP.BindPassword = "***"
	}
	for i := range masked.HTTPD.APIKeys {
		if masked.HTTPD.APIKeys[i].Key != "" {
			masked.HTTPD.APIKeys[i].Key = "***"
		}
	}
	return masked
}

func (c *Config) Validate() error {
	var errors []string

	if c.Common.LogLevel == "" {
		c.Common.LogLevel = "info"
	}
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[strings.ToLower(c.Common.LogLevel)] {
		errors = append(errors, fmt.Sprintf("invalid log level: %s", c.Common.LogLevel))
	}

	if c.DataProvider.Driver != "sqlite" && c.DataProvider.Driver != "mysql" {
		errors = append(errors, "data provider driver must be 'sqlite' or 'mysql'")
	}

	if c.SSH.Enabled {
		if c.SSH.ListenPort <= 0 || c.SSH.ListenPort > 65535 {
			errors = append(errors, "SSH listen port must be between 1 and 65535")
		}
		if !c.SSH.PasswordAuth && !c.SSH.PublicKeyAuth && !c.SSH.CertificateAuth {
			errors = append(errors, "SSH must enable at least one authentication method")
		}
	}

	if c.FTP.Enabled {
		if c.FTP.ListenPort <= 0 || c.FTP.ListenPort > 65535 {
			errors = append(errors, "FTP listen port must be between 1 and 65535")
		}
		if (c.FTP.TLSCertFile == "") != (c.FTP.TLSKeyFile == "") {
			errors = append(errors, "FTP TLS certificate and key must be configured together")
		}
		if (c.FTP.ForceControlTLS || c.FTP.ForceDataTLS) && (c.FTP.TLSCertFile == "" || c.FTP.TLSKeyFile == "") {
			errors = append(errors, "FTP forced TLS requires both TLS certificate and key")
		}
		if c.FTP.PassivePortStart > 0 && c.FTP.PassivePortEnd > 0 && c.FTP.PassivePortEnd < c.FTP.PassivePortStart {
			errors = append(errors, "FTP passive port end must be greater than or equal to passive port start")
		}
	}

	if c.WebDAV.Enabled {
		if c.WebDAV.ListenPort <= 0 || c.WebDAV.ListenPort > 65535 {
			errors = append(errors, "WebDAV listen port must be between 1 and 65535")
		}
		if (c.WebDAV.TLSCertFile == "") != (c.WebDAV.TLSKeyFile == "") {
			errors = append(errors, "WebDAV TLS certificate and key must be configured together")
		}
	}

	if c.HTTPD.Enabled {
		if c.HTTPD.ListenPort <= 0 || c.HTTPD.ListenPort > 65535 {
			errors = append(errors, "HTTPD listen port must be between 1 and 65535")
		}
		if c.HTTPD.JWT.Enabled {
			if c.HTTPD.JWT.Issuer == "" {
				c.HTTPD.JWT.Issuer = "sftpxy"
			}
			if c.HTTPD.JWT.ExpirySeconds <= 0 {
				c.HTTPD.JWT.ExpirySeconds = c.HTTPD.TokenExpiry
				if c.HTTPD.JWT.ExpirySeconds <= 0 {
					c.HTTPD.JWT.ExpirySeconds = 3600
				}
			}
		}
		if c.HTTPD.OIDC.Enabled {
			if c.HTTPD.OIDC.ClientID == "" {
				errors = append(errors, "HTTPD OIDC client_id is required when oidc is enabled")
			}
			if c.HTTPD.OIDC.ClientSecret == "" {
				errors = append(errors, "HTTPD OIDC client_secret is required when oidc is enabled")
			}
			if c.HTTPD.OIDC.AuthURL == "" {
				errors = append(errors, "HTTPD OIDC auth_url is required when oidc is enabled")
			}
			if c.HTTPD.OIDC.TokenURL == "" {
				errors = append(errors, "HTTPD OIDC token_url is required when oidc is enabled")
			}
			if c.HTTPD.OIDC.RedirectURL == "" {
				errors = append(errors, "HTTPD OIDC redirect_url is required when oidc is enabled")
			}
			if len(c.HTTPD.OIDC.Scopes) == 0 {
				c.HTTPD.OIDC.Scopes = []string{"openid", "profile", "email"}
			}
			if c.HTTPD.OIDC.UsernameField == "" {
				c.HTTPD.OIDC.UsernameField = "preferred_username"
			}
			if c.HTTPD.OIDC.EmailField == "" {
				c.HTTPD.OIDC.EmailField = "email"
			}
		}
		if c.HTTPD.LDAP.Enabled {
			if c.HTTPD.LDAP.URL == "" {
				errors = append(errors, "HTTPD LDAP url is required when ldap is enabled")
			}
			if c.HTTPD.LDAP.BaseDN == "" {
				errors = append(errors, "HTTPD LDAP base_dn is required when ldap is enabled")
			}
			if c.HTTPD.LDAP.UserFilter == "" {
				c.HTTPD.LDAP.UserFilter = "(&(objectClass=person)(uid=%s))"
			}
			if c.HTTPD.LDAP.UsernameAttribute == "" {
				c.HTTPD.LDAP.UsernameAttribute = "uid"
			}
		}
		for i, keyCfg := range c.HTTPD.APIKeys {
			if !keyCfg.Enabled {
				continue
			}
			if strings.TrimSpace(keyCfg.Key) == "" {
				errors = append(errors, fmt.Sprintf("HTTPD api_keys[%d].key is required when enabled", i))
			}
			if strings.TrimSpace(keyCfg.Role) == "" {
				c.HTTPD.APIKeys[i].Role = "admin"
			}
			if strings.TrimSpace(keyCfg.Subject) == "" {
				c.HTTPD.APIKeys[i].Subject = fmt.Sprintf("api-key-%d", i+1)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	if c.Auth.PasswordPolicy.MinLength <= 0 {
		c.Auth.PasswordPolicy.MinLength = 8
	}
	if c.Auth.MultiStepAuth.Enabled && len(c.Auth.MultiStepAuth.RequiredMethods) < 2 {
		errors = append(errors, "multistep_auth requires at least 2 required_methods")
	}
	if c.Auth.MultiStepAuth.TTLSeconds <= 0 {
		c.Auth.MultiStepAuth.TTLSeconds = 300
	}
	if len(c.Auth.GeoIP.AllowedCountries) > 0 && len(c.Auth.GeoIP.DeniedCountries) > 0 {
		errors = append(errors, "auth.geoip: cannot specify both allowed_countries and denied_countries")
	}

	if len(errors) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(errors, "; "))
	}

	return nil
}
