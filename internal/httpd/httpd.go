// SPDX-License-Identifier: MIT

// Package httpd implements REST API and Web interface for SFTPxy.
// The OpenAPI 3 schema for the supported API can be found inside the source tree:
// https://github.com/jincaiw/sftpxy/blob/main/openapi/openapi.yaml
package httpd

import (
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jincaiw/sftpxy/v2/internal/acme"
	"github.com/jincaiw/sftpxy/v2/internal/common"
	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/ftpd"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/mfa"
	"github.com/jincaiw/sftpxy/v2/internal/sftpd"
	"github.com/jincaiw/sftpxy/v2/internal/util"
	"github.com/jincaiw/sftpxy/v2/internal/webdavd"
)

const (
	logSender                             = "httpd"
	tokenPath                             = "/api/v2/token"
	logoutPath                            = "/api/v2/logout"
	userTokenPath                         = "/api/v2/user/token"
	userLogoutPath                        = "/api/v2/user/logout"
	activeConnectionsPath                 = "/api/v2/connections"
	quotasBasePath                        = "/api/v2/quotas"
	userPath                              = "/api/v2/users"
	versionPath                           = "/api/v2/version"
	folderPath                            = "/api/v2/folders"
	groupPath                             = "/api/v2/groups"
	serverStatusPath                      = "/api/v2/status"
	dumpDataPath                          = "/api/v2/dumpdata"
	loadDataPath                          = "/api/v2/loaddata"
	defenderHosts                         = "/api/v2/defender/hosts"
	adminPath                             = "/api/v2/admins"
	adminPwdPath                          = "/api/v2/admin/changepwd"
	adminProfilePath                      = "/api/v2/admin/profile"
	userPwdPath                           = "/api/v2/user/changepwd"
	userDirsPath                          = "/api/v2/user/dirs"
	userFilesPath                         = "/api/v2/user/files"
	userFileActionsPath                   = "/api/v2/user/file-actions"
	userStreamZipPath                     = "/api/v2/user/streamzip"
	userUploadFilePath                    = "/api/v2/user/files/upload"
	userFilesDirsMetadataPath             = "/api/v2/user/files/metadata"
	apiKeysPath                           = "/api/v2/apikeys"
	adminTOTPConfigsPath                  = "/api/v2/admin/totp/configs"
	adminTOTPGeneratePath                 = "/api/v2/admin/totp/generate"
	adminTOTPValidatePath                 = "/api/v2/admin/totp/validate"
	adminTOTPSavePath                     = "/api/v2/admin/totp/save"
	admin2FARecoveryCodesPath             = "/api/v2/admin/2fa/recoverycodes"
	userTOTPConfigsPath                   = "/api/v2/user/totp/configs"
	userTOTPGeneratePath                  = "/api/v2/user/totp/generate"
	userTOTPValidatePath                  = "/api/v2/user/totp/validate"
	userTOTPSavePath                      = "/api/v2/user/totp/save"
	user2FARecoveryCodesPath              = "/api/v2/user/2fa/recoverycodes"
	userProfilePath                       = "/api/v2/user/profile"
	userSharesPath                        = "/api/v2/user/shares"
	retentionChecksPath                   = "/api/v2/retention/users/checks"
	fsEventsPath                          = "/api/v2/events/fs"
	providerEventsPath                    = "/api/v2/events/provider"
	logEventsPath                         = "/api/v2/events/logs"
	sharesPath                            = "/api/v2/shares"
	eventActionsPath                      = "/api/v2/eventactions"
	eventRulesPath                        = "/api/v2/eventrules"
	rolesPath                             = "/api/v2/roles"
	ipListsPath                           = "/api/v2/iplists"
	healthzPath                           = "/healthz"
	webRootPathDefault                    = "/"
	webBasePathDefault                    = "/web"
	webBasePathAdminDefault               = "/web/admin"
	webBasePathClientDefault              = "/web/client"
	webAdminSetupPathDefault              = "/web/admin/setup"
	webAdminLoginPathDefault              = "/web/admin/login"
	webAdminOIDCLoginPathDefault          = "/web/admin/oidclogin"
	webOIDCRedirectPathDefault            = "/web/oidc/redirect"
	webOAuth2RedirectPathDefault          = "/web/oauth2/redirect"
	webOAuth2TokenPathDefault             = "/web/admin/oauth2/token"
	webAdminTwoFactorPathDefault          = "/web/admin/twofactor"
	webAdminTwoFactorRecoveryPathDefault  = "/web/admin/twofactor-recovery"
	webLogoutPathDefault                  = "/web/admin/logout"
	webUsersPathDefault                   = "/web/admin/users"
	webUserPathDefault                    = "/web/admin/user"
	webConnectionsPathDefault             = "/web/admin/connections"
	webFoldersPathDefault                 = "/web/admin/folders"
	webFolderPathDefault                  = "/web/admin/folder"
	webGroupsPathDefault                  = "/web/admin/groups"
	webGroupPathDefault                   = "/web/admin/group"
	webStatusPathDefault                  = "/web/admin/status"
	webAdminsPathDefault                  = "/web/admin/managers"
	webAdminPathDefault                   = "/web/admin/manager"
	webMaintenancePathDefault             = "/web/admin/maintenance"
	webBackupPathDefault                  = "/web/admin/backup"
	webRestorePathDefault                 = "/web/admin/restore"
	webScanVFolderPathDefault             = "/web/admin/quotas/scanfolder"
	webQuotaScanPathDefault               = "/web/admin/quotas/scanuser"
	webChangeAdminPwdPathDefault          = "/web/admin/changepwd"
	webAdminForgotPwdPathDefault          = "/web/admin/forgot-password"
	webAdminResetPwdPathDefault           = "/web/admin/reset-password"
	webAdminProfilePathDefault            = "/web/admin/profile"
	webAdminMFAPathDefault                = "/web/admin/mfa"
	webAdminEventRulesPathDefault         = "/web/admin/eventrules"
	webAdminEventRulePathDefault          = "/web/admin/eventrule"
	webAdminEventActionsPathDefault       = "/web/admin/eventactions"
	webAdminEventActionPathDefault        = "/web/admin/eventaction"
	webAdminRolesPathDefault              = "/web/admin/roles"
	webAdminRolePathDefault               = "/web/admin/role"
	webAdminTOTPGeneratePathDefault       = "/web/admin/totp/generate"
	webAdminTOTPValidatePathDefault       = "/web/admin/totp/validate"
	webAdminTOTPSavePathDefault           = "/web/admin/totp/save"
	webAdminRecoveryCodesPathDefault      = "/web/admin/recoverycodes"
	webTemplateUserDefault                = "/web/admin/template/user"
	webTemplateFolderDefault              = "/web/admin/template/folder"
	webDefenderPathDefault                = "/web/admin/defender"
	webIPListsPathDefault                 = "/web/admin/ip-lists"
	webIPListPathDefault                  = "/web/admin/ip-list"
	webDefenderHostsPathDefault           = "/web/admin/defender/hosts"
	webEventsPathDefault                  = "/web/admin/events"
	webEventsFsSearchPathDefault          = "/web/admin/events/fs"
	webEventsProviderSearchPathDefault    = "/web/admin/events/provider"
	webEventsLogSearchPathDefault         = "/web/admin/events/logs"
	webConfigsPathDefault                 = "/web/admin/configs"
	webClientLoginPathDefault             = "/web/client/login"
	webClientOIDCLoginPathDefault         = "/web/client/oidclogin"
	webClientTwoFactorPathDefault         = "/web/client/twofactor"
	webClientTwoFactorRecoveryPathDefault = "/web/client/twofactor-recovery"
	webClientFilesPathDefault             = "/web/client/files"
	webClientFilePathDefault              = "/web/client/file"
	webClientFileActionsPathDefault       = "/web/client/file-actions"
	webClientSharesPathDefault            = "/web/client/shares"
	webClientSharePathDefault             = "/web/client/share"
	webClientEditFilePathDefault          = "/web/client/editfile"
	webClientDirsPathDefault              = "/web/client/dirs"
	webClientDownloadZipPathDefault       = "/web/client/downloadzip"
	webClientProfilePathDefault           = "/web/client/profile"
	webClientPingPathDefault              = "/web/client/ping"
	webClientMFAPathDefault               = "/web/client/mfa"
	webClientTOTPGeneratePathDefault      = "/web/client/totp/generate"
	webClientTOTPValidatePathDefault      = "/web/client/totp/validate"
	webClientTOTPSavePathDefault          = "/web/client/totp/save"
	webClientRecoveryCodesPathDefault     = "/web/client/recoverycodes"
	webChangeClientPwdPathDefault         = "/web/client/changepwd"
	webClientLogoutPathDefault            = "/web/client/logout"
	webClientPubSharesPathDefault         = "/web/client/pubshares"
	webClientForgotPwdPathDefault         = "/web/client/forgot-password"
	webClientResetPwdPathDefault          = "/web/client/reset-password"
	webClientViewPDFPathDefault           = "/web/client/viewpdf"
	webClientGetPDFPathDefault            = "/web/client/getpdf"
	webClientExistPathDefault             = "/web/client/exist"
	webClientTasksPathDefault             = "/web/client/tasks"
	webStaticFilesPathDefault             = "/static"
	webOpenAPIPathDefault                 = "/openapi"
	// MaxRestoreSize defines the max size for the loaddata input file
	MaxRestoreSize       = 20 * 1048576 // 20 MB
	maxRequestSize       = 1048576      // 1MB
	maxLoginBodySize     = 262144       // 256 KB
	httpdMaxEditFileSize = 2 * 1048576  // 2 MB
	maxMultipartMem      = 10 * 1048576 // 10 MB
	osWindows            = "windows"
	otpHeaderCode        = "X-SFTPXY-OTP"
	mTimeHeader          = "X-SFTPXY-MTIME"
	acmeChallengeURI     = "/.well-known/acme-challenge/"
)

var (
	certMgr                        *common.CertManager
	cleanupTicker                  *time.Ticker
	cleanupDone                    chan bool
	invalidatedJWTTokens           tokenManager
	webRootPath                    string
	webBasePath                    string
	webBaseAdminPath               string
	webBaseClientPath              string
	webOIDCRedirectPath            string
	webOAuth2RedirectPath          string
	webOAuth2TokenPath             string
	webAdminSetupPath              string
	webAdminOIDCLoginPath          string
	webAdminLoginPath              string
	webAdminTwoFactorPath          string
	webAdminTwoFactorRecoveryPath  string
	webLogoutPath                  string
	webUsersPath                   string
	webUserPath                    string
	webConnectionsPath             string
	webFoldersPath                 string
	webFolderPath                  string
	webGroupsPath                  string
	webGroupPath                   string
	webStatusPath                  string
	webAdminsPath                  string
	webAdminPath                   string
	webMaintenancePath             string
	webBackupPath                  string
	webRestorePath                 string
	webScanVFolderPath             string
	webQuotaScanPath               string
	webAdminProfilePath            string
	webAdminMFAPath                string
	webAdminEventRulesPath         string
	webAdminEventRulePath          string
	webAdminEventActionsPath       string
	webAdminEventActionPath        string
	webAdminRolesPath              string
	webAdminRolePath               string
	webAdminTOTPGeneratePath       string
	webAdminTOTPValidatePath       string
	webAdminTOTPSavePath           string
	webAdminRecoveryCodesPath      string
	webChangeAdminPwdPath          string
	webAdminForgotPwdPath          string
	webAdminResetPwdPath           string
	webTemplateUser                string
	webTemplateFolder              string
	webDefenderPath                string
	webIPListPath                  string
	webIPListsPath                 string
	webEventsPath                  string
	webEventsFsSearchPath          string
	webEventsProviderSearchPath    string
	webEventsLogSearchPath         string
	webConfigsPath                 string
	webDefenderHostsPath           string
	webClientLoginPath             string
	webClientOIDCLoginPath         string
	webClientTwoFactorPath         string
	webClientTwoFactorRecoveryPath string
	webClientFilesPath             string
	webClientFilePath              string
	webClientFileActionsPath       string
	webClientSharesPath            string
	webClientSharePath             string
	webClientEditFilePath          string
	webClientDirsPath              string
	webClientDownloadZipPath       string
	webClientProfilePath           string
	webClientPingPath              string
	webChangeClientPwdPath         string
	webClientMFAPath               string
	webClientTOTPGeneratePath      string
	webClientTOTPValidatePath      string
	webClientTOTPSavePath          string
	webClientRecoveryCodesPath     string
	webClientPubSharesPath         string
	webClientLogoutPath            string
	webClientForgotPwdPath         string
	webClientResetPwdPath          string
	webClientViewPDFPath           string
	webClientGetPDFPath            string
	webClientExistPath             string
	webClientTasksPath             string
	webStaticFilesPath             string
	webOpenAPIPath                 string
	// max upload size for http clients, 1GB by default
	maxUploadFileSize          = int64(1048576000)
	hideSupportLink            bool
	installationCode           string
	installationCodeHint       string
	fnInstallationCodeResolver FnInstallationCodeResolver
	configurationDir           string
	dbBrandingConfig           brandingCache
)

func init() {
	updateWebAdminURLs("")
	updateWebClientURLs("")
	acme.SetReloadHTTPDCertsFn(ReloadCertificateMgr)
	common.SetUpdateBrandingFn(dbBrandingConfig.Set)
}

type brandingCache struct {
	mu      sync.RWMutex
	configs *dataprovider.BrandingConfigs
}

func (b *brandingCache) Set(configs *dataprovider.BrandingConfigs) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.configs = configs
}

func (b *brandingCache) getWebAdminLogo() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.configs.WebAdmin.Logo
}

func (b *brandingCache) getWebAdminFavicon() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.configs.WebAdmin.Favicon
}

func (b *brandingCache) getWebClientLogo() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.configs.WebClient.Logo
}

func (b *brandingCache) getWebClientFavicon() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return b.configs.WebClient.Favicon
}

func (b *brandingCache) mergeBrandingConfig(branding UIBranding, isWebClient bool) UIBranding {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var urlPrefix string
	var cfg dataprovider.BrandingConfig
	if isWebClient {
		cfg = b.configs.WebClient
		urlPrefix = "webclient"
	} else {
		cfg = b.configs.WebAdmin
		urlPrefix = "webadmin"
	}
	if cfg.Name != "" {
		branding.Name = cfg.Name
	}
	if cfg.ShortName != "" {
		branding.ShortName = cfg.ShortName
	}
	if cfg.DisclaimerName != "" {
		branding.DisclaimerName = cfg.DisclaimerName
	}
	if cfg.DisclaimerURL != "" {
		branding.DisclaimerPath = cfg.DisclaimerURL
	}
	if len(cfg.Logo) > 0 {
		branding.LogoPath = path.Join("/", "branding", urlPrefix, "logo.png")
	}
	if len(cfg.Favicon) > 0 {
		branding.FaviconPath = path.Join("/", "branding", urlPrefix, "favicon.png")
	}
	return branding
}

type defenderStatus struct {
	IsActive bool `json:"is_active"`
}

type allowListStatus struct {
	IsActive bool `json:"is_active"`
}

type rateLimiters struct {
	IsActive  bool     `json:"is_active"`
	Protocols []string `json:"protocols"`
}

// GetProtocolsAsString returns the enabled protocols as comma separated string
func (r *rateLimiters) GetProtocolsAsString() string {
	return strings.Join(r.Protocols, ", ")
}

// ServicesStatus keep the state of the running services
type ServicesStatus struct {
	SSH          sftpd.ServiceStatus         `json:"ssh"`
	FTP          ftpd.ServiceStatus          `json:"ftp"`
	WebDAV       webdavd.ServiceStatus       `json:"webdav"`
	DataProvider dataprovider.ProviderStatus `json:"data_provider"`
	Defender     defenderStatus              `json:"defender"`
	MFA          mfa.ServiceStatus           `json:"mfa"`
	AllowList    allowListStatus             `json:"allow_list"`
	RateLimiters rateLimiters                `json:"rate_limiters"`
}

// SetupConfig defines the configuration parameters for the initial web admin setup
type SetupConfig struct {
	// Installation code to require when creating the first admin account.
	// As for the other configurations, this value is read at SFTPxy startup and not at runtime
	// even if set using an environment variable.
	// This is not a license key or similar, the purpose here is to prevent anyone who can access
	// to the initial setup screen from creating an admin user
	InstallationCode string `json:"installation_code" mapstructure:"installation_code"`
	// Description for the installation code input field
	InstallationCodeHint string `json:"installation_code_hint" mapstructure:"installation_code_hint"`
}

// CorsConfig defines the CORS configuration
type CorsConfig struct {
	AllowedOrigins       []string `json:"allowed_origins" mapstructure:"allowed_origins"`
	AllowedMethods       []string `json:"allowed_methods" mapstructure:"allowed_methods"`
	AllowedHeaders       []string `json:"allowed_headers" mapstructure:"allowed_headers"`
	ExposedHeaders       []string `json:"exposed_headers" mapstructure:"exposed_headers"`
	AllowCredentials     bool     `json:"allow_credentials" mapstructure:"allow_credentials"`
	Enabled              bool     `json:"enabled" mapstructure:"enabled"`
	MaxAge               int      `json:"max_age" mapstructure:"max_age"`
	OptionsPassthrough   bool     `json:"options_passthrough" mapstructure:"options_passthrough"`
	OptionsSuccessStatus int      `json:"options_success_status" mapstructure:"options_success_status"`
	AllowPrivateNetwork  bool     `json:"allow_private_network" mapstructure:"allow_private_network"`
}

// Conf httpd daemon configuration
type Conf struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
	// Path to the HTML web templates. This can be an absolute path or a path relative to the config dir
	TemplatesPath string `json:"templates_path" mapstructure:"templates_path"`
	// Path to the static files for the web interface. This can be an absolute path or a path relative to the config dir.
	// If both TemplatesPath and StaticFilesPath are empty the built-in web interface will be disabled
	StaticFilesPath string `json:"static_files_path" mapstructure:"static_files_path"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	//BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
	// Path to the directory that contains the OpenAPI schema and the default renderer.
	// This can be an absolute path or a path relative to the config dir
	OpenAPIPath string `json:"openapi_path" mapstructure:"openapi_path"`
	// Defines a base URL for the web admin and client interfaces. If empty web admin and client resources will
	// be available at the root ("/") URI. If defined it must be an absolute URI or it will be ignored.
	WebRoot string `json:"web_root" mapstructure:"web_root"`
	// If files containing a certificate and matching private key for the server are provided you can enable
	// HTTPS connections for the configured bindings.
	// Certificate and key files can be reloaded on demand sending a "SIGHUP" signal on Unix based systems and a
	// "paramchange" request to the running service on Windows.
	CertificateFile    string `json:"certificate_file" mapstructure:"certificate_file"`
	CertificateKeyFile string `json:"certificate_key_file" mapstructure:"certificate_key_file"`
	// CACertificates defines the set of root certificate authorities to be used to verify client certificates.
	CACertificates []string `json:"ca_certificates" mapstructure:"ca_certificates"`
	// CARevocationLists defines a set a revocation lists, one for each root CA, to be used to check
	// if a client certificate has been revoked
	CARevocationLists []string `json:"ca_revocation_lists" mapstructure:"ca_revocation_lists"`
	// SigningPassphrase defines the passphrase to use to derive the signing key for JWT and CSRF tokens.
	// If empty a random signing key will be generated each time SFTPxy starts. If you set a
	// signing passphrase you should consider rotating it periodically for added security
	SigningPassphrase     string `json:"signing_passphrase" mapstructure:"signing_passphrase"`
	SigningPassphraseFile string `json:"signing_passphrase_file" mapstructure:"signing_passphrase_file"`
	// TokenValidation allows to define how to validate JWT tokens, cookies and CSRF tokens.
	// By default all the available security checks are enabled. Set to 1 to disable the requirement
	// that a token must be used by the same IP for which it was issued.
	TokenValidation int `json:"token_validation" mapstructure:"token_validation"`
	// CookieLifetime defines the duration of cookies for WebAdmin and WebClient
	CookieLifetime int `json:"cookie_lifetime" mapstructure:"cookie_lifetime"`
	// ShareCookieLifetime defines the duration of cookies for public shares
	ShareCookieLifetime int `json:"share_cookie_lifetime" mapstructure:"share_cookie_lifetime"`
	// JWTLifetime defines the duration of JWT tokens used in REST API
	JWTLifetime int `json:"jwt_lifetime" mapstructure:"jwt_lifetime"`
	// MaxUploadFileSize Defines the maximum request body size, in bytes, for Web Client/API HTTP upload requests.
	// 0 means no limit
	MaxUploadFileSize int64 `json:"max_upload_file_size" mapstructure:"max_upload_file_size"`
	// CORS configuration
	Cors CorsConfig `json:"cors" mapstructure:"cors"`
	// Initial setup configuration
	Setup SetupConfig `json:"setup" mapstructure:"setup"`
	// If enabled, the link to the sponsors section will not appear on the setup screen page
	HideSupportLink bool `json:"hide_support_link" mapstructure:"hide_support_link"`
	acmeDomain      string
}

type apiResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message"`
}

// ShouldBind returns true if there is at least a valid binding
func (c *Conf) ShouldBind() bool {
	for _, binding := range c.Bindings {
		if binding.IsValid() {
			return true
		}
	}

	return false
}

func (c *Conf) isWebAdminEnabled() bool {
	for _, binding := range c.Bindings {
		if binding.EnableWebAdmin {
			return true
		}
	}
	return false
}

func (c *Conf) isWebClientEnabled() bool {
	for _, binding := range c.Bindings {
		if binding.EnableWebClient {
			return true
		}
	}
	return false
}

func (c *Conf) checkRequiredDirs(staticFilesPath, templatesPath string) error {
	if (c.isWebAdminEnabled() || c.isWebClientEnabled()) && (staticFilesPath == "" || templatesPath == "") {
		return fmt.Errorf("required directory is invalid, static file path: %q template path: %q",
			staticFilesPath, templatesPath)
	}
	return nil
}

func (c *Conf) getRedacted() Conf {
	redacted := "[redacted]"
	conf := *c
	if conf.SigningPassphrase != "" {
		conf.SigningPassphrase = redacted
	}
	if conf.Setup.InstallationCode != "" {
		conf.Setup.InstallationCode = redacted
	}
	conf.Bindings = nil
	for _, binding := range c.Bindings {
		if binding.OIDC.ClientID != "" {
			binding.OIDC.ClientID = redacted
		}
		if binding.OIDC.ClientSecret != "" {
			binding.OIDC.ClientSecret = redacted
		}
		conf.Bindings = append(conf.Bindings, binding)
	}
	return conf
}

func (c *Conf) getKeyPairs(configDir string) []common.TLSKeyPair {
	var keyPairs []common.TLSKeyPair

	for _, binding := range c.Bindings {
		certificateFile := getConfigPath(binding.CertificateFile, configDir)
		certificateKeyFile := getConfigPath(binding.CertificateKeyFile, configDir)
		if certificateFile != "" && certificateKeyFile != "" {
			keyPairs = append(keyPairs, common.TLSKeyPair{
				Cert: certificateFile,
				Key:  certificateKeyFile,
				ID:   binding.GetAddress(),
			})
		}
	}
	var certificateFile, certificateKeyFile string
	if c.acmeDomain != "" {
		certificateFile, certificateKeyFile = util.GetACMECertificateKeyPair(c.acmeDomain)
	} else {
		certificateFile = getConfigPath(c.CertificateFile, configDir)
		certificateKeyFile = getConfigPath(c.CertificateKeyFile, configDir)
	}
	if certificateFile != "" && certificateKeyFile != "" {
		keyPairs = append(keyPairs, common.TLSKeyPair{
			Cert: certificateFile,
			Key:  certificateKeyFile,
			ID:   common.DefaultTLSKeyPaidID,
		})
	}
	return keyPairs
}

func (c *Conf) setTokenValidationMode() {
	tokenValidationMode = c.TokenValidation
}

func (c *Conf) loadFromProvider() error {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		return fmt.Errorf("unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	dbBrandingConfig.Set(configs.Branding)
	if configs.ACME.Domain == "" || !configs.ACME.HasProtocol(common.ProtocolHTTP) {
		return nil
	}
	crt, key := util.GetACMECertificateKeyPair(configs.ACME.Domain)
	if crt != "" && key != "" {
		if _, err := os.Stat(crt); err != nil {
			logger.Error(logSender, "", "unable to load acme cert file %q: %v", crt, err)
			return nil
		}
		if _, err := os.Stat(key); err != nil {
			logger.Error(logSender, "", "unable to load acme key file %q: %v", key, err)
			return nil
		}
		for idx := range c.Bindings {
			if c.Bindings[idx].Security.Enabled && c.Bindings[idx].Security.HTTPSRedirect {
				continue
			}
			c.Bindings[idx].EnableHTTPS = true
		}
		c.acmeDomain = configs.ACME.Domain
		logger.Info(logSender, "", "acme domain set to %q", c.acmeDomain)
		return nil
	}
	return nil
}

func (c *Conf) loadTemplates(templatesPath string) {
	if c.isWebAdminEnabled() {
		updateWebAdminURLs(c.WebRoot)
		loadAdminTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web admin interface disabled")
	}
	if c.isWebClientEnabled() {
		updateWebClientURLs(c.WebRoot)
		loadClientTemplates(templatesPath)
	} else {
		logger.Info(logSender, "", "built-in web client interface disabled")
	}
}

// Initialize configures and starts the HTTP server
func (c *Conf) Initialize(configDir string, isShared int) error {
	if err := c.loadFromProvider(); err != nil {
		return err
	}
	logger.Info(logSender, "", "initializing HTTP server with config %+v", c.getRedacted())
	configurationDir = configDir
	invalidatedJWTTokens = newTokenManager(isShared)
	resetCodesMgr = newResetCodeManager(isShared)
	oidcMgr = newOIDCManager(isShared)
	oauth2Mgr = newOAuth2Manager(isShared)
	webTaskMgr = newWebTaskManager(isShared)
	staticFilesPath := util.FindSharedDataPath(c.StaticFilesPath, configDir)
	templatesPath := util.FindSharedDataPath(c.TemplatesPath, configDir)
	openAPIPath := util.FindSharedDataPath(c.OpenAPIPath, configDir)
	if err := c.checkRequiredDirs(staticFilesPath, templatesPath); err != nil {
		return err
	}
	c.loadTemplates(templatesPath)
	keyPairs := c.getKeyPairs(configDir)
	if len(keyPairs) > 0 {
		mgr, err := common.NewCertManager(keyPairs, configDir, logSender)
		if err != nil {
			return err
		}
		mgr.SetCACertificates(c.CACertificates)
		if err := mgr.LoadRootCAs(); err != nil {
			return err
		}
		mgr.SetCARevocationLists(c.CARevocationLists)
		if err := mgr.LoadCRLs(); err != nil {
			return err
		}
		certMgr = mgr
	}

	passphrase, err := util.ResolveConfigValue(c.SigningPassphrase, c.SigningPassphraseFile, configDir)
	if err != nil {
		return err
	}
	c.SigningPassphrase = passphrase

	hideSupportLink = c.HideSupportLink

	exitChannel := make(chan error, 1)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}
		if err := binding.check(); err != nil {
			return err
		}

		go func(b Binding) {
			if err := b.OIDC.initialize(); err != nil {
				exitChannel <- err
				return
			}
			if err := b.checkLoginMethods(); err != nil {
				exitChannel <- err
				return
			}
			server := newHttpdServer(b, staticFilesPath, c.SigningPassphrase, c.Cors, openAPIPath)
			server.setShared(isShared)

			exitChannel <- server.listenAndServe()
		}(binding)
	}

	maxUploadFileSize = c.MaxUploadFileSize
	installationCode = c.Setup.InstallationCode
	installationCodeHint = c.Setup.InstallationCodeHint
	updateTokensDuration(c.JWTLifetime, c.CookieLifetime, c.ShareCookieLifetime)
	startCleanupTicker(10 * time.Minute)
	c.setTokenValidationMode()
	return <-exitChannel
}
