// SPDX-License-Identifier: MIT

package dataprovider

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jincaiw/sftpxy/sdk"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
	"github.com/jincaiw/sftpxy/v2/internal/util"
	"github.com/jincaiw/sftpxy/v2/internal/vfs"
)

const (
	// SQLiteDataProviderName defines the name for SQLite database provider
	SQLiteDataProviderName = "sqlite"
	// PGSQLDataProviderName defines the name for PostgreSQL database provider
	PGSQLDataProviderName = "postgresql"
	// MySQLDataProviderName defines the name for MySQL database provider
	MySQLDataProviderName = "mysql"
	// BoltDataProviderName defines the name for bbolt key/value store provider
	BoltDataProviderName = "bolt"
	// MemoryDataProviderName defines the name for memory provider
	MemoryDataProviderName = "memory"
	// CockroachDataProviderName defines the for CockroachDB provider
	CockroachDataProviderName = "cockroachdb"
	// DumpVersion defines the version for the dump.
	// For restore/load we support the current version and the previous one
	DumpVersion = 17

	argonPwdPrefix            = "$argon2id$"
	bcryptPwdPrefix           = "$2a$"
	pbkdf2SHA1Prefix          = "$pbkdf2-sha1$"
	pbkdf2SHA256Prefix        = "$pbkdf2-sha256$"
	pbkdf2SHA512Prefix        = "$pbkdf2-sha512$"
	pbkdf2SHA256B64SaltPrefix = "$pbkdf2-b64salt-sha256$"
	md5cryptPwdPrefix         = "$1$"
	md5cryptApr1PwdPrefix     = "$apr1$"
	sha256cryptPwdPrefix      = "$5$"
	sha512cryptPwdPrefix      = "$6$"
	yescryptPwdPrefix         = "$y$"
	md5DigestPwdPrefix        = "{MD5}"
	sha256DigestPwdPrefix     = "{SHA256}"
	sha512DigestPwdPrefix     = "{SHA512}"
	trackQuotaDisabledError   = "please enable track_quota in your configuration to use this method"
	operationAdd              = "add"
	operationUpdate           = "update"
	operationDelete           = "delete"
	sqlPrefixValidChars       = "abcdefghijklmnopqrstuvwxyz_0123456789"
	maxHookResponseSize       = 1048576 // 1MB
)

// Supported algorithms for hashing passwords.
// These algorithms can be used when SFTPxy hashes a plain text password
const (
	HashingAlgoBcrypt   = "bcrypt"
	HashingAlgoArgon2ID = "argon2id"
)

// ordering constants
const (
	OrderASC  = "ASC"
	OrderDESC = "DESC"
)

const (
	protocolSSH    = "SSH"
	protocolFTP    = "FTP"
	protocolWebDAV = "DAV"
	protocolHTTP   = "HTTP"
)

// Dump scopes
const (
	DumpScopeUsers   = "users"
	DumpScopeFolders = "folders"
	DumpScopeGroups  = "groups"
	DumpScopeAdmins  = "admins"
	DumpScopeAPIKeys = "api_keys"
	DumpScopeShares  = "shares"
	DumpScopeActions = "actions"
	DumpScopeRules   = "rules"
	DumpScopeRoles   = "roles"
	DumpScopeIPLists = "ip_lists"
	DumpScopeConfigs = "configs"
)

const (
	fieldUsername = 1
	fieldName     = 2
	fieldIPNet    = 3
)

var (
	// SupportedProviders defines the supported data providers
	SupportedProviders = []string{SQLiteDataProviderName, PGSQLDataProviderName, MySQLDataProviderName,
		BoltDataProviderName, MemoryDataProviderName, CockroachDataProviderName}
	// ValidPerms defines all the valid permissions for a user
	ValidPerms = []string{PermAny, PermListItems, PermDownload, PermUpload, PermOverwrite, PermCreateDirs, PermRename,
		PermRenameFiles, PermRenameDirs, PermDelete, PermDeleteFiles, PermDeleteDirs, PermCopy, PermCreateSymlinks,
		PermChmod, PermChown, PermChtimes}
	// ValidLoginMethods defines all the valid login methods
	ValidLoginMethods = []string{SSHLoginMethodPublicKey, LoginMethodPassword, SSHLoginMethodPassword,
		SSHLoginMethodKeyboardInteractive, SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt,
		LoginMethodTLSCertificate, LoginMethodTLSCertificateAndPwd}
	// SSHMultiStepsLoginMethods defines the supported Multi-Step Authentications
	SSHMultiStepsLoginMethods = []string{SSHLoginMethodKeyAndPassword, SSHLoginMethodKeyAndKeyboardInt}
	// ErrNoAuthTried defines the error for connection closed before authentication
	ErrNoAuthTried = errors.New("no auth tried")
	// ErrNotImplemented defines the error for features not supported for a particular data provider
	ErrNotImplemented = errors.New("feature not supported with the configured data provider")
	// ValidProtocols defines all the valid protcols
	ValidProtocols = []string{protocolSSH, protocolFTP, protocolWebDAV, protocolHTTP}
	// MFAProtocols defines the supported protocols for multi-factor authentication
	MFAProtocols = []string{protocolHTTP, protocolSSH, protocolFTP}
	// ErrNoInitRequired defines the error returned by InitProvider if no inizialization/update is required
	ErrNoInitRequired = errors.New("the data provider is up to date")
	// ErrInvalidCredentials defines the error to return if the supplied credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrLoginNotAllowedFromIP defines the error to return if login is denied from the current IP
	ErrLoginNotAllowedFromIP = errors.New("login is not allowed from this IP")
	// ErrDuplicatedKey occurs when there is a unique key constraint violation
	ErrDuplicatedKey = errors.New("duplicated key not allowed")
	// ErrForeignKeyViolated occurs when there is a foreign key constraint violation
	ErrForeignKeyViolated = errors.New("violates foreign key constraint")
	// ErrShareUsageExceeded is returned when reserving share usage tokens would exceed the share max_tokens limit
	ErrShareUsageExceeded = util.NewI18nError(
		util.NewRecordNotFoundError("max share usage exceeded"), util.I18nErrorShareUsage)
	errInvalidInput         = util.NewValidationError("Invalid input. Slashes (/ ), colons (:), control characters, and reserved system names are not allowed")
	tz                      = ""
	isAdminCreated          atomic.Bool
	validTLSUsernames       = []string{string(sdk.TLSUsernameNone), string(sdk.TLSUsernameCN)}
	sqlPlaceholders         []string
	internalHashPwdPrefixes = []string{argonPwdPrefix, bcryptPwdPrefix}
	hashPwdPrefixes         = []string{argonPwdPrefix, bcryptPwdPrefix, pbkdf2SHA1Prefix, pbkdf2SHA256Prefix,
		pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix, md5cryptPwdPrefix, md5cryptApr1PwdPrefix, md5DigestPwdPrefix,
		sha256DigestPwdPrefix, sha512DigestPwdPrefix, sha256cryptPwdPrefix, sha512cryptPwdPrefix, yescryptPwdPrefix}
	pbkdfPwdPrefixes        = []string{pbkdf2SHA1Prefix, pbkdf2SHA256Prefix, pbkdf2SHA512Prefix, pbkdf2SHA256B64SaltPrefix}
	pbkdfPwdB64SaltPrefixes = []string{pbkdf2SHA256B64SaltPrefix}
	unixPwdPrefixes         = []string{md5cryptPwdPrefix, md5cryptApr1PwdPrefix, sha256cryptPwdPrefix, sha512cryptPwdPrefix,
		yescryptPwdPrefix}
	digestPwdPrefixes            = []string{md5DigestPwdPrefix, sha256DigestPwdPrefix, sha512DigestPwdPrefix}
	sharedProviders              = []string{PGSQLDataProviderName, MySQLDataProviderName, CockroachDataProviderName}
	logSender                    = "dataprovider"
	sqlTableUsers                string
	sqlTableFolders              string
	sqlTableUsersFoldersMapping  string
	sqlTableAdmins               string
	sqlTableAPIKeys              string
	sqlTableShares               string
	sqlTableSharesGroupsMapping  string
	sqlTableDefenderHosts        string
	sqlTableDefenderEvents       string
	sqlTableActiveTransfers      string
	sqlTableGroups               string
	sqlTableUsersGroupsMapping   string
	sqlTableAdminsGroupsMapping  string
	sqlTableGroupsFoldersMapping string
	sqlTableSharedSessions       string
	sqlTableEventsActions        string
	sqlTableEventsRules          string
	sqlTableRulesActionsMapping  string
	sqlTableTasks                string
	sqlTableNodes                string
	sqlTableRoles                string
	sqlTableIPLists              string
	sqlTableConfigs              string
	sqlTableSchemaVersion        string
	lastLoginMinDelay            = 10 * time.Minute
	usernameRegex                = regexp.MustCompile("^[a-zA-Z0-9-_.~]+$")
	tempPath                     string
	allowSelfConnections         int
	fnReloadRules                FnReloadRules
	fnRemoveRule                 FnRemoveRule
	fnHandleRuleForProviderEvent FnHandleRuleForProviderEvent
)

func initSQLTables() {
	sqlTableUsers = "users"
	sqlTableFolders = "folders"
	sqlTableUsersFoldersMapping = "users_folders_mapping"
	sqlTableAdmins = "admins"
	sqlTableAPIKeys = "api_keys"
	sqlTableShares = "shares"
	sqlTableSharesGroupsMapping = "shares_groups_mapping"
	sqlTableDefenderHosts = "defender_hosts"
	sqlTableDefenderEvents = "defender_events"
	sqlTableActiveTransfers = "active_transfers"
	sqlTableGroups = "groups"
	sqlTableUsersGroupsMapping = "users_groups_mapping"
	sqlTableGroupsFoldersMapping = "groups_folders_mapping"
	sqlTableAdminsGroupsMapping = "admins_groups_mapping"
	sqlTableSharedSessions = "shared_sessions"
	sqlTableEventsActions = "events_actions"
	sqlTableEventsRules = "events_rules"
	sqlTableRulesActionsMapping = "rules_actions_mapping"
	sqlTableTasks = "tasks"
	sqlTableNodes = "nodes"
	sqlTableRoles = "roles"
	sqlTableIPLists = "ip_lists"
	sqlTableConfigs = "configurations"
	sqlTableSchemaVersion = "schema_version"
}

// FnReloadRules defined the callback to reload event rules
type FnReloadRules func()

// FnRemoveRule defines the callback to remove an event rule
type FnRemoveRule func(name string)

// FnHandleRuleForProviderEvent define the callback to handle event rules for provider events
type FnHandleRuleForProviderEvent func(operation, executor, ip, objectType, objectName, role string, object plugin.Renderer)

// SetEventRulesCallbacks sets the event rules callbacks
func SetEventRulesCallbacks(reload FnReloadRules, remove FnRemoveRule, handle FnHandleRuleForProviderEvent) {
	fnReloadRules = reload
	fnRemoveRule = remove
	fnHandleRuleForProviderEvent = handle
}

type schemaVersion struct {
	Version int
}

// BcryptOptions defines the options for bcrypt password hashing
type BcryptOptions struct {
	Cost int `json:"cost" mapstructure:"cost"`
}

// Argon2Options defines the options for argon2 password hashing
type Argon2Options struct {
	Memory      uint32 `json:"memory" mapstructure:"memory"`
	Iterations  uint32 `json:"iterations" mapstructure:"iterations"`
	Parallelism uint8  `json:"parallelism" mapstructure:"parallelism"`
}

// PasswordHashing defines the configuration for password hashing
type PasswordHashing struct {
	BcryptOptions BcryptOptions `json:"bcrypt_options" mapstructure:"bcrypt_options"`
	Argon2Options Argon2Options `json:"argon2_options" mapstructure:"argon2_options"`
	// Algorithm to use for hashing passwords. Available algorithms: argon2id, bcrypt. Default: bcrypt
	Algo string `json:"algo" mapstructure:"algo"`
}

// PasswordValidationRules defines the password validation rules
type PasswordValidationRules struct {
	// MinEntropy defines the minimum password entropy.
	// 0 means disabled, any password will be accepted.
	// Take a look at the following link for more details
	// https://github.com/wagslane/go-password-validator#what-entropy-value-should-i-use
	MinEntropy float64 `json:"min_entropy" mapstructure:"min_entropy"`
}

// PasswordValidation defines the password validation rules for admins and protocol users
type PasswordValidation struct {
	// Password validation rules for SFTPxy admin users
	Admins PasswordValidationRules `json:"admins" mapstructure:"admins"`
	// Password validation rules for SFTPxy protocol users
	Users PasswordValidationRules `json:"users" mapstructure:"users"`
}

type wrappedFolder struct {
	Folder vfs.BaseVirtualFolder
}

func (w *wrappedFolder) RenderAsJSON(reload bool) ([]byte, error) {
	if reload {
		folder, err := holder.getProvider().getFolderByName(w.Folder.Name)
		if err != nil {
			providerLog(logger.LevelError, "unable to reload folder before rendering as json: %v", err)
			return nil, err
		}
		folder.PrepareForRendering()
		return json.Marshal(folder)
	}
	w.Folder.PrepareForRendering()
	return json.Marshal(w.Folder)
}

// ObjectsActions defines the action to execute on user create, update, delete for the specified objects
type ObjectsActions struct {
	// Valid values are add, update, delete. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Valid values are user, admin, api_key
	ExecuteFor []string `json:"execute_for" mapstructure:"execute_for"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

// ProviderStatus defines the provider status
type ProviderStatus struct {
	Driver   string `json:"driver"`
	IsActive bool   `json:"is_active"`
	Error    string `json:"error"`
}

// Config defines the provider configuration
type Config struct {
	// Driver name, must be one of the SupportedProviders
	Driver string `json:"driver" mapstructure:"driver"`
	// Database name. For driver sqlite this can be the database name relative to the config dir
	// or the absolute path to the SQLite database.
	Name string `json:"name" mapstructure:"name"`
	// Database host. For postgresql and cockroachdb driver you can specify multiple hosts separated by commas
	Host string `json:"host" mapstructure:"host"`
	// Database port
	Port int `json:"port" mapstructure:"port"`
	// Database username
	Username string `json:"username" mapstructure:"username"`
	// Database password
	Password string `json:"password" mapstructure:"password"`
	// Path to a file containing the database password. If set, the password is
	// read from this file at startup, overriding the Password field. The path
	// can be absolute or relative to the configuration directory.
	PasswordFile string `json:"password_file" mapstructure:"password_file"`
	// Used for drivers mysql and postgresql.
	// 0 disable SSL/TLS connections.
	// 1 require ssl.
	// 2 set ssl mode to verify-ca for driver postgresql and skip-verify for driver mysql.
	// 3 set ssl mode to verify-full for driver postgresql and preferred for driver mysql.
	SSLMode int `json:"sslmode" mapstructure:"sslmode"`
	// Used for drivers mysql, postgresql and cockroachdb. Set to true to disable SNI
	DisableSNI bool `json:"disable_sni" mapstructure:"disable_sni"`
	// TargetSessionAttrs is a postgresql and cockroachdb specific option.
	// It determines whether the session must have certain properties to be acceptable.
	// It's typically used in combination with multiple host names to select the first
	// acceptable alternative among several hosts
	TargetSessionAttrs string `json:"target_session_attrs" mapstructure:"target_session_attrs"`
	// Path to the root certificate authority used to verify that the server certificate was signed by a trusted CA
	RootCert string `json:"root_cert" mapstructure:"root_cert"`
	// Path to the client certificate for two-way TLS authentication
	ClientCert string `json:"client_cert" mapstructure:"client_cert"`
	// Path to the client key for two-way TLS authentication
	ClientKey string `json:"client_key" mapstructure:"client_key"`
	// Custom database connection string.
	// If not empty this connection string will be used instead of build one using the previous parameters
	ConnectionString string `json:"connection_string" mapstructure:"connection_string"`
	// prefix for SQL tables
	SQLTablesPrefix string `json:"sql_tables_prefix" mapstructure:"sql_tables_prefix"`
	// Set the preferred way to track users quota between the following choices:
	// 0, disable quota tracking. REST API to scan user dir and update quota will do nothing
	// 1, quota is updated each time a user upload or delete a file even if the user has no quota restrictions
	// 2, quota is updated each time a user upload or delete a file but only for users with quota restrictions
	//    and for virtual folders.
	//    With this configuration the "quota scan" REST API can still be used to periodically update space usage
	//    for users without quota restrictions
	TrackQuota int `json:"track_quota" mapstructure:"track_quota"`
	// Sets the maximum number of open connections for mysql and postgresql driver.
	// Default 0 (unlimited)
	PoolSize int `json:"pool_size" mapstructure:"pool_size"`
	// Users default base directory.
	// If no home dir is defined while adding a new user, and this value is
	// a valid absolute path, then the user home dir will be automatically
	// defined as the path obtained joining the base dir and the username
	UsersBaseDir string `json:"users_base_dir" mapstructure:"users_base_dir"`
	// Actions to execute on objects add, update, delete.
	// The supported objects are user, admin, api_key.
	// Update action will not be fired for internal updates such as the last login or the user quota fields.
	Actions ObjectsActions `json:"actions" mapstructure:"actions"`
	// Absolute path to an external program or an HTTP URL to invoke for users authentication.
	// Leave empty to use builtin authentication.
	// If the authentication succeed the user will be automatically added/updated inside the defined data provider.
	// Actions defined for user added/updated will not be executed in this case.
	// This method is slower than built-in authentication methods, but it's very flexible as anyone can
	// easily write his own authentication hooks.
	ExternalAuthHook string `json:"external_auth_hook" mapstructure:"external_auth_hook"`
	// ExternalAuthScope defines the scope for the external authentication hook.
	// - 0 means all supported authentication scopes, the external hook will be executed for password,
	//     public key, keyboard interactive authentication and TLS certificates
	// - 1 means passwords only
	// - 2 means public keys only
	// - 4 means keyboard interactive only
	// - 8 means TLS certificates only
	// you can combine the scopes, for example 3 means password and public key, 5 password and keyboard
	// interactive and so on
	ExternalAuthScope int `json:"external_auth_scope" mapstructure:"external_auth_scope"`
	// Absolute path to an external program or an HTTP URL to invoke just before the user login.
	// This program/URL allows to modify or create the user trying to login.
	// It is useful if you have users with dynamic fields to update just before the login.
	// Please note that if you want to create a new user, the pre-login hook response must
	// include all the mandatory user fields.
	//
	// The pre-login hook must finish within 30 seconds.
	//
	// If an error happens while executing the "PreLoginHook" then login will be denied.
	// PreLoginHook and ExternalAuthHook are mutally exclusive.
	// Leave empty to disable.
	PreLoginHook string `json:"pre_login_hook" mapstructure:"pre_login_hook"`
	// Absolute path to an external program or an HTTP URL to invoke after the user login.
	// Based on the configured scope you can choose if notify failed or successful logins
	// or both
	PostLoginHook string `json:"post_login_hook" mapstructure:"post_login_hook"`
	// PostLoginScope defines the scope for the post-login hook.
	// - 0 means notify both failed and successful logins
	// - 1 means notify failed logins
	// - 2 means notify successful logins
	PostLoginScope int `json:"post_login_scope" mapstructure:"post_login_scope"`
	// Absolute path to an external program or an HTTP URL to invoke just before password
	// authentication. This hook allows you to externally check the provided password,
	// its main use case is to allow to easily support things like password+OTP for protocols
	// without keyboard interactive support such as FTP and WebDAV. You can ask your users
	// to login using a string consisting of a fixed password and a One Time Token, you
	// can verify the token inside the hook and ask to SFTPxy to verify the fixed part.
	CheckPasswordHook string `json:"check_password_hook" mapstructure:"check_password_hook"`
	// CheckPasswordScope defines the scope for the check password hook.
	// - 0 means all protocols
	// - 1 means SSH
	// - 2 means FTP
	// - 4 means WebDAV
	// you can combine the scopes, for example 6 means FTP and WebDAV
	CheckPasswordScope int `json:"check_password_scope" mapstructure:"check_password_scope"`
	// Defines how the database will be initialized/updated:
	// - 0 means automatically
	// - 1 means manually using the initprovider sub-command
	UpdateMode int `json:"update_mode" mapstructure:"update_mode"`
	// PasswordHashing defines the configuration for password hashing
	PasswordHashing PasswordHashing `json:"password_hashing" mapstructure:"password_hashing"`
	// PasswordValidation defines the password validation rules
	PasswordValidation PasswordValidation `json:"password_validation" mapstructure:"password_validation"`
	// Verifying argon2 passwords has a high memory and computational cost,
	// by enabling, in memory, password caching you reduce this cost.
	PasswordCaching bool `json:"password_caching" mapstructure:"password_caching"`
	// DelayedQuotaUpdate defines the number of seconds to accumulate quota updates.
	// If there are a lot of close uploads, accumulating quota updates can save you many
	// queries to the data provider.
	// If you want to track quotas, a scheduled quota update is recommended in any case, the stored
	// quota size may be incorrect for several reasons, such as an unexpected shutdown, temporary provider
	// failures, file copied outside of SFTPxy, and so on.
	// 0 means immediate quota update.
	DelayedQuotaUpdate int `json:"delayed_quota_update" mapstructure:"delayed_quota_update"`
	// If enabled, a default admin user with username "admin" and password "password" will be created
	// on first start.
	// You can also create the first admin user by using the web interface or by loading initial data.
	CreateDefaultAdmin bool `json:"create_default_admin" mapstructure:"create_default_admin"`
	// Rules for usernames and folder names:
	// - 0 means no rules
	// - 1 means you can use any UTF-8 character. The names are used in URIs for REST API and Web admin.
	//     By default only unreserved URI characters are allowed: ALPHA / DIGIT / "-" / "." / "_" / "~".
	// - 2 means names are converted to lowercase before saving/matching and so case
	//     insensitive matching is possible
	// - 4 means trimming trailing and leading white spaces before saving/matching
	// Rules can be combined, for example 3 means both converting to lowercase and allowing any UTF-8 character.
	// Enabling these options for existing installations could be backward incompatible, some users
	// could be unable to login, for example existing users with mixed cases in their usernames.
	// You have to ensure that all existing users respect the defined rules.
	NamingRules int `json:"naming_rules" mapstructure:"naming_rules"`
	// If the data provider is shared across multiple SFTPxy instances, set this parameter to 1.
	// MySQL, PostgreSQL and CockroachDB can be shared, this setting is ignored for other data
	// providers. For shared data providers, SFTPxy periodically reloads the latest updated users,
	// based on the "updated_at" field, and updates its internal caches if users are updated from
	// a different instance. This check, if enabled, is executed every 10 minutes.
	// For shared data providers, active transfers are persisted in the database and thus
	// quota checks between ongoing transfers will work cross multiple instances
	IsShared int `json:"is_shared" mapstructure:"is_shared"`
	// Node defines the configuration for this cluster node.
	// Ignored if the provider is not shared/shareable
	Node NodeConfig `json:"node" mapstructure:"node"`
	// Path to the backup directory. This can be an absolute path or a path relative to the config dir
	BackupsPath string `json:"backups_path" mapstructure:"backups_path"`
}

// GetShared returns the provider share mode.
// This method is called before the provider is initialized
func (c *Config) GetShared() int {
	if !slices.Contains(sharedProviders, c.Driver) {
		return 0
	}
	return c.IsShared
}

func (c *Config) convertName(name string) string {
	if c.NamingRules <= 1 {
		return name
	}
	if c.NamingRules&2 != 0 {
		name = strings.ToLower(name)
	}
	if c.NamingRules&4 != 0 {
		name = strings.TrimSpace(name)
	}

	return name
}

// IsDefenderSupported returns true if the configured provider supports the defender
func (c *Config) IsDefenderSupported() bool {
	switch c.Driver {
	case MySQLDataProviderName, PGSQLDataProviderName, CockroachDataProviderName:
		return true
	default:
		return false
	}
}

func (c *Config) requireCustomTLSForMySQL() bool {
	if holder.getConfig().DisableSNI {
		return holder.getConfig().SSLMode != 0
	}
	if holder.getConfig().RootCert != "" && util.IsFileInputValid(holder.getConfig().RootCert) {
		return holder.getConfig().SSLMode != 0
	}
	if holder.getConfig().ClientCert != "" && holder.getConfig().ClientKey != "" && util.IsFileInputValid(holder.getConfig().ClientCert) &&
		util.IsFileInputValid(holder.getConfig().ClientKey) {
		return holder.getConfig().SSLMode != 0
	}
	return false
}

func (c *Config) doBackup() (string, error) {
	now := time.Now().UTC()
	outputFile := filepath.Join(c.BackupsPath, fmt.Sprintf("backup_%s_%d.json", now.Weekday(), now.Hour()))
	providerLog(logger.LevelDebug, "starting backup to file %q", outputFile)
	err := os.MkdirAll(filepath.Dir(outputFile), 0700)
	if err != nil {
		providerLog(logger.LevelError, "unable to create backup dir %q: %v", outputFile, err)
		return outputFile, fmt.Errorf("unable to create backup dir: %w", err)
	}
	backup, err := DumpData(nil)
	if err != nil {
		providerLog(logger.LevelError, "unable to execute backup: %v", err)
		return outputFile, fmt.Errorf("unable to dump backup data: %w", err)
	}
	dump, err := json.Marshal(backup)
	if err != nil {
		providerLog(logger.LevelError, "unable to marshal backup as JSON: %v", err)
		return outputFile, fmt.Errorf("unable to marshal backup data as JSON: %w", err)
	}
	err = os.WriteFile(outputFile, dump, 0600)
	if err != nil {
		providerLog(logger.LevelError, "unable to save backup: %v", err)
		return outputFile, fmt.Errorf("unable to save backup: %w", err)
	}
	providerLog(logger.LevelDebug, "backup saved to %q", outputFile)
	return outputFile, nil
}

// SetTZ sets the configured timezone.
func SetTZ(val string) {
	tz = val
}

// UseLocalTime returns true if local time should be used instead of UTC.
func UseLocalTime() bool {
	return tz == "local"
}

// ExecuteBackup executes a backup
func ExecuteBackup() (string, error) {
	return holder.getConfig().doBackup()
}

// ConvertName converts the given name based on the configured rules
func ConvertName(name string) string {
	return holder.getConfig().convertName(name)
}

// IsSharedMode returns true if the data provider is configured as shared (cluster mode).
func IsSharedMode() bool {
	return holder.getConfig().IsShared == 1
}

// ActiveTransfer defines an active protocol transfer
type ActiveTransfer struct {
	ID            int64
	Type          int
	ConnID        string
	Username      string
	FolderName    string
	IP            string
	TruncatedSize int64
	CurrentULSize int64
	CurrentDLSize int64
	CreatedAt     int64
	UpdatedAt     int64
}

// TransferQuota stores the allowed transfer quota fields
type TransferQuota struct {
	ULSize           int64
	DLSize           int64
	TotalSize        int64
	AllowedULSize    int64
	AllowedDLSize    int64
	AllowedTotalSize int64
}

// HasSizeLimits returns true if any size limit is set
func (q *TransferQuota) HasSizeLimits() bool {
	return q.AllowedDLSize > 0 || q.AllowedULSize > 0 || q.AllowedTotalSize > 0
}

// HasUploadSpace returns true if there is transfer upload space available
func (q *TransferQuota) HasUploadSpace() bool {
	if q.TotalSize <= 0 && q.ULSize <= 0 {
		return true
	}
	if q.TotalSize > 0 {
		return q.AllowedTotalSize > 0
	}
	return q.AllowedULSize > 0
}

// HasDownloadSpace returns true if there is transfer download space available
func (q *TransferQuota) HasDownloadSpace() bool {
	if q.TotalSize <= 0 && q.DLSize <= 0 {
		return true
	}
	if q.TotalSize > 0 {
		return q.AllowedTotalSize > 0
	}
	return q.AllowedDLSize > 0
}

// DefenderEntry defines a defender entry
type DefenderEntry struct {
	ID      int64     `json:"-"`
	IP      string    `json:"ip"`
	Score   int       `json:"score,omitempty"`
	BanTime time.Time `json:"ban_time,omitempty"`
}

// GetID returns an unique ID for a defender entry
func (d *DefenderEntry) GetID() string {
	return hex.EncodeToString([]byte(d.IP))
}

// GetBanTime returns the ban time for a defender entry as string
func (d *DefenderEntry) GetBanTime() string {
	if d.BanTime.IsZero() {
		return ""
	}
	return d.BanTime.UTC().Format(time.RFC3339)
}

// MarshalJSON returns the JSON encoding of a DefenderEntry.
func (d *DefenderEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID      string `json:"id"`
		IP      string `json:"ip"`
		Score   int    `json:"score,omitempty"`
		BanTime string `json:"ban_time,omitempty"`
	}{
		ID:      d.GetID(),
		IP:      d.IP,
		Score:   d.Score,
		BanTime: d.GetBanTime(),
	})
}

// BackupData defines the structure for the backup/restore files
type BackupData struct {
	Users        []User                  `json:"users"`
	Groups       []Group                 `json:"groups"`
	Folders      []vfs.BaseVirtualFolder `json:"folders"`
	Admins       []Admin                 `json:"admins"`
	APIKeys      []APIKey                `json:"api_keys"`
	Shares       []Share                 `json:"shares"`
	EventActions []BaseEventAction       `json:"event_actions"`
	EventRules   []EventRule             `json:"event_rules"`
	Roles        []Role                  `json:"roles"`
	IPLists      []IPListEntry           `json:"ip_lists"`
	Configs      *Configs                `json:"configs"`
	Version      int                     `json:"version"`
}

// HasFolder returns true if the folder with the given name is included
func (d *BackupData) HasFolder(name string) bool {
	for _, folder := range d.Folders {
		if folder.Name == name {
			return true
		}
	}
	return false
}

type checkPasswordRequest struct {
	Username string `json:"username"`
	IP       string `json:"ip"`
	Password string `json:"password"`
	Protocol string `json:"protocol"`
}

type checkPasswordResponse struct {
	// 0 KO, 1 OK, 2 partial success, -1 not executed
	Status int `json:"status"`
	// for status = 2 this is the password to check against the one stored
	// inside the SFTPxy data provider
	ToVerify string `json:"to_verify"`
}

// GetQuotaTracking returns the configured mode for user's quota tracking
func GetQuotaTracking() int {
	return holder.getConfig().TrackQuota
}

// HasUsersBaseDir returns true if users base dir is set
func HasUsersBaseDir() bool {
	return holder.getConfig().UsersBaseDir != ""
}

// Provider is the composed contract every data backend must satisfy.
// Its definition lives in provider_iface.go, where it is assembled from
// domain-focused sub-interfaces (AuthStore, UserStore, FolderStore, ...).
// Keeping the decomposition in a dedicated file lets each capability be
// referenced and mocked independently in tests.

// SetAllowSelfConnections sets the desired behaviour for self connections
func SetAllowSelfConnections(value int) {
	allowSelfConnections = value
}

// SetTempPath sets the path for temporary files
func SetTempPath(fsPath string) {
	tempPath = fsPath
}
