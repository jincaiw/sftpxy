// Copyright (C) 2024 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/sftpgo/sdk"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func createProvider(basePath string) error {
	sqlPlaceholders = getSQLPlaceholders()
	if err := validateSQLTablesPrefix(); err != nil {
		return err
	}
	logSender = fmt.Sprintf("dataprovider_%v", holder.getConfig().Driver)

	switch holder.getConfig().Driver {
	case SQLiteDataProviderName:
		return initializeSQLiteProvider(basePath)
	case PGSQLDataProviderName, CockroachDataProviderName:
		return initializePGSQLProvider()
	case MySQLDataProviderName:
		return initializeMySQLProvider()
	case BoltDataProviderName:
		return initializeBoltProvider(basePath)
	case MemoryDataProviderName:
		if err := initializeMemoryProvider(basePath); err != nil {
			logger.Warn(logSender, "", "provider initialized but data loading failed: %v", err)
			logger.WarnToConsole("provider initialized but data loading failed: %v", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported data provider: %v", holder.getConfig().Driver)
	}
}

func copyBaseUserFilters(in sdk.BaseUserFilters) sdk.BaseUserFilters {
	filters := sdk.BaseUserFilters{}
	filters.MaxUploadFileSize = in.MaxUploadFileSize
	filters.TLSUsername = in.TLSUsername
	filters.UserType = in.UserType
	filters.AllowedIP = make([]string, len(in.AllowedIP))
	copy(filters.AllowedIP, in.AllowedIP)
	filters.DeniedIP = make([]string, len(in.DeniedIP))
	copy(filters.DeniedIP, in.DeniedIP)
	filters.DeniedLoginMethods = make([]string, len(in.DeniedLoginMethods))
	copy(filters.DeniedLoginMethods, in.DeniedLoginMethods)
	filters.FilePatterns = make([]sdk.PatternsFilter, len(in.FilePatterns))
	copy(filters.FilePatterns, in.FilePatterns)
	filters.DeniedProtocols = make([]string, len(in.DeniedProtocols))
	copy(filters.DeniedProtocols, in.DeniedProtocols)
	filters.TwoFactorAuthProtocols = make([]string, len(in.TwoFactorAuthProtocols))
	copy(filters.TwoFactorAuthProtocols, in.TwoFactorAuthProtocols)
	filters.Hooks.ExternalAuthDisabled = in.Hooks.ExternalAuthDisabled
	filters.Hooks.PreLoginDisabled = in.Hooks.PreLoginDisabled
	filters.Hooks.CheckPasswordDisabled = in.Hooks.CheckPasswordDisabled
	filters.DisableFsChecks = in.DisableFsChecks
	filters.StartDirectory = in.StartDirectory
	filters.FTPSecurity = in.FTPSecurity
	filters.IsAnonymous = in.IsAnonymous
	filters.AllowAPIKeyAuth = in.AllowAPIKeyAuth
	filters.ExternalAuthCacheTime = in.ExternalAuthCacheTime
	filters.DefaultSharesExpiration = in.DefaultSharesExpiration
	filters.MaxSharesExpiration = in.MaxSharesExpiration
	filters.PasswordExpiration = in.PasswordExpiration
	filters.PasswordStrength = in.PasswordStrength
	filters.WebClient = make([]string, len(in.WebClient))
	copy(filters.WebClient, in.WebClient)
	filters.TLSCerts = make([]string, len(in.TLSCerts))
	copy(filters.TLSCerts, in.TLSCerts)
	filters.BandwidthLimits = make([]sdk.BandwidthLimit, 0, len(in.BandwidthLimits))
	for _, limit := range in.BandwidthLimits {
		bwLimit := sdk.BandwidthLimit{
			UploadBandwidth:   limit.UploadBandwidth,
			DownloadBandwidth: limit.DownloadBandwidth,
			Sources:           make([]string, 0, len(limit.Sources)),
		}
		bwLimit.Sources = make([]string, len(limit.Sources))
		copy(bwLimit.Sources, limit.Sources)
		filters.BandwidthLimits = append(filters.BandwidthLimits, bwLimit)
	}
	filters.AccessTime = make([]sdk.TimePeriod, 0, len(in.AccessTime))
	for _, period := range in.AccessTime {
		filters.AccessTime = append(filters.AccessTime, sdk.TimePeriod{
			DayOfWeek: period.DayOfWeek,
			From:      period.From,
			To:        period.To,
		})
	}
	return filters
}

func buildUserHomeDir(user *User) {
	if user.HomeDir == "" {
		if holder.getConfig().UsersBaseDir != "" {
			user.HomeDir = filepath.Join(holder.getConfig().UsersBaseDir, user.Username)
			return
		}
		switch user.FsConfig.Provider {
		case sdk.SFTPFilesystemProvider, sdk.S3FilesystemProvider, sdk.AzureBlobFilesystemProvider, sdk.GCSFilesystemProvider, sdk.HTTPFilesystemProvider:
			if tempPath != "" {
				user.HomeDir = filepath.Join(tempPath, user.Username)
			} else {
				user.HomeDir = filepath.Join(os.TempDir(), user.Username)
			}
		}
	} else {
		user.HomeDir = filepath.Clean(user.HomeDir)
	}
}

func validateFolderQuotaLimits(folder vfs.VirtualFolder) error {
	if folder.QuotaSize < -1 {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("invalid quota_size: %v folder path %q", folder.QuotaSize, folder.MappedPath)),
			util.I18nErrorFolderQuotaSizeInvalid,
		)
	}
	if folder.QuotaFiles < -1 {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("invalid quota_file: %v folder path %q", folder.QuotaFiles, folder.MappedPath)),
			util.I18nErrorFolderQuotaFileInvalid,
		)
	}
	if (folder.QuotaSize == -1 && folder.QuotaFiles != -1) || (folder.QuotaFiles == -1 && folder.QuotaSize != -1) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("virtual folder quota_size and quota_files must be both -1 or >= 0, quota_size: %v quota_files: %v",
				folder.QuotaFiles, folder.QuotaSize)),
			util.I18nErrorFolderQuotaInvalid,
		)
	}
	return nil
}

func validateUserGroups(user *User) error {
	if len(user.Groups) == 0 {
		return nil
	}
	hasPrimary := false
	groupNames := make(map[string]bool)

	for _, g := range user.Groups {
		if g.Type < sdk.GroupTypePrimary || g.Type > sdk.GroupTypeMembership {
			return util.NewValidationError(fmt.Sprintf("invalid group type: %v", g.Type))
		}
		if g.Type == sdk.GroupTypePrimary {
			if hasPrimary {
				return util.NewI18nError(
					util.NewValidationError("only one primary group is allowed"),
					util.I18nErrorPrimaryGroup,
				)
			}
			hasPrimary = true
		}
		if groupNames[g.Name] {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("the group %q is duplicated", g.Name)),
				util.I18nErrorDuplicateGroup,
			)
		}
		groupNames[g.Name] = true
	}
	return nil
}

func validateAssociatedVirtualFolders(vfolders []vfs.VirtualFolder) ([]vfs.VirtualFolder, error) {
	if len(vfolders) == 0 {
		return []vfs.VirtualFolder{}, nil
	}
	var virtualFolders []vfs.VirtualFolder
	folderNames := make(map[string]bool)

	for _, v := range vfolders {
		v.Name = holder.getConfig().convertName(v.Name)
		if v.VirtualPath == "" {
			return nil, util.NewI18nError(
				util.NewValidationError("mount/virtual path is mandatory"),
				util.I18nErrorFolderMountPathRequired,
			)
		}
		cleanedVPath := util.CleanPath(v.VirtualPath)
		if err := validateFolderQuotaLimits(v); err != nil {
			return nil, err
		}
		if v.Name == "" {
			return nil, util.NewI18nError(util.NewValidationError("folder name is mandatory"), util.I18nErrorFolderNameRequired)
		}
		if folderNames[v.Name] {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("the folder %q is duplicated", v.Name)),
				util.I18nErrorDuplicatedFolders,
			)
		}
		for _, vFolder := range virtualFolders {
			if util.IsDirOverlapped(vFolder.VirtualPath, cleanedVPath, false, "/") {
				return nil, util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid virtual folder %q, it overlaps with virtual folder %q",
						v.VirtualPath, vFolder.VirtualPath)),
					util.I18nErrorOverlappedFolders,
				)
			}
		}
		virtualFolders = append(virtualFolders, vfs.VirtualFolder{
			BaseVirtualFolder: vfs.BaseVirtualFolder{
				Name: v.Name,
			},
			VirtualPath: cleanedVPath,
			QuotaSize:   v.QuotaSize,
			QuotaFiles:  v.QuotaFiles,
		})
		folderNames[v.Name] = true
	}
	return virtualFolders, nil
}

func validateUserTOTPConfig(c *UserTOTPConfig, username string) error {
	if !c.Enabled {
		c.ConfigName = ""
		c.Secret = kms.NewEmptySecret()
		c.Protocols = nil
		return nil
	}
	if c.ConfigName == "" {
		return util.NewValidationError("totp: config name is mandatory")
	}
	if !slices.Contains(mfa.GetAvailableTOTPConfigNames(), c.ConfigName) {
		return util.NewValidationError(fmt.Sprintf("totp: config name %q not found", c.ConfigName))
	}
	if c.Secret.IsEmpty() {
		return util.NewValidationError("totp: secret is mandatory")
	}
	if c.Secret.IsPlain() {
		c.Secret.SetAdditionalData(username)
		if err := c.Secret.Encrypt(); err != nil {
			return util.NewValidationError(fmt.Sprintf("totp: unable to encrypt secret: %v", err))
		}
	}
	if len(c.Protocols) == 0 {
		return util.NewValidationError("totp: specify at least one protocol")
	}
	for _, protocol := range c.Protocols {
		if !slices.Contains(MFAProtocols, protocol) {
			return util.NewValidationError(fmt.Sprintf("totp: invalid protocol %q", protocol))
		}
	}
	return nil
}

func validateUserRecoveryCodes(user *User) error {
	for i := 0; i < len(user.Filters.RecoveryCodes); i++ {
		code := &user.Filters.RecoveryCodes[i]
		if code.Secret.IsEmpty() {
			return util.NewValidationError("mfa: recovery code cannot be empty")
		}
		if code.Secret.IsPlain() {
			code.Secret.SetAdditionalData(user.Username)
			if err := code.Secret.Encrypt(); err != nil {
				return util.NewValidationError(fmt.Sprintf("mfa: unable to encrypt recovery code: %v", err))
			}
		}
	}
	return nil
}

func validateUserPermissions(permsToCheck map[string][]string) (map[string][]string, error) {
	permissions := make(map[string][]string)
	for dir, perms := range permsToCheck {
		if len(perms) == 0 && dir == "/" {
			return permissions, util.NewValidationError(fmt.Sprintf("no permissions granted for the directory: %q", dir))
		}
		if len(perms) > len(ValidPerms) {
			return permissions, util.NewValidationError("invalid permissions")
		}
		for _, p := range perms {
			if !slices.Contains(ValidPerms, p) {
				return permissions, util.NewValidationError(fmt.Sprintf("invalid permission: %q", p))
			}
		}
		cleanedDir := filepath.ToSlash(path.Clean(dir))
		if cleanedDir != "/" {
			cleanedDir = strings.TrimSuffix(cleanedDir, "/")
		}
		if !path.IsAbs(cleanedDir) {
			return permissions, util.NewValidationError(fmt.Sprintf("cannot set permissions for non absolute path: %q", dir))
		}
		if dir != cleanedDir && cleanedDir == "/" {
			return permissions, util.NewValidationError(fmt.Sprintf("cannot set permissions for invalid subdirectory: %q is an alias for \"/\"", dir))
		}
		if slices.Contains(perms, PermAny) {
			permissions[cleanedDir] = []string{PermAny}
		} else {
			permissions[cleanedDir] = util.RemoveDuplicates(perms, false)
		}
	}

	return permissions, nil
}

func validatePermissions(user *User) error {
	if len(user.Permissions) == 0 {
		return util.NewI18nError(util.NewValidationError("please grant some permissions to this user"), util.I18nErrorNoPermission)
	}
	if _, ok := user.Permissions["/"]; !ok {
		return util.NewI18nError(util.NewValidationError("permissions for the root dir \"/\" must be set"), util.I18nErrorNoRootPermission)
	}
	permissions, err := validateUserPermissions(user.Permissions)
	if err != nil {
		return util.NewI18nError(err, util.I18nErrorGenericPermission)
	}
	user.Permissions = permissions
	return nil
}

func validatePublicKeys(user *User) error {
	if len(user.PublicKeys) == 0 {
		user.PublicKeys = []string{}
	}
	var validatedKeys []string
	for idx, key := range user.PublicKeys {
		if key == "" {
			continue
		}
		out, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
		if err != nil {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("error parsing public key at position %d: %v", idx, err)),
				util.I18nErrorPubKeyInvalid,
			)
		}
		if out.Type() == ssh.InsecureKeyAlgoDSA { //nolint:staticcheck
			providerLog(logger.LevelError, "dsa public key not accepted, position: %d", idx)
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("DSA key format is insecure and it is not allowed for key at position %d", idx)),
				util.I18nErrorKeyInsecure,
			)
		}
		if k, ok := out.(ssh.CryptoPublicKey); ok {
			cryptoKey := k.CryptoPublicKey()
			if rsaKey, ok := cryptoKey.(*rsa.PublicKey); ok {
				if size := rsaKey.N.BitLen(); size < 2048 {
					providerLog(logger.LevelError, "rsa key with size %d at position %d not accepted, minimum 2048", size, idx)
					return util.NewI18nError(
						util.NewValidationError(fmt.Sprintf("invalid size %d for rsa key at position %d, minimum 2048",
							size, idx)),
						util.I18nErrorKeySizeInvalid,
					)
				}
			}
		}

		validatedKeys = append(validatedKeys, key)
	}
	user.PublicKeys = util.RemoveDuplicates(validatedKeys, false)
	return nil
}

func validateFiltersPatternExtensions(baseFilters *sdk.BaseUserFilters) error {
	if len(baseFilters.FilePatterns) == 0 {
		baseFilters.FilePatterns = []sdk.PatternsFilter{}
		return nil
	}
	filteredPaths := []string{}
	var filters []sdk.PatternsFilter
	for _, f := range baseFilters.FilePatterns {
		cleanedPath := filepath.ToSlash(path.Clean(f.Path))
		if !path.IsAbs(cleanedPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid path %q for file patterns filter", f.Path)),
				util.I18nErrorFilePatternPathInvalid,
			)
		}
		if slices.Contains(filteredPaths, cleanedPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("duplicate file patterns filter for path %q", f.Path)),
				util.I18nErrorFilePatternDuplicated,
			)
		}
		if len(f.AllowedPatterns) == 0 && len(f.DeniedPatterns) == 0 {
			return util.NewValidationError(fmt.Sprintf("empty file patterns filter for path %q", f.Path))
		}
		if f.DenyPolicy < sdk.DenyPolicyDefault || f.DenyPolicy > sdk.DenyPolicyHide {
			return util.NewValidationError(fmt.Sprintf("invalid deny policy %v for path %q", f.DenyPolicy, f.Path))
		}
		f.Path = cleanedPath
		allowed := make([]string, 0, len(f.AllowedPatterns))
		denied := make([]string, 0, len(f.DeniedPatterns))
		for _, pattern := range f.AllowedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid file pattern filter %q", pattern)),
					util.I18nErrorFilePatternInvalid,
				)
			}
			allowed = append(allowed, strings.ToLower(pattern))
		}
		for _, pattern := range f.DeniedPatterns {
			_, err := path.Match(pattern, "abc")
			if err != nil {
				return util.NewI18nError(
					util.NewValidationError(fmt.Sprintf("invalid file pattern filter %q", pattern)),
					util.I18nErrorFilePatternInvalid,
				)
			}
			denied = append(denied, strings.ToLower(pattern))
		}
		f.AllowedPatterns = util.RemoveDuplicates(allowed, false)
		f.DeniedPatterns = util.RemoveDuplicates(denied, false)
		filters = append(filters, f)
		filteredPaths = append(filteredPaths, cleanedPath)
	}
	baseFilters.FilePatterns = filters
	return nil
}

func checkEmptyFiltersStruct(filters *sdk.BaseUserFilters) {
	if len(filters.AllowedIP) == 0 {
		filters.AllowedIP = []string{}
	}
	if len(filters.DeniedIP) == 0 {
		filters.DeniedIP = []string{}
	}
	if len(filters.DeniedLoginMethods) == 0 {
		filters.DeniedLoginMethods = []string{}
	}
	if len(filters.DeniedProtocols) == 0 {
		filters.DeniedProtocols = []string{}
	}
}

func validateIPFilters(filters *sdk.BaseUserFilters) error {
	filters.DeniedIP = util.RemoveDuplicates(filters.DeniedIP, false)
	for _, IPMask := range filters.DeniedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse denied IP/Mask %q: %v", IPMask, err))
		}
	}
	filters.AllowedIP = util.RemoveDuplicates(filters.AllowedIP, false)
	for _, IPMask := range filters.AllowedIP {
		_, _, err := net.ParseCIDR(IPMask)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse allowed IP/Mask %q: %v", IPMask, err))
		}
	}
	return nil
}

func validateBandwidthLimit(bl sdk.BandwidthLimit) error {
	if len(bl.Sources) == 0 {
		return util.NewValidationError("no bandwidth limit source specified")
	}
	for _, source := range bl.Sources {
		_, _, err := net.ParseCIDR(source)
		if err != nil {
			return util.NewValidationError(fmt.Sprintf("could not parse bandwidth limit source %q: %v", source, err))
		}
	}
	return nil
}

func validateBandwidthLimitsFilter(filters *sdk.BaseUserFilters) error {
	for idx, bandwidthLimit := range filters.BandwidthLimits {
		if err := validateBandwidthLimit(bandwidthLimit); err != nil {
			return err
		}
		if bandwidthLimit.DownloadBandwidth < 0 {
			filters.BandwidthLimits[idx].DownloadBandwidth = 0
		}
		if bandwidthLimit.UploadBandwidth < 0 {
			filters.BandwidthLimits[idx].UploadBandwidth = 0
		}
	}
	return nil
}

func updateFiltersValues(filters *sdk.BaseUserFilters) {
	if filters.StartDirectory != "" {
		filters.StartDirectory = util.CleanPath(filters.StartDirectory)
		if filters.StartDirectory == "/" {
			filters.StartDirectory = ""
		}
	}
}

func validateFilterProtocols(filters *sdk.BaseUserFilters) error {
	if len(filters.DeniedProtocols) >= len(ValidProtocols) {
		return util.NewValidationError("invalid denied_protocols")
	}
	for _, p := range filters.DeniedProtocols {
		if !slices.Contains(ValidProtocols, p) {
			return util.NewValidationError(fmt.Sprintf("invalid denied protocol %q", p))
		}
	}

	for _, p := range filters.TwoFactorAuthProtocols {
		if !slices.Contains(MFAProtocols, p) {
			return util.NewValidationError(fmt.Sprintf("invalid two factor protocol %q", p))
		}
	}
	return nil
}

func validateTLSCerts(certs []string) ([]string, error) {
	var validateCerts []string
	for idx, cert := range certs {
		if cert == "" {
			continue
		}
		derBlock, _ := pem.Decode([]byte(cert))
		if derBlock == nil {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid TLS certificate %d", idx)),
				util.I18nErrorInvalidTLSCert,
			)
		}
		crt, err := x509.ParseCertificate(derBlock.Bytes)
		if err != nil {
			return nil, util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("error parsing TLS certificate %d", idx)),
				util.I18nErrorInvalidTLSCert,
			)
		}
		if crt.PublicKeyAlgorithm == x509.RSA {
			if rsaCert, ok := crt.PublicKey.(*rsa.PublicKey); ok {
				if size := rsaCert.N.BitLen(); size < 2048 {
					providerLog(logger.LevelError, "rsa cert with size %d not accepted, minimum 2048", size)
					return nil, util.NewI18nError(
						util.NewValidationError(fmt.Sprintf("invalid size %d for rsa cert at position %d, minimum 2048",
							size, idx)),
						util.I18nErrorKeySizeInvalid,
					)
				}
			}
		}
		validateCerts = append(validateCerts, cert)
	}
	return validateCerts, nil
}

func validateBaseFilters(filters *sdk.BaseUserFilters) error {
	checkEmptyFiltersStruct(filters)
	if err := validateIPFilters(filters); err != nil {
		return util.NewI18nError(err, util.I18nErrorIPFiltersInvalid)
	}
	if err := validateBandwidthLimitsFilter(filters); err != nil {
		return util.NewI18nError(err, util.I18nErrorSourceBWLimitInvalid)
	}
	if len(filters.DeniedLoginMethods) >= len(ValidLoginMethods) {
		return util.NewValidationError("invalid denied_login_methods")
	}
	for _, loginMethod := range filters.DeniedLoginMethods {
		if !slices.Contains(ValidLoginMethods, loginMethod) {
			return util.NewValidationError(fmt.Sprintf("invalid login method: %q", loginMethod))
		}
	}
	if err := validateFilterProtocols(filters); err != nil {
		return err
	}
	if filters.TLSUsername != "" {
		if !slices.Contains(validTLSUsernames, string(filters.TLSUsername)) {
			return util.NewValidationError(fmt.Sprintf("invalid TLS username: %q", filters.TLSUsername))
		}
	}
	certs, err := validateTLSCerts(filters.TLSCerts)
	if err != nil {
		return err
	}
	filters.TLSCerts = certs
	for _, opts := range filters.WebClient {
		if !slices.Contains(sdk.WebClientOptions, opts) {
			return util.NewValidationError(fmt.Sprintf("invalid web client options %q", opts))
		}
	}
	if filters.MaxSharesExpiration > 0 && filters.MaxSharesExpiration < filters.DefaultSharesExpiration {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("default shares expiration: %d must be less than or equal to max shares expiration: %d",
				filters.DefaultSharesExpiration, filters.MaxSharesExpiration)),
			util.I18nErrorShareExpirationInvalid,
		)
	}
	updateFiltersValues(filters)

	if err := validateAccessTimeFilters(filters); err != nil {
		return err
	}

	return validateFiltersPatternExtensions(filters)
}

func isTimeOfDayValid(value string) bool {
	if len(value) != 5 {
		return false
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	if hour < 0 || hour > 23 {
		return false
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	if minute < 0 || minute > 59 {
		return false
	}
	return true
}

func validateAccessTimeFilters(filters *sdk.BaseUserFilters) error {
	for _, period := range filters.AccessTime {
		if period.DayOfWeek < int(time.Sunday) || period.DayOfWeek > int(time.Saturday) {
			return util.NewValidationError(fmt.Sprintf("invalid day of week: %d", period.DayOfWeek))
		}
		if !isTimeOfDayValid(period.From) || !isTimeOfDayValid(period.To) {
			return util.NewI18nError(
				util.NewValidationError("invalid time of day. Supported format: HH:MM"),
				util.I18nErrorTimeOfDayInvalid,
			)
		}
		if period.To <= period.From {
			return util.NewI18nError(
				util.NewValidationError("invalid time of day. The end time cannot be earlier than the start time"),
				util.I18nErrorTimeOfDayConflict,
			)
		}
	}

	return nil
}

func validateCombinedUserFilters(user *User) error {
	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.WebClient, sdk.WebClientMFADisabled) {
		return util.NewI18nError(
			util.NewValidationError("two-factor authentication cannot be disabled for a user with an active configuration"),
			util.I18nErrorDisableActive2FA,
		)
	}
	if user.Filters.RequirePasswordChange && slices.Contains(user.Filters.WebClient, sdk.WebClientPasswordChangeDisabled) {
		return util.NewI18nError(
			util.NewValidationError("you cannot require password change and at the same time disallow it"),
			util.I18nErrorPwdChangeConflict,
		)
	}
	if len(user.Filters.TwoFactorAuthProtocols) > 0 && slices.Contains(user.Filters.WebClient, sdk.WebClientMFADisabled) {
		return util.NewI18nError(
			util.NewValidationError("you cannot require two-factor authentication and at the same time disallow it"),
			util.I18nError2FAConflict,
		)
	}
	return nil
}

func validateEmails(user *User) error {
	if user.Email != "" && !util.IsEmailValid(user.Email) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("email %q is not valid", user.Email)),
			util.I18nErrorInvalidEmail,
		)
	}
	for _, email := range user.Filters.AdditionalEmails {
		if !util.IsEmailValid(email) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("email %q is not valid", email)),
				util.I18nErrorInvalidEmail,
			)
		}
	}
	return nil
}

func validateBaseParams(user *User) error {
	if user.Username == "" {
		return util.NewI18nError(util.NewValidationError("username is mandatory"), util.I18nErrorUsernameRequired)
	}
	if !util.IsNameValid(user.Username) {
		return util.NewI18nError(errInvalidInput, util.I18nErrorInvalidInput)
	}
	if err := checkReservedUsernames(user.Username); err != nil {
		return util.NewI18nError(err, util.I18nErrorReservedUsername)
	}
	if err := validateEmails(user); err != nil {
		return err
	}
	if holder.getConfig().NamingRules&1 == 0 && !usernameRegex.MatchString(user.Username) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("username %q is not valid, the following characters are allowed: a-zA-Z0-9-_.~", user.Username)),
			util.I18nErrorInvalidUser,
		)
	}
	if user.hasRedactedSecret() {
		return util.NewValidationError("cannot save a user with a redacted secret")
	}
	if user.HomeDir == "" {
		return util.NewI18nError(util.NewValidationError("home_dir is mandatory"), util.I18nErrorHomeRequired)
	}
	// we can have users with no passwords and public keys, they can authenticate via SSH user certs or OIDC
	/*if user.Password == "" && len(user.PublicKeys) == 0 {
		return util.NewValidationError("please set a password or at least a public_key")
	}*/
	if !filepath.IsAbs(user.HomeDir) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("home_dir must be an absolute path, actual value: %v", user.HomeDir)),
			util.I18nErrorHomeInvalid,
		)
	}
	if user.DownloadBandwidth < 0 {
		user.DownloadBandwidth = 0
	}
	if user.UploadBandwidth < 0 {
		user.UploadBandwidth = 0
	}
	if user.TotalDataTransfer > 0 {
		// if a total data transfer is defined we reset the separate upload and download limits
		user.UploadDataTransfer = 0
		user.DownloadDataTransfer = 0
	}
	if user.Filters.IsAnonymous {
		user.setAnonymousSettings()
	}
	err := user.FsConfig.Validate(user.GetEncryptionAdditionalData())
	if err != nil {
		return err
	}
	return nil
}

func hashPlainPassword(plainPwd string) (string, error) {
	if holder.getConfig().PasswordHashing.Algo == HashingAlgoBcrypt {
		pwd, err := bcrypt.GenerateFromPassword([]byte(plainPwd), holder.getConfig().PasswordHashing.BcryptOptions.Cost)
		if err != nil {
			return "", fmt.Errorf("bcrypt hashing error: %w", err)
		}
		return string(pwd), nil
	}
	pwd, err := argon2id.CreateHash(plainPwd, holder.getArgon2Params())
	if err != nil {
		return "", fmt.Errorf("argon2ID hashing error: %w", err)
	}
	return pwd, nil
}

func createUserPasswordHash(user *User) error {
	if user.Password != "" && !user.IsPasswordHashed() {
		for _, g := range user.Groups {
			if g.Type == sdk.GroupTypePrimary {
				group, err := GroupExists(g.Name)
				if err != nil {
					return errors.New("unable to load group password policies")
				}
				if minEntropy := group.UserSettings.Filters.PasswordStrength; minEntropy > 0 {
					if err := passwordvalidator.Validate(user.Password, float64(minEntropy)); err != nil {
						return util.NewI18nError(util.NewValidationError(err.Error()), util.I18nErrorPasswordComplexity)
					}
				}
			}
		}
		if minEntropy := user.getMinPasswordEntropy(); minEntropy > 0 {
			if err := passwordvalidator.Validate(user.Password, minEntropy); err != nil {
				return util.NewI18nError(util.NewValidationError(err.Error()), util.I18nErrorPasswordComplexity)
			}
		}
		hashedPwd, err := hashPlainPassword(user.Password)
		if err != nil {
			return err
		}
		user.Password = hashedPwd
		user.LastPasswordChange = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	return nil
}

// ValidateFolder returns an error if the folder is not valid
// FIXME: this should be defined as Folder struct method
func ValidateFolder(folder *vfs.BaseVirtualFolder) error {
	folder.FsConfig.SetEmptySecretsIfNil()
	if folder.Name == "" {
		return util.NewI18nError(util.NewValidationError("folder name is mandatory"), util.I18nErrorNameRequired)
	}
	if !util.IsNameValid(folder.Name) {
		return util.NewI18nError(errInvalidInput, util.I18nErrorInvalidInput)
	}
	if holder.getConfig().NamingRules&1 == 0 && !usernameRegex.MatchString(folder.Name) {
		return util.NewI18nError(
			util.NewValidationError(fmt.Sprintf("folder name %q is not valid, the following characters are allowed: a-zA-Z0-9-_.~", folder.Name)),
			util.I18nErrorInvalidName,
		)
	}
	if folder.FsConfig.Provider == sdk.LocalFilesystemProvider || folder.FsConfig.Provider == sdk.CryptedFilesystemProvider ||
		folder.MappedPath != "" {
		cleanedMPath := filepath.Clean(folder.MappedPath)
		if !filepath.IsAbs(cleanedMPath) {
			return util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("invalid folder mapped path %q", folder.MappedPath)),
				util.I18nErrorInvalidHomeDir,
			)
		}
		folder.MappedPath = cleanedMPath
	}
	if folder.HasRedactedSecret() {
		return errors.New("cannot save a folder with a redacted secret")
	}
	return folder.FsConfig.Validate(folder.GetEncryptionAdditionalData())
}

// ValidateUser returns an error if the user is not valid
// FIXME: this should be defined as User struct method
func ValidateUser(user *User) error {
	user.OIDCCustomFields = nil
	user.HasPassword = false
	user.SetEmptySecretsIfNil()
	user.applyNamingRules()
	buildUserHomeDir(user)
	if err := validateBaseParams(user); err != nil {
		return err
	}
	if err := validateUserGroups(user); err != nil {
		return err
	}
	if err := validatePermissions(user); err != nil {
		return err
	}
	if err := validateUserTOTPConfig(&user.Filters.TOTPConfig, user.Username); err != nil {
		return util.NewI18nError(err, util.I18nError2FAInvalid)
	}
	if err := validateUserRecoveryCodes(user); err != nil {
		return util.NewI18nError(err, util.I18nErrorRecoveryCodesInvalid)
	}
	vfolders, err := validateAssociatedVirtualFolders(user.VirtualFolders)
	if err != nil {
		return err
	}
	user.VirtualFolders = vfolders
	if user.Status < 0 || user.Status > 1 {
		return util.NewValidationError(fmt.Sprintf("invalid user status: %v", user.Status))
	}
	if err := createUserPasswordHash(user); err != nil {
		return err
	}
	if err := validatePublicKeys(user); err != nil {
		return err
	}
	if err := validateBaseFilters(&user.Filters.BaseUserFilters); err != nil {
		return err
	}
	if !user.HasExternalAuth() {
		user.Filters.ExternalAuthCacheTime = 0
	}
	return validateCombinedUserFilters(user)
}
