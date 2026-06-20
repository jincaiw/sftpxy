// Copyright (C) 2019 Nicola Murino
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

package httpd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/sftpgo/sdk"
	sdkkms "github.com/sftpgo/sdk/kms"

	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/kms"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

func (s *httpdServer) renderForgotPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := forgotPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webAdminForgotPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseAdminPath),
		LoginURL:       webAdminLoginPath,
		Title:          util.I18nForgotPwdTitle,
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
	}
	renderAdminTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderResetPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := resetPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webAdminResetPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseAdminPath),
		LoginURL:       webAdminLoginPath,
		Title:          util.I18nResetPwdTitle,
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
	}
	renderAdminTemplate(w, templateResetPassword, data)
}

func (s *httpdServer) renderTwoFactorPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18n2FATitle,
		CurrentURL:     webAdminTwoFactorPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseAdminPath),
		RecoveryURL:    webAdminTwoFactorRecoveryPath,
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
	}
	renderAdminTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderTwoFactorRecoveryPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18n2FATitle,
		CurrentURL:     webAdminTwoFactorRecoveryPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseAdminPath),
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
	}
	renderAdminTemplate(w, templateTwoFactorRecovery, data)
}

func (s *httpdServer) renderMFAPage(w http.ResponseWriter, r *http.Request) {
	data := mfaPage{
		basePage:        s.getBasePageData(util.I18n2FATitle, webAdminMFAPath, w, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webAdminTOTPGeneratePath,
		ValidateTOTPURL: webAdminTOTPValidatePath,
		SaveTOTPURL:     webAdminTOTPSavePath,
		RecCodesURL:     webAdminRecoveryCodesPath,
	}
	admin, err := dataprovider.AdminExists(data.LoggedUser.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = admin.Filters.TOTPConfig
	data.RequireTwoFactor = admin.Filters.RequireTwoFactor
	if claims, claimsErr := jwt.FromContext(r.Context()); claimsErr == nil && claims.MustSetTwoFactorAuth {
		data.RequiredAction = util.NewI18nError(
			util.NewGenericError("Two-factor authentication setup required"),
			util.I18nError2FARequiredGeneric,
		)
	}
	renderAdminTemplate(w, templateMFA, data)
}

func (s *httpdServer) renderProfilePage(w http.ResponseWriter, r *http.Request, err error) {
	data := profilePage{
		basePage: s.getBasePageData(util.I18nProfileTitle, webAdminProfilePath, w, r),
		Error:    getI18nError(err),
	}
	admin, err := dataprovider.AdminExists(data.LoggedUser.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	data.AllowAPIKeyAuth = admin.Filters.AllowAPIKeyAuth
	data.Email = admin.Email
	data.Description = admin.Description

	renderAdminTemplate(w, templateProfile, data)
}

func (s *httpdServer) renderChangePasswordPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := changePasswordPage{
		basePage: s.getBasePageData(util.I18nChangePwdTitle, webChangeAdminPwdPath, w, r),
		Error:    err,
	}
	if claims, claimsErr := jwt.FromContext(r.Context()); claimsErr == nil && claims.MustChangePassword {
		data.RequiredAction = util.NewI18nError(
			util.NewGenericError("Password change required"),
			util.I18nErrorChangePwdRequired,
		)
	}
	renderAdminTemplate(w, templateChangePwd, data)
}

func (s *httpdServer) renderMaintenancePage(w http.ResponseWriter, r *http.Request, err error) {
	data := maintenancePage{
		basePage:    s.getBasePageData(util.I18nMaintenanceTitle, webMaintenancePath, w, r),
		BackupPath:  webBackupPath,
		RestorePath: webRestorePath,
		Error:       getI18nError(err),
	}

	renderAdminTemplate(w, templateMaintenance, data)
}

func (s *httpdServer) renderConfigsPage(w http.ResponseWriter, r *http.Request, configs dataprovider.Configs,
	err error, section int,
) {
	configs.SetNilsToEmpty()
	if configs.SMTP.Port == 0 {
		configs.SMTP.Port = 587
		configs.SMTP.AuthType = 1
		configs.SMTP.Encryption = 2
	}
	if configs.ACME.HTTP01Challenge.Port == 0 {
		configs.ACME.HTTP01Challenge.Port = 80
	}
	data := configsPage{
		basePage:          s.getBasePageData(util.I18nConfigsTitle, webConfigsPath, w, r),
		Configs:           configs,
		ConfigSection:     section,
		RedactedSecret:    redactedSecret,
		OAuth2TokenURL:    webOAuth2TokenPath,
		OAuth2RedirectURL: webOAuth2RedirectPath,
		WebClientBranding: s.binding.webClientBranding(),
		Error:             getI18nError(err),
	}

	renderAdminTemplate(w, templateConfigs, data)
}

func (s *httpdServer) renderAdminSetupPage(w http.ResponseWriter, r *http.Request, username string, err *util.I18nError) {
	data := setupPage{
		commonBasePage:       getCommonBasePage(r),
		Title:                util.I18nSetupTitle,
		CurrentURL:           webAdminSetupPath,
		CSRFToken:            createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseAdminPath),
		Username:             username,
		HasInstallationCode:  installationCode != "",
		InstallationCodeHint: installationCodeHint,
		HideSupportLink:      hideSupportLink,
		Error:                err,
		Branding:             s.binding.webAdminBranding(),
		Languages:            s.binding.languages(),
	}

	renderAdminTemplate(w, templateSetup, data)
}

func (s *httpdServer) renderAddUpdateAdminPage(w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	err error, isAdd bool) {
	groups, errGroups := s.getWebGroups(w, r, defaultQueryLimit, true)
	if errGroups != nil {
		return
	}
	roles, errRoles := s.getWebRoles(w, r, 10, true)
	if errRoles != nil {
		return
	}
	currentURL := webAdminPath
	title := util.I18nAddAdminTitle
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webAdminPath, url.PathEscape(admin.Username))
		title = util.I18nUpdateAdminTitle
	}
	data := adminPage{
		basePage: s.getBasePageData(title, currentURL, w, r),
		Admin:    admin,
		Groups:   groups,
		Roles:    roles,
		Error:    getI18nError(err),
		IsAdd:    isAdd,
	}

	renderAdminTemplate(w, templateAdmin, data)
}

func (s *httpdServer) getUserPageTitleAndURL(mode userPageMode, username string) (string, string) {
	var title, currentURL string
	switch mode {
	case userPageModeAdd:
		title = util.I18nAddUserTitle
		currentURL = webUserPath
	case userPageModeUpdate:
		title = util.I18nUpdateUserTitle
		currentURL = fmt.Sprintf("%v/%v", webUserPath, url.PathEscape(username))
	case userPageModeTemplate:
		title = util.I18nTemplateUserTitle
		currentURL = webTemplateUser
	}
	return title, currentURL
}

func (s *httpdServer) renderUserPage(w http.ResponseWriter, r *http.Request, user *dataprovider.User,
	mode userPageMode, err error, admin *dataprovider.Admin,
) {
	user.SetEmptySecretsIfNil()
	title, currentURL := s.getUserPageTitleAndURL(mode, user.Username)
	if user.Password != "" && user.IsPasswordHashed() {
		switch mode {
		case userPageModeUpdate:
			user.Password = redactedSecret
		default:
			user.Password = ""
		}
	}
	user.FsConfig.RedactedSecret = redactedSecret
	basePage := s.getBasePageData(title, currentURL, w, r)
	if (mode == userPageModeAdd || mode == userPageModeTemplate) && len(user.Groups) == 0 && admin != nil {
		for _, group := range admin.Groups {
			user.Groups = append(user.Groups, sdk.GroupMapping{
				Name: group.Name,
				Type: group.Options.GetUserGroupType(),
			})
		}
	}
	var roles []dataprovider.Role
	if basePage.LoggedUser.Role == "" {
		var errRoles error
		roles, errRoles = s.getWebRoles(w, r, 10, true)
		if errRoles != nil {
			return
		}
	}
	folders, errFolders := s.getWebVirtualFolders(w, r, defaultQueryLimit, true)
	if errFolders != nil {
		return
	}
	groups, errGroups := s.getWebGroups(w, r, defaultQueryLimit, true)
	if errGroups != nil {
		return
	}
	data := userPage{
		basePage:           basePage,
		Mode:               mode,
		Error:              getI18nError(err),
		User:               user,
		ValidPerms:         dataprovider.ValidPerms,
		ValidLoginMethods:  dataprovider.ValidLoginMethods,
		ValidProtocols:     dataprovider.ValidProtocols,
		TwoFactorProtocols: dataprovider.MFAProtocols,
		WebClientOptions:   sdk.WebClientOptions,
		RootDirPerms:       user.GetPermissionsForPath("/"),
		VirtualFolders:     folders,
		Groups:             groups,
		Roles:              roles,
		CanImpersonate:     os.Getuid() == 0,
		CanUseTLSCerts:     ftpd.GetStatus().IsActive || webdavd.GetStatus().IsActive,
		FsWrapper: fsWrapper{
			Filesystem:      user.FsConfig,
			IsUserPage:      true,
			IsGroupPage:     false,
			IsHidden:        basePage.LoggedUser.Filters.Preferences.HideFilesystem(),
			HasUsersBaseDir: dataprovider.HasUsersBaseDir(),
			DirPath:         user.HomeDir,
		},
	}
	renderAdminTemplate(w, templateUser, data)
}

func (s *httpdServer) renderIPListPage(w http.ResponseWriter, r *http.Request, entry dataprovider.IPListEntry,
	mode genericPageMode, err error,
) {
	var title, currentURL string
	switch mode {
	case genericPageModeAdd:
		title = util.I18nAddIPListTitle
		currentURL = fmt.Sprintf("%s/%d", webIPListPath, entry.Type)
	case genericPageModeUpdate:
		title = util.I18nUpdateIPListTitle
		currentURL = fmt.Sprintf("%s/%d/%s", webIPListPath, entry.Type, url.PathEscape(entry.IPOrNet))
	}
	data := ipListPage{
		basePage: s.getBasePageData(title, currentURL, w, r),
		Error:    getI18nError(err),
		Entry:    &entry,
		Mode:     mode,
	}
	renderAdminTemplate(w, templateIPList, data)
}

func (s *httpdServer) renderRolePage(w http.ResponseWriter, r *http.Request, role dataprovider.Role,
	mode genericPageMode, err error,
) {
	var title, currentURL string
	switch mode {
	case genericPageModeAdd:
		title = util.I18nRoleAddTitle
		currentURL = webAdminRolePath
	case genericPageModeUpdate:
		title = util.I18nRoleUpdateTitle
		currentURL = fmt.Sprintf("%s/%s", webAdminRolePath, url.PathEscape(role.Name))
	}
	data := rolePage{
		basePage: s.getBasePageData(title, currentURL, w, r),
		Error:    getI18nError(err),
		Role:     &role,
		Mode:     mode,
	}
	renderAdminTemplate(w, templateRole, data)
}

func (s *httpdServer) renderGroupPage(w http.ResponseWriter, r *http.Request, group dataprovider.Group,
	mode genericPageMode, err error,
) {
	folders, errFolders := s.getWebVirtualFolders(w, r, defaultQueryLimit, true)
	if errFolders != nil {
		return
	}
	group.SetEmptySecretsIfNil()
	group.UserSettings.FsConfig.RedactedSecret = redactedSecret
	var title, currentURL string
	switch mode {
	case genericPageModeAdd:
		title = util.I18nAddGroupTitle
		currentURL = webGroupPath
	case genericPageModeUpdate:
		title = util.I18nUpdateGroupTitle
		currentURL = fmt.Sprintf("%v/%v", webGroupPath, url.PathEscape(group.Name))
	}
	group.UserSettings.FsConfig.RedactedSecret = redactedSecret
	group.UserSettings.FsConfig.SetEmptySecretsIfNil()

	data := groupPage{
		basePage:           s.getBasePageData(title, currentURL, w, r),
		Error:              getI18nError(err),
		Group:              &group,
		Mode:               mode,
		ValidPerms:         dataprovider.ValidPerms,
		ValidLoginMethods:  dataprovider.ValidLoginMethods,
		ValidProtocols:     dataprovider.ValidProtocols,
		TwoFactorProtocols: dataprovider.MFAProtocols,
		WebClientOptions:   sdk.WebClientOptions,
		VirtualFolders:     folders,
		FsWrapper: fsWrapper{
			Filesystem:      group.UserSettings.FsConfig,
			IsUserPage:      false,
			IsGroupPage:     true,
			HasUsersBaseDir: false,
			DirPath:         group.UserSettings.HomeDir,
		},
	}
	renderAdminTemplate(w, templateGroup, data)
}

func (s *httpdServer) renderEventActionPage(w http.ResponseWriter, r *http.Request, action dataprovider.BaseEventAction,
	mode genericPageMode, err error,
) {
	action.Options.SetEmptySecretsIfNil()
	var title, currentURL string
	switch mode {
	case genericPageModeAdd:
		title = util.I18nAddActionTitle
		currentURL = webAdminEventActionPath
	case genericPageModeUpdate:
		title = util.I18nUpdateActionTitle
		currentURL = fmt.Sprintf("%s/%s", webAdminEventActionPath, url.PathEscape(action.Name))
	}
	if action.Options.HTTPConfig.Timeout == 0 {
		action.Options.HTTPConfig.Timeout = 20
	}
	if action.Options.CmdConfig.Timeout == 0 {
		action.Options.CmdConfig.Timeout = 20
	}
	if action.Options.PwdExpirationConfig.Threshold == 0 {
		action.Options.PwdExpirationConfig.Threshold = 10
	}

	data := eventActionPage{
		basePage:        s.getBasePageData(title, currentURL, w, r),
		Action:          action,
		ActionTypes:     dataprovider.EventActionTypes,
		FsActions:       dataprovider.FsActionTypes,
		HTTPMethods:     dataprovider.SupportedHTTPActionMethods,
		EnabledCommands: dataprovider.EnabledActionCommands,
		RedactedSecret:  redactedSecret,
		Error:           getI18nError(err),
		Mode:            mode,
	}
	renderAdminTemplate(w, templateEventAction, data)
}

func (s *httpdServer) renderEventRulePage(w http.ResponseWriter, r *http.Request, rule dataprovider.EventRule,
	mode genericPageMode, err error,
) {
	actions, errActions := s.getWebEventActions(w, r, defaultQueryLimit, true)
	if errActions != nil {
		return
	}
	var title, currentURL string
	switch mode {
	case genericPageModeAdd:
		title = util.I18nAddRuleTitle
		currentURL = webAdminEventRulePath
	case genericPageModeUpdate:
		title = util.I18nUpdateRuleTitle
		currentURL = fmt.Sprintf("%v/%v", webAdminEventRulePath, url.PathEscape(rule.Name))
	}

	data := eventRulePage{
		basePage:        s.getBasePageData(title, currentURL, w, r),
		Rule:            rule,
		TriggerTypes:    dataprovider.EventTriggerTypes,
		Actions:         actions,
		FsEvents:        dataprovider.SupportedFsEvents,
		Protocols:       dataprovider.SupportedRuleConditionProtocols,
		ProviderEvents:  dataprovider.SupportedProviderEvents,
		ProviderObjects: dataprovider.SupporteRuleConditionProviderObjects,
		Error:           getI18nError(err),
		Mode:            mode,
		IsShared:        s.isShared > 0,
	}
	renderAdminTemplate(w, templateEventRule, data)
}

func (s *httpdServer) renderFolderPage(w http.ResponseWriter, r *http.Request, folder vfs.BaseVirtualFolder,
	mode folderPageMode, err error,
) {
	var title, currentURL string
	switch mode {
	case folderPageModeAdd:
		title = util.I18nAddFolderTitle
		currentURL = webFolderPath
	case folderPageModeUpdate:
		title = util.I18nUpdateFolderTitle
		currentURL = fmt.Sprintf("%v/%v", webFolderPath, url.PathEscape(folder.Name))
	case folderPageModeTemplate:
		title = util.I18nTemplateFolderTitle
		currentURL = webTemplateFolder
	}
	folder.FsConfig.RedactedSecret = redactedSecret
	folder.FsConfig.SetEmptySecretsIfNil()

	data := folderPage{
		basePage: s.getBasePageData(title, currentURL, w, r),
		Error:    getI18nError(err),
		Folder:   folder,
		Mode:     mode,
		FsWrapper: fsWrapper{
			Filesystem:      folder.FsConfig,
			IsUserPage:      false,
			IsGroupPage:     false,
			HasUsersBaseDir: false,
			DirPath:         folder.MappedPath,
		},
	}
	renderAdminTemplate(w, templateFolder, data)
}

func getFoldersForTemplate(r *http.Request) []string {
	var res []string
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "template_folders[", "][tpl_foldername]") {
			r.Form.Add("tpl_foldername", r.Form.Get(k))
		}
	}
	folderNames := r.Form["tpl_foldername"]
	folders := make(map[string]bool)
	for _, name := range folderNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := folders[name]; ok {
			continue
		}
		folders[name] = true
		res = append(res, name)
	}
	return res
}

func getUsersForTemplate(r *http.Request) []userTemplateFields {
	var res []userTemplateFields
	tplUsernames := r.Form["tpl_username"]
	tplPasswords := r.Form["tpl_password"]
	tplPublicKeys := r.Form["tpl_public_keys"]

	users := make(map[string]bool)
	for idx := range tplUsernames {
		username := tplUsernames[idx]
		password := ""
		publicKey := ""
		if len(tplPasswords) > idx {
			password = strings.TrimSpace(tplPasswords[idx])
		}
		if len(tplPublicKeys) > idx {
			publicKey = strings.TrimSpace(tplPublicKeys[idx])
		}
		if username == "" {
			continue
		}
		if _, ok := users[username]; ok {
			continue
		}

		users[username] = true
		res = append(res, userTemplateFields{
			Username:         username,
			Password:         password,
			PublicKeys:       []string{publicKey},
			RequirePwdChange: r.Form.Get("tpl_require_password_change") != "",
		})
	}

	return res
}

func getVirtualFoldersFromPostFields(r *http.Request) []vfs.VirtualFolder {
	var virtualFolders []vfs.VirtualFolder
	folderPaths := r.Form["vfolder_path"]
	folderNames := r.Form["vfolder_name"]
	folderQuotaSizes := r.Form["vfolder_quota_size"]
	folderQuotaFiles := r.Form["vfolder_quota_files"]
	for idx, p := range folderPaths {
		name := ""
		if len(folderNames) > idx {
			name = folderNames[idx]
		}
		if p != "" && name != "" {
			vfolder := vfs.VirtualFolder{
				BaseVirtualFolder: vfs.BaseVirtualFolder{
					Name: name,
				},
				VirtualPath: p,
				QuotaFiles:  -1,
				QuotaSize:   -1,
			}
			if len(folderQuotaSizes) > idx {
				quotaSize, err := util.ParseBytes(folderQuotaSizes[idx])
				if err == nil {
					vfolder.QuotaSize = quotaSize
				}
			}
			if len(folderQuotaFiles) > idx {
				quotaFiles, err := strconv.Atoi(folderQuotaFiles[idx])
				if err == nil {
					vfolder.QuotaFiles = quotaFiles
				}
			}
			virtualFolders = append(virtualFolders, vfolder)
		}
	}

	return virtualFolders
}

func getSubDirPermissionsFromPostFields(r *http.Request) map[string][]string {
	permissions := make(map[string][]string)

	for idx, p := range r.Form["sub_perm_path"] {
		if p != "" {
			permissions[p] = r.Form["sub_perm_permissions"+strconv.Itoa(idx)]
		}
	}

	return permissions
}

func getUserPermissionsFromPostFields(r *http.Request) map[string][]string {
	permissions := getSubDirPermissionsFromPostFields(r)
	permissions["/"] = r.Form["permissions"]

	return permissions
}

func getAccessTimeRestrictionsFromPostFields(r *http.Request) []sdk.TimePeriod {
	var result []sdk.TimePeriod

	dayOfWeeks := r.Form["access_time_day_of_week"]
	starts := r.Form["access_time_start"]
	ends := r.Form["access_time_end"]

	for idx, dayOfWeek := range dayOfWeeks {
		dayOfWeek = strings.TrimSpace(dayOfWeek)
		start := ""
		if len(starts) > idx {
			start = strings.TrimSpace(starts[idx])
		}
		end := ""
		if len(ends) > idx {
			end = strings.TrimSpace(ends[idx])
		}
		dayNumber, err := strconv.Atoi(dayOfWeek)
		if err == nil && start != "" && end != "" {
			result = append(result, sdk.TimePeriod{
				DayOfWeek: dayNumber,
				From:      start,
				To:        end,
			})
		}
	}

	return result
}

func getBandwidthLimitsFromPostFields(r *http.Request) ([]sdk.BandwidthLimit, error) {
	var result []sdk.BandwidthLimit
	bwSources := r.Form["bandwidth_limit_sources"]
	uploadSources := r.Form["upload_bandwidth_source"]
	downloadSources := r.Form["download_bandwidth_source"]

	for idx, bwSource := range bwSources {
		sources := getSliceFromDelimitedValues(bwSource, ",")
		if len(sources) > 0 {
			bwLimit := sdk.BandwidthLimit{
				Sources: sources,
			}
			ul := ""
			dl := ""
			if len(uploadSources) > idx {
				ul = uploadSources[idx]
			}
			if len(downloadSources) > idx {
				dl = downloadSources[idx]
			}
			if ul != "" {
				bandwidthUL, err := strconv.ParseInt(ul, 10, 64)
				if err != nil {
					return result, fmt.Errorf("invalid upload_bandwidth_source%v %q: %w", idx, ul, err)
				}
				bwLimit.UploadBandwidth = bandwidthUL
			}
			if dl != "" {
				bandwidthDL, err := strconv.ParseInt(dl, 10, 64)
				if err != nil {
					return result, fmt.Errorf("invalid download_bandwidth_source%v %q: %w", idx, ul, err)
				}
				bwLimit.DownloadBandwidth = bandwidthDL
			}
			result = append(result, bwLimit)
		}
	}

	return result, nil
}

func getPatterDenyPolicyFromString(policy string) int {
	denyPolicy := sdk.DenyPolicyDefault
	if policy == "1" {
		denyPolicy = sdk.DenyPolicyHide
	}
	return denyPolicy
}

func getFilePatternsFromPostField(r *http.Request) []sdk.PatternsFilter {
	var result []sdk.PatternsFilter
	patternPaths := r.Form["pattern_path"]
	patterns := r.Form["patterns"]
	patternTypes := r.Form["pattern_type"]
	policies := r.Form["pattern_policy"]

	allowedPatterns := make(map[string][]string)
	deniedPatterns := make(map[string][]string)
	patternPolicies := make(map[string]string)

	for idx := range patternPaths {
		p := patternPaths[idx]
		filters := strings.ReplaceAll(patterns[idx], " ", "")
		patternType := patternTypes[idx]
		patternPolicy := policies[idx]
		if p != "" && filters != "" {
			if patternType == "allowed" {
				allowedPatterns[p] = append(allowedPatterns[p], strings.Split(filters, ",")...)
			} else {
				deniedPatterns[p] = append(deniedPatterns[p], strings.Split(filters, ",")...)
			}
			if patternPolicy != "" && patternPolicy != "0" {
				patternPolicies[p] = patternPolicy
			}
		}
	}

	for dirAllowed, allowPatterns := range allowedPatterns {
		filter := sdk.PatternsFilter{
			Path:            dirAllowed,
			AllowedPatterns: allowPatterns,
			DenyPolicy:      getPatterDenyPolicyFromString(patternPolicies[dirAllowed]),
		}
		for dirDenied, denPatterns := range deniedPatterns {
			if dirAllowed == dirDenied {
				filter.DeniedPatterns = denPatterns
				break
			}
		}
		result = append(result, filter)
	}
	for dirDenied, denPatterns := range deniedPatterns {
		found := false
		for _, res := range result {
			if res.Path == dirDenied {
				found = true
				break
			}
		}
		if !found {
			result = append(result, sdk.PatternsFilter{
				Path:           dirDenied,
				DeniedPatterns: denPatterns,
				DenyPolicy:     getPatterDenyPolicyFromString(patternPolicies[dirDenied]),
			})
		}
	}
	return result
}

func getGroupsFromUserPostFields(r *http.Request) []sdk.GroupMapping {
	var groups []sdk.GroupMapping

	primaryGroup := strings.TrimSpace(r.Form.Get("primary_group"))
	if primaryGroup != "" {
		groups = append(groups, sdk.GroupMapping{
			Name: primaryGroup,
			Type: sdk.GroupTypePrimary,
		})
	}
	secondaryGroups := r.Form["secondary_groups"]
	for _, name := range secondaryGroups {
		groups = append(groups, sdk.GroupMapping{
			Name: strings.TrimSpace(name),
			Type: sdk.GroupTypeSecondary,
		})
	}
	membershipGroups := r.Form["membership_groups"]
	for _, name := range membershipGroups {
		groups = append(groups, sdk.GroupMapping{
			Name: strings.TrimSpace(name),
			Type: sdk.GroupTypeMembership,
		})
	}
	return groups
}

func getFiltersFromUserPostFields(r *http.Request) (sdk.BaseUserFilters, error) {
	var filters sdk.BaseUserFilters
	bwLimits, err := getBandwidthLimitsFromPostFields(r)
	if err != nil {
		return filters, err
	}
	maxFileSize, err := util.ParseBytes(r.Form.Get("max_upload_file_size"))
	if err != nil {
		return filters, util.NewI18nError(fmt.Errorf("invalid max upload file size: %w", err), util.I18nErrorInvalidMaxFilesize)
	}
	defaultSharesExpiration, err := strconv.Atoi(r.Form.Get("default_shares_expiration"))
	if err != nil {
		return filters, fmt.Errorf("invalid default shares expiration: %w", err)
	}
	maxSharesExpiration, err := strconv.Atoi(r.Form.Get("max_shares_expiration"))
	if err != nil {
		return filters, fmt.Errorf("invalid max shares expiration: %w", err)
	}
	passwordExpiration, err := strconv.Atoi(r.Form.Get("password_expiration"))
	if err != nil {
		return filters, fmt.Errorf("invalid password expiration: %w", err)
	}
	passwordStrength, err := strconv.Atoi(r.Form.Get("password_strength"))
	if err != nil {
		return filters, fmt.Errorf("invalid password strength: %w", err)
	}
	if r.Form.Get("ftp_security") == "1" {
		filters.FTPSecurity = 1
	}
	filters.BandwidthLimits = bwLimits
	filters.AllowedIP = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	filters.DeniedIP = getSliceFromDelimitedValues(r.Form.Get("denied_ip"), ",")
	filters.DeniedLoginMethods = r.Form["denied_login_methods"]
	filters.DeniedProtocols = r.Form["denied_protocols"]
	filters.TwoFactorAuthProtocols = r.Form["required_two_factor_protocols"]
	filters.FilePatterns = getFilePatternsFromPostField(r)
	filters.TLSUsername = sdk.TLSUsername(strings.TrimSpace(r.Form.Get("tls_username")))
	filters.WebClient = r.Form["web_client_options"]
	filters.DefaultSharesExpiration = defaultSharesExpiration
	filters.MaxSharesExpiration = maxSharesExpiration
	filters.PasswordExpiration = passwordExpiration
	filters.PasswordStrength = passwordStrength
	filters.AccessTime = getAccessTimeRestrictionsFromPostFields(r)
	hooks := r.Form["hooks"]
	if slices.Contains(hooks, "external_auth_disabled") {
		filters.Hooks.ExternalAuthDisabled = true
	}
	if slices.Contains(hooks, "pre_login_disabled") {
		filters.Hooks.PreLoginDisabled = true
	}
	if slices.Contains(hooks, "check_password_disabled") {
		filters.Hooks.CheckPasswordDisabled = true
	}
	filters.IsAnonymous = r.Form.Get("is_anonymous") != ""
	filters.DisableFsChecks = r.Form.Get("disable_fs_checks") != ""
	filters.AllowAPIKeyAuth = r.Form.Get("allow_api_key_auth") != ""
	filters.StartDirectory = strings.TrimSpace(r.Form.Get("start_directory"))
	filters.MaxUploadFileSize = maxFileSize
	filters.ExternalAuthCacheTime, err = strconv.ParseInt(r.Form.Get("external_auth_cache_time"), 10, 64)
	if err != nil {
		return filters, fmt.Errorf("invalid external auth cache time: %w", err)
	}
	return filters, nil
}

func getSecretFromFormField(r *http.Request, field string) *kms.Secret {
	secret := kms.NewPlainSecret(r.Form.Get(field))
	if strings.TrimSpace(secret.GetPayload()) == redactedSecret {
		secret.SetStatus(sdkkms.SecretStatusRedacted)
	}
	if strings.TrimSpace(secret.GetPayload()) == "" {
		secret.SetStatus("")
	}
	return secret
}

func getS3Config(r *http.Request) (vfs.S3FsConfig, error) {
	var err error
	config := vfs.S3FsConfig{}
	config.Bucket = strings.TrimSpace(r.Form.Get("s3_bucket"))
	config.Region = strings.TrimSpace(r.Form.Get("s3_region"))
	config.AccessKey = strings.TrimSpace(r.Form.Get("s3_access_key"))
	config.RoleARN = strings.TrimSpace(r.Form.Get("s3_role_arn"))
	config.AccessSecret = getSecretFromFormField(r, "s3_access_secret")
	config.SSECustomerKey = getSecretFromFormField(r, "s3_sse_customer_key")
	config.Endpoint = strings.TrimSpace(r.Form.Get("s3_endpoint"))
	config.StorageClass = strings.TrimSpace(r.Form.Get("s3_storage_class"))
	config.ACL = strings.TrimSpace(r.Form.Get("s3_acl"))
	config.KeyPrefix = strings.TrimSpace(strings.TrimPrefix(r.Form.Get("s3_key_prefix"), "/"))
	config.UploadPartSize, err = strconv.ParseInt(r.Form.Get("s3_upload_part_size"), 10, 64)
	if err != nil {
		return config, fmt.Errorf("invalid s3 upload part size: %w", err)
	}
	config.UploadConcurrency, err = strconv.Atoi(r.Form.Get("s3_upload_concurrency"))
	if err != nil {
		return config, fmt.Errorf("invalid s3 upload concurrency: %w", err)
	}
	config.DownloadPartSize, err = strconv.ParseInt(r.Form.Get("s3_download_part_size"), 10, 64)
	if err != nil {
		return config, fmt.Errorf("invalid s3 download part size: %w", err)
	}
	config.DownloadConcurrency, err = strconv.Atoi(r.Form.Get("s3_download_concurrency"))
	if err != nil {
		return config, fmt.Errorf("invalid s3 download concurrency: %w", err)
	}
	config.ForcePathStyle = r.Form.Get("s3_force_path_style") != ""
	config.SkipTLSVerify = r.Form.Get("s3_skip_tls_verify") != ""
	config.DownloadPartMaxTime, err = strconv.Atoi(r.Form.Get("s3_download_part_max_time"))
	if err != nil {
		return config, fmt.Errorf("invalid s3 download part max time: %w", err)
	}
	config.UploadPartMaxTime, err = strconv.Atoi(r.Form.Get("s3_upload_part_max_time"))
	if err != nil {
		return config, fmt.Errorf("invalid s3 upload part max time: %w", err)
	}
	return config, nil
}

func getGCSConfig(r *http.Request) (vfs.GCSFsConfig, error) {
	var err error
	config := vfs.GCSFsConfig{}

	config.Bucket = strings.TrimSpace(r.Form.Get("gcs_bucket"))
	config.StorageClass = strings.TrimSpace(r.Form.Get("gcs_storage_class"))
	config.ACL = strings.TrimSpace(r.Form.Get("gcs_acl"))
	config.KeyPrefix = strings.TrimSpace(strings.TrimPrefix(r.Form.Get("gcs_key_prefix"), "/"))
	uploadPartSize, err := strconv.ParseInt(r.Form.Get("gcs_upload_part_size"), 10, 64)
	if err == nil {
		config.UploadPartSize = uploadPartSize
	}
	uploadPartMaxTime, err := strconv.Atoi(r.Form.Get("gcs_upload_part_max_time"))
	if err == nil {
		config.UploadPartMaxTime = uploadPartMaxTime
	}
	autoCredentials := r.Form.Get("gcs_auto_credentials")
	if autoCredentials != "" {
		config.AutomaticCredentials = 1
	} else {
		config.AutomaticCredentials = 0
	}
	credentials, _, err := r.FormFile("gcs_credential_file")
	if errors.Is(err, http.ErrMissingFile) {
		return config, nil
	}
	if err != nil {
		return config, err
	}
	defer credentials.Close()
	fileBytes, err := io.ReadAll(credentials)
	if err != nil || len(fileBytes) == 0 {
		if len(fileBytes) == 0 {
			err = errors.New("credentials file size must be greater than 0")
		}
		return config, err
	}
	config.Credentials = kms.NewPlainSecret(string(fileBytes))
	config.AutomaticCredentials = 0
	return config, err
}

func getSFTPConfig(r *http.Request) (vfs.SFTPFsConfig, error) {
	var err error
	config := vfs.SFTPFsConfig{}
	config.Endpoint = strings.TrimSpace(r.Form.Get("sftp_endpoint"))
	config.Username = strings.TrimSpace(r.Form.Get("sftp_username"))
	config.Password = getSecretFromFormField(r, "sftp_password")
	config.PrivateKey = getSecretFromFormField(r, "sftp_private_key")
	config.KeyPassphrase = getSecretFromFormField(r, "sftp_key_passphrase")
	fingerprintsFormValue := r.Form.Get("sftp_fingerprints")
	config.Fingerprints = getSliceFromDelimitedValues(fingerprintsFormValue, "\n")
	config.Prefix = strings.TrimSpace(r.Form.Get("sftp_prefix"))
	config.DisableCouncurrentReads = r.Form.Get("sftp_disable_concurrent_reads") != ""
	config.BufferSize, err = strconv.ParseInt(r.Form.Get("sftp_buffer_size"), 10, 64)
	if r.Form.Get("sftp_equality_check_mode") != "" {
		config.EqualityCheckMode = 1
	} else {
		config.EqualityCheckMode = 0
	}
	if err != nil {
		return config, fmt.Errorf("invalid SFTP buffer size: %w", err)
	}
	return config, nil
}

func getHTTPFsConfig(r *http.Request) vfs.HTTPFsConfig {
	config := vfs.HTTPFsConfig{}
	config.Endpoint = strings.TrimSpace(r.Form.Get("http_endpoint"))
	config.Username = strings.TrimSpace(r.Form.Get("http_username"))
	config.SkipTLSVerify = r.Form.Get("http_skip_tls_verify") != ""
	config.Password = getSecretFromFormField(r, "http_password")
	config.APIKey = getSecretFromFormField(r, "http_api_key")
	if r.Form.Get("http_equality_check_mode") != "" {
		config.EqualityCheckMode = 1
	} else {
		config.EqualityCheckMode = 0
	}
	return config
}

func getAzureConfig(r *http.Request) (vfs.AzBlobFsConfig, error) {
	var err error
	config := vfs.AzBlobFsConfig{}
	config.Container = strings.TrimSpace(r.Form.Get("az_container"))
	config.AccountName = strings.TrimSpace(r.Form.Get("az_account_name"))
	config.AccountKey = getSecretFromFormField(r, "az_account_key")
	config.SASURL = getSecretFromFormField(r, "az_sas_url")
	config.Endpoint = strings.TrimSpace(r.Form.Get("az_endpoint"))
	config.KeyPrefix = strings.TrimSpace(strings.TrimPrefix(r.Form.Get("az_key_prefix"), "/"))
	config.AccessTier = strings.TrimSpace(r.Form.Get("az_access_tier"))
	config.UseEmulator = r.Form.Get("az_use_emulator") != ""
	config.UploadPartSize, err = strconv.ParseInt(r.Form.Get("az_upload_part_size"), 10, 64)
	if err != nil {
		return config, fmt.Errorf("invalid azure upload part size: %w", err)
	}
	config.UploadConcurrency, err = strconv.Atoi(r.Form.Get("az_upload_concurrency"))
	if err != nil {
		return config, fmt.Errorf("invalid azure upload concurrency: %w", err)
	}
	config.DownloadPartSize, err = strconv.ParseInt(r.Form.Get("az_download_part_size"), 10, 64)
	if err != nil {
		return config, fmt.Errorf("invalid azure download part size: %w", err)
	}
	config.DownloadConcurrency, err = strconv.Atoi(r.Form.Get("az_download_concurrency"))
	if err != nil {
		return config, fmt.Errorf("invalid azure download concurrency: %w", err)
	}
	return config, nil
}

func getOsConfigFromPostFields(r *http.Request, readBufferField, writeBufferField string) sdk.OSFsConfig {
	config := sdk.OSFsConfig{}
	readBuffer, err := strconv.Atoi(r.Form.Get(readBufferField))
	if err == nil {
		config.ReadBufferSize = readBuffer
	}
	writeBuffer, err := strconv.Atoi(r.Form.Get(writeBufferField))
	if err == nil {
		config.WriteBufferSize = writeBuffer
	}
	return config
}

func getFsConfigFromPostFields(r *http.Request) (vfs.Filesystem, error) {
	var fs vfs.Filesystem
	fs.Provider = dataprovider.GetProviderFromValue(r.Form.Get("fs_provider"))
	switch fs.Provider {
	case sdk.LocalFilesystemProvider:
		fs.OSConfig = getOsConfigFromPostFields(r, "osfs_read_buffer_size", "osfs_write_buffer_size")
	case sdk.S3FilesystemProvider:
		config, err := getS3Config(r)
		if err != nil {
			return fs, err
		}
		fs.S3Config = config
	case sdk.AzureBlobFilesystemProvider:
		config, err := getAzureConfig(r)
		if err != nil {
			return fs, err
		}
		fs.AzBlobConfig = config
	case sdk.GCSFilesystemProvider:
		config, err := getGCSConfig(r)
		if err != nil {
			return fs, err
		}
		fs.GCSConfig = config
	case sdk.CryptedFilesystemProvider:
		fs.CryptConfig.Passphrase = getSecretFromFormField(r, "crypt_passphrase")
		fs.CryptConfig.OSFsConfig = getOsConfigFromPostFields(r, "cryptfs_read_buffer_size", "cryptfs_write_buffer_size")
	case sdk.SFTPFilesystemProvider:
		config, err := getSFTPConfig(r)
		if err != nil {
			return fs, err
		}
		fs.SFTPConfig = config
	case sdk.HTTPFilesystemProvider:
		fs.HTTPConfig = getHTTPFsConfig(r)
	}
	return fs, nil
}

func getAdminHiddenUserPageSections(r *http.Request) int {
	var result int

	for _, val := range r.Form["user_page_hidden_sections"] {
		switch val {
		case "1":
			result++
		case "2":
			result += 2
		case "3":
			result += 4
		case "4":
			result += 8
		case "5":
			result += 16
		case "6":
			result += 32
		case "7":
			result += 64
		}
	}

	return result
}

func getAdminFromPostFields(r *http.Request) (dataprovider.Admin, error) {
	var admin dataprovider.Admin
	err := r.ParseForm()
	if err != nil {
		return admin, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	status, err := strconv.Atoi(r.Form.Get("status"))
	if err != nil {
		return admin, fmt.Errorf("invalid status: %w", err)
	}
	admin.Username = strings.TrimSpace(r.Form.Get("username"))
	admin.Password = strings.TrimSpace(r.Form.Get("password"))
	admin.Permissions = r.Form["permissions"]
	admin.Email = strings.TrimSpace(r.Form.Get("email"))
	admin.Status = status
	admin.Role = strings.TrimSpace(r.Form.Get("role"))
	admin.Filters.AllowList = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	admin.Filters.AllowAPIKeyAuth = r.Form.Get("allow_api_key_auth") != ""
	admin.Filters.RequireTwoFactor = r.Form.Get("require_two_factor") != ""
	admin.Filters.RequirePasswordChange = r.Form.Get("require_password_change") != ""
	admin.AdditionalInfo = r.Form.Get("additional_info")
	admin.Description = r.Form.Get("description")
	admin.Filters.Preferences.HideUserPageSections = getAdminHiddenUserPageSections(r)
	admin.Filters.Preferences.DefaultUsersExpiration = 0
	if val := r.Form.Get("default_users_expiration"); val != "" {
		defaultUsersExpiration, err := strconv.Atoi(r.Form.Get("default_users_expiration"))
		if err != nil {
			return admin, fmt.Errorf("invalid default users expiration: %w", err)
		}
		admin.Filters.Preferences.DefaultUsersExpiration = defaultUsersExpiration
	}
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "groups[", "][group]") {
			groupName := strings.TrimSpace(r.Form.Get(k))
			if groupName != "" {
				group := dataprovider.AdminGroupMapping{
					Name: groupName,
				}
				base, _ := strings.CutSuffix(k, "[group]")
				addAsGroupType := strings.TrimSpace(r.Form.Get(base + "[group_type]"))
				switch addAsGroupType {
				case "1":
					group.Options.AddToUsersAs = dataprovider.GroupAddToUsersAsPrimary
				case "2":
					group.Options.AddToUsersAs = dataprovider.GroupAddToUsersAsSecondary
				default:
					group.Options.AddToUsersAs = dataprovider.GroupAddToUsersAsMembership
				}
				admin.Groups = append(admin.Groups, group)
			}
		}
	}
	return admin, nil
}

func replacePlaceholders(field string, replacements map[string]string) string {
	for k, v := range replacements {
		field = strings.ReplaceAll(field, k, v)
	}
	return field
}

func getFolderFromTemplate(folder vfs.BaseVirtualFolder, name string) vfs.BaseVirtualFolder {
	folder.Name = name
	replacements := make(map[string]string)
	replacements["%name%"] = folder.Name

	folder.MappedPath = replacePlaceholders(folder.MappedPath, replacements)
	folder.Description = replacePlaceholders(folder.Description, replacements)
	switch folder.FsConfig.Provider {
	case sdk.CryptedFilesystemProvider:
		folder.FsConfig.CryptConfig = getCryptFsFromTemplate(folder.FsConfig.CryptConfig, replacements)
	case sdk.S3FilesystemProvider:
		folder.FsConfig.S3Config = getS3FsFromTemplate(folder.FsConfig.S3Config, replacements)
	case sdk.GCSFilesystemProvider:
		folder.FsConfig.GCSConfig = getGCSFsFromTemplate(folder.FsConfig.GCSConfig, replacements)
	case sdk.AzureBlobFilesystemProvider:
		folder.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(folder.FsConfig.AzBlobConfig, replacements)
	case sdk.SFTPFilesystemProvider:
		folder.FsConfig.SFTPConfig = getSFTPFsFromTemplate(folder.FsConfig.SFTPConfig, replacements)
	case sdk.HTTPFilesystemProvider:
		folder.FsConfig.HTTPConfig = getHTTPFsFromTemplate(folder.FsConfig.HTTPConfig, replacements)
	}

	return folder
}

func getCryptFsFromTemplate(fsConfig vfs.CryptFsConfig, replacements map[string]string) vfs.CryptFsConfig {
	if fsConfig.Passphrase != nil {
		if fsConfig.Passphrase.IsPlain() {
			payload := replacePlaceholders(fsConfig.Passphrase.GetPayload(), replacements)
			fsConfig.Passphrase = kms.NewPlainSecret(payload)
		}
	}
	return fsConfig
}

func getS3FsFromTemplate(fsConfig vfs.S3FsConfig, replacements map[string]string) vfs.S3FsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	fsConfig.AccessKey = replacePlaceholders(fsConfig.AccessKey, replacements)
	if fsConfig.AccessSecret != nil && fsConfig.AccessSecret.IsPlain() {
		payload := replacePlaceholders(fsConfig.AccessSecret.GetPayload(), replacements)
		fsConfig.AccessSecret = kms.NewPlainSecret(payload)
	}
	if fsConfig.SSECustomerKey != nil && fsConfig.SSECustomerKey.IsPlain() {
		payload := replacePlaceholders(fsConfig.SSECustomerKey.GetPayload(), replacements)
		fsConfig.SSECustomerKey = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getGCSFsFromTemplate(fsConfig vfs.GCSFsConfig, replacements map[string]string) vfs.GCSFsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	return fsConfig
}

func getAzBlobFsFromTemplate(fsConfig vfs.AzBlobFsConfig, replacements map[string]string) vfs.AzBlobFsConfig {
	fsConfig.KeyPrefix = replacePlaceholders(fsConfig.KeyPrefix, replacements)
	fsConfig.AccountName = replacePlaceholders(fsConfig.AccountName, replacements)
	if fsConfig.AccountKey != nil && fsConfig.AccountKey.IsPlain() {
		payload := replacePlaceholders(fsConfig.AccountKey.GetPayload(), replacements)
		fsConfig.AccountKey = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getSFTPFsFromTemplate(fsConfig vfs.SFTPFsConfig, replacements map[string]string) vfs.SFTPFsConfig {
	fsConfig.Prefix = replacePlaceholders(fsConfig.Prefix, replacements)
	fsConfig.Username = replacePlaceholders(fsConfig.Username, replacements)
	if fsConfig.Password != nil && fsConfig.Password.IsPlain() {
		payload := replacePlaceholders(fsConfig.Password.GetPayload(), replacements)
		fsConfig.Password = kms.NewPlainSecret(payload)
	}
	return fsConfig
}

func getHTTPFsFromTemplate(fsConfig vfs.HTTPFsConfig, replacements map[string]string) vfs.HTTPFsConfig {
	fsConfig.Username = replacePlaceholders(fsConfig.Username, replacements)
	return fsConfig
}

func getUserFromTemplate(user dataprovider.User, template userTemplateFields) dataprovider.User {
	user.Username = template.Username
	user.Password = template.Password
	user.PublicKeys = template.PublicKeys
	user.Filters.RequirePasswordChange = template.RequirePwdChange
	replacements := make(map[string]string)
	replacements["%username%"] = user.Username
	if user.Password != "" && !user.IsPasswordHashed() {
		user.Password = replacePlaceholders(user.Password, replacements)
		replacements["%password%"] = user.Password
	}

	user.HomeDir = replacePlaceholders(user.HomeDir, replacements)
	var vfolders []vfs.VirtualFolder
	for _, vfolder := range user.VirtualFolders {
		vfolder.Name = replacePlaceholders(vfolder.Name, replacements)
		vfolder.VirtualPath = replacePlaceholders(vfolder.VirtualPath, replacements)
		vfolders = append(vfolders, vfolder)
	}
	user.VirtualFolders = vfolders
	user.Description = replacePlaceholders(user.Description, replacements)
	user.AdditionalInfo = replacePlaceholders(user.AdditionalInfo, replacements)
	user.Filters.StartDirectory = replacePlaceholders(user.Filters.StartDirectory, replacements)

	switch user.FsConfig.Provider {
	case sdk.CryptedFilesystemProvider:
		user.FsConfig.CryptConfig = getCryptFsFromTemplate(user.FsConfig.CryptConfig, replacements)
	case sdk.S3FilesystemProvider:
		user.FsConfig.S3Config = getS3FsFromTemplate(user.FsConfig.S3Config, replacements)
	case sdk.GCSFilesystemProvider:
		user.FsConfig.GCSConfig = getGCSFsFromTemplate(user.FsConfig.GCSConfig, replacements)
	case sdk.AzureBlobFilesystemProvider:
		user.FsConfig.AzBlobConfig = getAzBlobFsFromTemplate(user.FsConfig.AzBlobConfig, replacements)
	case sdk.SFTPFilesystemProvider:
		user.FsConfig.SFTPConfig = getSFTPFsFromTemplate(user.FsConfig.SFTPConfig, replacements)
	case sdk.HTTPFilesystemProvider:
		user.FsConfig.HTTPConfig = getHTTPFsFromTemplate(user.FsConfig.HTTPConfig, replacements)
	}

	return user
}

func getTransferLimits(r *http.Request) (int64, int64, int64, error) {
	dataTransferUL, err := strconv.ParseInt(r.Form.Get("upload_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid upload data transfer: %w", err)
	}
	dataTransferDL, err := strconv.ParseInt(r.Form.Get("download_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid download data transfer: %w", err)
	}
	dataTransferTotal, err := strconv.ParseInt(r.Form.Get("total_data_transfer"), 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid total data transfer: %w", err)
	}
	return dataTransferUL, dataTransferDL, dataTransferTotal, nil
}

func getQuotaLimits(r *http.Request) (int64, int, error) {
	quotaSize, err := util.ParseBytes(r.Form.Get("quota_size"))
	if err != nil {
		return 0, 0, util.NewI18nError(fmt.Errorf("invalid quota size: %w", err), util.I18nErrorInvalidQuotaSize)
	}
	quotaFiles, err := strconv.Atoi(r.Form.Get("quota_files"))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid quota files: %w", err)
	}
	return quotaSize, quotaFiles, nil
}

func updateRepeaterFormFields(r *http.Request) {
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "public_keys[", "][public_key]") {
			key := r.Form.Get(k)
			if strings.TrimSpace(key) != "" {
				r.Form.Add("public_keys", key)
			}
			continue
		}
		if hasPrefixAndSuffix(k, "tls_certs[", "][tls_cert]") {
			cert := strings.TrimSpace(r.Form.Get(k))
			if cert != "" {
				r.Form.Add("tls_certs", cert)
			}
			continue
		}
		if hasPrefixAndSuffix(k, "additional_emails[", "][additional_email]") {
			email := strings.TrimSpace(r.Form.Get(k))
			if email != "" {
				r.Form.Add("additional_emails", email)
			}
			continue
		}
		if hasPrefixAndSuffix(k, "virtual_folders[", "][vfolder_path]") {
			base, _ := strings.CutSuffix(k, "[vfolder_path]")
			r.Form.Add("vfolder_path", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("vfolder_name", strings.TrimSpace(r.Form.Get(base+"[vfolder_name]")))
			r.Form.Add("vfolder_quota_files", strings.TrimSpace(r.Form.Get(base+"[vfolder_quota_files]")))
			r.Form.Add("vfolder_quota_size", strings.TrimSpace(r.Form.Get(base+"[vfolder_quota_size]")))
			continue
		}
		if hasPrefixAndSuffix(k, "directory_permissions[", "][sub_perm_path]") {
			base, _ := strings.CutSuffix(k, "[sub_perm_path]")
			r.Form.Add("sub_perm_path", strings.TrimSpace(r.Form.Get(k)))
			r.Form["sub_perm_permissions"+strconv.Itoa(len(r.Form["sub_perm_path"])-1)] = r.Form[base+"[sub_perm_permissions][]"]
			continue
		}
		if hasPrefixAndSuffix(k, "directory_patterns[", "][pattern_path]") {
			base, _ := strings.CutSuffix(k, "[pattern_path]")
			r.Form.Add("pattern_path", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("patterns", strings.TrimSpace(r.Form.Get(base+"[patterns]")))
			r.Form.Add("pattern_type", strings.TrimSpace(r.Form.Get(base+"[pattern_type]")))
			r.Form.Add("pattern_policy", strings.TrimSpace(r.Form.Get(base+"[pattern_policy]")))
			continue
		}
		if hasPrefixAndSuffix(k, "access_time_restrictions[", "][access_time_day_of_week]") {
			base, _ := strings.CutSuffix(k, "[access_time_day_of_week]")
			r.Form.Add("access_time_day_of_week", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("access_time_start", strings.TrimSpace(r.Form.Get(base+"[access_time_start]")))
			r.Form.Add("access_time_end", strings.TrimSpace(r.Form.Get(base+"[access_time_end]")))
			continue
		}
		if hasPrefixAndSuffix(k, "src_bandwidth_limits[", "][bandwidth_limit_sources]") {
			base, _ := strings.CutSuffix(k, "[bandwidth_limit_sources]")
			r.Form.Add("bandwidth_limit_sources", r.Form.Get(k))
			r.Form.Add("upload_bandwidth_source", strings.TrimSpace(r.Form.Get(base+"[upload_bandwidth_source]")))
			r.Form.Add("download_bandwidth_source", strings.TrimSpace(r.Form.Get(base+"[download_bandwidth_source]")))
			continue
		}
		if hasPrefixAndSuffix(k, "template_users[", "][tpl_username]") {
			base, _ := strings.CutSuffix(k, "[tpl_username]")
			r.Form.Add("tpl_username", strings.TrimSpace(r.Form.Get(k)))
			r.Form.Add("tpl_password", strings.TrimSpace(r.Form.Get(base+"[tpl_password]")))
			r.Form.Add("tpl_public_keys", strings.TrimSpace(r.Form.Get(base+"[tpl_public_keys]")))
			continue
		}
	}
}
