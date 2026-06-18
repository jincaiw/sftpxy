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
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)


type userPageMode int

const (
	userPageModeAdd userPageMode = iota + 1
	userPageModeUpdate
	userPageModeTemplate
)

type folderPageMode int

const (
	folderPageModeAdd folderPageMode = iota + 1
	folderPageModeUpdate
	folderPageModeTemplate
)

type genericPageMode int

const (
	genericPageModeAdd genericPageMode = iota + 1
	genericPageModeUpdate
)

const (
	templateAdminDir     = "webadmin"
	templateBase         = "base.html"
	templateFsConfig     = "fsconfig.html"
	templateUsers        = "users.html"
	templateUser         = "user.html"
	templateAdmins       = "admins.html"
	templateAdmin        = "admin.html"
	templateConnections  = "connections.html"
	templateGroups       = "groups.html"
	templateGroup        = "group.html"
	templateFolders      = "folders.html"
	templateFolder       = "folder.html"
	templateEventRules   = "eventrules.html"
	templateEventRule    = "eventrule.html"
	templateEventActions = "eventactions.html"
	templateEventAction  = "eventaction.html"
	templateRoles        = "roles.html"
	templateRole         = "role.html"
	templateEvents       = "events.html"
	templateStatus       = "status.html"
	templateDefender     = "defender.html"
	templateIPLists      = "iplists.html"
	templateIPList       = "iplist.html"
	templateConfigs      = "configs.html"
	templateProfile      = "profile.html"
	templateMaintenance  = "maintenance.html"
	templateMFA          = "mfa.html"
	templateSetup        = "adminsetup.html"
	defaultQueryLimit    = 1000
	inversePatternType   = "inverse"
)

var (
	adminTemplates = make(map[string]*template.Template)
)

type basePage struct {
	commonBasePage
	Title               string
	CurrentURL          string
	UsersURL            string
	UserURL             string
	UserTemplateURL     string
	AdminsURL           string
	AdminURL            string
	QuotaScanURL        string
	ConnectionsURL      string
	GroupsURL           string
	GroupURL            string
	FoldersURL          string
	FolderURL           string
	FolderTemplateURL   string
	DefenderURL         string
	IPListsURL          string
	IPListURL           string
	EventsURL           string
	ConfigsURL          string
	LogoutURL           string
	LoginURL            string
	ProfileURL          string
	ChangePwdURL        string
	MFAURL              string
	EventRulesURL       string
	EventRuleURL        string
	EventActionsURL     string
	EventActionURL      string
	RolesURL            string
	RoleURL             string
	FolderQuotaScanURL  string
	StatusURL           string
	MaintenanceURL      string
	CSRFToken           string
	IsEventManagerPage  bool
	IsIPManagerPage     bool
	IsServerManagerPage bool
	HasDefender         bool
	HasSearcher         bool
	HasExternalLogin    bool
	LoggedUser          *dataprovider.Admin
	IsLoggedToShare     bool
	Branding            UIBranding
	Languages           []string
}

type statusPage struct {
	basePage
	Status *ServicesStatus
}

type fsWrapper struct {
	vfs.Filesystem
	IsUserPage      bool
	IsGroupPage     bool
	IsHidden        bool
	HasUsersBaseDir bool
	DirPath         string
}

type userPage struct {
	basePage
	User               *dataprovider.User
	RootPerms          []string
	Error              *util.I18nError
	ValidPerms         []string
	ValidLoginMethods  []string
	ValidProtocols     []string
	TwoFactorProtocols []string
	WebClientOptions   []string
	RootDirPerms       []string
	Mode               userPageMode
	VirtualFolders     []vfs.BaseVirtualFolder
	Groups             []dataprovider.Group
	Roles              []dataprovider.Role
	CanImpersonate     bool
	FsWrapper          fsWrapper
	CanUseTLSCerts     bool
}

type adminPage struct {
	basePage
	Admin  *dataprovider.Admin
	Groups []dataprovider.Group
	Roles  []dataprovider.Role
	Error  *util.I18nError
	IsAdd  bool
}

type profilePage struct {
	basePage
	Error           *util.I18nError
	AllowAPIKeyAuth bool
	Email           string
	Description     string
}

type changePasswordPage struct {
	basePage
	Error          *util.I18nError
	RequiredAction *util.I18nError
}

type mfaPage struct {
	basePage
	TOTPConfigs      []string
	TOTPConfig       dataprovider.AdminTOTPConfig
	GenerateTOTPURL  string
	ValidateTOTPURL  string
	SaveTOTPURL      string
	RecCodesURL      string
	RequireTwoFactor bool
	RequiredAction   *util.I18nError
}

type maintenancePage struct {
	basePage
	BackupPath  string
	RestorePath string
	Error       *util.I18nError
}

type defenderHostsPage struct {
	basePage
	DefenderHostsURL string
}

type ipListsPage struct {
	basePage
	IPListsSearchURL      string
	RateLimitersStatus    bool
	RateLimitersProtocols string
	IsAllowListEnabled    bool
}

type ipListPage struct {
	basePage
	Entry *dataprovider.IPListEntry
	Error *util.I18nError
	Mode  genericPageMode
}

type setupPage struct {
	commonBasePage
	CurrentURL           string
	Error                *util.I18nError
	CSRFToken            string
	Username             string
	HasInstallationCode  bool
	InstallationCodeHint string
	HideSupportLink      bool
	Title                string
	Branding             UIBranding
	Languages            []string
	CheckRedirect        bool
}

type folderPage struct {
	basePage
	Folder    vfs.BaseVirtualFolder
	Error     *util.I18nError
	Mode      folderPageMode
	FsWrapper fsWrapper
}

type groupPage struct {
	basePage
	Group              *dataprovider.Group
	Error              *util.I18nError
	Mode               genericPageMode
	ValidPerms         []string
	ValidLoginMethods  []string
	ValidProtocols     []string
	TwoFactorProtocols []string
	WebClientOptions   []string
	VirtualFolders     []vfs.BaseVirtualFolder
	FsWrapper          fsWrapper
}

type rolePage struct {
	basePage
	Role  *dataprovider.Role
	Error *util.I18nError
	Mode  genericPageMode
}

type eventActionPage struct {
	basePage
	Action          dataprovider.BaseEventAction
	ActionTypes     []dataprovider.EnumMapping
	FsActions       []dataprovider.EnumMapping
	HTTPMethods     []string
	EnabledCommands []string
	RedactedSecret  string
	Error           *util.I18nError
	Mode            genericPageMode
}

type eventRulePage struct {
	basePage
	Rule            dataprovider.EventRule
	TriggerTypes    []dataprovider.EnumMapping
	Actions         []dataprovider.BaseEventAction
	FsEvents        []string
	Protocols       []string
	ProviderEvents  []string
	ProviderObjects []string
	Error           *util.I18nError
	Mode            genericPageMode
	IsShared        bool
}

type eventsPage struct {
	basePage
	FsEventsSearchURL       string
	ProviderEventsSearchURL string
	LogEventsSearchURL      string
}

type configsPage struct {
	basePage
	Configs           dataprovider.Configs
	ConfigSection     int
	RedactedSecret    string
	OAuth2TokenURL    string
	OAuth2RedirectURL string
	WebClientBranding UIBranding
	Error             *util.I18nError
}

type messagePage struct {
	basePage
	Error   *util.I18nError
	Success string
	Text    string
}

type userTemplateFields struct {
	Username         string
	Password         string
	PublicKeys       []string
	RequirePwdChange bool
}

func loadAdminTemplates(templatesPath string) {
	usersPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateUsers),
	}
	userPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateUser),
	}
	adminsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateAdmins),
	}
	adminPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateAdmin),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateCommonDir, templateChangePwd),
	}
	connectionsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateConnections),
	}
	messagePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateCommonDir, templateMessage),
	}
	foldersPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFolders),
	}
	folderPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateFolder),
	}
	groupsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateGroups),
	}
	groupPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateFsConfig),
		filepath.Join(templatesPath, templateAdminDir, templateGroup),
	}
	eventRulesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateEventRules),
	}
	eventRulePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateEventRule),
	}
	eventActionsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateEventActions),
	}
	eventActionPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateEventAction),
	}
	statusPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateStatus),
	}
	loginPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateCommonLogin),
	}
	maintenancePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMaintenance),
	}
	defenderPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateDefender),
	}
	ipListsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateIPLists),
	}
	ipListPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateIPList),
	}
	mfaPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateMFA),
	}
	twoFactorPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateTwoFactor),
	}
	twoFactorRecoveryPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateTwoFactorRecovery),
	}
	setupPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateAdminDir, templateSetup),
	}
	forgotPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateForgotPassword),
	}
	resetPwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateResetPassword),
	}
	rolesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateRoles),
	}
	rolePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateRole),
	}
	eventsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateEvents),
	}
	configsPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateAdminDir, templateBase),
		filepath.Join(templatesPath, templateAdminDir, templateConfigs),
	}

	fsBaseTpl := template.New("fsBaseTemplate").Funcs(template.FuncMap{
		"HumanizeBytes": util.ByteCountSI,
	})
	usersTmpl := util.LoadTemplate(nil, usersPaths...)
	userTmpl := util.LoadTemplate(fsBaseTpl, userPaths...)
	adminsTmpl := util.LoadTemplate(nil, adminsPaths...)
	adminTmpl := util.LoadTemplate(nil, adminPaths...)
	connectionsTmpl := util.LoadTemplate(nil, connectionsPaths...)
	messageTmpl := util.LoadTemplate(nil, messagePaths...)
	groupsTmpl := util.LoadTemplate(nil, groupsPaths...)
	groupTmpl := util.LoadTemplate(fsBaseTpl, groupPaths...)
	foldersTmpl := util.LoadTemplate(nil, foldersPaths...)
	folderTmpl := util.LoadTemplate(fsBaseTpl, folderPaths...)
	eventRulesTmpl := util.LoadTemplate(nil, eventRulesPaths...)
	eventRuleTmpl := util.LoadTemplate(fsBaseTpl, eventRulePaths...)
	eventActionsTmpl := util.LoadTemplate(nil, eventActionsPaths...)
	eventActionTmpl := util.LoadTemplate(nil, eventActionPaths...)
	statusTmpl := util.LoadTemplate(nil, statusPaths...)
	loginTmpl := util.LoadTemplate(nil, loginPaths...)
	profileTmpl := util.LoadTemplate(nil, profilePaths...)
	changePwdTmpl := util.LoadTemplate(nil, changePwdPaths...)
	maintenanceTmpl := util.LoadTemplate(nil, maintenancePaths...)
	defenderTmpl := util.LoadTemplate(nil, defenderPaths...)
	ipListsTmpl := util.LoadTemplate(nil, ipListsPaths...)
	ipListTmpl := util.LoadTemplate(nil, ipListPaths...)
	mfaTmpl := util.LoadTemplate(nil, mfaPaths...)
	twoFactorTmpl := util.LoadTemplate(nil, twoFactorPaths...)
	twoFactorRecoveryTmpl := util.LoadTemplate(nil, twoFactorRecoveryPaths...)
	setupTmpl := util.LoadTemplate(nil, setupPaths...)
	forgotPwdTmpl := util.LoadTemplate(nil, forgotPwdPaths...)
	resetPwdTmpl := util.LoadTemplate(nil, resetPwdPaths...)
	rolesTmpl := util.LoadTemplate(nil, rolesPaths...)
	roleTmpl := util.LoadTemplate(nil, rolePaths...)
	eventsTmpl := util.LoadTemplate(nil, eventsPaths...)
	configsTmpl := util.LoadTemplate(nil, configsPaths...)

	adminTemplates[templateUsers] = usersTmpl
	adminTemplates[templateUser] = userTmpl
	adminTemplates[templateAdmins] = adminsTmpl
	adminTemplates[templateAdmin] = adminTmpl
	adminTemplates[templateConnections] = connectionsTmpl
	adminTemplates[templateMessage] = messageTmpl
	adminTemplates[templateGroups] = groupsTmpl
	adminTemplates[templateGroup] = groupTmpl
	adminTemplates[templateFolders] = foldersTmpl
	adminTemplates[templateFolder] = folderTmpl
	adminTemplates[templateEventRules] = eventRulesTmpl
	adminTemplates[templateEventRule] = eventRuleTmpl
	adminTemplates[templateEventActions] = eventActionsTmpl
	adminTemplates[templateEventAction] = eventActionTmpl
	adminTemplates[templateStatus] = statusTmpl
	adminTemplates[templateCommonLogin] = loginTmpl
	adminTemplates[templateProfile] = profileTmpl
	adminTemplates[templateChangePwd] = changePwdTmpl
	adminTemplates[templateMaintenance] = maintenanceTmpl
	adminTemplates[templateDefender] = defenderTmpl
	adminTemplates[templateIPLists] = ipListsTmpl
	adminTemplates[templateIPList] = ipListTmpl
	adminTemplates[templateMFA] = mfaTmpl
	adminTemplates[templateTwoFactor] = twoFactorTmpl
	adminTemplates[templateTwoFactorRecovery] = twoFactorRecoveryTmpl
	adminTemplates[templateSetup] = setupTmpl
	adminTemplates[templateForgotPassword] = forgotPwdTmpl
	adminTemplates[templateResetPassword] = resetPwdTmpl
	adminTemplates[templateRoles] = rolesTmpl
	adminTemplates[templateRole] = roleTmpl
	adminTemplates[templateEvents] = eventsTmpl
	adminTemplates[templateConfigs] = configsTmpl
}

func isEventManagerResource(currentURL string) bool {
	if currentURL == webAdminEventRulesPath {
		return true
	}
	if currentURL == webAdminEventActionsPath {
		return true
	}
	if currentURL == webAdminEventRulePath || strings.HasPrefix(currentURL, webAdminEventRulePath+"/") {
		return true
	}
	if currentURL == webAdminEventActionPath || strings.HasPrefix(currentURL, webAdminEventActionPath+"/") {
		return true
	}
	return false
}

func isIPListsResource(currentURL string) bool {
	if currentURL == webDefenderPath {
		return true
	}
	if currentURL == webIPListsPath {
		return true
	}
	if strings.HasPrefix(currentURL, webIPListPath+"/") {
		return true
	}
	return false
}

func isServerManagerResource(currentURL string) bool {
	return currentURL == webEventsPath || currentURL == webStatusPath || currentURL == webMaintenancePath ||
		currentURL == webConfigsPath
}

func (s *httpdServer) getBasePageData(title, currentURL string, w http.ResponseWriter, r *http.Request) basePage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseAdminPath)
	}
	return basePage{
		commonBasePage:      getCommonBasePage(r),
		Title:               title,
		CurrentURL:          currentURL,
		UsersURL:            webUsersPath,
		UserURL:             webUserPath,
		UserTemplateURL:     webTemplateUser,
		AdminsURL:           webAdminsPath,
		AdminURL:            webAdminPath,
		GroupsURL:           webGroupsPath,
		GroupURL:            webGroupPath,
		FoldersURL:          webFoldersPath,
		FolderURL:           webFolderPath,
		FolderTemplateURL:   webTemplateFolder,
		DefenderURL:         webDefenderPath,
		IPListsURL:          webIPListsPath,
		IPListURL:           webIPListPath,
		EventsURL:           webEventsPath,
		ConfigsURL:          webConfigsPath,
		LogoutURL:           webLogoutPath,
		LoginURL:            webAdminLoginPath,
		ProfileURL:          webAdminProfilePath,
		ChangePwdURL:        webChangeAdminPwdPath,
		MFAURL:              webAdminMFAPath,
		EventRulesURL:       webAdminEventRulesPath,
		EventRuleURL:        webAdminEventRulePath,
		EventActionsURL:     webAdminEventActionsPath,
		EventActionURL:      webAdminEventActionPath,
		RolesURL:            webAdminRolesPath,
		RoleURL:             webAdminRolePath,
		QuotaScanURL:        webQuotaScanPath,
		ConnectionsURL:      webConnectionsPath,
		StatusURL:           webStatusPath,
		FolderQuotaScanURL:  webScanVFolderPath,
		MaintenanceURL:      webMaintenancePath,
		LoggedUser:          getAdminFromToken(r),
		IsEventManagerPage:  isEventManagerResource(currentURL),
		IsIPManagerPage:     isIPListsResource(currentURL),
		IsServerManagerPage: isServerManagerResource(currentURL),
		HasDefender:         common.Config.DefenderConfig.Enabled,
		HasSearcher:         plugin.Handler.HasSearcher(),
		HasExternalLogin:    isLoggedInWithOIDC(r),
		CSRFToken:           csrfToken,
		Branding:            s.binding.webAdminBranding(),
		Languages:           s.binding.languages(),
	}
}

func renderAdminTemplate(w http.ResponseWriter, tmplName string, data any) {
	err := adminTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderMessagePageWithString(w http.ResponseWriter, r *http.Request, title string, statusCode int,
	err error, message, text string,
) {
	data := messagePage{
		basePage: s.getBasePageData(title, "", w, r),
		Error:    getI18nError(err),
		Success:  message,
		Text:     text,
	}
	w.WriteHeader(statusCode)
	renderAdminTemplate(w, templateMessage, data)
}

func (s *httpdServer) renderMessagePage(w http.ResponseWriter, r *http.Request, title string, statusCode int,
	err error, message string,
) {
	s.renderMessagePageWithString(w, r, title, statusCode, err, message, "")
}

func (s *httpdServer) renderInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, util.I18nError500Title, http.StatusInternalServerError,
		util.NewI18nError(err, util.I18nError500Message), "")
}

func (s *httpdServer) renderBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, util.I18nError400Title, http.StatusBadRequest,
		util.NewI18nError(err, util.I18nError400Message), "")
}

func (s *httpdServer) renderForbiddenPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, util.I18nError403Title, http.StatusForbidden,
		util.NewI18nError(err, util.I18nError403Message), "")
}

func (s *httpdServer) renderNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderMessagePage(w, r, util.I18nError404Title, http.StatusNotFound,
		util.NewI18nError(err, util.I18nError404Message), "")
}

