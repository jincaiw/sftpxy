// SPDX-License-Identifier: MIT

package httpd

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/jwt"
	"github.com/jincaiw/sftpxy/v2/internal/mfa"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func loadClientTemplates(templatesPath string) {
	filesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientFiles),
	}
	editFilePath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientEditFile),
	}
	sharesPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShares),
	}
	sharePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientShare),
	}
	profilePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientProfile),
	}
	changePwdPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateCommonDir, templateChangePwd),
	}
	loginPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateCommonDir, templateCommonLogin),
	}
	messagePaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateCommonDir, templateMessage),
	}
	mfaPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateClientMFA),
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
	viewPDFPaths := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientViewPDF),
	}
	shareLoginPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateCommonDir, templateCommonBaseLogin),
		filepath.Join(templatesPath, templateClientDir, templateShareLogin),
	}
	shareUploadPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateUploadToShare),
	}
	shareDownloadPath := []string{
		filepath.Join(templatesPath, templateCommonDir, templateCommonBase),
		filepath.Join(templatesPath, templateClientDir, templateClientBase),
		filepath.Join(templatesPath, templateClientDir, templateShareDownload),
	}

	filesTmpl := util.LoadTemplate(nil, filesPaths...)
	profileTmpl := util.LoadTemplate(nil, profilePaths...)
	changePwdTmpl := util.LoadTemplate(nil, changePwdPaths...)
	loginTmpl := util.LoadTemplate(nil, loginPaths...)
	messageTmpl := util.LoadTemplate(nil, messagePaths...)
	mfaTmpl := util.LoadTemplate(nil, mfaPaths...)
	twoFactorTmpl := util.LoadTemplate(nil, twoFactorPaths...)
	twoFactorRecoveryTmpl := util.LoadTemplate(nil, twoFactorRecoveryPaths...)
	editFileTmpl := util.LoadTemplate(nil, editFilePath...)
	shareLoginTmpl := util.LoadTemplate(nil, shareLoginPath...)
	sharesTmpl := util.LoadTemplate(nil, sharesPaths...)
	shareTmpl := util.LoadTemplate(nil, sharePaths...)
	forgotPwdTmpl := util.LoadTemplate(nil, forgotPwdPaths...)
	resetPwdTmpl := util.LoadTemplate(nil, resetPwdPaths...)
	viewPDFTmpl := util.LoadTemplate(nil, viewPDFPaths...)
	shareUploadTmpl := util.LoadTemplate(nil, shareUploadPath...)
	shareDownloadTmpl := util.LoadTemplate(nil, shareDownloadPath...)

	clientTemplates[templateClientFiles] = filesTmpl
	clientTemplates[templateClientProfile] = profileTmpl
	clientTemplates[templateChangePwd] = changePwdTmpl
	clientTemplates[templateCommonLogin] = loginTmpl
	clientTemplates[templateMessage] = messageTmpl
	clientTemplates[templateClientMFA] = mfaTmpl
	clientTemplates[templateTwoFactor] = twoFactorTmpl
	clientTemplates[templateTwoFactorRecovery] = twoFactorRecoveryTmpl
	clientTemplates[templateClientEditFile] = editFileTmpl
	clientTemplates[templateClientShares] = sharesTmpl
	clientTemplates[templateClientShare] = shareTmpl
	clientTemplates[templateForgotPassword] = forgotPwdTmpl
	clientTemplates[templateResetPassword] = resetPwdTmpl
	clientTemplates[templateClientViewPDF] = viewPDFTmpl
	clientTemplates[templateShareLogin] = shareLoginTmpl
	clientTemplates[templateUploadToShare] = shareUploadTmpl
	clientTemplates[templateShareDownload] = shareDownloadTmpl
}

func (s *httpdServer) getBaseClientPageData(title, currentURL string, w http.ResponseWriter, r *http.Request) baseClientPage {
	var csrfToken string
	if currentURL != "" {
		csrfToken = createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseClientPath)
	}

	data := baseClientPage{
		commonBasePage:  getCommonBasePage(r),
		Title:           title,
		CurrentURL:      currentURL,
		FilesURL:        webClientFilesPath,
		SharesURL:       webClientSharesPath,
		ShareURL:        webClientSharePath,
		ProfileURL:      webClientProfilePath,
		PingURL:         webClientPingPath,
		ChangePwdURL:    webChangeClientPwdPath,
		LogoutURL:       webClientLogoutPath,
		EditURL:         webClientEditFilePath,
		MFAURL:          webClientMFAPath,
		CSRFToken:       csrfToken,
		LoggedUser:      getUserFromToken(r),
		IsLoggedToShare: false,
		Branding:        s.binding.webClientBranding(),
		Languages:       s.binding.languages(),
	}
	if !strings.HasPrefix(r.RequestURI, webClientPubSharesPath) {
		data.LoginURL = webClientLoginPath
	}
	return data
}

func renderClientTemplate(w http.ResponseWriter, tmplName string, data any) {
	err := clientTemplates[tmplName].ExecuteTemplate(w, tmplName, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *httpdServer) renderClientMessagePage(w http.ResponseWriter, r *http.Request, title string, statusCode int, err error, message string) {
	data := clientMessagePage{
		baseClientPage: s.getBaseClientPageData(title, "", w, r),
		Error:          getI18nError(err),
		Success:        message,
	}
	w.WriteHeader(statusCode)
	renderClientTemplate(w, templateMessage, data)
}

func (s *httpdServer) renderClientInternalServerErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError500Title, http.StatusInternalServerError,
		util.NewI18nError(err, util.I18nError500Message), "")
}

func (s *httpdServer) renderClientBadRequestPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError400Title, http.StatusBadRequest,
		util.NewI18nError(err, util.I18nError400Message), "")
}

func (s *httpdServer) renderClientForbiddenPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError403Title, http.StatusForbidden,
		util.NewI18nError(err, util.I18nError403Message), "")
}

func (s *httpdServer) renderClientNotFoundPage(w http.ResponseWriter, r *http.Request, err error) {
	s.renderClientMessagePage(w, r, util.I18nError404Title, http.StatusNotFound,
		util.NewI18nError(err, util.I18nError404Message), "")
}

func (s *httpdServer) renderClientForgotPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := forgotPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webClientForgotPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseClientPath),
		LoginURL:       webClientLoginPath,
		Title:          util.I18nForgotPwdTitle,
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
	}
	renderClientTemplate(w, templateForgotPassword, data)
}

func (s *httpdServer) renderClientResetPwdPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := resetPwdPage{
		commonBasePage: getCommonBasePage(r),
		CurrentURL:     webClientResetPwdPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseClientPath),
		LoginURL:       webClientLoginPath,
		Title:          util.I18nResetPwdTitle,
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
	}
	renderClientTemplate(w, templateResetPassword, data)
}

func (s *httpdServer) renderShareLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := shareLoginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nShareLoginTitle,
		CurrentURL:     r.RequestURI,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseClientPath),
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
		CheckRedirect:  false,
	}
	renderClientTemplate(w, templateShareLogin, data)
}

func (s *httpdServer) renderClientTwoFactorPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18n2FATitle,
		CurrentURL:     webClientTwoFactorPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseClientPath),
		RecoveryURL:    webClientTwoFactorRecoveryPath,
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
	}
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		data.CurrentURL += "?next=" + url.QueryEscape(next)
	}
	renderClientTemplate(w, templateTwoFactor, data)
}

func (s *httpdServer) renderClientTwoFactorRecoveryPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := twoFactorPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18n2FATitle,
		CurrentURL:     webClientTwoFactorRecoveryPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, "", webBaseClientPath),
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
	}
	renderClientTemplate(w, templateTwoFactorRecovery, data)
}

func (s *httpdServer) renderClientMFAPage(w http.ResponseWriter, r *http.Request) {
	data := clientMFAPage{
		baseClientPage:  s.getBaseClientPageData(util.I18n2FATitle, webClientMFAPath, w, r),
		TOTPConfigs:     mfa.GetAvailableTOTPConfigNames(),
		GenerateTOTPURL: webClientTOTPGeneratePath,
		ValidateTOTPURL: webClientTOTPValidatePath,
		SaveTOTPURL:     webClientTOTPSavePath,
		RecCodesURL:     webClientRecoveryCodesPath,
		Protocols:       dataprovider.MFAProtocols,
	}
	user, err := dataprovider.GetUserWithGroupSettings(data.LoggedUser.Username, "")
	if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	data.TOTPConfig = user.Filters.TOTPConfig
	data.RequiredProtocols = user.Filters.TwoFactorAuthProtocols
	if claims, claimsErr := jwt.FromContext(r.Context()); claimsErr == nil && claims.MustSetTwoFactorAuth {
		if len(claims.RequiredTwoFactorProtocols) > 0 {
			protocols := strings.Join(claims.RequiredTwoFactorProtocols, ", ")
			data.RequiredAction = util.NewI18nError(
				util.NewGenericError("Two-factor authentication setup required"),
				util.I18nError2FARequired,
				util.I18nErrorArgs(map[string]any{
					"val": protocols,
				}),
			)
		} else {
			data.RequiredAction = util.NewI18nError(
				util.NewGenericError("Two-factor authentication setup required"),
				util.I18nError2FARequiredGeneric,
			)
		}
	}
	renderClientTemplate(w, templateClientMFA, data)
}

func (s *httpdServer) renderEditFilePage(w http.ResponseWriter, r *http.Request, fileName, fileData string, readOnly bool) {
	title := util.I18nViewFileTitle
	if !readOnly {
		title = util.I18nEditFileTitle
	}
	data := editFilePage{
		baseClientPage: s.getBaseClientPageData(title, webClientEditFilePath, w, r),
		Path:           fileName,
		Name:           path.Base(fileName),
		CurrentDir:     path.Dir(fileName),
		FileURL:        webClientFilePath,
		ReadOnly:       readOnly,
		Data:           fileData,
	}

	renderClientTemplate(w, templateClientEditFile, data)
}

func (s *httpdServer) renderAddUpdateSharePage(w http.ResponseWriter, r *http.Request, share *dataprovider.Share,
	err *util.I18nError, isAdd bool) {
	currentURL := webClientSharePath
	title := util.I18nShareAddTitle
	if !isAdd {
		currentURL = fmt.Sprintf("%v/%v", webClientSharePath, url.PathEscape(share.ShareID))
		title = util.I18nShareUpdateTitle
	}
	if share.IsPasswordHashed() {
		share.Password = redactedSecret
	}
	data := clientSharePage{
		baseClientPage: s.getBaseClientPageData(title, currentURL, w, r),
		Share:          share,
		Error:          err,
		IsAdd:          isAdd,
	}

	renderClientTemplate(w, templateClientShare, data)
}

func (s *httpdServer) renderSharedFilesPage(w http.ResponseWriter, r *http.Request, dirName string,
	err *util.I18nError, share dataprovider.Share,
) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "browse")
	baseData := s.getBaseClientPageData(util.I18nSharedFilesTitle, currentURL, w, r)
	baseData.FilesURL = currentURL
	baseSharePath := path.Join(webClientPubSharesPath, share.ShareID)
	baseData.LogoutURL = path.Join(webClientPubSharesPath, share.ShareID, "logout")
	baseData.IsLoggedToShare = share.Password != ""

	data := filesPage{
		baseClientPage: baseData,
		Error:          err,
		CurrentDir:     url.QueryEscape(dirName),
		DownloadURL:    path.Join(baseSharePath, "partial"),
		// dirName must be escaped because the router expects the full path as single argument
		ShareUploadBaseURL: path.Join(baseSharePath, url.PathEscape(dirName)),
		ViewPDFURL:         path.Join(baseSharePath, "viewpdf"),
		DirsURL:            path.Join(baseSharePath, "dirs"),
		FileURL:            "",
		FileActionsURL:     "",
		CheckExistURL:      path.Join(baseSharePath, "browse", "exist"),
		TasksURL:           "",
		CanAddFiles:        share.Scope == dataprovider.ShareScopeReadWrite,
		CanCreateDirs:      false,
		CanRename:          false,
		CanDelete:          false,
		CanDownload:        share.Scope != dataprovider.ShareScopeWrite,
		CanShare:           false,
		CanCopy:            false,
		Paths:              getDirMapping(dirName, currentURL),
		QuotaUsage:         newUserQuotaUsage(&dataprovider.User{}),
		KeepAliveInterval:  int(cookieRefreshThreshold / time.Millisecond),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderShareDownloadPage(w http.ResponseWriter, r *http.Request, share *dataprovider.Share,
	downloadLink string,
) {
	data := shareDownloadPage{
		baseClientPage: s.getBaseClientPageData(util.I18nShareDownloadTitle, "", w, r),
		DownloadLink:   downloadLink,
	}
	data.LogoutURL = ""
	if share.Password != "" {
		data.LogoutURL = path.Join(webClientPubSharesPath, share.ShareID, "logout")
	}

	renderClientTemplate(w, templateShareDownload, data)
}

func (s *httpdServer) renderUploadToSharePage(w http.ResponseWriter, r *http.Request, share *dataprovider.Share) {
	currentURL := path.Join(webClientPubSharesPath, share.ShareID, "upload")
	data := shareUploadPage{
		baseClientPage: s.getBaseClientPageData(util.I18nShareUploadTitle, currentURL, w, r),
		Share:          share,
		UploadBasePath: path.Join(webClientPubSharesPath, share.ShareID),
	}
	data.LogoutURL = ""
	if share.Password != "" {
		data.LogoutURL = path.Join(webClientPubSharesPath, share.ShareID, "logout")
	}
	renderClientTemplate(w, templateUploadToShare, data)
}

func (s *httpdServer) renderFilesPage(w http.ResponseWriter, r *http.Request, dirName string,
	err *util.I18nError, user *dataprovider.User) {
	data := filesPage{
		baseClientPage:     s.getBaseClientPageData(util.I18nFilesTitle, webClientFilesPath, w, r),
		Error:              err,
		CurrentDir:         url.QueryEscape(dirName),
		DownloadURL:        webClientDownloadZipPath,
		ViewPDFURL:         webClientViewPDFPath,
		DirsURL:            webClientDirsPath,
		FileURL:            webClientFilePath,
		FileActionsURL:     webClientFileActionsPath,
		CheckExistURL:      webClientExistPath,
		TasksURL:           webClientTasksPath,
		CanAddFiles:        user.CanAddFilesFromWeb(dirName),
		CanCreateDirs:      user.CanAddDirsFromWeb(dirName),
		CanRename:          user.CanRenameFromWeb(dirName, dirName),
		CanDelete:          user.CanDeleteFromWeb(dirName),
		CanDownload:        user.HasPerm(dataprovider.PermDownload, dirName),
		CanShare:           user.CanManageShares(),
		CanCopy:            user.CanCopyFromWeb(dirName, dirName),
		ShareUploadBaseURL: "",
		Paths:              getDirMapping(dirName, webClientFilesPath),
		QuotaUsage:         newUserQuotaUsage(user),
		KeepAliveInterval:  int(cookieRefreshThreshold / time.Millisecond),
	}
	renderClientTemplate(w, templateClientFiles, data)
}

func (s *httpdServer) renderClientProfilePage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := clientProfilePage{
		baseClientPage: s.getBaseClientPageData(util.I18nProfileTitle, webClientProfilePath, w, r),
		Error:          err,
	}
	user, userMerged, errUser := dataprovider.GetUserVariants(data.LoggedUser.Username, "")
	if errUser != nil {
		s.renderClientInternalServerErrorPage(w, r, errUser)
		return
	}
	data.PublicKeys = user.PublicKeys
	data.TLSCerts = user.Filters.TLSCerts
	data.AllowAPIKeyAuth = user.Filters.AllowAPIKeyAuth
	data.Email = user.Email
	data.AdditionalEmails = user.Filters.AdditionalEmails
	data.AdditionalEmailsString = strings.Join(data.AdditionalEmails, ", ")
	data.Description = user.Description
	data.CanSubmit = userMerged.CanUpdateProfile()
	renderClientTemplate(w, templateClientProfile, data)
}

func (s *httpdServer) renderClientChangePasswordPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := changeClientPasswordPage{
		baseClientPage: s.getBaseClientPageData(util.I18nChangePwdTitle, webChangeClientPwdPath, w, r),
		Error:          err,
	}
	if claims, claimsErr := jwt.FromContext(r.Context()); claimsErr == nil && claims.MustChangePassword {
		data.RequiredAction = util.NewI18nError(
			util.NewGenericError("Password change required"),
			util.I18nErrorChangePwdRequired,
		)
	}
	renderClientTemplate(w, templateChangePwd, data)
}
