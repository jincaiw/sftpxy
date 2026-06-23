// SPDX-License-Identifier: MIT

package httpd

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/render"
	"github.com/jincaiw/sftpxy/sdk"
	"github.com/rs/xid"

	"github.com/jincaiw/sftpxy/v2/internal/common"
	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/jwt"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/mfa"
	"github.com/jincaiw/sftpxy/v2/internal/smtp"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func (s *httpdServer) renderClientLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := loginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nLoginTitle,
		CurrentURL:     webClientLoginPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseClientPath),
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
		FormDisabled:   s.binding.isWebClientLoginFormDisabled(),
		CheckRedirect:  true,
	}
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		data.CurrentURL += "?next=" + url.QueryEscape(next)
	}
	if s.binding.showAdminLoginURL() {
		data.AltLoginURL = webAdminLoginPath
		data.AltLoginName = s.binding.webAdminBranding().ShortName
	}
	if smtp.IsEnabled() && !data.FormDisabled {
		data.ForgotPwdURL = webClientForgotPwdPath
	}
	if s.binding.OIDC.isEnabled() && !s.binding.isWebClientOIDCLoginDisabled() {
		data.OpenIDLoginURL = webClientOIDCLoginPath
	}
	renderClientTemplate(w, templateCommonLogin, data)
}

func (s *httpdServer) handleWebClientLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	removeCookie(w, r, webBaseClientPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webClientLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebClientChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if err := r.ParseForm(); err != nil {
		s.renderClientChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err := doChangeUserPassword(r, strings.TrimSpace(r.Form.Get("current_password")),
		strings.TrimSpace(r.Form.Get("new_password1")), strings.TrimSpace(r.Form.Get("new_password2")))
	if err != nil {
		s.renderClientChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}
	s.handleWebClientLogout(w, r)
}

func (s *httpdServer) handleClientWebLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	msg := getFlashMessage(w, r)
	s.renderClientLoginPage(w, r, msg.getI18nError())
}

func (s *httpdServer) handleWebClientLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	protocol := common.ProtocolHTTP
	username := strings.TrimSpace(r.Form.Get("username"))
	password := r.Form.Get("password")
	if username == "" || password == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		s.renderClientLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
	}

	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}

	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nError403Message))
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientLoginPage(w, r, util.NewI18nError(err, util.I18nErrorFsGeneric))
		return
	}
	s.loginUser(w, r, &user, connectionID, ipAddr, false, s.renderClientLoginPage)
}

func (s *httpdServer) handleWebClientPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	newPassword := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	_, user, err := handleResetPassword(r, strings.TrimSpace(r.Form.Get("code")),
		newPassword, confirmPassword, false)
	if err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}
	connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
	if err := checkHTTPClientUser(user, r, connectionID, true, false); err != nil {
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorLoginAfterReset))
		return
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		s.renderClientResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorLoginAfterReset))
		return
	}
	s.loginUser(w, r, user, connectionID, ipAddr, false, s.renderClientResetPwdPage)
}

func (s *httpdServer) handleWebClientTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	recoveryCode := strings.TrimSpace(r.Form.Get("recovery_code"))
	if username == "" || recoveryCode == "" {
		s.renderClientTwoFactorRecoveryPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user, userMerged, err := dataprovider.GetUserVariants(username, "")
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderClientTwoFactorRecoveryPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if !userMerged.Filters.TOTPConfig.Enabled || !slices.Contains(userMerged.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(
			util.NewValidationError("two factory authentication is not enabled"), util.I18n2FADisabled))
		return
	}
	for idx, code := range user.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderClientInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderClientTwoFactorRecoveryPage(w, r,
					util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
				return
			}
			user.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %q as used: %v", recoveryCode, err)
				s.renderClientInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			connectionID := fmt.Sprintf("%v_%v", getProtocolFromRequest(r), xid.New().String())
			s.loginUser(w, r, &userMerged, connectionID, ipAddr, true,
				s.renderClientTwoFactorRecoveryPage)
			return
		}
	}
	handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
	s.renderClientTwoFactorRecoveryPage(w, r,
		util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
}

func (s *httpdServer) handleWebClientTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	passcode := strings.TrimSpace(r.Form.Get("passcode"))
	if username == "" || passcode == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(username, "")
	if err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials))
		return
	}
	if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientTwoFactorPage(w, r, util.NewI18nError(common.ErrInternalFailure, util.I18n2FADisabled))
		return
	}
	err = user.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
		s.renderClientTwoFactorPage(w, r,
			util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	connectionID := fmt.Sprintf("%s_%s", getProtocolFromRequest(r), xid.New().String())
	s.loginUser(w, r, &user, connectionID, ipAddr, true, s.renderClientTwoFactorPage)
}

func (s *httpdServer) handleWebAdminTwoFactorRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	recoveryCode := strings.TrimSpace(r.Form.Get("recovery_code"))
	if username == "" || recoveryCode == "" {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(util.NewValidationError("two factory authentication is not enabled"), util.I18n2FADisabled))
		return
	}
	for idx, code := range admin.Filters.RecoveryCodes {
		if err := code.Secret.Decrypt(); err != nil {
			s.renderInternalServerErrorPage(w, r, fmt.Errorf("unable to decrypt recovery code: %w", err))
			return
		}
		if code.Secret.GetPayload() == recoveryCode {
			if code.Used {
				s.renderTwoFactorRecoveryPage(w, r,
					util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
				return
			}
			admin.Filters.RecoveryCodes[idx].Used = true
			err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role)
			if err != nil {
				logger.Warn(logSender, "", "unable to set the recovery code %q as used: %v", recoveryCode, err)
				s.renderInternalServerErrorPage(w, r, errors.New("unable to set the recovery code as used"))
				return
			}
			s.loginAdmin(w, r, &admin, true, s.renderTwoFactorRecoveryPage, ipAddr)
			return
		}
	}
	handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
	s.renderTwoFactorRecoveryPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
}

func (s *httpdServer) handleWebAdminTwoFactorPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		s.renderNotFoundPage(w, r, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := claims.Username
	passcode := strings.TrimSpace(r.Form.Get("passcode"))
	if username == "" || passcode == "" {
		s.renderTwoFactorPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.AdminExists(username)
	if err != nil {
		if errors.Is(err, util.ErrNotFound) {
			handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		}
		s.renderTwoFactorPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials))
		return
	}
	if !admin.Filters.TOTPConfig.Enabled {
		s.renderTwoFactorPage(w, r, util.NewI18nError(common.ErrInternalFailure, util.I18n2FADisabled))
		return
	}
	err = admin.Filters.TOTPConfig.Secret.Decrypt()
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	match, err := mfa.ValidateTOTPPasscode(admin.Filters.TOTPConfig.ConfigName, passcode,
		admin.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
		s.renderTwoFactorPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	s.loginAdmin(w, r, &admin, true, s.renderTwoFactorPage, ipAddr)
}

func (s *httpdServer) handleWebAdminLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))
	if username == "" || password == "" {
		s.renderAdminLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderAdminLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	admin, err := dataprovider.CheckAdminAndPass(username, password, ipAddr)
	if err != nil {
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		s.renderAdminLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	s.loginAdmin(w, r, &admin, false, s.renderAdminLoginPage, ipAddr)
}

func (s *httpdServer) renderAdminLoginPage(w http.ResponseWriter, r *http.Request, err *util.I18nError) {
	data := loginPage{
		commonBasePage: getCommonBasePage(r),
		Title:          util.I18nLoginTitle,
		CurrentURL:     webAdminLoginPath,
		Error:          err,
		CSRFToken:      createCSRFToken(w, r, s.csrfTokenAuth, rand.Text(), webBaseAdminPath),
		Branding:       s.binding.webAdminBranding(),
		Languages:      s.binding.languages(),
		FormDisabled:   s.binding.isWebAdminLoginFormDisabled(),
		CheckRedirect:  false,
	}
	if s.binding.showClientLoginURL() {
		data.AltLoginURL = webClientLoginPath
		data.AltLoginName = s.binding.webClientBranding().ShortName
	}
	if smtp.IsEnabled() && !data.FormDisabled {
		data.ForgotPwdURL = webAdminForgotPwdPath
	}
	if s.binding.OIDC.hasRoles() && !s.binding.isWebAdminOIDCLoginDisabled() {
		data.OpenIDLoginURL = webAdminOIDCLoginPath
	}
	renderAdminTemplate(w, templateCommonLogin, data)
}

func (s *httpdServer) handleWebAdminLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
		return
	}
	msg := getFlashMessage(w, r)
	s.renderAdminLoginPage(w, r, msg.getI18nError())
}

func (s *httpdServer) handleWebAdminLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	removeCookie(w, r, webBaseAdminPath)
	s.logoutOIDCUser(w, r)

	http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
}

func (s *httpdServer) handleWebAdminChangePwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = doChangeAdminPassword(r, strings.TrimSpace(r.Form.Get("current_password")),
		strings.TrimSpace(r.Form.Get("new_password1")), strings.TrimSpace(r.Form.Get("new_password2")))
	if err != nil {
		s.renderChangePasswordPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}
	s.handleWebAdminLogout(w, r)
}

func (s *httpdServer) handleWebAdminPasswordResetPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	newPassword := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	admin, _, err := handleResetPassword(r, strings.TrimSpace(r.Form.Get("code")),
		newPassword, confirmPassword, true)
	if err != nil {
		s.renderResetPwdPage(w, r, util.NewI18nError(err, util.I18nErrorChangePwdGeneric))
		return
	}

	s.loginAdmin(w, r, admin, false, s.renderResetPwdPage, ipAddr)
}

func (s *httpdServer) handleWebAdminSetupPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if dataprovider.HasAdmin() {
		s.renderBadRequestPage(w, r, errors.New("an admin user already exists"))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err := r.ParseForm()
	if err != nil {
		s.renderAdminSetupPage(w, r, "", util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	password := strings.TrimSpace(r.Form.Get("password"))
	confirmPassword := strings.TrimSpace(r.Form.Get("confirm_password"))
	installCode := strings.TrimSpace(r.Form.Get("install_code"))
	if installationCode != "" && installCode != resolveInstallationCode() {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("%v mismatch", installationCodeHint)),
				util.I18nErrorSetupInstallCode),
		)
		return
	}
	if username == "" {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(util.NewValidationError("please set a username"), util.I18nError500Message))
		return
	}
	if password == "" {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(util.NewValidationError("please set a password"), util.I18nError500Message))
		return
	}
	if password != confirmPassword {
		s.renderAdminSetupPage(w, r, username,
			util.NewI18nError(errors.New("the two password fields do not match"), util.I18nErrorChangePwdNoMatch))
		return
	}
	admin := dataprovider.Admin{
		Username:    username,
		Password:    password,
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
	}
	err = dataprovider.AddAdmin(&admin, username, ipAddr, "")
	if err != nil {
		s.renderAdminSetupPage(w, r, username, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	s.loginAdmin(w, r, &admin, false, nil, ipAddr)
}

func (s *httpdServer) loginUser(
	w http.ResponseWriter, r *http.Request, user *dataprovider.User, connectionID, ipAddr string,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, r *http.Request, err *util.I18nError),
) {
	c := &jwt.Claims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Role:                       user.Role,
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		MustChangePassword:         user.MustChangePassword(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}
	c.Subject = user.GetSignature()

	audience := tokenAudienceWebClient
	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) &&
		user.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebClientPartial
	}

	err := createAndSetCookie(w, r, c, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to set user login cookie %v", err)
		updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		errorFunc(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	invalidateToken(r)
	if audience == tokenAudienceWebClientPartial {
		redirectPath := webClientTwoFactorPath
		if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
			redirectPath += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, redirectPath, http.StatusFound)
		return
	}
	updateLoginMetrics(user, dataprovider.LoginMethodPassword, ipAddr, err, r)
	dataprovider.UpdateLastLogin(user)
	if next := r.URL.Query().Get("next"); strings.HasPrefix(next, webClientFilesPath) {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	http.Redirect(w, r, webClientFilesPath, http.StatusFound)
}

func (s *httpdServer) loginAdmin(
	w http.ResponseWriter, r *http.Request, admin *dataprovider.Admin,
	isSecondFactorAuth bool, errorFunc func(w http.ResponseWriter, r *http.Request, err *util.I18nError),
	ipAddr string,
) {
	c := &jwt.Claims{
		Username:             admin.Username,
		Permissions:          admin.Permissions,
		Role:                 admin.Role,
		HideUserPageSections: admin.Filters.Preferences.HideUserPageSections,
		MustSetTwoFactorAuth: admin.Filters.RequireTwoFactor && !admin.Filters.TOTPConfig.Enabled,
		MustChangePassword:   admin.Filters.RequirePasswordChange,
	}
	c.Subject = admin.GetSignature()

	audience := tokenAudienceWebAdmin
	if admin.Filters.TOTPConfig.Enabled && admin.CanManageMFA() && !isSecondFactorAuth {
		audience = tokenAudienceWebAdminPartial
	}

	err := createAndSetCookie(w, r, c, s.tokenAuth, audience, ipAddr)
	if err != nil {
		logger.Warn(logSender, "", "unable to set admin login cookie %v", err)
		if errorFunc == nil {
			s.renderAdminSetupPage(w, r, admin.Username, util.NewI18nError(err, util.I18nError500Message))
			return
		}
		errorFunc(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	invalidateToken(r)
	if audience == tokenAudienceWebAdminPartial {
		http.Redirect(w, r, webAdminTwoFactorPath, http.StatusFound)
		return
	}
	dataprovider.UpdateAdminLastLogin(admin)
	common.DelayLogin(nil)
	redirectURL := webUsersPath
	if errorFunc == nil {
		redirectURL = webAdminMFAPath
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *httpdServer) logout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	invalidateToken(r)
	sendAPIResponse(w, r, nil, "Your token has been invalidated", http.StatusOK)
}

func (s *httpdServer) getUserToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	username, password, ok := r.BasicAuth()
	protocol := common.ProtocolHTTP
	if !ok {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if username == "" || strings.TrimSpace(password) == "" {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, common.ErrNoCredentials, r)
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := common.Config.ExecutePostConnectHook(ipAddr, protocol); err != nil {
		updateLoginMetrics(&dataprovider.User{BaseUser: sdk.BaseUser{Username: username}},
			dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	user, err := dataprovider.CheckUserAndPass(username, password, ipAddr, protocol)
	if err != nil {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	connectionID := fmt.Sprintf("%v_%v", protocol, xid.New().String())
	if err := checkHTTPClientUser(&user, r, connectionID, true, false); err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, common.ProtocolHTTP) {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for user %q and not passcode provided, authentication refused", user.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
		err = user.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err), http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
			user.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for user %q, match? %v, err: %v", user.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, dataprovider.ErrInvalidCredentials, r)
			sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	defer user.CloseFs() //nolint:errcheck
	err = user.CheckFsRoot(connectionID)
	if err != nil {
		logger.Warn(logSender, connectionID, "unable to check fs root: %v", err)
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	s.generateAndSendUserToken(w, r, ipAddr, user)
}

func (s *httpdServer) generateAndSendUserToken(w http.ResponseWriter, r *http.Request, ipAddr string, user dataprovider.User) {
	c := &jwt.Claims{
		Username:                   user.Username,
		Permissions:                user.Filters.WebClient,
		Role:                       user.Role,
		MustSetTwoFactorAuth:       user.MustSetSecondFactor(),
		MustChangePassword:         user.MustChangePassword(),
		RequiredTwoFactorProtocols: user.Filters.TwoFactorAuthProtocols,
	}
	c.Subject = user.GetSignature()

	token, err := s.tokenAuth.SignWithParams(c, tokenAudienceAPIUser, ipAddr, getTokenDuration(tokenAudienceAPIUser))
	if err != nil {
		updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, common.ErrInternalFailure, r)
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	updateLoginMetrics(&user, dataprovider.LoginMethodPassword, ipAddr, err, r)
	dataprovider.UpdateLastLogin(&user)

	render.JSON(w, r, c.BuildTokenResponse(token))
}

func (s *httpdServer) getToken(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	admin, err := dataprovider.CheckAdminAndPass(username, password, ipAddr)
	if err != nil {
		handleDefenderEventLoginFailed(ipAddr, err) //nolint:errcheck
		w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
		sendAPIResponse(w, r, dataprovider.ErrInvalidCredentials, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	if admin.Filters.TOTPConfig.Enabled {
		passcode := r.Header.Get(otpHeaderCode)
		if passcode == "" {
			logger.Debug(logSender, "", "TOTP enabled for admin %q and not passcode provided, authentication refused", admin.Username)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			err = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		err = admin.Filters.TOTPConfig.Secret.Decrypt()
		if err != nil {
			sendAPIResponse(w, r, fmt.Errorf("unable to decrypt TOTP secret: %w", err),
				http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		match, err := mfa.ValidateTOTPPasscode(admin.Filters.TOTPConfig.ConfigName, passcode,
			admin.Filters.TOTPConfig.Secret.GetPayload())
		if !match || err != nil {
			logger.Debug(logSender, "invalid passcode for admin %q, match? %v, err: %v", admin.Username, match, err)
			w.Header().Set(common.HTTPAuthenticationHeader, basicRealm)
			err = handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials)
			sendAPIResponse(w, r, err, http.StatusText(http.StatusUnauthorized),
				http.StatusUnauthorized)
			return
		}
	}

	s.generateAndSendToken(w, r, admin, ipAddr)
}

func (s *httpdServer) generateAndSendToken(w http.ResponseWriter, r *http.Request, admin dataprovider.Admin, ip string) {
	c := &jwt.Claims{
		Username:             admin.Username,
		Permissions:          admin.Permissions,
		Role:                 admin.Role,
		MustSetTwoFactorAuth: admin.Filters.RequireTwoFactor && !admin.Filters.TOTPConfig.Enabled,
		MustChangePassword:   admin.Filters.RequirePasswordChange,
	}
	c.Subject = admin.GetSignature()

	token, err := s.tokenAuth.SignWithParams(c, tokenAudienceAPI, ip, getTokenDuration(tokenAudienceAPI))
	if err != nil {
		sendAPIResponse(w, r, err, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	dataprovider.UpdateAdminLastLogin(&admin)
	common.DelayLogin(nil)
	render.JSON(w, r, c.BuildTokenResponse(token))
}
