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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sftpgo/sdk"
	"golang.org/x/oauth2"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/smtp"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func (s *httpdServer) handleWebAdminForgotPwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		s.renderNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderForgotPwdPage(w, r, nil)
}

func (s *httpdServer) handleWebAdminForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	err := r.ParseForm()
	if err != nil {
		s.renderForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = handleForgotPassword(r, r.Form.Get("username"), true)
	if err != nil {
		s.renderForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorPwdResetGeneric))
		return
	}
	http.Redirect(w, r, webAdminResetPwdPath, http.StatusFound)
}

func (s *httpdServer) handleWebAdminPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !smtp.IsEnabled() {
		s.renderNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderResetPwdPage(w, r, nil)
}

func (s *httpdServer) handleWebAdminTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderTwoFactorPage(w, r, nil)
}

func (s *httpdServer) handleWebAdminTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderTwoFactorRecoveryPage(w, r, nil)
}

func (s *httpdServer) handleWebAdminMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderMFAPage(w, r)
}

func (s *httpdServer) handleWebAdminProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderProfilePage(w, r, nil)
}

func (s *httpdServer) handleWebAdminChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderChangePasswordPage(w, r, nil)
}

func (s *httpdServer) handleWebAdminProfilePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderProfilePage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderProfilePage(w, r, util.NewI18nError(err, util.I18nErrorInvalidToken))
		return
	}
	admin, err := dataprovider.AdminExists(claims.Username)
	if err != nil {
		s.renderProfilePage(w, r, err)
		return
	}
	admin.Filters.AllowAPIKeyAuth = r.Form.Get("allow_api_key_auth") != ""
	admin.Email = r.Form.Get("email")
	admin.Description = r.Form.Get("description")
	err = dataprovider.UpdateAdmin(&admin, dataprovider.ActionExecutorSelf, ipAddr, admin.Role)
	if err != nil {
		s.renderProfilePage(w, r, err)
		return
	}
	s.renderMessagePage(w, r, util.I18nProfileTitle, http.StatusOK, nil, util.I18nProfileUpdated)
}

func (s *httpdServer) handleWebMaintenance(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderMaintenancePage(w, r, nil)
}

func (s *httpdServer) handleWebRestore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRestoreSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	err = r.ParseMultipartForm(MaxRestoreSize)
	if err != nil {
		s.renderMaintenancePage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	restoreMode, err := strconv.Atoi(r.Form.Get("mode"))
	if err != nil {
		s.renderMaintenancePage(w, r, err)
		return
	}
	scanQuota, err := strconv.Atoi(r.Form.Get("quota"))
	if err != nil {
		s.renderMaintenancePage(w, r, err)
		return
	}
	backupFile, _, err := r.FormFile("backup_file")
	if err != nil {
		s.renderMaintenancePage(w, r, util.NewI18nError(err, util.I18nErrorBackupFile))
		return
	}
	defer backupFile.Close()

	backupContent, err := io.ReadAll(backupFile)
	if err != nil || len(backupContent) == 0 {
		if len(backupContent) == 0 {
			err = errors.New("backup file size must be greater than 0")
		}
		s.renderMaintenancePage(w, r, util.NewI18nError(err, util.I18nErrorBackupFile))
		return
	}

	if err := restoreBackup(backupContent, "", scanQuota, restoreMode, claims.Username, ipAddr, claims.Role); err != nil {
		s.renderMaintenancePage(w, r, util.NewI18nError(err, util.I18nErrorRestore))
		return
	}

	s.renderMessagePage(w, r, util.I18nMaintenanceTitle, http.StatusOK, nil, util.I18nBackupOK)
}

func getAllAdmins(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorInvalidToken, http.StatusForbidden)
		return
	}

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetAdmins(limit, offset, dataprovider.OrderASC)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleGetWebAdmins(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := s.getBasePageData(util.I18nAdminsTitle, webAdminsPath, w, r)
	renderAdminTemplate(w, templateAdmins, data)
}

func (s *httpdServer) handleWebAdminSetupGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webAdminLoginPath, http.StatusFound)
		return
	}
	s.renderAdminSetupPage(w, r, "", nil)
}

func (s *httpdServer) handleWebAddAdminGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	admin := &dataprovider.Admin{
		Status:      1,
		Permissions: []string{dataprovider.PermAdminAny},
	}
	s.renderAddUpdateAdminPage(w, r, admin, nil, true)
}

func (s *httpdServer) handleWebUpdateAdminGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if err == nil {
		s.renderAddUpdateAdminPage(w, r, &admin, nil, false)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebAddAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	admin, err := getAdminFromPostFields(r)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &admin, err, true)
		return
	}
	if admin.Password == "" {
		// Administrators can be used with OpenID Connect or for authentication
		// via API key, in these cases the password is not necessary, we create
		// a non-usable one. This feature is only useful for WebAdmin, in REST
		// API you can create an unusable password externally.
		admin.Password = util.GenerateUniqueID()
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = dataprovider.AddAdmin(&admin, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &admin, err, true)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateAdminPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	username := getURLParam(r, "username")
	admin, err := dataprovider.AdminExists(username)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}

	updatedAdmin, err := getAdminFromPostFields(r)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &updatedAdmin, err, false)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedAdmin.ID = admin.ID
	updatedAdmin.Username = admin.Username
	if updatedAdmin.Password == "" {
		updatedAdmin.Password = admin.Password
	}
	updatedAdmin.Filters.TOTPConfig = admin.Filters.TOTPConfig
	updatedAdmin.Filters.RecoveryCodes = admin.Filters.RecoveryCodes
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderAddUpdateAdminPage(w, r, &updatedAdmin, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken), false)
		return
	}
	if username == claims.Username {
		if !util.SlicesEqual(admin.Permissions, updatedAdmin.Permissions) {
			s.renderAddUpdateAdminPage(w, r, &updatedAdmin,
				util.NewI18nError(errors.New("you cannot change your permissions"),
					util.I18nErrorAdminSelfPerms,
				), false)
			return
		}
		if updatedAdmin.Status == 0 {
			s.renderAddUpdateAdminPage(w, r, &updatedAdmin,
				util.NewI18nError(errors.New("you cannot disable yourself"),
					util.I18nErrorAdminSelfDisable,
				), false)
			return
		}
		if updatedAdmin.Role != claims.Role {
			s.renderAddUpdateAdminPage(w, r, &updatedAdmin,
				util.NewI18nError(
					errors.New("you cannot add/change your role"),
					util.I18nErrorAdminSelfRole,
				), false)
			return
		}
		updatedAdmin.Filters.RequirePasswordChange = admin.Filters.RequirePasswordChange
		updatedAdmin.Filters.RequireTwoFactor = admin.Filters.RequireTwoFactor
	}
	err = dataprovider.UpdateAdmin(&updatedAdmin, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderAddUpdateAdminPage(w, r, &updatedAdmin, err, false)
		return
	}
	http.Redirect(w, r, webAdminsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebDefenderPage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	data := defenderHostsPage{
		basePage:         s.getBasePageData(util.I18nDefenderTitle, webDefenderPath, w, r),
		DefenderHostsURL: webDefenderHostsPath,
	}

	renderAdminTemplate(w, templateDefender, data)
}

func getAllUsers(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorInvalidToken, http.StatusForbidden)
		return
	}

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetUsers(limit, offset, dataprovider.OrderASC, claims.Role)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleGetWebUsers(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	data := s.getBasePageData(util.I18nUsersTitle, webUsersPath, w, r)
	renderAdminTemplate(w, templateUsers, data)
}

func (s *httpdServer) handleWebTemplateFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if r.URL.Query().Get("from") != "" {
		name := r.URL.Query().Get("from")
		folder, err := dataprovider.GetFolderByName(name)
		if err == nil {
			folder.FsConfig.SetEmptySecrets()
			s.renderFolderPage(w, r, folder, folderPageModeTemplate, nil)
		} else if errors.Is(err, util.ErrNotFound) {
			s.renderNotFoundPage(w, r, err)
		} else {
			s.renderInternalServerErrorPage(w, r, err)
		}
	} else {
		folder := vfs.BaseVirtualFolder{}
		s.renderFolderPage(w, r, folder, folderPageModeTemplate, nil)
	}
}

func (s *httpdServer) handleWebTemplateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	templateFolder := vfs.BaseVirtualFolder{}
	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderMessagePage(w, r, util.I18nTemplateFolderTitle, http.StatusBadRequest, util.NewI18nError(err, util.I18nErrorInvalidForm), "")
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}

	templateFolder.MappedPath = r.Form.Get("mapped_path")
	templateFolder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderMessagePage(w, r, util.I18nTemplateFolderTitle, http.StatusBadRequest, err, "")
		return
	}
	templateFolder.FsConfig = fsConfig

	var dump dataprovider.BackupData

	foldersFields := getFoldersForTemplate(r)
	for _, tmpl := range foldersFields {
		f := getFolderFromTemplate(templateFolder, tmpl)
		if err := dataprovider.ValidateFolder(&f); err != nil {
			s.renderMessagePage(w, r, util.I18nTemplateFolderTitle, http.StatusBadRequest, err, "")
			return
		}
		dump.Folders = append(dump.Folders, f)
	}

	if len(dump.Folders) == 0 {
		s.renderMessagePage(w, r, util.I18nTemplateFolderTitle, http.StatusBadRequest,
			util.NewI18nError(
				errors.New("no valid folder defined, unable to complete the requested action"),
				util.I18nErrorFolderTemplate,
			), "")
		return
	}
	if err = RestoreFolders(dump.Folders, "", 1, 0, claims.Username, ipAddr, claims.Role); err != nil {
		s.renderMessagePage(w, r, util.I18nTemplateFolderTitle, getRespStatus(err), err, "")
		return
	}
	http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebTemplateUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	tokenAdmin := getAdminFromToken(r)
	admin, err := dataprovider.AdminExists(tokenAdmin.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, fmt.Errorf("unable to get the admin %q: %w", tokenAdmin.Username, err))
		return
	}
	if r.URL.Query().Get("from") != "" {
		username := r.URL.Query().Get("from")
		user, err := dataprovider.UserExists(username, admin.Role)
		if err == nil {
			user.SetEmptySecrets()
			user.PublicKeys = nil
			user.Email = ""
			user.Filters.AdditionalEmails = nil
			user.Description = ""
			if user.ExpirationDate == 0 && admin.Filters.Preferences.DefaultUsersExpiration > 0 {
				user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(admin.Filters.Preferences.DefaultUsersExpiration)))
			}
			s.renderUserPage(w, r, &user, userPageModeTemplate, nil, &admin)
		} else if errors.Is(err, util.ErrNotFound) {
			s.renderNotFoundPage(w, r, err)
		} else {
			s.renderInternalServerErrorPage(w, r, err)
		}
	} else {
		user := dataprovider.User{BaseUser: sdk.BaseUser{
			Status: 1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		}}
		if admin.Filters.Preferences.DefaultUsersExpiration > 0 {
			user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(admin.Filters.Preferences.DefaultUsersExpiration)))
		}
		s.renderUserPage(w, r, &user, userPageModeTemplate, nil, &admin)
	}
}

func (s *httpdServer) handleWebTemplateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	templateUser, err := getUserFromPostFields(r)
	if err != nil {
		s.renderMessagePage(w, r, util.I18nTemplateUserTitle, http.StatusBadRequest, err, "")
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}

	var dump dataprovider.BackupData

	userTmplFields := getUsersForTemplate(r)
	for _, tmpl := range userTmplFields {
		u := getUserFromTemplate(templateUser, tmpl)
		if err := dataprovider.ValidateUser(&u); err != nil {
			s.renderMessagePage(w, r, util.I18nTemplateUserTitle, http.StatusBadRequest, err, "")
			return
		}
		if claims.Role != "" {
			u.Role = claims.Role
		}
		dump.Users = append(dump.Users, u)
	}

	if len(dump.Users) == 0 {
		s.renderMessagePage(w, r, util.I18nTemplateUserTitle,
			http.StatusBadRequest, util.NewI18nError(
				errors.New("no valid user defined, unable to complete the requested action"),
				util.I18nErrorUserTemplate,
			), "")
		return
	}
	if err = RestoreUsers(dump.Users, "", 1, 0, claims.Username, ipAddr, claims.Role); err != nil {
		s.renderMessagePage(w, r, util.I18nTemplateUserTitle, getRespStatus(err), err, "")
		return
	}
	http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebAddUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	tokenAdmin := getAdminFromToken(r)
	admin, err := dataprovider.AdminExists(tokenAdmin.Username)
	if err != nil {
		s.renderInternalServerErrorPage(w, r, fmt.Errorf("unable to get the admin %q: %w", tokenAdmin.Username, err))
		return
	}
	user := dataprovider.User{BaseUser: sdk.BaseUser{
		Status: 1,
		Permissions: map[string][]string{
			"/": {dataprovider.PermAny},
		}},
	}
	if admin.Filters.Preferences.DefaultUsersExpiration > 0 {
		user.ExpirationDate = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(admin.Filters.Preferences.DefaultUsersExpiration)))
	}
	s.renderUserPage(w, r, &user, userPageModeAdd, nil, &admin)
}

func (s *httpdServer) handleWebUpdateUserGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username, claims.Role)
	if err == nil {
		s.renderUserPage(w, r, &user, userPageModeUpdate, nil, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebAddUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, err := getUserFromPostFields(r)
	if err != nil {
		s.renderUserPage(w, r, &user, userPageModeAdd, err, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	user = getUserFromTemplate(user, userTemplateFields{
		Username:         user.Username,
		Password:         user.Password,
		PublicKeys:       user.PublicKeys,
		RequirePwdChange: user.Filters.RequirePasswordChange,
	})
	if claims.Role != "" {
		user.Role = claims.Role
	}
	user.Filters.RecoveryCodes = nil
	user.Filters.TOTPConfig = dataprovider.UserTOTPConfig{
		Enabled: false,
	}
	err = dataprovider.AddUser(&user, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderUserPage(w, r, &user, userPageModeAdd, err, nil)
		return
	}
	http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateUserPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	username := getURLParam(r, "username")
	user, err := dataprovider.UserExists(username, claims.Role)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedUser, err := getUserFromPostFields(r)
	if err != nil {
		s.renderUserPage(w, r, &user, userPageModeUpdate, err, nil)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedUser.ID = user.ID
	updatedUser.Username = user.Username
	updatedUser.Filters.RecoveryCodes = user.Filters.RecoveryCodes
	updatedUser.Filters.TOTPConfig = user.Filters.TOTPConfig
	updatedUser.LastPasswordChange = user.LastPasswordChange
	updatedUser.SetEmptySecretsIfNil()
	if updatedUser.Password == redactedSecret {
		updatedUser.Password = user.Password
	}
	updateEncryptedSecrets(&updatedUser.FsConfig, &user.FsConfig)

	updatedUser = getUserFromTemplate(updatedUser, userTemplateFields{
		Username:         updatedUser.Username,
		Password:         updatedUser.Password,
		PublicKeys:       updatedUser.PublicKeys,
		RequirePwdChange: updatedUser.Filters.RequirePasswordChange,
	})
	if claims.Role != "" {
		updatedUser.Role = claims.Role
	}

	err = dataprovider.UpdateUser(&updatedUser, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderUserPage(w, r, &updatedUser, userPageModeUpdate, err, nil)
		return
	}
	if r.Form.Get("disconnect") != "" {
		disconnectUser(user.Username, claims.Username, claims.Role)
	}
	http.Redirect(w, r, webUsersPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebGetStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	data := statusPage{
		basePage: s.getBasePageData(util.I18nStatusTitle, webStatusPath, w, r),
		Status:   getServicesStatus(),
	}
	renderAdminTemplate(w, templateStatus, data)
}

func (s *httpdServer) handleWebGetConnections(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}

	data := s.getBasePageData(util.I18nSessionsTitle, webConnectionsPath, w, r)
	renderAdminTemplate(w, templateConnections, data)
}

func (s *httpdServer) handleWebAddFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderFolderPage(w, r, vfs.BaseVirtualFolder{}, folderPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	folder := vfs.BaseVirtualFolder{}
	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	folder.MappedPath = strings.TrimSpace(r.Form.Get("mapped_path"))
	folder.Name = strings.TrimSpace(r.Form.Get("name"))
	folder.Description = r.Form.Get("description")
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, err)
		return
	}
	folder.FsConfig = fsConfig
	folder = getFolderFromTemplate(folder, folder.Name)

	err = dataprovider.AddFolder(&folder, claims.Username, ipAddr, claims.Role)
	if err == nil {
		http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
	} else {
		s.renderFolderPage(w, r, folder, folderPageModeAdd, err)
	}
}

func (s *httpdServer) handleWebUpdateFolderGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if err == nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateFolderPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := getURLParam(r, "name")
	folder, err := dataprovider.GetFolderByName(name)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}

	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	fsConfig, err := getFsConfigFromPostFields(r)
	if err != nil {
		s.renderFolderPage(w, r, folder, folderPageModeUpdate, err)
		return
	}
	updatedFolder := vfs.BaseVirtualFolder{
		MappedPath:  strings.TrimSpace(r.Form.Get("mapped_path")),
		Description: r.Form.Get("description"),
	}
	updatedFolder.ID = folder.ID
	updatedFolder.Name = folder.Name
	updatedFolder.FsConfig = fsConfig
	updatedFolder.FsConfig.SetEmptySecretsIfNil()
	updateEncryptedSecrets(&updatedFolder.FsConfig, &folder.FsConfig)

	updatedFolder = getFolderFromTemplate(updatedFolder, updatedFolder.Name)

	err = dataprovider.UpdateFolder(&updatedFolder, folder.Users, folder.Groups, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderFolderPage(w, r, updatedFolder, folderPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webFoldersPath, http.StatusSeeOther)
}

func (s *httpdServer) getWebVirtualFolders(w http.ResponseWriter, r *http.Request, limit int, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)
	for {
		f, err := dataprovider.GetFolders(limit, len(folders), dataprovider.OrderASC, minimal)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return folders, err
		}
		folders = append(folders, f...)
		if len(f) < limit {
			break
		}
	}
	return folders, nil
}

func getAllFolders(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetFolders(limit, offset, dataprovider.OrderASC, false)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleWebGetFolders(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := s.getBasePageData(util.I18nFoldersTitle, webFoldersPath, w, r)
	renderAdminTemplate(w, templateFolders, data)
}

func (s *httpdServer) getWebGroups(w http.ResponseWriter, r *http.Request, limit int, minimal bool) ([]dataprovider.Group, error) {
	groups := make([]dataprovider.Group, 0, 50)
	for {
		f, err := dataprovider.GetGroups(limit, len(groups), dataprovider.OrderASC, minimal)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return groups, err
		}
		groups = append(groups, f...)
		if len(f) < limit {
			break
		}
	}
	return groups, nil
}

func getAllGroups(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetGroups(limit, offset, dataprovider.OrderASC, false)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleWebGetGroups(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := s.getBasePageData(util.I18nGroupsTitle, webGroupsPath, w, r)
	renderAdminTemplate(w, templateGroups, data)
}

func (s *httpdServer) handleWebAddGroupGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderGroupPage(w, r, dataprovider.Group{}, genericPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddGroupPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	group, err := getGroupFromPostFields(r)
	if err != nil {
		s.renderGroupPage(w, r, group, genericPageModeAdd, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = dataprovider.AddGroup(&group, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderGroupPage(w, r, group, genericPageModeAdd, err)
		return
	}
	http.Redirect(w, r, webGroupsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateGroupGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	group, err := dataprovider.GroupExists(name)
	if err == nil {
		s.renderGroupPage(w, r, group, genericPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateGroupPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := getURLParam(r, "name")
	group, err := dataprovider.GroupExists(name)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedGroup, err := getGroupFromPostFields(r)
	if err != nil {
		s.renderGroupPage(w, r, group, genericPageModeUpdate, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedGroup.ID = group.ID
	updatedGroup.Name = group.Name
	updatedGroup.SetEmptySecretsIfNil()

	updateEncryptedSecrets(&updatedGroup.UserSettings.FsConfig, &group.UserSettings.FsConfig)

	err = dataprovider.UpdateGroup(&updatedGroup, group.Users, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderGroupPage(w, r, updatedGroup, genericPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webGroupsPath, http.StatusSeeOther)
}

func (s *httpdServer) getWebEventActions(w http.ResponseWriter, r *http.Request, limit int, minimal bool,
) ([]dataprovider.BaseEventAction, error) {
	actions := make([]dataprovider.BaseEventAction, 0, limit)
	for {
		res, err := dataprovider.GetEventActions(limit, len(actions), dataprovider.OrderASC, minimal)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return actions, err
		}
		actions = append(actions, res...)
		if len(res) < limit {
			break
		}
	}
	return actions, nil
}

func getAllActions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetEventActions(limit, offset, dataprovider.OrderASC, false)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleWebGetEventActions(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := s.getBasePageData(util.I18nActionsTitle, webAdminEventActionsPath, w, r)
	renderAdminTemplate(w, templateEventActions, data)
}

func (s *httpdServer) handleWebAddEventActionGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	action := dataprovider.BaseEventAction{
		Type: dataprovider.ActionTypeHTTP,
	}
	s.renderEventActionPage(w, r, action, genericPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddEventActionPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	action, err := getEventActionFromPostFields(r)
	if err != nil {
		s.renderEventActionPage(w, r, action, genericPageModeAdd, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	if err = dataprovider.AddEventAction(&action, claims.Username, ipAddr, claims.Role); err != nil {
		s.renderEventActionPage(w, r, action, genericPageModeAdd, err)
		return
	}
	http.Redirect(w, r, webAdminEventActionsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateEventActionGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	action, err := dataprovider.EventActionExists(name)
	if err == nil {
		s.renderEventActionPage(w, r, action, genericPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateEventActionPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := getURLParam(r, "name")
	action, err := dataprovider.EventActionExists(name)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedAction, err := getEventActionFromPostFields(r)
	if err != nil {
		s.renderEventActionPage(w, r, updatedAction, genericPageModeUpdate, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedAction.ID = action.ID
	updatedAction.Name = action.Name
	updatedAction.Options.SetEmptySecretsIfNil()
	switch updatedAction.Type {
	case dataprovider.ActionTypeHTTP:
		if updatedAction.Options.HTTPConfig.Password.IsNotPlainAndNotEmpty() {
			updatedAction.Options.HTTPConfig.Password = action.Options.HTTPConfig.Password
		}
	}
	err = dataprovider.UpdateEventAction(&updatedAction, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderEventActionPage(w, r, updatedAction, genericPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webAdminEventActionsPath, http.StatusSeeOther)
}

func getAllRules(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetEventRules(limit, offset, dataprovider.OrderASC)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleWebGetEventRules(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := s.getBasePageData(util.I18nRulesTitle, webAdminEventRulesPath, w, r)
	renderAdminTemplate(w, templateEventRules, data)
}

func (s *httpdServer) handleWebAddEventRuleGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	rule := dataprovider.EventRule{
		Status:  1,
		Trigger: dataprovider.EventTriggerFsEvent,
	}
	s.renderEventRulePage(w, r, rule, genericPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddEventRulePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	rule, err := getEventRuleFromPostFields(r)
	if err != nil {
		s.renderEventRulePage(w, r, rule, genericPageModeAdd, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	err = verifyCSRFToken(r, s.csrfTokenAuth)
	if err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	if err = dataprovider.AddEventRule(&rule, claims.Username, ipAddr, claims.Role); err != nil {
		s.renderEventRulePage(w, r, rule, genericPageModeAdd, err)
		return
	}
	http.Redirect(w, r, webAdminEventRulesPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateEventRuleGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	name := getURLParam(r, "name")
	rule, err := dataprovider.EventRuleExists(name)
	if err == nil {
		s.renderEventRulePage(w, r, rule, genericPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateEventRulePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := getURLParam(r, "name")
	rule, err := dataprovider.EventRuleExists(name)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedRule, err := getEventRuleFromPostFields(r)
	if err != nil {
		s.renderEventRulePage(w, r, updatedRule, genericPageModeUpdate, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedRule.ID = rule.ID
	updatedRule.Name = rule.Name
	err = dataprovider.UpdateEventRule(&updatedRule, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderEventRulePage(w, r, updatedRule, genericPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webAdminEventRulesPath, http.StatusSeeOther)
}

func (s *httpdServer) getWebRoles(w http.ResponseWriter, r *http.Request, limit int, minimal bool) ([]dataprovider.Role, error) {
	roles := make([]dataprovider.Role, 0, 10)
	for {
		res, err := dataprovider.GetRoles(limit, len(roles), dataprovider.OrderASC, minimal)
		if err != nil {
			s.renderInternalServerErrorPage(w, r, err)
			return roles, err
		}
		roles = append(roles, res...)
		if len(res) < limit {
			break
		}
	}
	return roles, nil
}

func getAllRoles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		results, err := dataprovider.GetRoles(limit, offset, dataprovider.OrderASC, false)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(results)
		return data, len(results), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleWebGetRoles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	data := s.getBasePageData(util.I18nRolesTitle, webAdminRolesPath, w, r)

	renderAdminTemplate(w, templateRoles, data)
}

func (s *httpdServer) handleWebAddRoleGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderRolePage(w, r, dataprovider.Role{}, genericPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddRolePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	role, err := getRoleFromPostFields(r)
	if err != nil {
		s.renderRolePage(w, r, role, genericPageModeAdd, err)
		return
	}
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = dataprovider.AddRole(&role, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderRolePage(w, r, role, genericPageModeAdd, err)
		return
	}
	http.Redirect(w, r, webAdminRolesPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateRoleGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	role, err := dataprovider.RoleExists(getURLParam(r, "name"))
	if err == nil {
		s.renderRolePage(w, r, role, genericPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateRolePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	role, err := dataprovider.RoleExists(getURLParam(r, "name"))
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}

	updatedRole, err := getRoleFromPostFields(r)
	if err != nil {
		s.renderRolePage(w, r, role, genericPageModeUpdate, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedRole.ID = role.ID
	updatedRole.Name = role.Name
	err = dataprovider.UpdateRole(&updatedRole, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderRolePage(w, r, updatedRole, genericPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webAdminRolesPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebGetEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := eventsPage{
		basePage:                s.getBasePageData(util.I18nEventsTitle, webEventsPath, w, r),
		FsEventsSearchURL:       webEventsFsSearchPath,
		ProviderEventsSearchURL: webEventsProviderSearchPath,
		LogEventsSearchURL:      webEventsLogSearchPath,
	}
	renderAdminTemplate(w, templateEvents, data)
}

func (s *httpdServer) handleWebIPListsPage(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	rtlStatus, rtlProtocols := common.Config.GetRateLimitersStatus()
	data := ipListsPage{
		basePage:              s.getBasePageData(util.I18nIPListsTitle, webIPListsPath, w, r),
		RateLimitersStatus:    rtlStatus,
		RateLimitersProtocols: strings.Join(rtlProtocols, ", "),
		IsAllowListEnabled:    common.Config.IsAllowListEnabled(),
	}

	renderAdminTemplate(w, templateIPLists, data)
}

func (s *httpdServer) handleWebAddIPListEntryGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	listType, _, err := getIPListPathParams(r)
	if err != nil {
		s.renderBadRequestPage(w, r, err)
		return
	}
	s.renderIPListPage(w, r, dataprovider.IPListEntry{Type: listType}, genericPageModeAdd, nil)
}

func (s *httpdServer) handleWebAddIPListEntryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	listType, _, err := getIPListPathParams(r)
	if err != nil {
		s.renderBadRequestPage(w, r, err)
		return
	}
	entry, err := getIPListEntryFromPostFields(r, listType)
	if err != nil {
		s.renderIPListPage(w, r, entry, genericPageModeAdd, err)
		return
	}
	entry.Type = listType
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	err = dataprovider.AddIPListEntry(&entry, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderIPListPage(w, r, entry, genericPageModeAdd, err)
		return
	}
	http.Redirect(w, r, webIPListsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebUpdateIPListEntryGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	listType, ipOrNet, err := getIPListPathParams(r)
	if err != nil {
		s.renderBadRequestPage(w, r, err)
		return
	}
	entry, err := dataprovider.IPListEntryExists(ipOrNet, listType)
	if err == nil {
		s.renderIPListPage(w, r, entry, genericPageModeUpdate, nil)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
	} else {
		s.renderInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleWebUpdateIPListEntryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	listType, ipOrNet, err := getIPListPathParams(r)
	if err != nil {
		s.renderBadRequestPage(w, r, err)
		return
	}
	entry, err := dataprovider.IPListEntryExists(ipOrNet, listType)
	if errors.Is(err, util.ErrNotFound) {
		s.renderNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	updatedEntry, err := getIPListEntryFromPostFields(r, listType)
	if err != nil {
		s.renderIPListPage(w, r, entry, genericPageModeUpdate, err)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedEntry.Type = listType
	updatedEntry.IPOrNet = ipOrNet
	err = dataprovider.UpdateIPListEntry(&updatedEntry, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderIPListPage(w, r, entry, genericPageModeUpdate, err)
		return
	}
	http.Redirect(w, r, webIPListsPath, http.StatusSeeOther)
}

func (s *httpdServer) handleWebConfigs(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	s.renderConfigsPage(w, r, configs, nil, 0)
}

func (s *httpdServer) handleWebConfigsPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		s.renderInternalServerErrorPage(w, r, err)
		return
	}
	err = r.ParseMultipartForm(maxRequestSize)
	if err != nil {
		s.renderBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	defer r.MultipartForm.RemoveAll() //nolint:errcheck

	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	var configSection int
	switch r.Form.Get("form_action") {
	case "sftp_submit":
		configSection = 1
		sftpConfigs := getSFTPConfigsFromPostFields(r)
		configs.SFTPD = sftpConfigs
	case "acme_submit":
		configSection = 2
		acmeConfigs := getACMEConfigsFromPostFields(r)
		configs.ACME = acmeConfigs
		if err := acme.GetCertificatesForConfig(acmeConfigs, configurationDir); err != nil {
			logger.Info(logSender, "", "unable to get ACME certificates: %v", err)
			s.renderConfigsPage(w, r, configs, util.NewI18nError(err, util.I18nErrorACMEGeneric), configSection)
			return
		}
	case "smtp_submit":
		configSection = 3
		smtpConfigs := getSMTPConfigsFromPostFields(r)
		updateSMTPSecrets(smtpConfigs, configs.SMTP)
		configs.SMTP = smtpConfigs
	case "branding_submit":
		configSection = 4
		brandingConfigs, err := getBrandingConfigFromPostFields(r, configs.Branding)
		configs.Branding = brandingConfigs
		if err != nil {
			logger.Info(logSender, "", "unable to get branding config: %v", err)
			s.renderConfigsPage(w, r, configs, err, configSection)
			return
		}
	default:
		s.renderBadRequestPage(w, r, errors.New("unsupported form action"))
		return
	}

	err = dataprovider.UpdateConfigs(&configs, claims.Username, ipAddr, claims.Role)
	if err != nil {
		s.renderConfigsPage(w, r, configs, err, configSection)
		return
	}
	postConfigsUpdate(configSection, configs)
	s.renderMessagePage(w, r, util.I18nConfigsTitle, http.StatusOK, nil, util.I18nConfigsOK)
}

func postConfigsUpdate(section int, configs dataprovider.Configs) {
	switch section {
	case 3:
		err := configs.SMTP.TryDecrypt()
		if err == nil {
			smtp.Activate(configs.SMTP)
		} else {
			logger.Error(logSender, "", "unable to decrypt SMTP configuration, cannot activate configuration: %v", err)
		}
	case 4:
		dbBrandingConfig.Set(configs.Branding)
	}
}

func (s *httpdServer) handleOAuth2TokenRedirect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	stateToken := r.URL.Query().Get("state")

	state, err := verifyOAuth2Token(s.csrfTokenAuth, stateToken, util.GetIPFromRemoteAddress(r.RemoteAddr))
	if err != nil {
		s.renderMessagePage(w, r, util.I18nOAuth2ErrorTitle, http.StatusBadRequest, err, "")
		return
	}

	pendingAuth, err := oauth2Mgr.getPendingAuth(state)
	if err != nil {
		oauth2Mgr.removePendingAuth(state)
		s.renderMessagePage(w, r, util.I18nOAuth2ErrorTitle, http.StatusInternalServerError,
			util.NewI18nError(err, util.I18nOAuth2ErrorValidateState), "")
		return
	}
	oauth2Mgr.removePendingAuth(state)

	oauth2Config := smtp.OAuth2Config{
		Provider:     pendingAuth.Provider,
		ClientID:     pendingAuth.ClientID,
		ClientSecret: pendingAuth.ClientSecret.GetPayload(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := oauth2Config.GetOAuth2()
	cfg.RedirectURL = pendingAuth.RedirectURL
	token, err := cfg.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pendingAuth.Verifier))
	if err != nil {
		s.renderMessagePage(w, r, util.I18nOAuth2ErrorTitle, http.StatusInternalServerError,
			util.NewI18nError(err, util.I18nOAuth2ErrTokenExchange), "")
		return
	}
	if token.RefreshToken == "" {
		errTxt := "the OAuth2 provider returned an empty token. " +
			"Some providers only return the token when the user first authorizes. " +
			"If you have already registered SFTPGo with this user in the past, revoke access and try again. " +
			"This way you will invalidate the previous token"
		s.renderMessagePage(w, r, util.I18nOAuth2ErrorTitle, http.StatusBadRequest,
			util.NewI18nError(errors.New(errTxt), util.I18nOAuth2ErrNoRefreshToken), "")
		return
	}
	s.renderMessagePageWithString(w, r, util.I18nOAuth2Title, http.StatusOK, nil, util.I18nOAuth2OK,
		fmt.Sprintf("%q", token.RefreshToken))
}

func updateSMTPSecrets(newConfigs, currentConfigs *dataprovider.SMTPConfigs) {
	if currentConfigs == nil {
		currentConfigs = &dataprovider.SMTPConfigs{}
	}
	if newConfigs.Password.IsNotPlainAndNotEmpty() {
		newConfigs.Password = currentConfigs.Password
	}
	if newConfigs.OAuth2.ClientSecret.IsNotPlainAndNotEmpty() {
		newConfigs.OAuth2.ClientSecret = currentConfigs.OAuth2.ClientSecret
	}
	if newConfigs.OAuth2.RefreshToken.IsNotPlainAndNotEmpty() {
		newConfigs.OAuth2.RefreshToken = currentConfigs.OAuth2.RefreshToken
	}
}
