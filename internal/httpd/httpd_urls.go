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
	"crypto/sha256"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/ftpd"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/sftpd"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/webdavd"
)

func isWebRequest(r *http.Request) bool {
	return strings.HasPrefix(r.RequestURI, webBasePath+"/")
}

func isWebClientRequest(r *http.Request) bool {
	return strings.HasPrefix(r.RequestURI, webBaseClientPath+"/")
}

// ReloadCertificateMgr reloads the certificate manager
func ReloadCertificateMgr() error {
	if certMgr != nil {
		return certMgr.Reload()
	}
	return nil
}

func getConfigPath(name, configDir string) string {
	if !util.IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}

func getServicesStatus() *ServicesStatus {
	rtlEnabled, rtlProtocols := common.Config.GetRateLimitersStatus()
	status := &ServicesStatus{
		SSH:          sftpd.GetStatus(),
		FTP:          ftpd.GetStatus(),
		WebDAV:       webdavd.GetStatus(),
		DataProvider: dataprovider.GetProviderStatus(),
		Defender: defenderStatus{
			IsActive: common.Config.DefenderConfig.Enabled,
		},
		MFA: mfa.GetStatus(),
		AllowList: allowListStatus{
			IsActive: common.Config.IsAllowListEnabled(),
		},
		RateLimiters: rateLimiters{
			IsActive:  rtlEnabled,
			Protocols: rtlProtocols,
		},
	}
	return status
}

func fileServer(r chi.Router, path string, root http.FileSystem, disableDirectoryIndex bool) {
	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", http.StatusMovedPermanently).ServeHTTP)
		path += "/"
	}
	path += "*"

	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		if disableDirectoryIndex {
			root = neuteredFileSystem{root}
		}
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func updateWebClientURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseClientPath = path.Join(baseURL, webBasePathClientDefault)
	webOIDCRedirectPath = path.Join(baseURL, webOIDCRedirectPathDefault)
	webClientLoginPath = path.Join(baseURL, webClientLoginPathDefault)
	webClientOIDCLoginPath = path.Join(baseURL, webClientOIDCLoginPathDefault)
	webClientTwoFactorPath = path.Join(baseURL, webClientTwoFactorPathDefault)
	webClientTwoFactorRecoveryPath = path.Join(baseURL, webClientTwoFactorRecoveryPathDefault)
	webClientFilesPath = path.Join(baseURL, webClientFilesPathDefault)
	webClientFilePath = path.Join(baseURL, webClientFilePathDefault)
	webClientFileActionsPath = path.Join(baseURL, webClientFileActionsPathDefault)
	webClientSharesPath = path.Join(baseURL, webClientSharesPathDefault)
	webClientPubSharesPath = path.Join(baseURL, webClientPubSharesPathDefault)
	webClientSharePath = path.Join(baseURL, webClientSharePathDefault)
	webClientEditFilePath = path.Join(baseURL, webClientEditFilePathDefault)
	webClientDirsPath = path.Join(baseURL, webClientDirsPathDefault)
	webClientDownloadZipPath = path.Join(baseURL, webClientDownloadZipPathDefault)
	webClientProfilePath = path.Join(baseURL, webClientProfilePathDefault)
	webClientPingPath = path.Join(baseURL, webClientPingPathDefault)
	webChangeClientPwdPath = path.Join(baseURL, webChangeClientPwdPathDefault)
	webClientLogoutPath = path.Join(baseURL, webClientLogoutPathDefault)
	webClientMFAPath = path.Join(baseURL, webClientMFAPathDefault)
	webClientTOTPGeneratePath = path.Join(baseURL, webClientTOTPGeneratePathDefault)
	webClientTOTPValidatePath = path.Join(baseURL, webClientTOTPValidatePathDefault)
	webClientTOTPSavePath = path.Join(baseURL, webClientTOTPSavePathDefault)
	webClientRecoveryCodesPath = path.Join(baseURL, webClientRecoveryCodesPathDefault)
	webClientForgotPwdPath = path.Join(baseURL, webClientForgotPwdPathDefault)
	webClientResetPwdPath = path.Join(baseURL, webClientResetPwdPathDefault)
	webClientViewPDFPath = path.Join(baseURL, webClientViewPDFPathDefault)
	webClientGetPDFPath = path.Join(baseURL, webClientGetPDFPathDefault)
	webClientExistPath = path.Join(baseURL, webClientExistPathDefault)
	webClientTasksPath = path.Join(baseURL, webClientTasksPathDefault)
	webStaticFilesPath = path.Join(baseURL, webStaticFilesPathDefault)
	webOpenAPIPath = path.Join(baseURL, webOpenAPIPathDefault)
}

func updateWebAdminURLs(baseURL string) {
	if !path.IsAbs(baseURL) {
		baseURL = "/"
	}
	webRootPath = path.Join(baseURL, webRootPathDefault)
	webBasePath = path.Join(baseURL, webBasePathDefault)
	webBaseAdminPath = path.Join(baseURL, webBasePathAdminDefault)
	webOIDCRedirectPath = path.Join(baseURL, webOIDCRedirectPathDefault)
	webOAuth2RedirectPath = path.Join(baseURL, webOAuth2RedirectPathDefault)
	webOAuth2TokenPath = path.Join(baseURL, webOAuth2TokenPathDefault)
	webAdminSetupPath = path.Join(baseURL, webAdminSetupPathDefault)
	webAdminLoginPath = path.Join(baseURL, webAdminLoginPathDefault)
	webAdminOIDCLoginPath = path.Join(baseURL, webAdminOIDCLoginPathDefault)
	webAdminTwoFactorPath = path.Join(baseURL, webAdminTwoFactorPathDefault)
	webAdminTwoFactorRecoveryPath = path.Join(baseURL, webAdminTwoFactorRecoveryPathDefault)
	webLogoutPath = path.Join(baseURL, webLogoutPathDefault)
	webUsersPath = path.Join(baseURL, webUsersPathDefault)
	webUserPath = path.Join(baseURL, webUserPathDefault)
	webConnectionsPath = path.Join(baseURL, webConnectionsPathDefault)
	webFoldersPath = path.Join(baseURL, webFoldersPathDefault)
	webFolderPath = path.Join(baseURL, webFolderPathDefault)
	webGroupsPath = path.Join(baseURL, webGroupsPathDefault)
	webGroupPath = path.Join(baseURL, webGroupPathDefault)
	webStatusPath = path.Join(baseURL, webStatusPathDefault)
	webAdminsPath = path.Join(baseURL, webAdminsPathDefault)
	webAdminPath = path.Join(baseURL, webAdminPathDefault)
	webMaintenancePath = path.Join(baseURL, webMaintenancePathDefault)
	webBackupPath = path.Join(baseURL, webBackupPathDefault)
	webRestorePath = path.Join(baseURL, webRestorePathDefault)
	webScanVFolderPath = path.Join(baseURL, webScanVFolderPathDefault)
	webQuotaScanPath = path.Join(baseURL, webQuotaScanPathDefault)
	webChangeAdminPwdPath = path.Join(baseURL, webChangeAdminPwdPathDefault)
	webAdminForgotPwdPath = path.Join(baseURL, webAdminForgotPwdPathDefault)
	webAdminResetPwdPath = path.Join(baseURL, webAdminResetPwdPathDefault)
	webAdminProfilePath = path.Join(baseURL, webAdminProfilePathDefault)
	webAdminMFAPath = path.Join(baseURL, webAdminMFAPathDefault)
	webAdminEventRulesPath = path.Join(baseURL, webAdminEventRulesPathDefault)
	webAdminEventRulePath = path.Join(baseURL, webAdminEventRulePathDefault)
	webAdminEventActionsPath = path.Join(baseURL, webAdminEventActionsPathDefault)
	webAdminEventActionPath = path.Join(baseURL, webAdminEventActionPathDefault)
	webAdminRolesPath = path.Join(baseURL, webAdminRolesPathDefault)
	webAdminRolePath = path.Join(baseURL, webAdminRolePathDefault)
	webAdminTOTPGeneratePath = path.Join(baseURL, webAdminTOTPGeneratePathDefault)
	webAdminTOTPValidatePath = path.Join(baseURL, webAdminTOTPValidatePathDefault)
	webAdminTOTPSavePath = path.Join(baseURL, webAdminTOTPSavePathDefault)
	webAdminRecoveryCodesPath = path.Join(baseURL, webAdminRecoveryCodesPathDefault)
	webTemplateUser = path.Join(baseURL, webTemplateUserDefault)
	webTemplateFolder = path.Join(baseURL, webTemplateFolderDefault)
	webDefenderHostsPath = path.Join(baseURL, webDefenderHostsPathDefault)
	webDefenderPath = path.Join(baseURL, webDefenderPathDefault)
	webIPListPath = path.Join(baseURL, webIPListPathDefault)
	webIPListsPath = path.Join(baseURL, webIPListsPathDefault)
	webEventsPath = path.Join(baseURL, webEventsPathDefault)
	webEventsFsSearchPath = path.Join(baseURL, webEventsFsSearchPathDefault)
	webEventsProviderSearchPath = path.Join(baseURL, webEventsProviderSearchPathDefault)
	webEventsLogSearchPath = path.Join(baseURL, webEventsLogSearchPathDefault)
	webConfigsPath = path.Join(baseURL, webConfigsPathDefault)
	webStaticFilesPath = path.Join(baseURL, webStaticFilesPathDefault)
	webOpenAPIPath = path.Join(baseURL, webOpenAPIPathDefault)
}

// GetHTTPRouter returns an HTTP handler suitable to use for test cases
func GetHTTPRouter(b Binding) (http.Handler, error) {
	server := newHttpdServer(b, filepath.Join("..", "..", "static"), "", CorsConfig{}, filepath.Join("..", "..", "openapi"))
	if err := server.initializeRouter(); err != nil {
		return nil, err
	}
	return server.router, nil
}

// the ticker cannot be started/stopped from multiple goroutines
func startCleanupTicker(duration time.Duration) {
	stopCleanupTicker()
	cleanupTicker = time.NewTicker(duration)
	cleanupDone = make(chan bool)

	go func() {
		counter := int64(0)
		for {
			select {
			case <-cleanupDone:
				return
			case <-cleanupTicker.C:
				counter++
				invalidatedJWTTokens.Cleanup()
				resetCodesMgr.Cleanup()
				webTaskMgr.Cleanup()
				if counter%2 == 0 {
					oidcMgr.cleanup()
					oauth2Mgr.cleanup()
				}
			}
		}
	}()
}

func stopCleanupTicker() {
	if cleanupTicker != nil {
		cleanupTicker.Stop()
		cleanupDone <- true
		cleanupTicker = nil
	}
}

func getSigningKey(signingPassphrase string) []byte {
	var key []byte
	if signingPassphrase != "" {
		key = []byte(signingPassphrase)
	} else {
		key = util.GenerateRandomBytes(32)
	}
	sk := sha256.Sum256(key)
	return sk[:]
}

// SetInstallationCodeResolver sets a function to call to resolve the installation code
func SetInstallationCodeResolver(fn FnInstallationCodeResolver) {
	fnInstallationCodeResolver = fn
}

func resolveInstallationCode() string {
	if fnInstallationCodeResolver != nil {
		return fnInstallationCodeResolver(installationCode)
	}
	return installationCode
}

type neuteredFileSystem struct {
	fs http.FileSystem
}

func (nfs neuteredFileSystem) Open(name string) (http.File, error) {
	f, err := nfs.fs.Open(name)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if s.IsDir() {
		index := path.Join(name, "index.html")
		if _, err := nfs.fs.Open(index); err != nil {
			defer f.Close()

			return nil, err
		}
	}

	return f, nil
}
