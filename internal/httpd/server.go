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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-jose/go-jose/v4"
	"github.com/rs/cors"
	"github.com/sftpgo/sdk"
	"github.com/unrolled/secure"

	"github.com/drakkan/sftpgo/v2/internal/acme"
	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

const (
	jsonAPISuffix = "/json"
)

var (
	compressor      = middleware.NewCompressor(5)
	xForwardedProto = http.CanonicalHeaderKey("X-Forwarded-Proto")
)

type httpdServer struct {
	binding           Binding
	staticFilesPath   string
	openAPIPath       string
	enableWebAdmin    bool
	enableWebClient   bool
	enableRESTAPI     bool
	renderOpenAPI     bool
	isShared          int
	router            *chi.Mux
	tokenAuth         *jwt.Signer
	csrfTokenAuth     *jwt.Signer
	signingPassphrase string
	cors              CorsConfig
}

func newHttpdServer(b Binding, staticFilesPath, signingPassphrase string, cors CorsConfig,
	openAPIPath string,
) *httpdServer {
	if openAPIPath == "" {
		b.RenderOpenAPI = false
	}
	return &httpdServer{
		binding:           b,
		staticFilesPath:   staticFilesPath,
		openAPIPath:       openAPIPath,
		enableWebAdmin:    b.EnableWebAdmin,
		enableWebClient:   b.EnableWebClient,
		enableRESTAPI:     b.EnableRESTAPI,
		renderOpenAPI:     b.RenderOpenAPI,
		signingPassphrase: signingPassphrase,
		cors:              cors,
	}
}

func (s *httpdServer) setShared(value int) {
	s.isShared = value
}

func (s *httpdServer) listenAndServe() error {
	if err := s.initializeRouter(); err != nil {
		return err
	}
	httpServer := &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
		ErrorLog:          log.New(&logger.StdLoggerWrapper{Sender: logSender}, "", 0),
	}
	if certMgr != nil && s.binding.EnableHTTPS {
		certID := common.DefaultTLSKeyPaidID
		if getConfigPath(s.binding.CertificateFile, "") != "" && getConfigPath(s.binding.CertificateKeyFile, "") != "" {
			certID = s.binding.GetAddress()
		}
		config := &tls.Config{
			GetCertificate: certMgr.GetCertificateFunc(certID),
			MinVersion:     util.GetTLSVersion(s.binding.MinTLSVersion),
			NextProtos:     util.GetALPNProtocols(s.binding.Protocols),
			CipherSuites:   util.GetTLSCiphersFromNames(s.binding.TLSCipherSuites),
		}
		httpServer.TLSConfig = config
		logger.Debug(logSender, "", "configured TLS cipher suites for binding %q: %v, certID: %v",
			s.binding.GetAddress(), httpServer.TLSConfig.CipherSuites, certID)
		if s.binding.isMutualTLSEnabled() {
			httpServer.TLSConfig.ClientCAs = certMgr.GetRootCAs()
			httpServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			httpServer.TLSConfig.VerifyConnection = s.verifyTLSConnection
		}
		return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, true,
			s.binding.listenerWrapper(), logSender)
	}
	return util.HTTPListenAndServe(httpServer, s.binding.Address, s.binding.Port, false,
		s.binding.listenerWrapper(), logSender)
}

func (s *httpdServer) verifyTLSConnection(state tls.ConnectionState) error {
	if certMgr != nil {
		var clientCrt *x509.Certificate
		var clientCrtName string
		if len(state.PeerCertificates) > 0 {
			clientCrt = state.PeerCertificates[0]
			clientCrtName = clientCrt.Subject.String()
		}
		if len(state.VerifiedChains) == 0 {
			logger.Warn(logSender, "", "TLS connection cannot be verified: unable to get verification chain")
			return errors.New("TLS connection cannot be verified: unable to get verification chain")
		}
		for _, verifiedChain := range state.VerifiedChains {
			var caCrt *x509.Certificate
			if len(verifiedChain) > 0 {
				caCrt = verifiedChain[len(verifiedChain)-1]
			}
			if certMgr.IsRevoked(clientCrt, caCrt) {
				logger.Debug(logSender, "", "tls handshake error, client certificate %q has been revoked", clientCrtName)
				return common.ErrCrtRevoked
			}
		}
	}

	return nil
}

func (s *httpdServer) initializeRouter() error {
	signer, err := jwt.NewSigner(jose.HS256, getSigningKey(s.signingPassphrase))
	if err != nil {
		return err
	}
	csrfSigner, err := jwt.NewSigner(jose.HS256, getSigningKey(s.signingPassphrase))
	if err != nil {
		return err
	}
	var hasHTTPSRedirect bool
	s.tokenAuth = signer
	s.csrfTokenAuth = csrfSigner
	s.router = chi.NewRouter()

	s.router.Use(middleware.RequestID)
	s.router.Use(s.parseHeaders)
	s.router.Use(logger.NewStructuredLogger(logger.GetLogger()))
	s.router.Use(middleware.Recoverer)
	if s.binding.Security.Enabled {
		secureMiddleware := secure.New(secure.Options{
			AllowedHosts:              s.binding.Security.AllowedHosts,
			AllowedHostsAreRegex:      s.binding.Security.AllowedHostsAreRegex,
			HostsProxyHeaders:         s.binding.Security.HostsProxyHeaders,
			SSLProxyHeaders:           s.binding.Security.getHTTPSProxyHeaders(),
			STSSeconds:                s.binding.Security.STSSeconds,
			STSIncludeSubdomains:      s.binding.Security.STSIncludeSubdomains,
			STSPreload:                s.binding.Security.STSPreload,
			ContentTypeNosniff:        s.binding.Security.ContentTypeNosniff,
			ContentSecurityPolicy:     s.binding.Security.ContentSecurityPolicy,
			PermissionsPolicy:         s.binding.Security.PermissionsPolicy,
			CrossOriginOpenerPolicy:   s.binding.Security.CrossOriginOpenerPolicy,
			CrossOriginResourcePolicy: s.binding.Security.CrossOriginResourcePolicy,
			CrossOriginEmbedderPolicy: s.binding.Security.CrossOriginEmbedderPolicy,
			ReferrerPolicy:            s.binding.Security.ReferrerPolicy,
		})
		secureMiddleware.SetBadHostHandler(http.HandlerFunc(s.badHostHandler))
		if s.binding.Security.CacheControl == "private" {
			s.router.Use(cacheControlMiddleware)
		}
		s.router.Use(secureMiddleware.Handler)
		if s.binding.Security.HTTPSRedirect {
			s.router.Use(s.binding.Security.redirectHandler)
			hasHTTPSRedirect = true
		}
	}
	if s.cors.Enabled {
		c := cors.New(cors.Options{
			AllowedOrigins:       util.RemoveDuplicates(s.cors.AllowedOrigins, true),
			AllowedMethods:       util.RemoveDuplicates(s.cors.AllowedMethods, true),
			AllowedHeaders:       util.RemoveDuplicates(s.cors.AllowedHeaders, true),
			ExposedHeaders:       util.RemoveDuplicates(s.cors.ExposedHeaders, true),
			MaxAge:               s.cors.MaxAge,
			AllowCredentials:     s.cors.AllowCredentials,
			OptionsPassthrough:   s.cors.OptionsPassthrough,
			OptionsSuccessStatus: s.cors.OptionsSuccessStatus,
			AllowPrivateNetwork:  s.cors.AllowPrivateNetwork,
		})
		s.router.Use(c.Handler)
	}
	s.router.Use(middleware.Maybe(s.checkConnection, s.mustCheckPath))
	s.router.Use(middleware.GetHead)
	s.router.Use(middleware.Maybe(middleware.StripSlashes, s.mustStripSlash))

	s.router.NotFound(s.notFoundHandler)

	s.router.Get(healthzPath, func(w http.ResponseWriter, r *http.Request) {
		render.PlainText(w, r, "ok")
	})

	if hasHTTPSRedirect {
		if p := acme.GetHTTP01WebRoot(); p != "" {
			serveStaticDir(s.router, acmeChallengeURI, p, true)
		}
	}

	s.setupRESTAPIRoutes()

	if s.enableWebAdmin || s.enableWebClient {
		s.router.Group(func(router chi.Router) {
			router.Use(cleanCacheControlMiddleware)
			router.Use(compressor.Handler)
			serveStaticDir(router, webStaticFilesPath, s.staticFilesPath, true)
		})
		if s.binding.OIDC.isEnabled() {
			s.router.Get(webOIDCRedirectPath, s.handleOIDCRedirect)
		}
		if s.enableWebClient {
			s.router.Get(webRootPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webClientLoginPath)
			})
			s.router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webClientLoginPath)
			})
		} else {
			s.router.Get(webRootPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webAdminLoginPath)
			})
			s.router.Get(webBasePath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				s.redirectToWebPath(w, r, webAdminLoginPath)
			})
		}
	}

	s.setupWebClientRoutes()
	s.setupWebAdminRoutes()
	return nil
}

func (s *httpdServer) setupRESTAPIRoutes() {
	if s.enableRESTAPI {
		if !s.binding.isAdminTokenEndpointDisabled() {
			s.router.Get(tokenPath, s.getToken)
			s.router.Post(adminPath+"/{username}/forgot-password", forgotAdminPassword)
			s.router.Post(adminPath+"/{username}/reset-password", resetAdminPassword)
		}

		s.router.Group(func(router chi.Router) {
			router.Use(checkNodeToken(s.tokenAuth))
			if !s.binding.isAdminAPIKeyAuthDisabled() {
				router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeAdmin))
			}
			router.Use(jwt.Verify(s.tokenAuth, jwt.TokenFromHeader))
			router.Use(jwtAuthenticatorAPI)

			router.Get(versionPath, func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				render.JSON(w, r, version.Get())
			})

			router.With(forbidAPIKeyAuthentication).Get(logoutPath, s.logout)
			router.With(forbidAPIKeyAuthentication).Get(adminProfilePath, getAdminProfile)
			router.With(forbidAPIKeyAuthentication, s.checkAuthRequirements).Put(adminProfilePath, updateAdminProfile)
			router.With(forbidAPIKeyAuthentication).Put(adminPwdPath, changeAdminPassword)
			// admin TOTP APIs
			router.With(forbidAPIKeyAuthentication).Get(adminTOTPConfigsPath, getTOTPConfigs)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPGeneratePath, generateTOTPSecret)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPValidatePath, validateTOTPPasscode)
			router.With(forbidAPIKeyAuthentication).Post(adminTOTPSavePath, saveTOTPConfig)
			router.With(forbidAPIKeyAuthentication).Get(admin2FARecoveryCodesPath, getRecoveryCodes)
			router.With(forbidAPIKeyAuthentication).Post(admin2FARecoveryCodesPath, generateRecoveryCodes)

			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Get(apiKeysPath, getAPIKeys)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Post(apiKeysPath, addAPIKey)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Get(apiKeysPath+"/{id}", getAPIKeyByID)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Put(apiKeysPath+"/{id}", updateAPIKey)
			router.With(forbidAPIKeyAuthentication, s.checkPerms(dataprovider.PermAdminAny)).
				Delete(apiKeysPath+"/{id}", deleteAPIKey)

			router.Group(func(router chi.Router) {
				router.Use(s.checkAuthRequirements)

				router.With(s.checkPerms(dataprovider.PermAdminViewServerStatus)).
					Get(serverStatusPath, func(w http.ResponseWriter, r *http.Request) {
						r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
						render.JSON(w, r, getServicesStatus())
					})

				router.With(s.checkPerms(dataprovider.PermAdminViewConnections)).Get(activeConnectionsPath, getActiveConnections)
				router.With(s.checkPerms(dataprovider.PermAdminCloseConnections)).
					Delete(activeConnectionsPath+"/{connectionID}", handleCloseConnection)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/users/scans", getUsersQuotaScans)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/users/{username}/scan", startUserQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Get(quotasBasePath+"/folders/scans", getFoldersQuotaScans)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans)).Post(quotasBasePath+"/folders/{name}/scan", startFolderQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers)).Get(userPath, getUsers)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers)).Post(userPath, addUser)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers)).Get(userPath+"/{username}", getUserByUsername) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(userPath+"/{username}", updateUser)
				router.With(s.checkPerms(dataprovider.PermAdminDeleteUsers)).Delete(userPath+"/{username}", deleteUser)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA)).Put(userPath+"/{username}/2fa/disable", disableUser2FA) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Get(folderPath, getFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Get(folderPath+"/{name}", getFolderByName) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(folderPath, addFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Put(folderPath+"/{name}", updateFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Delete(folderPath+"/{name}", deleteFolder)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Get(groupPath, getGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Get(groupPath+"/{name}", getGroupByName)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(groupPath, addGroup)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Put(groupPath+"/{name}", updateGroup)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Delete(groupPath+"/{name}", deleteGroup)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(dumpDataPath, dumpData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(loadDataPath, loadData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(loadDataPath, loadDataFromRequest)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/usage",
					updateUserQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Put(quotasBasePath+"/users/{username}/transfer-usage",
					updateUserTransferQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Put(quotasBasePath+"/folders/{name}/usage",
					updateFolderQuotaUsage)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(defenderHosts, getDefenderHosts)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(defenderHosts+"/{id}", getDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminManageDefender)).Delete(defenderHosts+"/{id}", deleteDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(adminPath, getAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(adminPath, addAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(adminPath+"/{username}", getAdminByUsername)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(adminPath+"/{username}", updateAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(adminPath+"/{username}", deleteAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(adminPath+"/{username}/2fa/disable", disableAdmin2FA)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(retentionChecksPath, getRetentionChecks)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(fsEventsPath, searchFsEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(providerEventsPath, searchProviderEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler).
					Get(logEventsPath, searchLogEvents)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventActionsPath, getEventActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventActionsPath+"/{name}", getEventActionByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventActionsPath, addEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(eventActionsPath+"/{name}", updateEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(eventActionsPath+"/{name}", deleteEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventRulesPath, getEventRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(eventRulesPath+"/{name}", getEventRuleByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventRulesPath, addEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(eventRulesPath+"/{name}", updateEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(eventRulesPath+"/{name}", deleteEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(eventRulesPath+"/run/{name}", runOnDemandRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(rolesPath, getRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(rolesPath, addRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(rolesPath+"/{name}", getRoleByName)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(rolesPath+"/{name}", updateRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(rolesPath+"/{name}", deleteRole)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler).Get(ipListsPath+"/{type}", getIPListEntries) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(ipListsPath+"/{type}", addIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(ipListsPath+"/{type}/{ipornet}", getIPListEntry) //nolint:goconst
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Put(ipListsPath+"/{type}/{ipornet}", updateIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Delete(ipListsPath+"/{type}/{ipornet}", deleteIPListEntry)
			})
		})

		// share API available to external users
		s.router.Get(sharesPath+"/{id}", s.downloadFromShare)
		s.router.Post(sharesPath+"/{id}", s.uploadFilesToShare)
		s.router.Post(sharesPath+"/{id}/{name}", s.uploadFileToShare)
		s.router.With(compressor.Handler).Get(sharesPath+"/{id}/dirs", s.readBrowsableShareContents)
		s.router.Get(sharesPath+"/{id}/files", s.downloadBrowsableSharedFile)

		if !s.binding.isUserTokenEndpointDisabled() {
			s.router.Get(userTokenPath, s.getUserToken)
			s.router.Post(userPath+"/{username}/forgot-password", forgotUserPassword)
			s.router.Post(userPath+"/{username}/reset-password", resetUserPassword)
		}

		s.router.Group(func(router chi.Router) {
			if !s.binding.isUserAPIKeyAuthDisabled() {
				router.Use(checkAPIKeyAuth(s.tokenAuth, dataprovider.APIKeyScopeUser))
			}
			router.Use(jwt.Verify(s.tokenAuth, jwt.TokenFromHeader))
			router.Use(jwtAuthenticatorAPIUser)

			router.With(forbidAPIKeyAuthentication).Get(userLogoutPath, s.logout)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Put(userPwdPath, changeUserPassword)
			router.With(forbidAPIKeyAuthentication).Get(userProfilePath, getUserProfile)
			router.With(forbidAPIKeyAuthentication, s.checkAuthRequirements).Put(userProfilePath, updateUserProfile)
			// user TOTP APIs
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Get(userTOTPConfigsPath, getTOTPConfigs)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Post(userTOTPGeneratePath, generateTOTPSecret)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Post(userTOTPValidatePath, validateTOTPPasscode)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Post(userTOTPSavePath, saveTOTPConfig)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Get(user2FARecoveryCodesPath, getRecoveryCodes)
			router.With(forbidAPIKeyAuthentication, s.checkHTTPUserPerm(sdk.WebClientMFADisabled)).
				Post(user2FARecoveryCodesPath, generateRecoveryCodes)

			router.With(s.checkAuthRequirements, compressor.Handler).Get(userDirsPath, readUserFolder)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userDirsPath, createUserDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userDirsPath, renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Delete(userDirsPath, deleteUserDir)
			router.With(s.checkAuthRequirements).Get(userFilesPath, getUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFilesPath, uploadUserFiles)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userFilesPath, renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Delete(userFilesPath, deleteUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFileActionsPath+"/move", renameUserFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userFileActionsPath+"/copy", copyUserFsEntry)
			router.With(s.checkAuthRequirements).Post(userStreamZipPath, getUserFilesAsZipStream)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Get(userSharesPath, getShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(userSharesPath, addShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Get(userSharesPath+"/{id}", getShareByID)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Put(userSharesPath+"/{id}", updateShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Delete(userSharesPath+"/{id}", deleteShare)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Post(userUploadFilePath, uploadUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled)).
				Patch(userFilesDirsMetadataPath, setFileDirMetadata)
		})

		if s.renderOpenAPI {
			s.router.Group(func(router chi.Router) {
				router.Use(cleanCacheControlMiddleware)
				router.Use(compressor.Handler)
				serveStaticDir(router, webOpenAPIPath, s.openAPIPath, false)
			})
		}
	}
}

func (s *httpdServer) setupWebClientRoutes() {
	if s.enableWebClient {
		s.router.Get(webBaseClientPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
			http.Redirect(w, r, webClientLoginPath, http.StatusFound)
		})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webclient/logo.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebClientLogo())
			})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webclient/favicon.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebClientFavicon())
			})
		s.router.Get(webClientLoginPath, s.handleClientWebLogin)
		if s.binding.OIDC.isEnabled() && !s.binding.isWebClientOIDCLoginDisabled() {
			s.router.Get(webClientOIDCLoginPath, s.handleWebClientOIDCLogin)
		}
		if !s.binding.isWebClientLoginFormDisabled() {
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webClientLoginPath, s.handleWebClientLoginPost)
			s.router.Get(webClientForgotPwdPath, s.handleWebClientForgotPwd)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webClientForgotPwdPath, s.handleWebClientForgotPwdPost)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Get(webClientResetPwdPath, s.handleWebClientPasswordReset)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webClientResetPwdPath, s.handleWebClientPasswordResetPost)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
				Get(webClientTwoFactorPath, s.handleWebClientTwoFactor)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
				Post(webClientTwoFactorPath, s.handleWebClientTwoFactorPost)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
				Get(webClientTwoFactorRecoveryPath, s.handleWebClientTwoFactorRecovery)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebClientPartial)).
				Post(webClientTwoFactorRecoveryPath, s.handleWebClientTwoFactorRecoveryPost)
		}
		// share routes available to external users
		s.router.Get(webClientPubSharesPath+"/{id}/login", s.handleClientShareLoginGet)
		s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
			Post(webClientPubSharesPath+"/{id}/login", s.handleClientShareLoginPost)
		s.router.Get(webClientPubSharesPath+"/{id}/logout", s.handleClientShareLogout)
		s.router.Get(webClientPubSharesPath+"/{id}", s.downloadFromShare)
		s.router.Post(webClientPubSharesPath+"/{id}/partial", s.handleClientSharePartialDownload)
		s.router.Get(webClientPubSharesPath+"/{id}/browse", s.handleShareGetFiles)
		s.router.Post(webClientPubSharesPath+"/{id}/browse/exist", s.handleClientShareCheckExist)
		s.router.Get(webClientPubSharesPath+"/{id}/download", s.handleClientSharedFile)
		s.router.Get(webClientPubSharesPath+"/{id}/upload", s.handleClientUploadToShare)
		s.router.With(compressor.Handler).Get(webClientPubSharesPath+"/{id}/dirs", s.handleShareGetDirContents)
		s.router.Post(webClientPubSharesPath+"/{id}", s.uploadFilesToShare)
		s.router.Post(webClientPubSharesPath+"/{id}/{name}", s.uploadFileToShare)
		s.router.Get(webClientPubSharesPath+"/{id}/viewpdf", s.handleShareViewPDF)
		s.router.Get(webClientPubSharesPath+"/{id}/getpdf", s.handleShareGetPDF)

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebClient))
			}
			router.Use(jwt.Verify(s.tokenAuth, oidcTokenFromContext, jwt.TokenFromCookie))
			router.Use(jwtAuthenticatorWebClient)

			router.Get(webClientLogoutPath, s.handleWebClientLogout)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientFilesPath, s.handleClientGetFiles)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientViewPDFPath, s.handleClientViewPDF)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientGetPDFPath, s.handleClientGetPDF)
			router.With(s.checkAuthRequirements, s.refreshCookie, s.verifyCSRFHeader).Get(webClientFilePath, getUserFile)
			router.With(s.checkAuthRequirements, s.refreshCookie, s.verifyCSRFHeader).Get(webClientTasksPath+"/{id}",
				getWebTask)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFilePath, uploadUserFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientExistPath, s.handleClientCheckExist)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientEditFilePath, s.handleClientEditFile)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Delete(webClientFilesPath, deleteUserFile)
			router.With(s.checkAuthRequirements, compressor.Handler, s.refreshCookie).
				Get(webClientDirsPath, s.handleClientGetDirContents)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientDirsPath, createUserDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Delete(webClientDirsPath, taskDeleteDir)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFileActionsPath+"/move", taskRenameFsEntry)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientWriteDisabled), s.verifyCSRFHeader).
				Post(webClientFileActionsPath+"/copy", taskCopyFsEntry)
			router.With(s.checkAuthRequirements, s.refreshCookie).
				Post(webClientDownloadZipPath, s.handleWebClientDownloadZip)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientPingPath, handlePingRequest)
			router.With(s.checkAuthRequirements, s.refreshCookie).Get(webClientProfilePath,
				s.handleClientGetProfile)
			router.With(s.checkAuthRequirements).Post(webClientProfilePath, s.handleWebClientProfilePost)
			router.With(s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Get(webChangeClientPwdPath, s.handleWebClientChangePwd)
			router.With(s.checkHTTPUserPerm(sdk.WebClientPasswordChangeDisabled)).
				Post(webChangeClientPwdPath, s.handleWebClientChangePwdPost)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath, s.handleWebClientMFA)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.refreshCookie).
				Get(webClientMFAPath+"/qrcode", getQRCode)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPGeneratePath, generateTOTPSecret)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPValidatePath, validateTOTPPasscode)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientTOTPSavePath, saveTOTPConfig)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader, s.refreshCookie).
				Get(webClientRecoveryCodesPath, getRecoveryCodes)
			router.With(s.checkHTTPUserPerm(sdk.WebClientMFADisabled), s.verifyCSRFHeader).
				Post(webClientRecoveryCodesPath, generateRecoveryCodes)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), compressor.Handler, s.refreshCookie).
				Get(webClientSharesPath+jsonAPISuffix, getAllShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharesPath, s.handleClientGetShares)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath, s.handleClientAddShareGet)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath, s.handleClientAddSharePost)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.refreshCookie).
				Get(webClientSharePath+"/{id}", s.handleClientUpdateShareGet)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled)).
				Post(webClientSharePath+"/{id}", s.handleClientUpdateSharePost)
			router.With(s.checkAuthRequirements, s.checkHTTPUserPerm(sdk.WebClientSharesDisabled), s.verifyCSRFHeader).
				Delete(webClientSharePath+"/{id}", deleteShare)
		})
	}
}

func (s *httpdServer) setupWebAdminRoutes() {
	if s.enableWebAdmin {
		s.router.Get(webBaseAdminPath, func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
			s.redirectToWebPath(w, r, webAdminLoginPath)
		})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webadmin/logo.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebAdminLogo())
			})
		s.router.With(cleanCacheControlMiddleware).Get(path.Join(webStaticFilesPath, "branding/webadmin/favicon.png"),
			func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
				renderPNGImage(w, r, dbBrandingConfig.getWebAdminFavicon())
			})
		s.router.Get(webAdminLoginPath, s.handleWebAdminLogin)
		if s.binding.OIDC.hasRoles() && !s.binding.isWebAdminOIDCLoginDisabled() {
			s.router.Get(webAdminOIDCLoginPath, s.handleWebAdminOIDCLogin)
		}
		s.router.Get(webOAuth2RedirectPath, s.handleOAuth2TokenRedirect)
		s.router.Get(webAdminSetupPath, s.handleWebAdminSetupGet)
		s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
			Post(webAdminSetupPath, s.handleWebAdminSetupPost)
		if !s.binding.isWebAdminLoginFormDisabled() {
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webAdminLoginPath, s.handleWebAdminLoginPost)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
				Get(webAdminTwoFactorPath, s.handleWebAdminTwoFactor)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
				Post(webAdminTwoFactorPath, s.handleWebAdminTwoFactorPost)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
				Get(webAdminTwoFactorRecoveryPath, s.handleWebAdminTwoFactorRecovery)
			s.router.With(jwt.Verify(s.tokenAuth, jwt.TokenFromCookie),
				s.jwtAuthenticatorPartial(tokenAudienceWebAdminPartial)).
				Post(webAdminTwoFactorRecoveryPath, s.handleWebAdminTwoFactorRecoveryPost)
			s.router.Get(webAdminForgotPwdPath, s.handleWebAdminForgotPwd)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webAdminForgotPwdPath, s.handleWebAdminForgotPwdPost)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Get(webAdminResetPwdPath, s.handleWebAdminPasswordReset)
			s.router.With(jwt.Verify(s.csrfTokenAuth, jwt.TokenFromCookie)).
				Post(webAdminResetPwdPath, s.handleWebAdminPasswordResetPost)
		}

		s.router.Group(func(router chi.Router) {
			if s.binding.OIDC.isEnabled() {
				router.Use(s.oidcTokenAuthenticator(tokenAudienceWebAdmin))
			}
			router.Use(jwt.Verify(s.tokenAuth, oidcTokenFromContext, jwt.TokenFromCookie))
			router.Use(jwtAuthenticatorWebAdmin)

			router.Get(webLogoutPath, s.handleWebAdminLogout)
			router.With(s.refreshCookie, s.checkAuthRequirements, s.requireBuiltinLogin).Get(
				webAdminProfilePath, s.handleWebAdminProfile)
			router.With(s.checkAuthRequirements, s.requireBuiltinLogin).Post(webAdminProfilePath, s.handleWebAdminProfilePost)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webChangeAdminPwdPath, s.handleWebAdminChangePwd)
			router.With(s.requireBuiltinLogin).Post(webChangeAdminPwdPath, s.handleWebAdminChangePwdPost)

			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminMFAPath, s.handleWebAdminMFA)
			router.With(s.refreshCookie, s.requireBuiltinLogin).Get(webAdminMFAPath+"/qrcode", getQRCode)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPGeneratePath, generateTOTPSecret)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPValidatePath, validateTOTPPasscode)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminTOTPSavePath, saveTOTPConfig)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin, s.refreshCookie).Get(webAdminRecoveryCodesPath,
				getRecoveryCodes)
			router.With(s.verifyCSRFHeader, s.requireBuiltinLogin).Post(webAdminRecoveryCodesPath, generateRecoveryCodes)

			router.Group(func(router chi.Router) {
				router.Use(s.checkAuthRequirements)

				router.With(s.checkPerms(dataprovider.PermAdminViewUsers), s.refreshCookie).
					Get(webUsersPath, s.handleGetWebUsers)
				router.With(s.checkPerms(dataprovider.PermAdminViewUsers), compressor.Handler, s.refreshCookie).
					Get(webUsersPath+jsonAPISuffix, getAllUsers)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers), s.refreshCookie).
					Get(webUserPath, s.handleWebAddUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers), s.refreshCookie).
					Get(webUserPath+"/{username}", s.handleWebUpdateUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers)).Post(webUserPath, s.handleWebAddUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminChangeUsers)).Post(webUserPath+"/{username}",
					s.handleWebUpdateUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupsPath, s.handleWebGetGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), compressor.Handler, s.refreshCookie).
					Get(webGroupsPath+jsonAPISuffix, getAllGroups)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupPath, s.handleWebAddGroupGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(webGroupPath, s.handleWebAddGroupPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.refreshCookie).
					Get(webGroupPath+"/{name}", s.handleWebUpdateGroupGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups)).Post(webGroupPath+"/{name}",
					s.handleWebUpdateGroupPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageGroups), s.verifyCSRFHeader).
					Delete(webGroupPath+"/{name}", deleteGroup)
				router.With(s.checkPerms(dataprovider.PermAdminViewConnections), s.refreshCookie).
					Get(webConnectionsPath, s.handleWebGetConnections)
				router.With(s.checkPerms(dataprovider.PermAdminViewConnections), s.refreshCookie).
					Get(webConnectionsPath+jsonAPISuffix, getActiveConnections)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFoldersPath, s.handleWebGetFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), compressor.Handler, s.refreshCookie).
					Get(webFoldersPath+jsonAPISuffix, getAllFolders)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFolderPath, s.handleWebAddFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webFolderPath, s.handleWebAddFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminViewServerStatus), s.refreshCookie).
					Get(webStatusPath, s.handleWebGetStatus)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminsPath, s.handleGetWebAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminsPath+jsonAPISuffix, getAllAdmins)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminPath, s.handleWebAddAdminGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminPath+"/{username}", s.handleWebUpdateAdminGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminPath, s.handleWebAddAdminPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminPath+"/{username}",
					s.handleWebUpdateAdminPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminPath+"/{username}", deleteAdmin)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Put(webAdminPath+"/{username}/2fa/disable", disableAdmin2FA)
				router.With(s.checkPerms(dataprovider.PermAdminCloseConnections), s.verifyCSRFHeader).
					Delete(webConnectionsPath+"/{connectionID}", handleCloseConnection)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webFolderPath+"/{name}", s.handleWebUpdateFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webFolderPath+"/{name}",
					s.handleWebUpdateFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.verifyCSRFHeader).
					Delete(webFolderPath+"/{name}", deleteFolder)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans), s.verifyCSRFHeader).
					Post(webScanVFolderPath+"/{name}", startFolderQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminDeleteUsers), s.verifyCSRFHeader).
					Delete(webUserPath+"/{username}", deleteUser)
				router.With(s.checkPerms(dataprovider.PermAdminDisableMFA), s.verifyCSRFHeader).
					Put(webUserPath+"/{username}/2fa/disable", disableUser2FA)
				router.With(s.checkPerms(dataprovider.PermAdminQuotaScans), s.verifyCSRFHeader).
					Post(webQuotaScanPath+"/{username}", startUserQuotaScan)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webMaintenancePath, s.handleWebMaintenance)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webBackupPath, dumpData)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webRestorePath, s.handleWebRestore)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers, dataprovider.PermAdminChangeUsers), s.refreshCookie).
					Get(webTemplateUser, s.handleWebTemplateUserGet)
				router.With(s.checkPerms(dataprovider.PermAdminAddUsers, dataprovider.PermAdminChangeUsers)).
					Post(webTemplateUser, s.handleWebTemplateUserPost)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders), s.refreshCookie).
					Get(webTemplateFolder, s.handleWebTemplateFolderGet)
				router.With(s.checkPerms(dataprovider.PermAdminManageFolders)).Post(webTemplateFolder, s.handleWebTemplateFolderPost)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(webDefenderPath, s.handleWebDefenderPage)
				router.With(s.checkPerms(dataprovider.PermAdminViewDefender)).Get(webDefenderHostsPath, getDefenderHosts)
				router.With(s.checkPerms(dataprovider.PermAdminManageDefender), s.verifyCSRFHeader).
					Delete(webDefenderHostsPath+"/{id}", deleteDefenderHostByID)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminEventActionsPath+jsonAPISuffix, getAllActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionsPath, s.handleWebGetEventActions)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionPath, s.handleWebAddEventActionGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventActionPath,
					s.handleWebAddEventActionPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventActionPath+"/{name}", s.handleWebUpdateEventActionGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventActionPath+"/{name}",
					s.handleWebUpdateEventActionPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminEventActionPath+"/{name}", deleteEventAction)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminEventRulesPath+jsonAPISuffix, getAllRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulesPath, s.handleWebGetEventRules)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulePath, s.handleWebAddEventRuleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventRulePath,
					s.handleWebAddEventRulePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminEventRulePath+"/{name}", s.handleWebUpdateEventRuleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminEventRulePath+"/{name}",
					s.handleWebUpdateEventRulePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminEventRulePath+"/{name}", deleteEventRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Post(webAdminEventRulePath+"/run/{name}", runOnDemandRule)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolesPath, s.handleWebGetRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webAdminRolesPath+jsonAPISuffix, getAllRoles)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolePath, s.handleWebAddRoleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminRolePath, s.handleWebAddRolePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).
					Get(webAdminRolePath+"/{name}", s.handleWebUpdateRoleGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webAdminRolePath+"/{name}",
					s.handleWebUpdateRolePost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webAdminRolePath+"/{name}", deleteRole)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), s.refreshCookie).Get(webEventsPath,
					s.handleWebGetEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsFsSearchPath, searchFsEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsProviderSearchPath, searchProviderEvents)
				router.With(s.checkPerms(dataprovider.PermAdminViewEvents), compressor.Handler, s.refreshCookie).
					Get(webEventsLogSearchPath, searchLogEvents)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Get(webIPListsPath, s.handleWebIPListsPage)
				router.With(s.checkPerms(dataprovider.PermAdminAny), compressor.Handler, s.refreshCookie).
					Get(webIPListsPath+"/{type}", getIPListEntries)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webIPListPath+"/{type}",
					s.handleWebAddIPListEntryGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webIPListPath+"/{type}",
					s.handleWebAddIPListEntryPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webIPListPath+"/{type}/{ipornet}",
					s.handleWebUpdateIPListEntryGet)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webIPListPath+"/{type}/{ipornet}",
					s.handleWebUpdateIPListEntryPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader).
					Delete(webIPListPath+"/{type}/{ipornet}", deleteIPListEntry)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.refreshCookie).Get(webConfigsPath, s.handleWebConfigs)
				router.With(s.checkPerms(dataprovider.PermAdminAny)).Post(webConfigsPath, s.handleWebConfigsPost)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader, s.refreshCookie).
					Post(webConfigsPath+"/smtp/test", testSMTPConfig)
				router.With(s.checkPerms(dataprovider.PermAdminAny), s.verifyCSRFHeader, s.refreshCookie).
					Post(webOAuth2TokenPath, s.handleSMTPOAuth2TokenRequestPost)
			})
		})
	}
}
