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
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/jwt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
)

func (s *httpdServer) refreshCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.checkCookieExpiration(w, r)
		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) checkCookieExpiration(w http.ResponseWriter, r *http.Request) {
	if _, ok := r.Context().Value(oidcTokenKey).(string); ok {
		return
	}
	claims, err := jwt.FromContext(r.Context())
	if err != nil {
		return
	}
	if claims.Username == "" || claims.Subject == "" {
		return
	}
	if time.Until(claims.Expiry.Time()) > cookieRefreshThreshold {
		return
	}
	if (time.Since(claims.IssuedAt.Time()) + cookieTokenDuration) > maxTokenDuration {
		return
	}
	if claims.Audience.Contains(tokenAudienceWebClient) {
		s.refreshClientToken(w, r, claims)
	} else {
		s.refreshAdminToken(w, r, claims)
	}
}

func (s *httpdServer) refreshClientToken(w http.ResponseWriter, r *http.Request, tokenClaims *jwt.Claims) {
	user, err := dataprovider.GetUserWithGroupSettings(tokenClaims.Username, "")
	if err != nil {
		return
	}
	if user.GetSignature() != tokenClaims.Subject {
		logger.Debug(logSender, "", "signature mismatch for user %q, unable to refresh cookie", user.Username)
		return
	}
	if err := user.CheckLoginConditions(); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for user %q: %v", user.Username, err)
		return
	}
	if err := checkHTTPClientUser(&user, r, xid.New().String(), true, false); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for user %q: %v", user.Username, err)
		return
	}

	tokenClaims.Permissions = user.Filters.WebClient
	tokenClaims.Role = user.Role
	logger.Debug(logSender, "", "cookie refreshed for user %q", user.Username)
	createAndSetCookie(w, r, tokenClaims, s.tokenAuth, tokenAudienceWebClient, util.GetIPFromRemoteAddress(r.RemoteAddr)) //nolint:errcheck
}

func (s *httpdServer) refreshAdminToken(w http.ResponseWriter, r *http.Request, tokenClaims *jwt.Claims) {
	admin, err := dataprovider.AdminExists(tokenClaims.Username)
	if err != nil {
		return
	}
	if admin.GetSignature() != tokenClaims.Subject {
		logger.Debug(logSender, "", "signature mismatch for admin %q, unable to refresh cookie", admin.Username)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := admin.CanLogin(ipAddr); err != nil {
		logger.Debug(logSender, "", "unable to refresh cookie for admin %q, err: %v", admin.Username, err)
		return
	}
	tokenClaims.Permissions = admin.Permissions
	tokenClaims.Role = admin.Role
	tokenClaims.HideUserPageSections = admin.Filters.Preferences.HideUserPageSections
	logger.Debug(logSender, "", "cookie refreshed for admin %q", admin.Username)
	createAndSetCookie(w, r, tokenClaims, s.tokenAuth, tokenAudienceWebAdmin, ipAddr) //nolint:errcheck
}

func (s *httpdServer) updateContextFromCookie(r *http.Request) *http.Request {
	_, err := jwt.FromContext(r.Context())
	if err != nil {
		_, err = r.Cookie(jwt.CookieKey)
		if err != nil {
			return r
		}
		token, err := jwt.VerifyRequest(s.tokenAuth, r, jwt.TokenFromCookie)
		ctx := jwt.NewContext(r.Context(), token, err)
		return r.WithContext(ctx)
	}
	return r
}

func (s *httpdServer) parseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		responseControllerDeadlines(
			http.NewResponseController(w),
			time.Now().Add(60*time.Second),
			time.Now().Add(60*time.Second),
		)
		w.Header().Set("Server", version.GetServerVersion("/", false))
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		var ip net.IP
		isUnixSocket := filepath.IsAbs(s.binding.Address)
		if !isUnixSocket {
			ip = net.ParseIP(ipAddr)
		}
		areHeadersAllowed := false
		if isUnixSocket || ip != nil {
			for _, allow := range s.binding.allowHeadersFrom {
				if allow(ip) {
					parsedIP := util.GetRealIP(r, s.binding.ClientIPProxyHeader, s.binding.ClientIPHeaderDepth)
					if parsedIP != "" {
						ipAddr = parsedIP
						r.RemoteAddr = ipAddr
					}
					if forwardedProto := r.Header.Get(xForwardedProto); forwardedProto != "" {
						ctx := context.WithValue(r.Context(), forwardedProtoKey, forwardedProto)
						r = r.WithContext(ctx)
					}
					areHeadersAllowed = true
					break
				}
			}
		}
		if !areHeadersAllowed {
			for idx := range s.binding.Security.proxyHeaders {
				r.Header.Del(s.binding.Security.proxyHeaders[idx])
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) checkConnection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
		common.Connections.AddClientConnection(ipAddr)
		defer common.Connections.RemoveClientConnection(ipAddr)

		if err := common.Connections.IsNewConnectionAllowed(ipAddr, common.ProtocolHTTP); err != nil {
			logger.Log(logger.LevelDebug, common.ProtocolHTTP, "", "connection not allowed from ip %q: %v", ipAddr, err)
			s.sendForbiddenResponse(w, r, util.NewI18nError(err, util.I18nErrorConnectionForbidden))
			return
		}
		if common.IsBanned(ipAddr, common.ProtocolHTTP) {
			s.sendForbiddenResponse(w, r, util.NewI18nError(
				util.NewGenericError("your IP address is blocked"),
				util.I18nErrorIPForbidden),
			)
			return
		}
		if delay, err := common.LimitRate(common.ProtocolHTTP, ipAddr); err != nil {
			delay += 499999999 * time.Nanosecond
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
			w.Header().Set("X-Retry-In", delay.String())
			s.sendTooManyRequestResponse(w, r, err)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *httpdServer) sendTooManyRequestResponse(w http.ResponseWriter, r *http.Request, err error) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
				util.NewI18nError(errors.New(http.StatusText(http.StatusTooManyRequests)), util.I18nError429Message), "")
			return
		}
		s.renderMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(errors.New(http.StatusText(http.StatusTooManyRequests)), util.I18nError429Message), "")
		return
	}
	sendAPIResponse(w, r, err, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
}

func (s *httpdServer) sendForbiddenResponse(w http.ResponseWriter, r *http.Request, err error) {
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			s.renderClientForbiddenPage(w, r, err)
			return
		}
		s.renderForbiddenPage(w, r, err)
		return
	}
	sendAPIResponse(w, r, err, "", http.StatusForbidden)
}

func (s *httpdServer) badHostHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	for _, header := range s.binding.Security.HostsProxyHeaders {
		if h := r.Header.Get(header); h != "" {
			host = h
			break
		}
	}
	logger.Debug(logSender, "", "the host %q is not allowed", host)
	s.sendForbiddenResponse(w, r, util.NewI18nError(
		util.NewGenericError(http.StatusText(http.StatusForbidden)),
		util.I18nErrorConnectionForbidden,
	))
}

func (s *httpdServer) notFoundHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if (s.enableWebAdmin || s.enableWebClient) && isWebRequest(r) {
		r = s.updateContextFromCookie(r)
		if s.enableWebClient && (isWebClientRequest(r) || !s.enableWebAdmin) {
			s.renderClientNotFoundPage(w, r, nil)
			return
		}
		s.renderNotFoundPage(w, r, nil)
		return
	}
	sendAPIResponse(w, r, nil, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

func (s *httpdServer) redirectToWebPath(w http.ResponseWriter, r *http.Request, webPath string) {
	if dataprovider.HasAdmin() {
		http.Redirect(w, r, webPath, http.StatusFound)
		return
	}
	if s.enableWebAdmin {
		http.Redirect(w, r, webAdminSetupPath, http.StatusFound)
	}
}

// The StripSlashes causes infinite redirects at the root path if used with http.FileServer.
// We also don't strip paths with more than one trailing slash, see #1434
func (s *httpdServer) mustStripSlash(r *http.Request) bool {
	urlPath := getURLPath(r)
	return !strings.HasSuffix(urlPath, "//") && !strings.HasPrefix(urlPath, webOpenAPIPath) &&
		!strings.HasPrefix(urlPath, webStaticFilesPath) && !strings.HasPrefix(urlPath, acmeChallengeURI)
}

func (s *httpdServer) mustCheckPath(r *http.Request) bool {
	urlPath := getURLPath(r)
	return !strings.HasPrefix(urlPath, webStaticFilesPath) && !strings.HasPrefix(urlPath, acmeChallengeURI)
}
