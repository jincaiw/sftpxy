package webdav

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/net/webdav"
)

// Server represents the WebDAV server
type Server struct {
	config       config.WebDAVConfig
	logger       *zap.Logger
	authService  *auth.AuthenticationService
	policyEngine *policy.PolicyEngine
	userRepo     repository.UserRepository
	auditRepo    repository.AuditRepository
	sessionRepo  repository.SessionRepository
	listener     net.Listener
	server       *http.Server
	lockSystem   webdav.LockSystem
}

// NewServer creates a new WebDAV server
func NewServer(
	cfg config.WebDAVConfig,
	log *zap.Logger,
	authSvc *auth.AuthenticationService,
	policyEng *policy.PolicyEngine,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	sessionRepo repository.SessionRepository,
) *Server {
	return &Server{
		config:       cfg,
		logger:       log,
		authService:  authSvc,
		policyEngine: policyEng,
		userRepo:     userRepo,
		auditRepo:    auditRepo,
		sessionRepo:  sessionRepo,
		lockSystem:   webdav.NewMemLS(),
	}
}

// Start starts the WebDAV server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("WebDAV server is disabled")
		return nil
	}
	if (s.config.TLSCertFile == "") != (s.config.TLSKeyFile == "") {
		return fmt.Errorf("webdav tls_cert_file and tls_key_file must be configured together")
	}
	if s.config.ClientCert {
		return fmt.Errorf("webdav client certificate authentication is not implemented in the minimal protocol closure")
	}
	if s.config.BasePath == "" || !strings.HasPrefix(s.config.BasePath, "/") {
		return fmt.Errorf("webdav base_path must start with '/'")
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener
	s.server = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(s.handleRequest),
	}

	s.logger.Info("WebDAV server started", zap.String("address", addr))

	go func() {
		var err error
		if s.config.TLSCertFile != "" {
			err = s.server.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("WebDAV server error", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the WebDAV server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		s.logger.Info("Shutting down WebDAV server")
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	basePath := normalizeBasePath(s.config.BasePath)
	virtualPath, ok := requestVirtualPath(r.URL.Path, basePath)
	if !ok {
		http.NotFound(w, r)
		return
	}

	clientIP := requestIP(r.RemoteAddr)
	username, password, ok := r.BasicAuth()
	if !ok {
		s.writeAuthFailure(w)
		s.recordAudit("", clientIP, r.Method, r.URL.Path, "failure", "missing basic auth")
		return
	}

	result, err := s.authService.LoginUser(r.Context(), username, password)
	if err != nil || result == nil || !result.Success || result.User == nil {
		s.writeAuthFailure(w)
		s.recordAudit(username, clientIP, r.Method, r.URL.Path, "failure", "invalid credentials")
		return
	}

	user := result.User
	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(r.Context(), policy.AuthRequest{
			Username:   user.Username,
			Protocol:   "webdav",
			ClientIP:   clientIP,
			AuthMethod: "password",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			http.Error(w, reason, http.StatusForbidden)
			s.recordAudit(username, clientIP, r.Method, r.URL.Path, "failure", reason)
			return
		}
	}

	if s.sessionRepo != nil {
		sessionID := newProtocolSessionID("webdav")
		if err := s.sessionRepo.CreateSession(r.Context(), sessionID, user.ID, "webdav", clientIP.String()); err != nil {
			s.logger.Warn("Failed to create WebDAV session record", zap.String("username", user.Username), zap.Error(err))
		} else {
			defer func() {
				if err := s.sessionRepo.DeactivateSession(context.Background(), sessionID); err != nil {
					s.logger.Warn("Failed to deactivate WebDAV session record", zap.String("username", user.Username), zap.Error(err))
				}
			}()
		}
	}

	if err := os.MkdirAll(user.HomeDir, 0755); err != nil {
		http.Error(w, "failed to prepare user home", http.StatusInternalServerError)
		s.recordAudit(username, clientIP, r.Method, virtualPath, "failure", err.Error())
		return
	}

	if op, targetPath, size := s.operationFromRequest(r, virtualPath, basePath); op != "" && s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanPerformOperation(r.Context(), policy.OperationRequest{
			UserID:    user.ID,
			Username:  user.Username,
			Protocol:  "webdav",
			ClientIP:  clientIP,
			Operation: op,
			FilePath:  targetPath,
			FileSize:  size,
		}); policyErr != nil || !allowed {
			reason := "operation denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			http.Error(w, reason, http.StatusForbidden)
			s.recordAudit(username, clientIP, r.Method, targetPath, "failure", reason)
			return
		}
	}

	recorder := &statusCapturingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	handler := &webdav.Handler{
		Prefix:     basePath,
		FileSystem: webdav.Dir(user.HomeDir),
		LockSystem: s.lockSystem,
	}
	handler.ServeHTTP(recorder, r)

	resultStatus := "success"
	errMsg := ""
	if recorder.statusCode >= http.StatusBadRequest {
		resultStatus = "failure"
		errMsg = http.StatusText(recorder.statusCode)
	}

	s.recordAudit(username, clientIP, r.Method, virtualPath, resultStatus, errMsg)
}

func (s *Server) operationFromRequest(r *http.Request, virtualPath, basePath string) (policy.OperationType, string, int64) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return policy.OpDownload, virtualPath, 0
	case http.MethodPut:
		return policy.OpUpload, virtualPath, r.ContentLength
	case http.MethodDelete:
		return policy.OpDelete, virtualPath, 0
	case "PROPFIND", http.MethodOptions:
		return policy.OpList, virtualPath, 0
	case "MKCOL":
		return policy.OpMkdir, virtualPath, 0
	case "MOVE":
		if destinationPath, ok := destinationVirtualPath(r.Header.Get("Destination"), basePath); ok {
			return policy.OpRename, destinationPath, 0
		}
		return policy.OpRename, virtualPath, 0
	case "COPY":
		return policy.OpCopy, virtualPath, 0
	default:
		return "", virtualPath, 0
	}
}

func (s *Server) writeAuthFailure(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="SFTPxy WebDAV"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (s *Server) recordAudit(username string, clientIP net.IP, _ string, requestPath, result, errMsg string) {
	if s.auditRepo == nil {
		return
	}

	_, _ = s.auditRepo.CreateAuditLog(context.Background(), &repository.AuditLog{
		EventID:      fmt.Sprintf("webdav-%d", time.Now().UnixNano()),
		EventType:    "webdav_request",
		ActorType:    "user",
		ActorName:    username,
		TargetType:   "path",
		TargetID:     requestPath,
		Protocol:     "webdav",
		ClientIP:     clientIP.String(),
		Result:       result,
		ErrorMessage: errMsg,
	})
}

func requestIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	if ip := net.ParseIP(remoteAddr); ip != nil {
		return ip
	}
	return net.IPv4(127, 0, 0, 1)
}

func newProtocolSessionID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func normalizeBasePath(raw string) string {
	cleaned := path.Clean("/" + strings.TrimSpace(raw))
	if cleaned == "." {
		return "/"
	}
	if cleaned != "/" {
		cleaned = strings.TrimSuffix(cleaned, "/")
	}
	return cleaned
}

func requestVirtualPath(requestPath, basePath string) (string, bool) {
	cleanedPath := path.Clean("/" + strings.TrimSpace(requestPath))
	if basePath == "/" {
		return cleanedPath, true
	}
	if cleanedPath != basePath && !strings.HasPrefix(cleanedPath, basePath+"/") {
		return "", false
	}
	virtualPath := strings.TrimPrefix(cleanedPath, basePath)
	if virtualPath == "" {
		virtualPath = "/"
	}
	return virtualPath, true
}

func destinationVirtualPath(rawDestination, basePath string) (string, bool) {
	if strings.TrimSpace(rawDestination) == "" {
		return "", false
	}
	if parsed, err := url.Parse(rawDestination); err == nil && parsed.Path != "" {
		return requestVirtualPath(parsed.Path, basePath)
	}
	return requestVirtualPath(rawDestination, basePath)
}

type statusCapturingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusCapturingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}
