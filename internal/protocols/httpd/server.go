package httpd

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jincaiw/sftpxy/internal/audit"
	authn "github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/shares"
	"github.com/jincaiw/sftpxy/internal/storage"
	"github.com/jincaiw/sftpxy/internal/storage/encrypted"
	"github.com/jincaiw/sftpxy/internal/storage/httpfs"
	"github.com/jincaiw/sftpxy/internal/storage/local"
	"github.com/jincaiw/sftpxy/internal/storage/remotesftp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"
)

type contextKey string

const sessionContextKey contextKey = "httpd_session"

type authSession struct {
	Token     string
	SessionID string
	UserID    int64
	Username  string
	Role      string
	Scopes    []string
	Filters   map[string]any
	HomeDir   string
	ExpiresAt time.Time
}

type oidcState struct {
	State     string
	Verifier  string
	ReturnTo  string
	RoleHint  string
	CreatedAt time.Time
}

type apiKeyPrincipal struct {
	Subject string
	Role    string
	Scopes  []string
}

// Server represents the HTTP server
type Server struct {
	config               config.HTTPDConfig
	authConfig           config.AuthConfig
	router               *chi.Mux
	server               *http.Server
	clientServer         *http.Server
	logger               *zap.Logger
	startTime            time.Time
	version              string
	db                   *sql.DB
	userRepo             repository.UserRepository
	policyEngine         *policy.PolicyEngine
	shareManager         *shares.Manager
	auditRepo            repository.AuditRepository
	auditRecorder        audit.AuditRecorder
	eventManager         *events.Manager
	metricsCollector     *metrics.Collector
	telemetryEnabled     bool
	protocols            map[string]bool
	sessions             map[string]*authSession
	sessionsMu           sync.RWMutex
	statusMu             sync.RWMutex
	jwtManager           *authn.JWTManager
	ldapAuth             *authn.LDAPAuthenticator
	oidcAuth             *authn.OIDCAuthenticator
	apiKeys              map[string]apiKeyPrincipal
	oidcStates           map[string]oidcState
	oidcStatesMu         sync.RWMutex
	fullConfig           *config.Config
	passwordPolicy       *authn.PasswordPolicy
	passwordChangeTokens map[string]*passwordChangeToken
	passwordChangeMu     sync.RWMutex
	hookManager          *hooks.HookManager
	sessionLastTouch     sync.Map
	configPath           string
	auditQueue           chan func()
	auditWg              sync.WaitGroup
}

type passwordChangeToken struct {
	UserID    int64
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// NewServer creates a new HTTP server
func NewServer(cfg config.HTTPDConfig, log *zap.Logger) *Server {
	return NewServerWithDB(cfg, log, nil)
}

// NewServerWithDB creates a new HTTP server with a database connection
func NewServerWithDB(cfg config.HTTPDConfig, log *zap.Logger, db *sql.DB) *Server {
	return NewServerWithDependencies(cfg, log, ServerDependencies{DB: db})
}

// NewServerWithDependencies creates a new HTTP server with optional collaborators.
func NewServerWithDependencies(cfg config.HTTPDConfig, log *zap.Logger, deps ServerDependencies) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	if cfg.RequestTimeout > 0 {
		r.Use(middleware.Timeout(cfg.RequestTimeout))
	}

	s := &Server{
		config:           cfg,
		router:           r,
		logger:           log,
		startTime:        time.Now(),
		version:          "1.0.0",
		db:               deps.DB,
		userRepo:         deps.UserRepo,
		policyEngine:     deps.PolicyEngine,
		shareManager:     deps.ShareManager,
		auditRepo:        deps.AuditRepo,
		eventManager:     deps.EventManager,
		metricsCollector: deps.MetricsCollector,
		telemetryEnabled: deps.TelemetryEnabled,
		protocols: map[string]bool{
			"ssh":    false,
			"ftp":    false,
			"webdav": false,
			"http":   cfg.Enabled,
		},
		sessions:             make(map[string]*authSession),
		apiKeys:              make(map[string]apiKeyPrincipal),
		oidcStates:           make(map[string]oidcState),
		fullConfig:           deps.FullConfig,
		passwordChangeTokens: make(map[string]*passwordChangeToken),
		configPath:           deps.ConfigPath,
	}
	if deps.FullConfig != nil {
		s.authConfig = deps.FullConfig.Auth
		if deps.FullConfig.Auth.PasswordPolicy.MinLength > 0 || deps.FullConfig.Auth.PasswordPolicy.RequireUppercase || deps.FullConfig.Auth.PasswordPolicy.RequireLowercase || deps.FullConfig.Auth.PasswordPolicy.RequireDigit || deps.FullConfig.Auth.PasswordPolicy.RequireSpecial {
			s.passwordPolicy = authn.NewPasswordPolicy(deps.FullConfig.Auth.PasswordPolicy)
		}
	}
	s.initAuthProviders()
	for name, enabled := range deps.ProtocolEnabled {
		s.protocols[name] = enabled
	}

	s.auditQueue = make(chan func(), 1024)
	s.auditWg.Add(1)
	go s.processAuditQueue()

	r.Use(s.httpAuditMiddleware)

	s.setupRoutes()

	return s
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	hasClientPort := s.config.ClientListenPort > 0 && s.config.ClientListenPort != s.config.ListenPort

	if s.config.RESTAPIEnabled {
		s.router.Route("/api/v1", func(r chi.Router) {
			r.Post("/auth/admin/login", s.adminLogin)
			r.Post("/auth/admin/init", s.adminInit)
			if !hasClientPort {
				r.Post("/auth/user/login", s.userLogin)
			}
			r.Get("/auth/oidc/start", s.oidcStart)
			r.Get("/auth/oidc/callback", s.oidcCallback)
			r.With(s.requireRole("")).Post("/auth/refresh", s.refreshToken)
			r.Post("/auth/user/password/change", s.forcedPasswordChange)
			if !hasClientPort {
				r.Get("/shares/access/{token}", s.accessShare)
				r.Post("/shares/access/{token}", s.accessShare)
				r.Get("/shares/download/{token}", s.downloadSharedFile)
			}
			r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
				s.writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireRole("admin"))
				r.With(s.requireAdminPermission("admins:read", "admins:write")).Get("/admins", s.getAdmins)
				r.With(s.requireAdminPermission("admins:write")).Post("/admins", s.createAdmin)
				r.With(s.requireAdminPermission("admins:write")).Put("/admins/{id}", s.updateAdmin)
				r.With(s.requireAdminPermission("admins:write")).Delete("/admins/{id}", s.deleteAdmin)
				r.With(s.requireAdminPermission("groups:read", "groups:write")).Get("/groups", s.getGroups)
				r.With(s.requireAdminPermission("groups:write")).Post("/groups", s.createGroup)
				r.With(s.requireAdminPermission("groups:write")).Put("/groups/{id}", s.updateGroup)
				r.With(s.requireAdminPermission("groups:write")).Delete("/groups/{id}", s.deleteGroup)
				r.With(s.requireAdminPermission("roles:read", "roles:write")).Get("/roles", s.getRoles)
				r.With(s.requireAdminPermission("roles:write")).Post("/roles", s.createRole)
				r.With(s.requireAdminPermission("roles:write")).Put("/roles/{id}", s.updateRole)
				r.With(s.requireAdminPermission("roles:write")).Delete("/roles/{id}", s.deleteRole)
				r.With(s.requireAdminPermission("users:read", "users:write")).Get("/users", s.getUsers)
				r.With(s.requireAdminPermission("users:write")).Post("/users", s.createUser)
				r.With(s.requireAdminPermission("users:write")).Put("/users/{id}", s.updateUser)
				r.With(s.requireAdminPermission("users:write")).Delete("/users/{id}", s.deleteUser)
				r.With(s.requireAdminPermission("connections:read", "connections:write")).Get("/connections", s.getConnections)
				r.With(s.requireAdminPermission("connections:write")).Delete("/connections/{id}", s.disconnectConnection)
				r.With(s.requireAdminPermission("logs:read")).Get("/logs", s.listLogs)
				r.With(s.requireAdminPermission("events:read", "events:write")).Get("/events/rules", s.listEventRules)
				r.With(s.requireAdminPermission("events:write")).Post("/events/rules", s.createEventRule)
				r.With(s.requireAdminPermission("events:write")).Put("/events/rules/{ruleID}", s.updateEventRule)
				r.With(s.requireAdminPermission("events:write")).Delete("/events/rules/{ruleID}", s.deleteEventRule)
				r.With(s.requireAdminPermission("events:read", "events:write")).Get("/events/history", s.listEventHistory)
				r.With(s.requireAdminPermission("events:write")).Post("/events/emit", s.emitEvent)
				r.With(s.requireAdminPermission("folders:read", "folders:write")).Get("/folders", s.listVirtualFolders)
				r.With(s.requireAdminPermission("folders:write")).Post("/folders", s.createVirtualFolder)
				r.With(s.requireAdminPermission("folders:read", "folders:write")).Get("/folders/{folderID}", s.getVirtualFolder)
				r.With(s.requireAdminPermission("folders:write")).Put("/folders/{folderID}", s.updateVirtualFolder)
				r.With(s.requireAdminPermission("folders:write")).Delete("/folders/{folderID}", s.deleteVirtualFolder)
				r.With(s.requireAdminPermission("folders:write")).Post("/folders/{folderID}/users", s.addUserToFolder)
				r.With(s.requireAdminPermission("folders:write")).Delete("/folders/{folderID}/users/{userID}", s.removeUserFromFolder)
				r.With(s.requireAdminPermission("folders:write")).Post("/folders/{folderID}/groups", s.addGroupToFolder)
				r.With(s.requireAdminPermission("folders:write")).Delete("/folders/{folderID}/groups/{groupID}", s.removeGroupFromFolder)
				r.With(s.requireAdminPermission("users:read")).Get("/quota/users/{userID}", s.getUserQuota)
				r.With(s.requireAdminPermission("users:write")).Post("/quota/users/{userID}/scan", s.scanUserQuota)
				r.With(s.requireAdminPermission("users:write")).Post("/quota/users/{userID}/recalculate", s.recalculateUserQuota)
				r.With(s.requireAdminPermission("folders:read")).Get("/quota/folders/{folderID}", s.getFolderQuota)
				r.With(s.requireAdminPermission("admins:read")).Get("/backup", s.exportBackup)
				r.With(s.requireAdminPermission("admins:write")).Post("/restore", s.importRestore)
				r.With(s.requireAdminPermission("connections:read")).Get("/defender/blocked", s.listBlockedIPs)
				r.With(s.requireAdminPermission("connections:read")).Get("/defender/blocked/{ip}", s.getBlockedIP)
				r.With(s.requireAdminPermission("connections:write")).Delete("/defender/blocked/{ip}", s.unblockIP)
				r.With(s.requireAdminPermission("admins:read")).Get("/config", s.getConfig)
				r.With(s.requireAdminPermission("admins:write")).Put("/config", s.updateConfig)
				r.With(s.requireAdminPermission("users:read")).Get("/admin/shares", s.adminListShares)
				r.With(s.requireAdminPermission("users:write")).Delete("/admin/shares/{shareID}", s.adminDeleteShare)
				r.With(s.requireAdminPermission("events:read", "events:write")).Get("/data-retention", s.listDataRetentionPolicies)
				r.With(s.requireAdminPermission("events:write")).Post("/data-retention", s.createDataRetentionPolicy)
				r.With(s.requireAdminPermission("events:write")).Put("/data-retention/{id}", s.updateDataRetentionPolicy)
				r.With(s.requireAdminPermission("events:write")).Delete("/data-retention/{id}", s.deleteDataRetentionPolicy)
			})

			if !hasClientPort {
				r.Group(func(r chi.Router) {
					r.Use(s.requireRole("user"))
					r.Get("/profile", s.getProfile)
					r.Post("/profile/password", s.changePassword)
					r.Get("/files", s.listFiles)
					r.Get("/files/download", s.downloadFile)
					r.Post("/files/download/zip", s.downloadZip)
					r.Post("/files/upload", s.uploadFile)
					r.Delete("/files", s.deleteFile)
					r.Put("/files/rename", s.renameFile)
					r.Post("/files/folder", s.createFolder)
					r.Get("/shares", s.listShares)
					r.Post("/shares", s.createShare)
					r.Post("/shares/{shareID}/revoke", s.revokeShare)
					r.Get("/user/quota", s.getOwnQuota)
					r.Get("/user/sessions", s.getOwnSessions)
					r.Delete("/user/sessions/{sessionID}", s.disconnectOwnSession)
					r.Post("/user/public-keys", s.addOwnPublicKey)
					r.Delete("/user/public-keys/{keyID}", s.removeOwnPublicKey)
					r.Post("/user/mfa/setup", s.setupMFA)
					r.Post("/user/mfa/verify", s.verifyMFA)
					r.Delete("/user/mfa", s.disableMFA)
				})
			}
		})
	}

	s.router.Get("/health", s.handleHealth)
	s.router.Get("/status", s.handleStatus)

	if s.config.OpenAPIEnabled {
		s.router.Get("/openapi", s.handleOpenAPI)
	}

	s.router.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if s.metricsCollector != nil {
			s.metricsCollector.Handler().ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	if s.config.WebAdminEnabled || s.config.WebClientEnabled {
		staticPath := s.config.StaticPath
		if staticPath == "" {
			staticPath = "./web/dist"
		}

		if _, err := os.Stat(staticPath); err == nil {
			s.logger.Info("Serving static files", zap.String("path", staticPath))
			spaHandler := &spaHandler{
				staticPath: staticPath,
				indexPath:  "index.html",
			}

			s.router.Get("/admin*", spaHandler.ServeHTTP)
			if !hasClientPort {
				s.router.Get("/client*", spaHandler.ServeHTTP)
			}
			s.router.Get("/assets/*", func(w http.ResponseWriter, r *http.Request) {
				filePath := staticPath + r.URL.Path
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
				http.NotFound(w, r)
			})
			s.router.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
				filePath := staticPath + "/favicon.ico"
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
				http.NotFound(w, r)
			})
			s.router.HandleFunc("/vite.svg", func(w http.ResponseWriter, r *http.Request) {
				filePath := staticPath + "/vite.svg"
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
				http.NotFound(w, r)
			})
			s.router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.Redirect(w, r, "/admin", http.StatusFound)
					return
				}
				http.ServeFile(w, r, staticPath+"/index.html")
			})
		} else {
			s.logger.Warn("Static files directory not found", zap.String("path", staticPath))
		}
	}
}

func (s *Server) setupClientRoutes(r *chi.Mux) {
	if s.config.RESTAPIEnabled {
		r.Route("/api/v1", func(r chi.Router) {
			r.Post("/auth/user/login", s.userLogin)
			r.Get("/auth/oidc/start", s.oidcStart)
			r.Get("/auth/oidc/callback", s.oidcCallback)
			r.With(s.requireRole("")).Post("/auth/refresh", s.refreshToken)
			r.Post("/auth/user/password/change", s.forcedPasswordChange)
			r.Get("/shares/access/{token}", s.accessShare)
			r.Post("/shares/access/{token}", s.accessShare)
			r.Get("/shares/download/{token}", s.downloadSharedFile)
			r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
				s.writeJSON(w, http.StatusOK, map[string]string{"status": "running"})
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireRole("user"))
				r.Get("/profile", s.getProfile)
				r.Post("/profile/password", s.changePassword)
				r.Get("/files", s.listFiles)
				r.Get("/files/download", s.downloadFile)
				r.Post("/files/download/zip", s.downloadZip)
				r.Post("/files/upload", s.uploadFile)
				r.Delete("/files", s.deleteFile)
				r.Put("/files/rename", s.renameFile)
				r.Post("/files/folder", s.createFolder)
				r.Get("/shares", s.listShares)
				r.Post("/shares", s.createShare)
				r.Post("/shares/{shareID}/revoke", s.revokeShare)
				r.Get("/user/quota", s.getOwnQuota)
				r.Get("/user/sessions", s.getOwnSessions)
				r.Delete("/user/sessions/{sessionID}", s.disconnectOwnSession)
				r.Post("/user/public-keys", s.addOwnPublicKey)
				r.Delete("/user/public-keys/{keyID}", s.removeOwnPublicKey)
				r.Post("/user/mfa/setup", s.setupMFA)
				r.Post("/user/mfa/verify", s.verifyMFA)
				r.Delete("/user/mfa", s.disableMFA)
			})
		})
	}

	r.Get("/health", s.handleHealth)
	r.Get("/status", s.handleStatus)

	if s.config.WebClientEnabled {
		staticPath := s.config.StaticPath
		if staticPath == "" {
			staticPath = "./web/dist"
		}
		if _, err := os.Stat(staticPath); err == nil {
			spaHandler := &spaHandler{
				staticPath: staticPath,
				indexPath:  "index.html",
			}
			r.Get("/client*", spaHandler.ServeHTTP)
			r.Get("/assets/*", func(w http.ResponseWriter, r *http.Request) {
				filePath := staticPath + r.URL.Path
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
				http.NotFound(w, r)
			})
			r.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
				filePath := staticPath + "/favicon.ico"
				if _, err := os.Stat(filePath); err == nil {
					http.ServeFile(w, r, filePath)
					return
				}
				http.NotFound(w, r)
			})
			r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/" {
					http.Redirect(w, r, "/client", http.StatusFound)
					return
				}
				http.ServeFile(w, r, staticPath+"/index.html")
			})
		}
	}
}

func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("HTTP server is disabled")
		return nil
	}
	if s.config.WebAdminEnabled || s.config.WebClientEnabled {
		staticPath := s.config.StaticPath
		if staticPath == "" {
			staticPath = "./web/dist"
		}
		if info, err := os.Stat(staticPath); err != nil {
			return fmt.Errorf("http static_path %q is not accessible: %w", staticPath, err)
		} else if !info.IsDir() {
			return fmt.Errorf("http static_path %q must be a directory", staticPath)
		}
		indexPath := filepath.Join(staticPath, "index.html")
		if info, err := os.Stat(indexPath); err != nil {
			return fmt.Errorf("http static index %q is not accessible: %w", indexPath, err)
		} else if info.IsDir() {
			return fmt.Errorf("http static index %q must be a file", indexPath)
		}
	}
	if (s.config.TLSCertFile == "") != (s.config.TLSKeyFile == "") {
		return fmt.Errorf("http tls_cert_file and tls_key_file must be configured together")
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Starting HTTP admin server", zap.String("address", addr))

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		var err error
		if s.config.TLSCertFile != "" || s.config.TLSKeyFile != "" {
			err = s.server.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.server.Serve(listener)
		}
		if err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP admin server error", zap.Error(err))
		}
	}()

	if s.config.ClientListenPort > 0 && s.config.ClientListenPort != s.config.ListenPort {
		clientAddr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ClientListenPort)
		clientRouter := chi.NewRouter()
		clientRouter.Use(middleware.RequestID)
		clientRouter.Use(middleware.RealIP)
		clientRouter.Use(middleware.Logger)
		clientRouter.Use(middleware.Recoverer)
		if s.config.RequestTimeout > 0 {
			clientRouter.Use(middleware.Timeout(s.config.RequestTimeout))
		}
		clientRouter.Use(s.httpAuditMiddleware)
		s.setupClientRoutes(clientRouter)

		s.clientServer = &http.Server{
			Addr:         clientAddr,
			Handler:      clientRouter,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 60 * time.Second,
			IdleTimeout:  120 * time.Second,
		}

		s.logger.Info("Starting HTTP client server", zap.String("address", clientAddr))

		clientListener, err := net.Listen("tcp", clientAddr)
		if err != nil {
			s.server.Shutdown(context.Background())
			return fmt.Errorf("failed to listen on %s: %w", clientAddr, err)
		}

		go func() {
			var err error
			if s.config.TLSCertFile != "" || s.config.TLSKeyFile != "" {
				err = s.clientServer.ServeTLS(clientListener, s.config.TLSCertFile, s.config.TLSKeyFile)
			} else {
				err = s.clientServer.Serve(clientListener)
			}
			if err != nil && err != http.ErrServerClosed {
				s.logger.Error("HTTP client server error", zap.Error(err))
			}
		}()
	}

	return nil
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.auditQueue != nil {
		close(s.auditQueue)
		s.auditWg.Wait()
	}
	var err error
	if s.clientServer != nil {
		s.logger.Info("Shutting down HTTP client server")
		if cerr := s.clientServer.Shutdown(ctx); cerr != nil {
			err = cerr
		}
	}
	if s.server != nil {
		s.logger.Info("Shutting down HTTP admin server")
		if cerr := s.server.Shutdown(ctx); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// adminLogin handles admin authentication
func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var id int64
	var passwordHash string
	var status string
	loginCtx, loginCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer loginCancel()
	if err := s.db.QueryRowContext(loginCtx,
		"SELECT id, password_hash, status FROM admins WHERE username = ?",
		req.Username,
	).Scan(&id, &passwordHash, &status); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		s.logger.Error("admin login query failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if status != "active" {
		s.writeError(w, http.StatusUnauthorized, "Account is disabled")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	permissions, filters, err := s.loadAdminPermissions(id)
	if err != nil {
		s.logger.Error("load admin permissions failed", zap.Error(err), zap.Int64("admin_id", id))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	session := &authSession{
		UserID:    id,
		Username:  req.Username,
		Role:      "admin",
		Scopes:    permissions,
		Filters:   filters,
		ExpiresAt: time.Now().Add(s.tokenTTL()),
	}
	token, err := s.issueToken(session)
	if err != nil {
		s.logger.Error("generate admin token failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	session.Token = token
	s.storeSession(session)

	if _, err := s.db.ExecContext(loginCtx, "UPDATE admins SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", id); err != nil {
		s.logger.Warn("update admin last login failed", zap.Error(err))
	}
	s.recordAudit(req.Username, "admin", "login", "http", "", "success", "")

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"token_type": s.tokenType(),
		"user": map[string]interface{}{
			"id":       id,
			"username": req.Username,
			"role":     "admin",
			"status":   status,
		},
	})
}

// adminInit creates the first admin when no admins exist
func (s *Server) adminInit(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count); err != nil {
		s.logger.Error("admin init count failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	if count > 0 {
		s.writeError(w, http.StatusForbidden, "System already initialized")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash admin password failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to create admin")
		return
	}

	result, err := s.db.Exec(
		"INSERT INTO admins (username, password_hash, status, permissions) VALUES (?, ?, 'active', ?)",
		strings.TrimSpace(req.Username), string(passwordHash), "[\"*\"]",
	)
	if err != nil {
		s.logger.Error("admin init insert failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create admin")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create admin")
		return
	}

	s.logger.Info("Admin initialized", zap.Int64("id", id), zap.String("username", req.Username))
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id":       id,
		"username": req.Username,
		"status":   "active",
	})
}

// userLogin handles user authentication
func (s *Server) userLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var (
		id                int64
		passwordHash      string
		status            string
		homeDir           string
		mfaEnabled        bool
		passwordChangedAt sql.NullString
	)
	queryErr := s.db.QueryRow(
		"SELECT id, password_hash, status, home_dir, mfa_enabled, COALESCE(password_changed_at, '') FROM users WHERE username = ?",
		req.Username,
	).Scan(&id, &passwordHash, &status, &homeDir, &mfaEnabled, &passwordChangedAt)
	if queryErr != nil {
		if queryErr != sql.ErrNoRows {
			s.logger.Error("user login query failed", zap.Error(queryErr))
			s.writeError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		if handled := s.tryLDAPLogin(w, r, req.Username, req.Password); handled {
			return
		}
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if err := s.ensurePolicyAllowsAuthentication(r, req.Username); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		if handled := s.tryLDAPLogin(w, r, req.Username, req.Password); handled {
			return
		}
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}
	if status != "active" {
		s.writeError(w, http.StatusUnauthorized, "Account is disabled")
		return
	}
	if mfaEnabled && strings.TrimSpace(req.MFACode) == "" {
		s.writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"message":      "MFA code required",
			"mfa_required": true,
		})
		return
	}
	if s.isPasswordExpired(passwordChangedAt) {
		changeToken, err := generateToken()
		if err != nil {
			s.logger.Error("generate password change token failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		s.passwordChangeMu.Lock()
		s.passwordChangeTokens[changeToken] = &passwordChangeToken{
			UserID:    id,
			Username:  req.Username,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		s.passwordChangeMu.Unlock()
		s.writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"message":               "Password has expired and must be changed",
			"password_expired":      true,
			"password_change_token": changeToken,
		})
		return
	}
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		s.logger.Error("ensure user home dir failed", zap.Error(err), zap.String("home_dir", homeDir))
		s.writeError(w, http.StatusInternalServerError, "User home directory is not available")
		return
	}

	sessionID, err := generateToken()
	if err != nil {
		s.logger.Error("generate session id failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	session := &authSession{
		SessionID: sessionID,
		UserID:    id,
		Username:  req.Username,
		Role:      "user",
		HomeDir:   homeDir,
		ExpiresAt: time.Now().Add(s.tokenTTL()),
	}
	token, err := s.issueToken(session)
	if err != nil {
		s.logger.Error("generate user token failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	session.Token = token
	s.storeSession(session)

	if _, err := s.db.Exec(
		"INSERT INTO sessions (session_id, user_id, protocol, client_ip, connected_at, last_activity_at, is_active) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)",
		sessionID, id, "http", s.clientIP(r),
	); err != nil {
		s.deleteSession(token)
		s.logger.Error("create http session failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if _, err := s.db.Exec("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", id); err != nil {
		s.logger.Warn("update user last login failed", zap.Error(err))
	}

	s.recordAudit(req.Username, "user", "login", "http", "", "success", "")

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"token_type": s.tokenType(),
		"user": map[string]interface{}{
			"id":       id,
			"username": req.Username,
			"role":     "user",
			"status":   status,
		},
	})
}

func (s *Server) ensurePolicyAllowsAuthentication(r *http.Request, username string) error {
	if s.policyEngine == nil {
		return nil
	}
	allowed, policyErr := s.policyEngine.CanAuthenticate(r.Context(), policy.AuthRequest{
		Username:   username,
		Protocol:   "http",
		ClientIP:   parseRemoteIP(s.clientIP(r)),
		AuthMethod: "password",
	})
	if policyErr != nil {
		return policyErr
	}
	if !allowed {
		return fmt.Errorf("protocol access denied")
	}
	return nil
}

func (s *Server) tryLDAPLogin(w http.ResponseWriter, r *http.Request, username, password string) bool {
	if s.ldapAuth == nil {
		return false
	}
	if err := s.ensurePolicyAllowsAuthentication(r, username); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return true
	}
	identity, err := s.ldapAuth.Authenticate(username, password)
	if err != nil {
		return false
	}
	user, err := s.findOrProvisionLDAPUser(r.Context(), identity)
	if err != nil {
		s.logger.Error("ldap user resolution failed", zap.Error(err), zap.String("username", username))
		s.writeError(w, http.StatusInternalServerError, "LDAP login failed")
		return true
	}
	if user.Status != "active" {
		s.writeError(w, http.StatusUnauthorized, "Account is disabled")
		return true
	}
	sessionID, err := generateToken()
	if err != nil {
		s.logger.Error("generate session id failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return true
	}
	session := &authSession{
		SessionID: sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      "user",
		HomeDir:   user.HomeDir,
		ExpiresAt: time.Now().Add(s.tokenTTL()),
	}
	token, err := s.issueToken(session)
	if err != nil {
		s.logger.Error("generate ldap token failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return true
	}
	session.Token = token
	s.storeSession(session)
	if _, err := s.db.Exec(
		"INSERT INTO sessions (session_id, user_id, protocol, client_ip, connected_at, last_activity_at, is_active) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)",
		sessionID, user.ID, "http", s.clientIP(r),
	); err != nil {
		s.deleteSession(token)
		s.logger.Error("create ldap session failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Internal server error")
		return true
	}
	s.recordAudit(user.Username, "user", "login_ldap", "http", "", "success", "")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"token_type": s.tokenType(),
		"user": map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"role":     "user",
			"status":   user.Status,
			"email":    user.Email.String,
		},
	})
	return true
}

func (s *Server) findOrProvisionLDAPUser(ctx context.Context, identity *authn.LDAPUser) (*repository.User, error) {
	if s.userRepo != nil {
		user, err := s.userRepo.GetByUsername(ctx, identity.Username)
		if err == nil {
			return user, nil
		}
	}
	if !s.config.LDAP.AutoCreateUsers {
		return nil, fmt.Errorf("ldap user %q is not provisioned locally", identity.Username)
	}

	homeDir := filepath.Join(firstNonEmptyString(s.config.LDAP.UserHomeBaseDir, "./data/ldap-users"), identity.Username)
	email := sql.NullString{}
	if strings.TrimSpace(identity.Email) != "" {
		email = sql.NullString{String: identity.Email, Valid: true}
	}

	user := &repository.User{
		Username:    identity.Username,
		Email:       email,
		Status:      "active",
		HomeDir:     homeDir,
		MaxSessions: 10,
	}
	if s.userRepo != nil {
		return s.userRepo.Create(ctx, user)
	}
	result, err := s.db.ExecContext(
		ctx,
		"INSERT INTO users (username, email, status, home_dir, max_sessions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		user.Username, user.Email, user.Status, user.HomeDir, user.MaxSessions,
	)
	if err != nil {
		return nil, err
	}
	user.ID, err = result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.oidcAuth == nil {
		s.writeError(w, http.StatusNotFound, "OIDC is not enabled")
		return
	}
	state, verifier, challenge, err := s.oidcAuth.NewStatePair()
	if err != nil {
		s.logger.Error("generate oidc state failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to initialize OIDC login")
		return
	}
	returnTo := strings.TrimSpace(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		returnTo = "/client"
	}
	roleHint := strings.TrimSpace(r.URL.Query().Get("role"))
	if roleHint == "" {
		roleHint = "user"
	}
	s.oidcStatesMu.Lock()
	s.oidcStates[state] = oidcState{
		State:     state,
		Verifier:  verifier,
		ReturnTo:  returnTo,
		RoleHint:  roleHint,
		CreatedAt: time.Now(),
	}
	s.oidcStatesMu.Unlock()

	redirectURL := s.oidcAuth.AuthCodeURL(state, challenge)
	if wantsJSON(r) {
		s.writeJSON(w, http.StatusOK, map[string]string{
			"redirect_url": redirectURL,
			"state":        state,
		})
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidcAuth == nil {
		s.writeError(w, http.StatusNotFound, "OIDC is not enabled")
		return
	}
	if errValue := strings.TrimSpace(r.URL.Query().Get("error")); errValue != "" {
		s.writeError(w, http.StatusUnauthorized, "OIDC login failed: "+errValue)
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if state == "" || code == "" {
		s.writeError(w, http.StatusBadRequest, "OIDC state and code are required")
		return
	}
	s.oidcStatesMu.Lock()
	storedState, ok := s.oidcStates[state]
	if ok {
		delete(s.oidcStates, state)
	}
	s.oidcStatesMu.Unlock()
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "OIDC state is invalid or expired")
		return
	}
	identity, err := s.oidcAuth.ExchangeCode(r.Context(), code, storedState.Verifier)
	if err != nil {
		s.logger.Error("oidc exchange failed", zap.Error(err))
		s.writeError(w, http.StatusUnauthorized, "OIDC login failed")
		return
	}
	session, returnTo, err := s.buildOIDCSession(r.Context(), identity, storedState)
	if err != nil {
		s.logger.Error("oidc session build failed", zap.Error(err))
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	token, err := s.issueToken(session)
	if err != nil {
		s.logger.Error("generate oidc token failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to issue token")
		return
	}
	session.Token = token
	s.storeSession(session)

	callbackURL, err := url.Parse(returnTo)
	if err != nil {
		callbackURL = &url.URL{Path: "/client"}
	}
	query := callbackURL.Query()
	query.Set("token", token)
	query.Set("token_type", s.tokenType())
	query.Set("username", session.Username)
	query.Set("role", session.Role)
	callbackURL.RawQuery = query.Encode()
	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

func (s *Server) buildOIDCSession(ctx context.Context, identity *authn.OIDCIdentity, state oidcState) (*authSession, string, error) {
	role := strings.ToLower(firstNonEmptyString(identity.Role, state.RoleHint, "user"))
	if role == "admin" {
		if !s.config.OIDC.AllowAdmin {
			return nil, "", fmt.Errorf("oidc admin login is disabled")
		}
		var id int64
		var status string
		if err := s.db.QueryRowContext(ctx, "SELECT id, status FROM admins WHERE username = ?", identity.Username).Scan(&id, &status); err != nil {
			if err == sql.ErrNoRows {
				return nil, "", fmt.Errorf("oidc admin account is not provisioned")
			}
			return nil, "", err
		}
		if status != "active" {
			return nil, "", fmt.Errorf("admin account is disabled")
		}
		session := &authSession{
			UserID:    id,
			Username:  identity.Username,
			Role:      "admin",
			ExpiresAt: time.Now().Add(s.tokenTTL()),
		}
		s.recordAudit(identity.Username, "admin", "login_oidc", "http", "", "success", "")
		return session, normalizeReturnTo(state.ReturnTo, "/admin"), nil
	}
	if !s.config.OIDC.AllowUser {
		return nil, "", fmt.Errorf("oidc user login is disabled")
	}
	user, err := s.findOrProvisionOIDCUser(ctx, identity)
	if err != nil {
		return nil, "", err
	}
	sessionID, err := generateToken()
	if err != nil {
		return nil, "", err
	}
	session := &authSession{
		SessionID: sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		Role:      "user",
		HomeDir:   user.HomeDir,
		ExpiresAt: time.Now().Add(s.tokenTTL()),
	}
	if _, err := s.db.ExecContext(
		ctx,
		"INSERT INTO sessions (session_id, user_id, protocol, client_ip, connected_at, last_activity_at, is_active) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)",
		sessionID, user.ID, "http", "oidc",
	); err != nil {
		return nil, "", err
	}
	s.recordAudit(user.Username, "user", "login_oidc", "http", "", "success", "")
	return session, normalizeReturnTo(state.ReturnTo, "/client"), nil
}

func (s *Server) findOrProvisionOIDCUser(ctx context.Context, identity *authn.OIDCIdentity) (*repository.User, error) {
	if s.userRepo != nil {
		user, err := s.userRepo.GetByUsername(ctx, identity.Username)
		if err == nil {
			return user, nil
		}
	}
	if !s.config.OIDC.AutoCreateUsers {
		return nil, fmt.Errorf("oidc user %q is not provisioned locally", identity.Username)
	}

	homeDir := filepath.Join(firstNonEmptyString(s.config.OIDC.UserHomeBaseDir, "./data/oidc-users"), identity.Username)
	email := sql.NullString{}
	if strings.TrimSpace(identity.Email) != "" {
		email = sql.NullString{String: identity.Email, Valid: true}
	}
	user := &repository.User{
		Username:    identity.Username,
		Email:       email,
		Status:      "active",
		HomeDir:     homeDir,
		MaxSessions: 10,
	}
	if s.userRepo != nil {
		return s.userRepo.Create(ctx, user)
	}
	result, err := s.db.ExecContext(
		ctx,
		"INSERT INTO users (username, email, status, home_dir, max_sessions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		user.Username, user.Email, user.Status, user.HomeDir, user.MaxSessions,
	)
	if err != nil {
		return nil, err
	}
	user.ID, err = result.LastInsertId()
	if err != nil {
		return nil, err
	}
	return user, nil
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

func normalizeReturnTo(returnTo, fallback string) string {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") {
		return fallback
	}
	return returnTo
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstNonEmptyRole(values ...string) string {
	return firstNonEmptyString(values...)
}

func nullableInt(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}

func nullableInt64Value(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func decodeJSONRaw(raw string, fallback any) any {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	switch fallback.(type) {
	case []any:
		var out []any
		if err := json.Unmarshal([]byte(raw), &out); err == nil {
			return out
		}
	case map[string]any:
		var out map[string]any
		if err := json.Unmarshal([]byte(raw), &out); err == nil {
			return out
		}
	}
	return fallback
}

func decodeJSONStringList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var direct []string
	if err := json.Unmarshal([]byte(raw), &direct); err == nil {
		return uniqueStrings(direct)
	}

	var generic []any
	if err := json.Unmarshal([]byte(raw), &generic); err == nil {
		out := make([]string, 0, len(generic))
		for _, item := range generic {
			value := strings.TrimSpace(fmt.Sprint(item))
			if value != "" && value != "<nil>" {
				out = append(out, value)
			}
		}
		return uniqueStrings(out)
	}

	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func decodeJSONObject(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func mergeScopeMaps(base, overlay map[string]any) map[string]any {
	if len(base) == 0 && len(overlay) == 0 {
		return map[string]any{}
	}
	merged := make(map[string]any, len(base)+len(overlay))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range overlay {
		if existingMap, ok := merged[key].(map[string]any); ok {
			if overlayMap, ok := value.(map[string]any); ok {
				merged[key] = mergeScopeMaps(existingMap, overlayMap)
				continue
			}
		}
		existingList := decodeStringSlice(merged[key])
		incomingList := decodeStringSlice(value)
		if len(existingList) > 0 || len(incomingList) > 0 {
			merged[key] = uniqueStrings(append(existingList, incomingList...))
			continue
		}
		merged[key] = value
	}
	return merged
}

func decodeStringSlice(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case []string:
		return uniqueStrings(typed)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			normalized := strings.TrimSpace(fmt.Sprint(item))
			if normalized != "" && normalized != "<nil>" {
				out = append(out, normalized)
			}
		}
		return uniqueStrings(out)
	default:
		return nil
	}
}

func uniqueInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	out := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func decodeInt64Slice(value any) []int64 {
	switch typed := value.(type) {
	case nil:
		return nil
	case []int64:
		return uniqueInt64s(typed)
	case []int:
		out := make([]int64, 0, len(typed))
		for _, item := range typed {
			out = append(out, int64(item))
		}
		return uniqueInt64s(out)
	case []float64:
		out := make([]int64, 0, len(typed))
		for _, item := range typed {
			out = append(out, int64(item))
		}
		return uniqueInt64s(out)
	case []any:
		out := make([]int64, 0, len(typed))
		for _, item := range typed {
			switch value := item.(type) {
			case int:
				out = append(out, int64(value))
			case int64:
				out = append(out, value)
			case float64:
				out = append(out, int64(value))
			case string:
				parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
				if err == nil {
					out = append(out, parsed)
				}
			}
		}
		return uniqueInt64s(out)
	default:
		return nil
	}
}

func containsAnyInt64(haystack, needles []int64) bool {
	if len(haystack) == 0 || len(needles) == 0 {
		return false
	}
	set := make(map[int64]struct{}, len(haystack))
	for _, item := range haystack {
		set[item] = struct{}{}
	}
	for _, item := range needles {
		if _, ok := set[item]; ok {
			return true
		}
	}
	return false
}

func scopeSection(scope map[string]any, key string) map[string]any {
	if len(scope) == 0 {
		return nil
	}
	if value, ok := scope[key]; ok {
		if nested, ok := value.(map[string]any); ok {
			return nested
		}
	}
	return nil
}

func usernameScopeConfig(scope map[string]any, section string) ([]string, []string, bool) {
	if len(scope) == 0 {
		return nil, nil, false
	}
	globalExact := decodeStringSlice(scope["usernames"])
	globalPrefixes := decodeStringSlice(scope["username_prefixes"])
	sectionMap := scopeSection(scope, section)
	sectionExact := decodeStringSlice(sectionMap["usernames"])
	sectionPrefixes := decodeStringSlice(sectionMap["username_prefixes"])
	exact := uniqueStrings(append(globalExact, sectionExact...))
	prefixes := uniqueStrings(append(globalPrefixes, sectionPrefixes...))
	return exact, prefixes, len(exact) > 0 || len(prefixes) > 0
}

func scopeGroupIDs(scope map[string]any, section string) []int64 {
	if len(scope) == 0 {
		return nil
	}
	global := decodeInt64Slice(scope["group_ids"])
	sectionMap := scopeSection(scope, section)
	if len(sectionMap) == 0 {
		return uniqueInt64s(global)
	}
	return uniqueInt64s(append(global, decodeInt64Slice(sectionMap["group_ids"])...))
}

func matchesScopedUsername(scope map[string]any, section, username string) bool {
	exact, prefixes, restricted := usernameScopeConfig(scope, section)
	if !restricted {
		return true
	}
	username = strings.ToLower(strings.TrimSpace(username))
	for _, item := range exact {
		if username == item {
			return true
		}
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(username, prefix) {
			return true
		}
	}
	return false
}

func matchesScopedUser(scope map[string]any, section, username string, groupIDs []int64) bool {
	if matchesScopedUsername(scope, section, username) {
		allowedGroupIDs := scopeGroupIDs(scope, section)
		if len(allowedGroupIDs) == 0 {
			return true
		}
		return containsAnyInt64(groupIDs, allowedGroupIDs)
	}
	allowedGroupIDs := scopeGroupIDs(scope, section)
	if len(allowedGroupIDs) > 0 && containsAnyInt64(groupIDs, allowedGroupIDs) {
		return true
	}
	_, _, usernameRestricted := usernameScopeConfig(scope, section)
	return !usernameRestricted && len(allowedGroupIDs) == 0
}

func (s *Server) isAdminRestrictedToUser(session *authSession, section, username string, groupIDs []int64) bool {
	if session == nil || session.Role != "admin" {
		return false
	}
	return !matchesScopedUser(session.Filters, section, username, groupIDs)
}

func (s *Server) isAdminRestrictedToUsername(session *authSession, section, username string) bool {
	return s.isAdminRestrictedToUser(session, section, username, nil)
}

func loadIDList(rows *sql.Rows) ([]int64, error) {
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return uniqueInt64s(ids), nil
}

func (s *Server) loadUserGroupIDs(userID int64) ([]int64, error) {
	rows, err := s.db.Query("SELECT group_id FROM user_groups WHERE user_id = ? ORDER BY group_id ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return loadIDList(rows)
}

func (s *Server) loadUserRoleIDs(userID int64) ([]int64, error) {
	rows, err := s.db.Query("SELECT role_id FROM user_roles WHERE user_id = ? ORDER BY role_id ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return loadIDList(rows)
}

func replaceRelationIDs(tx *sql.Tx, deleteQuery, insertQuery string, parentID int64, relatedIDs []int64) error {
	if _, err := tx.Exec(deleteQuery, parentID); err != nil {
		return err
	}
	for _, relatedID := range uniqueInt64s(relatedIDs) {
		if _, err := tx.Exec(insertQuery, parentID, relatedID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) replaceUserRelations(userID int64, groupIDs, roleIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = replaceRelationIDs(tx, "DELETE FROM user_groups WHERE user_id = ?", "INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", userID, groupIDs); err != nil {
		return err
	}
	if err = replaceRelationIDs(tx, "DELETE FROM user_roles WHERE user_id = ?", "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", userID, roleIDs); err != nil {
		return err
	}
	return tx.Commit()
}

func int64IDsToAny(values []int64) []any {
	out := make([]any, 0, len(values))
	for _, value := range uniqueInt64s(values) {
		out = append(out, value)
	}
	return out
}

func hasAnyPermission(granted []string, required ...string) bool {
	if len(granted) == 0 {
		return false
	}
	grantedSet := make(map[string]struct{}, len(granted))
	for _, permission := range granted {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if normalized == "" {
			continue
		}
		grantedSet[normalized] = struct{}{}
	}
	if _, ok := grantedSet["*"]; ok {
		return true
	}
	if _, ok := grantedSet["admin:*"]; ok {
		return true
	}
	for _, permission := range required {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if normalized == "" {
			continue
		}
		if _, ok := grantedSet[normalized]; ok {
			return true
		}
		if namespace, _, ok := strings.Cut(normalized, ":"); ok {
			if _, ok := grantedSet[namespace+":*"]; ok {
				return true
			}
		}
	}
	return false
}

func permissionPayload(value []string) []any {
	if len(value) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(value))
	for _, item := range uniqueStrings(value) {
		out = append(out, item)
	}
	return out
}

func normalizePermissionValues(values []any) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(fmt.Sprint(value))
		if normalized != "" && normalized != "<nil>" {
			out = append(out, normalized)
		}
	}
	return uniqueStrings(out)
}

func formatDBTime(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) getUsers(w http.ResponseWriter, r *http.Request) {
	admin := s.currentSession(r)
	rows, err := s.db.Query("SELECT id, username, COALESCE(email, ''), home_dir, status, COALESCE(last_login_at, ''), created_at FROM users ORDER BY id ASC")
	if err != nil {
		s.logger.Error("list users failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load users")
		return
	}
	defer rows.Close()

	users := make([]map[string]interface{}, 0)
	for rows.Next() {
		var (
			id        int64
			username  string
			email     string
			homeDir   string
			status    string
			lastLogin string
			createdAt string
		)
		if err := rows.Scan(&id, &username, &email, &homeDir, &status, &lastLogin, &createdAt); err != nil {
			s.logger.Error("scan user failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load users")
			return
		}
		groupIDs, err := s.loadUserGroupIDs(id)
		if err != nil {
			s.logger.Error("load user groups failed", zap.Error(err), zap.Int64("user_id", id))
			s.writeError(w, http.StatusInternalServerError, "Failed to load users")
			return
		}
		roleIDs, err := s.loadUserRoleIDs(id)
		if err != nil {
			s.logger.Error("load user roles failed", zap.Error(err), zap.Int64("user_id", id))
			s.writeError(w, http.StatusInternalServerError, "Failed to load users")
			return
		}
		if s.isAdminRestrictedToUser(admin, "users", username, groupIDs) {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":             id,
			"username":       username,
			"email":          email,
			"home_directory": homeDir,
			"group_ids":      int64IDsToAny(groupIDs),
			"role_ids":       int64IDsToAny(roleIDs),
			"status":         status,
			"created_at":     formatDBTime(createdAt),
			"last_login":     formatDBTime(lastLogin),
		})
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("iterate users failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load users")
		return
	}

	s.writeJSON(w, http.StatusOK, users)
}

func (s *Server) getAdmins(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, username, status, COALESCE(last_login_at, ''), created_at, role_id, COALESCE(permissions, '[]') FROM admins ORDER BY id ASC")
	if err != nil {
		s.logger.Error("list admins failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load admins")
		return
	}
	defer rows.Close()

	admins := make([]map[string]any, 0)
	for rows.Next() {
		var (
			id        int64
			username  string
			status    string
			lastLogin string
			createdAt string
			roleID    sql.NullInt64
			permsRaw  string
		)
		if err := rows.Scan(&id, &username, &status, &lastLogin, &createdAt, &roleID, &permsRaw); err != nil {
			s.logger.Error("scan admin failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load admins")
			return
		}
		admins = append(admins, map[string]any{
			"id":          id,
			"username":    username,
			"status":      status,
			"last_login":  formatDBTime(lastLogin),
			"created_at":  formatDBTime(createdAt),
			"permissions": permissionPayload(decodeJSONStringList(permsRaw)),
			"role_id":     nullableInt(roleID),
		})
	}
	s.writeJSON(w, http.StatusOK, admins)
}

func (s *Server) createAdmin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		Status      string `json:"status"`
		Permissions []any  `json:"permissions"`
		RoleID      *int64 `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}
	status := firstNonEmptyString(req.Status, "active")
	normalizedPermissions := normalizePermissionValues(req.Permissions)
	permissionsJSON, _ := json.Marshal(permissionPayload(normalizedPermissions))
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash admin password failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to create admin")
		return
	}
	result, err := s.db.Exec(
		"INSERT INTO admins (username, password_hash, status, permissions, role_id) VALUES (?, ?, ?, ?, ?)",
		strings.TrimSpace(req.Username), string(passwordHash), status, string(permissionsJSON), nullableInt64Value(req.RoleID),
	)
	if err != nil {
		s.logger.Error("create admin failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create admin")
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to create admin")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "create_admin", "http", req.Username, "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id":          id,
		"username":    req.Username,
		"status":      status,
		"permissions": permissionPayload(normalizedPermissions),
		"role_id":     req.RoleID,
	})
}

func (s *Server) updateAdmin(w http.ResponseWriter, r *http.Request) {
	adminID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || adminID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid admin id")
		return
	}
	var req struct {
		Password    string `json:"password"`
		Status      string `json:"status"`
		Permissions []any  `json:"permissions"`
		RoleID      *int64 `json:"role_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	status := firstNonEmptyString(req.Status, "active")
	normalizedPermissions := normalizePermissionValues(req.Permissions)
	permissionsJSON, _ := json.Marshal(permissionPayload(normalizedPermissions))
	if strings.TrimSpace(req.Password) != "" {
		passwordHash, hashErr := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if hashErr != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to update admin")
			return
		}
		if _, err := s.db.Exec("UPDATE admins SET password_hash = ?, status = ?, permissions = ?, role_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", string(passwordHash), status, string(permissionsJSON), nullableInt64Value(req.RoleID), adminID); err != nil {
			s.logger.Error("update admin failed", zap.Error(err))
			s.writeError(w, http.StatusBadRequest, "Failed to update admin")
			return
		}
	} else {
		if _, err := s.db.Exec("UPDATE admins SET status = ?, permissions = ?, role_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", status, string(permissionsJSON), nullableInt64Value(req.RoleID), adminID); err != nil {
			s.logger.Error("update admin failed", zap.Error(err))
			s.writeError(w, http.StatusBadRequest, "Failed to update admin")
			return
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "admin updated"})
}

func (s *Server) deleteAdmin(w http.ResponseWriter, r *http.Request) {
	adminID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || adminID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid admin id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM admins WHERE id = ?", adminID); err != nil {
		s.logger.Error("delete admin failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to delete admin")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "admin deleted"})
}

func (s *Server) getGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, name, COALESCE(description, ''), created_at, updated_at FROM groups ORDER BY id ASC")
	if err != nil {
		s.logger.Error("list groups failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load groups")
		return
	}
	defer rows.Close()
	groups := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var name, description, createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &description, &createdAt, &updatedAt); err != nil {
			s.logger.Error("scan group failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load groups")
			return
		}
		groups = append(groups, map[string]any{
			"id":          id,
			"name":        name,
			"description": description,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		})
	}
	s.writeJSON(w, http.StatusOK, groups)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "Group name is required")
		return
	}
	result, err := s.db.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", strings.TrimSpace(req.Name), strings.TrimSpace(req.Description))
	if err != nil {
		s.logger.Error("create group failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create group")
		return
	}
	id, _ := result.LastInsertId()
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": strings.TrimSpace(req.Name), "description": strings.TrimSpace(req.Description)})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || groupID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid group id")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if _, err := s.db.Exec("UPDATE groups SET name = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), groupID); err != nil {
		s.logger.Error("update group failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to update group")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "group updated"})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || groupID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid group id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM groups WHERE id = ?", groupID); err != nil {
		s.logger.Error("delete group failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to delete group")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "group deleted"})
}

func (s *Server) getRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, name, COALESCE(description, ''), COALESCE(permissions, '[]'), COALESCE(scope, '{}'), created_at FROM roles ORDER BY id ASC")
	if err != nil {
		s.logger.Error("list roles failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load roles")
		return
	}
	defer rows.Close()
	roles := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var name, description, permissions, scope, createdAt string
		if err := rows.Scan(&id, &name, &description, &permissions, &scope, &createdAt); err != nil {
			s.logger.Error("scan role failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load roles")
			return
		}
		roles = append(roles, map[string]any{
			"id":          id,
			"name":        name,
			"description": description,
			"permissions": decodeJSONRaw(permissions, []any{}),
			"scope":       decodeJSONRaw(scope, map[string]any{}),
			"created_at":  createdAt,
		})
	}
	s.writeJSON(w, http.StatusOK, roles)
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []any  `json:"permissions"`
		Scope       any    `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "Role name is required")
		return
	}
	permissionsJSON, _ := json.Marshal(req.Permissions)
	scopeJSON, _ := json.Marshal(req.Scope)
	result, err := s.db.Exec("INSERT INTO roles (name, description, permissions, scope) VALUES (?, ?, ?, ?)", strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), string(permissionsJSON), string(scopeJSON))
	if err != nil {
		s.logger.Error("create role failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create role")
		return
	}
	id, _ := result.LastInsertId()
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": strings.TrimSpace(req.Name), "description": strings.TrimSpace(req.Description), "permissions": req.Permissions, "scope": req.Scope})
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || roleID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid role id")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []any  `json:"permissions"`
		Scope       any    `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	permissionsJSON, _ := json.Marshal(req.Permissions)
	scopeJSON, _ := json.Marshal(req.Scope)
	if _, err := s.db.Exec("UPDATE roles SET name = ?, description = ?, permissions = ?, scope = ? WHERE id = ?", strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), string(permissionsJSON), string(scopeJSON), roleID); err != nil {
		s.logger.Error("update role failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to update role")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "role updated"})
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || roleID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid role id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM roles WHERE id = ?", roleID); err != nil {
		s.logger.Error("delete role failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to delete role")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "role deleted"})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username      string `json:"username"`
		Email         string `json:"email"`
		HomeDirectory string `json:"home_directory"`
		GroupIDs      []any  `json:"group_ids"`
		RoleIDs       []any  `json:"role_ids"`
		Status        string `json:"status"`
		Password      string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		s.writeError(w, http.StatusBadRequest, "Username and password are required")
		return
	}
	if s.passwordPolicy != nil {
		if err := s.passwordPolicy.ValidatePassword(req.Password, strings.TrimSpace(req.Username)); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	admin := s.currentSession(r)
	groupIDs := decodeInt64Slice(req.GroupIDs)
	if s.isAdminRestrictedToUser(admin, "users", req.Username, groupIDs) {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	homeDir, err := s.normalizeHomeDir(req.Username, req.HomeDirectory)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		s.logger.Error("create user home dir failed", zap.Error(err), zap.String("home_dir", homeDir))
		s.writeError(w, http.StatusInternalServerError, "Failed to create user home directory")
		return
	}

	status := req.Status
	if status == "" {
		status = "active"
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash user password failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	email := strings.TrimSpace(req.Email)
	result, err := s.db.Exec(
		"INSERT INTO users (username, email, status, password_hash, home_dir, max_sessions) VALUES (?, ?, ?, ?, ?, ?)",
		req.Username, email, status, string(passwordHash), homeDir, 10,
	)
	if err != nil {
		s.logger.Error("create user failed", zap.Error(err))
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			s.writeError(w, http.StatusConflict, "Username already exists")
		} else {
			s.writeError(w, http.StatusInternalServerError, "Failed to create user")
		}
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		s.logger.Error("read created user id failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}
	roleIDs := decodeInt64Slice(req.RoleIDs)
	if err := s.replaceUserRelations(id, groupIDs, roleIDs); err != nil {
		s.logger.Error("replace user relations failed", zap.Error(err), zap.Int64("user_id", id))
		s.writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	s.recordAudit(admin.Username, "admin", "create_user", "http", req.Username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":             id,
		"username":       req.Username,
		"email":          email,
		"home_directory": homeDir,
		"group_ids":      int64IDsToAny(groupIDs),
		"role_ids":       int64IDsToAny(roleIDs),
		"status":         status,
		"created_at":     time.Now().UTC().Format(time.RFC3339),
		"last_login":     "",
	})
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}

	var req struct {
		Email         string `json:"email"`
		HomeDirectory string `json:"home_directory"`
		GroupIDs      []any  `json:"group_ids"`
		RoleIDs       []any  `json:"role_ids"`
		Status        string `json:"status"`
		Password      string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var (
		username     string
		email        string
		currentHome  string
		currentState string
		passwordHash string
		createdAt    string
		lastLoginAt  string
	)
	if err := s.db.QueryRow(
		"SELECT username, COALESCE(email, ''), home_dir, status, password_hash, created_at, COALESCE(last_login_at, '') FROM users WHERE id = ?",
		id,
	).Scan(&username, &email, &currentHome, &currentState, &passwordHash, &createdAt, &lastLoginAt); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.logger.Error("load user failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}
	admin := s.currentSession(r)
	currentGroupIDs, err := s.loadUserGroupIDs(id)
	if err != nil {
		s.logger.Error("load current user groups failed", zap.Error(err), zap.Int64("user_id", id))
		s.writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}
	currentRoleIDs, err := s.loadUserRoleIDs(id)
	if err != nil {
		s.logger.Error("load current user roles failed", zap.Error(err), zap.Int64("user_id", id))
		s.writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}
	if s.isAdminRestrictedToUser(admin, "users", username, currentGroupIDs) {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	homeDir := currentHome
	if strings.TrimSpace(req.HomeDirectory) != "" {
		homeDir, err = s.normalizeHomeDir(username, req.HomeDirectory)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := os.MkdirAll(homeDir, 0o755); err != nil {
			s.logger.Error("ensure updated user home dir failed", zap.Error(err), zap.String("home_dir", homeDir))
			s.writeError(w, http.StatusInternalServerError, "Failed to update user")
			return
		}
	}

	status := currentState
	if strings.TrimSpace(req.Status) != "" {
		status = req.Status
	}
	if strings.TrimSpace(req.Email) != "" {
		email = strings.TrimSpace(req.Email)
	}

	if strings.TrimSpace(req.Password) != "" {
		if s.passwordPolicy != nil {
			if err := s.passwordPolicy.ValidatePassword(req.Password, username); err != nil {
				s.writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Error("hash updated password failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to update user")
			return
		}
		passwordHash = string(hashed)
	}
	groupIDs := currentGroupIDs
	if req.GroupIDs != nil {
		groupIDs = decodeInt64Slice(req.GroupIDs)
	}
	roleIDs := currentRoleIDs
	if req.RoleIDs != nil {
		roleIDs = decodeInt64Slice(req.RoleIDs)
	}
	if s.isAdminRestrictedToUser(admin, "users", username, groupIDs) {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	if _, err := s.db.Exec(
		"UPDATE users SET email = ?, status = ?, password_hash = ?, home_dir = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		email, status, passwordHash, homeDir, id,
	); err != nil {
		s.logger.Error("update user failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}
	if err := s.replaceUserRelations(id, groupIDs, roleIDs); err != nil {
		s.logger.Error("replace updated user relations failed", zap.Error(err), zap.Int64("user_id", id))
		s.writeError(w, http.StatusInternalServerError, "Failed to update user")
		return
	}

	s.recordAudit(admin.Username, "admin", "update_user", "http", username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":             id,
		"username":       username,
		"email":          email,
		"home_directory": homeDir,
		"group_ids":      int64IDsToAny(groupIDs),
		"role_ids":       int64IDsToAny(roleIDs),
		"status":         status,
		"created_at":     formatDBTime(createdAt),
		"last_login":     formatDBTime(lastLoginAt),
	})
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}

	var username string
	if err := s.db.QueryRow("SELECT username FROM users WHERE id = ?", id).Scan(&username); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.logger.Error("load user before delete failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	admin := s.currentSession(r)
	groupIDs, err := s.loadUserGroupIDs(id)
	if err != nil {
		s.logger.Error("load user groups before delete failed", zap.Error(err), zap.Int64("user_id", id))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	if s.isAdminRestrictedToUser(admin, "users", username, groupIDs) {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	rows, err := s.db.Query("SELECT session_id FROM sessions WHERE user_id = ? AND is_active = TRUE", id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sessionID string
			if scanErr := rows.Scan(&sessionID); scanErr == nil {
				s.invalidateSessionByID(sessionID)
			}
		}
	}

	if _, err := s.db.Exec("DELETE FROM users WHERE id = ?", id); err != nil {
		s.logger.Error("delete user failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	s.recordAudit(admin.Username, "admin", "delete_user", "http", username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) getConnections(w http.ResponseWriter, r *http.Request) {
	admin := s.currentSession(r)

	var rows *sql.Rows
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		rows, err = s.db.QueryContext(r.Context(), `
			SELECT s.session_id, u.username, s.protocol, COALESCE(s.client_ip, ''), s.connected_at
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			WHERE s.is_active = TRUE
			ORDER BY s.connected_at DESC
		`)
		if err == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
		}
	}
	if err != nil {
		s.logger.Error("list connections failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load connections")
		return
	}
	defer rows.Close()

	connections := make([]map[string]interface{}, 0)
	for rows.Next() {
		var (
			id          string
			username    string
			protocol    string
			remoteAddr  string
			connectedAt string
		)
		if err := rows.Scan(&id, &username, &protocol, &remoteAddr, &connectedAt); err != nil {
			s.logger.Error("scan connection failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load connections")
			return
		}
		if s.isAdminRestrictedToUsername(admin, "connections", username) {
			continue
		}
		connections = append(connections, map[string]interface{}{
			"id":           id,
			"username":     username,
			"protocol":     protocol,
			"remote_addr":  remoteAddr,
			"connected_at": connectedAt,
			"bytes_sent":   0,
			"bytes_recv":   0,
		})
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("iterate connections failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load connections")
		return
	}

	s.writeJSON(w, http.StatusOK, connections)
}

func (s *Server) disconnectConnection(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid connection id")
		return
	}

	var targetUsername string
	if err := s.db.QueryRow(
		`SELECT COALESCE(u.username, '')
		FROM sessions s
		LEFT JOIN users u ON u.id = s.user_id
		WHERE s.session_id = ? LIMIT 1`,
		sessionID,
	).Scan(&targetUsername); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Connection not found")
			return
		}
		s.logger.Error("load connection target failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to disconnect connection")
		return
	}
	admin := s.currentSession(r)
	if s.isAdminRestrictedToUsername(admin, "connections", targetUsername) {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	result, err := s.db.Exec("UPDATE sessions SET is_active = FALSE WHERE session_id = ?", sessionID)
	if err != nil {
		s.logger.Error("disconnect connection failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to disconnect connection")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		s.writeError(w, http.StatusNotFound, "Connection not found")
		return
	}

	s.invalidateSessionByID(sessionID)
	s.recordAudit(admin.Username, "admin", "disconnect", "http", sessionID, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	virtualPath, storagePath, err := s.resolveVirtualPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpList, virtualPath, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	entries, err := fs.ListDir(r.Context(), storagePath)
	if err != nil {
		s.logger.Error("list files failed", zap.Error(err), zap.String("path", virtualPath))
		s.writeError(w, http.StatusBadRequest, "Failed to list files")
		return
	}

	items := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		items = append(items, map[string]interface{}{
			"name":     entry.Name,
			"size":     entry.Size,
			"mod_time": entry.ModTime.Format(time.RFC3339),
			"is_dir":   entry.IsDir,
			"mode":     entry.Mode.String(),
			"path":     joinVirtualPath(virtualPath, entry.Name),
		})
	}

	s.writeJSON(w, http.StatusOK, items)
}

func (s *Server) downloadFile(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	virtualPath, storagePath, err := s.resolveVirtualPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpDownload, virtualPath, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if s.hookManager != nil {
		if hookErr := s.hookManager.OnFileEvent(r.Context(), hooks.FileEventPreDownload, &hooks.FileEventPayload{
			Event:     hooks.FileEventPreDownload,
			FilePath:  virtualPath,
			FileName:  pathpkg.Base(virtualPath),
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		}); hookErr != nil {
			s.writeError(w, http.StatusForbidden, hookErr.Error())
			return
		}
	}

	info, err := fs.Stat(r.Context(), storagePath)
	if err != nil || info.IsDir {
		s.writeError(w, http.StatusNotFound, "File not found")
		return
	}
	reader, err := fs.Open(r.Context(), storagePath)
	if err != nil {
		s.logger.Error("open download file failed", zap.Error(err), zap.String("path", virtualPath))
		s.writeError(w, http.StatusInternalServerError, "Failed to download file")
		return
	}
	defer reader.Close()

	s.recordAudit(session.Username, "user", "download", "http", virtualPath, "success", "")

	if s.hookManager != nil {
		go s.hookManager.OnFileEvent(context.Background(), hooks.FileEventDownload, &hooks.FileEventPayload{
			Event:     hooks.FileEventDownload,
			FilePath:  virtualPath,
			FileName:  pathpkg.Base(virtualPath),
			FileSize:  info.Size,
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		})
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", pathpkg.Base(virtualPath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if info.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	}
	if _, err := io.Copy(w, reader); err != nil {
		s.logger.Warn("stream download file failed", zap.Error(err), zap.String("path", virtualPath))
	}
}

type downloadZipRequest struct {
	Paths []string `json:"paths"`
}

func (s *Server) downloadZip(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	var req downloadZipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Paths) == 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid request: paths array is required")
		return
	}

	for _, p := range req.Paths {
		virtualPath, _, err := s.resolveVirtualPath(p)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpDownload, virtualPath, 0); err != nil {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	zipName := fmt.Sprintf("download_%s.zip", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", zipName))
	w.Header().Set("Content-Type", "application/zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	var totalSize int64
	for _, p := range req.Paths {
		virtualPath, storagePath, err := s.resolveVirtualPath(p)
		if err != nil {
			continue
		}
		info, err := fs.Stat(r.Context(), storagePath)
		if err != nil {
			continue
		}
		if info.IsDir {
			if err := s.addDirToZip(r.Context(), fs, zw, virtualPath, storagePath, pathpkg.Base(virtualPath)); err != nil {
				s.logger.Warn("add dir to zip failed", zap.Error(err), zap.String("path", virtualPath))
			}
		} else {
			if err := s.addFileToZip(r.Context(), fs, zw, virtualPath, storagePath, info); err != nil {
				s.logger.Warn("add file to zip failed", zap.Error(err), zap.String("path", virtualPath))
			}
			totalSize += info.Size
		}
	}

	for _, p := range req.Paths {
		virtualPath, _, _ := s.resolveVirtualPath(p)
		s.recordAudit(session.Username, "user", "download_zip", "http", virtualPath, "success", "")
		if s.hookManager != nil {
			go s.hookManager.OnFileEvent(context.Background(), hooks.FileEventDownload, &hooks.FileEventPayload{
				Event:     hooks.FileEventDownload,
				FilePath:  virtualPath,
				FileName:  pathpkg.Base(virtualPath),
				FileSize:  totalSize,
				Username:  session.Username,
				UserID:    session.UserID,
				Protocol:  "http",
				ClientIP:  r.RemoteAddr,
				Timestamp: time.Now(),
			})
		}
	}
}

func (s *Server) addFileToZip(ctx context.Context, fs storage.FileSystem, zw *zip.Writer, virtualPath, storagePath string, info *storage.FileInfo) error {
	reader, err := fs.Open(ctx, storagePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", virtualPath, err)
	}
	defer reader.Close()

	fh := &zip.FileHeader{
		Name:               pathpkg.Base(virtualPath),
		UncompressedSize64: uint64(info.Size),
		Modified:           info.ModTime,
		Method:             zip.Deflate,
	}
	writer, err := zw.CreateHeader(fh)
	if err != nil {
		return fmt.Errorf("failed to create zip entry for %s: %w", virtualPath, err)
	}

	if _, err := io.Copy(writer, reader); err != nil {
		return fmt.Errorf("failed to write file %s to zip: %w", virtualPath, err)
	}
	return nil
}

func (s *Server) addDirToZip(ctx context.Context, fs storage.FileSystem, zw *zip.Writer, virtualPath, storagePath, prefix string) error {
	_, err := zw.Create(prefix + "/")
	if err != nil {
		return fmt.Errorf("failed to create zip dir entry for %s: %w", prefix, err)
	}

	entries, err := fs.ListDir(ctx, storagePath)
	if err != nil {
		return fmt.Errorf("failed to list directory %s: %w", virtualPath, err)
	}

	for _, entry := range entries {
		entryVirtualPath := virtualPath + "/" + entry.Name
		entryStoragePath := storagePath + "/" + entry.Name
		entryPrefix := prefix + "/" + entry.Name

		if entry.IsDir {
			if err := s.addDirToZip(ctx, fs, zw, entryVirtualPath, entryStoragePath, entryPrefix); err != nil {
				s.logger.Warn("add subdir to zip failed", zap.Error(err), zap.String("path", entryVirtualPath))
			}
		} else {
			if err := s.addFileToZip(ctx, fs, zw, entryVirtualPath, entryStoragePath, entry); err != nil {
				s.logger.Warn("add file to zip failed", zap.Error(err), zap.String("path", entryVirtualPath))
			}
		}
	}
	return nil
}

func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	virtualPath, storagePath, err := s.resolveVirtualPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid upload request")
		return
	}

	src, header, err := r.FormFile("file")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "File is required")
		return
	}
	defer src.Close()

	targetVirtual := joinVirtualPath(virtualPath, pathpkg.Base(header.Filename))
	targetStoragePath := storageChildPath(storagePath, pathpkg.Base(header.Filename))
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpUpload, targetVirtual, header.Size); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if s.hookManager != nil {
		if hookErr := s.hookManager.OnFileEvent(r.Context(), hooks.FileEventPreUpload, &hooks.FileEventPayload{
			Event:     hooks.FileEventPreUpload,
			FilePath:  targetVirtual,
			FileName:  pathpkg.Base(targetVirtual),
			FileSize:  header.Size,
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		}); hookErr != nil {
			s.writeError(w, http.StatusForbidden, hookErr.Error())
			return
		}
	}

	parentStoragePath := pathpkg.Dir(targetStoragePath)
	if parentStoragePath == "." {
		parentStoragePath = ""
	}
	if parentStoragePath != "" {
		if err := fs.Mkdir(r.Context(), parentStoragePath); err != nil {
			s.logger.Error("create upload dir failed", zap.Error(err), zap.String("path", targetVirtual))
			s.writeError(w, http.StatusInternalServerError, "Failed to upload file")
			return
		}
	}

	dst, err := fs.Create(r.Context(), targetStoragePath)
	if err != nil {
		s.logger.Error("create uploaded file failed", zap.Error(err), zap.String("path", targetVirtual))
		s.writeError(w, http.StatusInternalServerError, "Failed to upload file")
		return
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		s.logger.Error("write uploaded file failed", zap.Error(err), zap.String("path", targetVirtual))
		s.writeError(w, http.StatusInternalServerError, "Failed to upload file")
		return
	}
	if err := dst.Close(); err != nil {
		s.logger.Error("finalize uploaded file failed", zap.Error(err), zap.String("path", targetVirtual))
		s.writeError(w, http.StatusInternalServerError, "Failed to upload file")
		return
	}

	s.recordAudit(session.Username, "user", "upload", "http", targetVirtual, "success", "")

	if s.hookManager != nil {
		go s.hookManager.OnFileEvent(context.Background(), hooks.FileEventUpload, &hooks.FileEventPayload{
			Event:     hooks.FileEventUpload,
			FilePath:  targetVirtual,
			FileName:  pathpkg.Base(targetVirtual),
			FileSize:  header.Size,
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	virtualPath, storagePath, err := s.resolveVirtualPath(r.URL.Query().Get("path"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if virtualPath == "/" {
		s.writeError(w, http.StatusBadRequest, "Root directory cannot be deleted")
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpDelete, virtualPath, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if _, err := fs.Stat(r.Context(), storagePath); err != nil {
		s.writeError(w, http.StatusNotFound, "Path not found")
		return
	}

	if s.hookManager != nil {
		if hookErr := s.hookManager.OnFileEvent(r.Context(), hooks.FileEventPreDelete, &hooks.FileEventPayload{
			Event:     hooks.FileEventPreDelete,
			FilePath:  virtualPath,
			FileName:  pathpkg.Base(virtualPath),
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		}); hookErr != nil {
			s.writeError(w, http.StatusForbidden, hookErr.Error())
			return
		}
	}

	if err := removeAllFromFS(r.Context(), fs, storagePath); err != nil {
		s.logger.Error("delete file failed", zap.Error(err), zap.String("path", virtualPath))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete file")
		return
	}

	s.recordAudit(session.Username, "user", "delete", "http", virtualPath, "success", "")

	if s.hookManager != nil {
		go s.hookManager.OnFileEvent(context.Background(), hooks.FileEventDelete, &hooks.FileEventPayload{
			Event:     hooks.FileEventDelete,
			FilePath:  virtualPath,
			FileName:  pathpkg.Base(virtualPath),
			Username:  session.Username,
			UserID:    session.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) renameFile(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	var req struct {
		OldPath string `json:"old_path"`
		NewPath string `json:"new_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	oldVirtual, oldStoragePath, err := s.resolveVirtualPath(req.OldPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	newVirtual, newStoragePath, err := s.resolveVirtualPath(req.NewPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if oldVirtual == "/" {
		s.writeError(w, http.StatusBadRequest, "Root directory cannot be renamed")
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpRename, oldVirtual, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpRename, newVirtual, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	parentStoragePath := pathpkg.Dir(newStoragePath)
	if parentStoragePath == "." {
		parentStoragePath = ""
	}
	if parentStoragePath != "" {
		if err := fs.Mkdir(r.Context(), parentStoragePath); err != nil {
			s.logger.Error("prepare rename target failed", zap.Error(err), zap.String("path", newVirtual))
			s.writeError(w, http.StatusInternalServerError, "Failed to rename file")
			return
		}
	}
	if err := fs.Rename(r.Context(), oldStoragePath, newStoragePath); err != nil {
		s.logger.Error("rename file failed", zap.Error(err), zap.String("old", oldVirtual), zap.String("new", newVirtual))
		s.writeError(w, http.StatusInternalServerError, "Failed to rename file")
		return
	}

	s.recordAudit(session.Username, "user", "rename", "http", oldVirtual+" -> "+newVirtual, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, fs, cleanup, err := s.fileAccessContext(r.Context(), session)
	if err != nil {
		s.logger.Error("file access context failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to access files")
		return
	}
	defer cleanup()

	virtualPath, storagePath, err := s.resolveVirtualPath(req.Path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpMkdir, virtualPath, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := fs.Mkdir(r.Context(), storagePath); err != nil {
		s.logger.Error("create folder failed", zap.Error(err), zap.String("path", virtualPath))
		s.writeError(w, http.StatusInternalServerError, "Failed to create folder")
		return
	}

	s.recordAudit(session.Username, "user", "mkdir", "http", virtualPath, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var (
		userID     int64
		username   string
		status     string
		homeDir    string
		quotas     sql.NullString
		mfaEnabled bool
		createdAt  string
		updatedAt  string
	)
	if err := s.db.QueryRow(
		"SELECT id, username, status, home_dir, quotas, mfa_enabled, created_at, updated_at FROM users WHERE id = ?",
		session.UserID,
	).Scan(&userID, &username, &status, &homeDir, &quotas, &mfaEnabled, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.logger.Error("load profile failed", zap.Error(err), zap.Int64("user_id", session.UserID))
		s.writeError(w, http.StatusInternalServerError, "Failed to load profile")
		return
	}

	type publicKey struct {
		ID          int64  `json:"id"`
		Label       string `json:"label"`
		CreatedAt   string `json:"created_at"`
		Fingerprint string `json:"fingerprint"`
	}
	keys := make([]publicKey, 0)
	rows, err := s.db.Query("SELECT id, COALESCE(label, ''), COALESCE(public_key, ''), created_at FROM public_keys WHERE user_id = ? ORDER BY created_at ASC", session.UserID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var item publicKey
			var pubKeyStr string
			if scanErr := rows.Scan(&item.ID, &item.Label, &pubKeyStr, &item.CreatedAt); scanErr == nil {
				if parsedKey, parseErr := ssh.ParsePublicKey([]byte(pubKeyStr)); parseErr == nil {
					item.Fingerprint = ssh.FingerprintSHA256(parsedKey)
				}
				keys = append(keys, item)
			}
		}
	} else {
		s.logger.Warn("load public keys failed", zap.Error(err), zap.Int64("user_id", session.UserID))
	}

	quota := map[string]interface{}{
		"configured": false,
	}
	if quotas.Valid && strings.TrimSpace(quotas.String) != "" {
		quota["configured"] = true
		var parsed interface{}
		if err := json.Unmarshal([]byte(quotas.String), &parsed); err == nil {
			quota["raw"] = parsed
		} else {
			quota["raw"] = quotas.String
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":             userID,
		"username":       username,
		"status":         status,
		"home_directory": homeDir,
		"mfa_enabled":    mfaEnabled,
		"quota":          quota,
		"public_keys":    keys,
		"created_at":     createdAt,
		"updated_at":     updatedAt,
	})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.CurrentPassword) == "" || strings.TrimSpace(req.NewPassword) == "" {
		s.writeError(w, http.StatusBadRequest, "Current password and new password are required")
		return
	}
	if s.passwordPolicy != nil {
		if err := s.passwordPolicy.ValidatePassword(req.NewPassword, session.Username); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else if len(req.NewPassword) < 6 {
		s.writeError(w, http.StatusBadRequest, "New password must be at least 6 characters")
		return
	}

	var passwordHash string
	if err := s.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", session.UserID).Scan(&passwordHash); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.logger.Error("load password hash failed", zap.Error(err), zap.Int64("user_id", session.UserID))
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.CurrentPassword)); err != nil {
		s.writeError(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash new password failed", zap.Error(err), zap.Int64("user_id", session.UserID))
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}
	if _, err := s.db.Exec("UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?", string(newHash), session.UserID); err != nil {
		s.logger.Error("update password failed", zap.Error(err), zap.Int64("user_id", session.UserID))
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}

	s.recordAudit(session.Username, "user", "change_password", "http", session.Username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Password updated"})
}

func (s *Server) isPasswordExpired(passwordChangedAt sql.NullString) bool {
	if s.authConfig.PasswordExpiresDays <= 0 {
		return false
	}
	if !passwordChangedAt.Valid || strings.TrimSpace(passwordChangedAt.String) == "" {
		return false
	}
	changedAt, err := time.Parse(time.RFC3339, passwordChangedAt.String)
	if err != nil {
		s.logger.Warn("failed to parse password_changed_at", zap.String("value", passwordChangedAt.String), zap.Error(err))
		return false
	}
	expiry := changedAt.AddDate(0, 0, s.authConfig.PasswordExpiresDays)
	return time.Now().After(expiry)
}

func (s *Server) forcedPasswordChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PasswordChangeToken string `json:"password_change_token"`
		NewPassword         string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.PasswordChangeToken) == "" || strings.TrimSpace(req.NewPassword) == "" {
		s.writeError(w, http.StatusBadRequest, "Password change token and new password are required")
		return
	}

	s.passwordChangeMu.Lock()
	tokenData, exists := s.passwordChangeTokens[req.PasswordChangeToken]
	if exists {
		if time.Now().After(tokenData.ExpiresAt) {
			delete(s.passwordChangeTokens, req.PasswordChangeToken)
			exists = false
		}
	}
	if exists {
		delete(s.passwordChangeTokens, req.PasswordChangeToken)
	}
	s.passwordChangeMu.Unlock()

	if !exists {
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired password change token")
		return
	}

	if s.passwordPolicy != nil {
		if err := s.passwordPolicy.ValidatePassword(req.NewPassword, tokenData.Username); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash new password failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}

	if _, err := s.db.Exec(
		"UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		string(newHash), tokenData.UserID,
	); err != nil {
		s.logger.Error("update expired password failed", zap.Error(err), zap.Int64("user_id", tokenData.UserID))
		s.writeError(w, http.StatusInternalServerError, "Failed to change password")
		return
	}

	s.recordAudit(tokenData.Username, "user", "forced_password_change", "http", tokenData.Username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func (s *Server) requireRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := s.sessionFromRequest(r)
			if !ok {
				s.writeError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			if time.Now().After(session.ExpiresAt) {
				s.invalidateSessionByToken(session.Token)
				if session.SessionID != "" {
					s.invalidateSessionByID(session.SessionID)
				}
				s.writeError(w, http.StatusUnauthorized, "Session expired")
				return
			}
			if requiredRole != "" && session.Role != requiredRole {
				s.writeError(w, http.StatusForbidden, "Forbidden")
				return
			}
			if session.Role == "admin" && session.UserID > 0 && (len(session.Scopes) == 0 || len(session.Filters) == 0) {
				permissions, filters, err := s.loadAdminAccessProfile(session.UserID)
				if err != nil {
					s.logger.Warn("load admin access profile failed", zap.Error(err), zap.Int64("admin_id", session.UserID))
					s.writeError(w, http.StatusInternalServerError, "Failed to load admin access")
					return
				}
				session.Scopes = permissions
				session.Filters = filters
			}
			if session.SessionID != "" {
				if lastTouch, ok := s.sessionLastTouch.Load(session.SessionID); !ok || time.Since(lastTouch.(time.Time)) > 300*time.Second {
					s.sessionLastTouch.Store(session.SessionID, time.Now())
					touchCtx, touchCancel := context.WithTimeout(context.Background(), 5*time.Second)
					if _, err := s.db.ExecContext(touchCtx, "UPDATE sessions SET last_activity_at = CURRENT_TIMESTAMP WHERE session_id = ?", session.SessionID); err != nil {
						s.logger.Debug("touch session failed", zap.Error(err), zap.String("session_id", session.SessionID))
					}
					touchCancel()
				}
			}
			ctx := context.WithValue(r.Context(), sessionContextKey, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (s *Server) requireAdminPermission(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := s.currentSession(r)
			if session == nil || session.Role != "admin" {
				s.writeError(w, http.StatusForbidden, "Forbidden")
				return
			}
			if !hasAnyPermission(session.Scopes, required...) {
				s.writeError(w, http.StatusForbidden, "Forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) currentSession(r *http.Request) *authSession {
	session, _ := r.Context().Value(sessionContextKey).(*authSession)
	return session
}

func (s *Server) loadAdminAccessProfile(adminID int64) ([]string, map[string]any, error) {
	if s.db == nil {
		return nil, nil, nil
	}

	var adminPermissions string
	var adminFilters string
	var rolePermissions string
	var roleScope string

	query := "SELECT COALESCE(a.permissions, '[]'), COALESCE(a.filters, '{}'), COALESCE(r.permissions, '[]'), COALESCE(r.scope, '{}') FROM admins a LEFT JOIN roles r ON a.role_id = r.id WHERE a.id = ? LIMIT 1"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := s.db.QueryRowContext(ctx, query, adminID).Scan(&adminPermissions, &adminFilters, &rolePermissions, &roleScope)
		cancel()
		if err == nil {
			lastErr = nil
			break
		}
		if !isSQLiteBusyError(err) {
			return nil, nil, err
		}
		lastErr = err
		time.Sleep(time.Duration(50*(attempt+1)) * time.Millisecond)
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}

	merged := append(decodeJSONStringList(adminPermissions), decodeJSONStringList(rolePermissions)...)
	filters := mergeScopeMaps(decodeJSONObject(roleScope), decodeJSONObject(adminFilters))
	return uniqueStrings(merged), filters, nil
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

func (s *Server) loadAdminPermissions(adminID int64) ([]string, map[string]any, error) {
	return s.loadAdminAccessProfile(adminID)
}

func (s *Server) sessionFromRequest(r *http.Request) (*authSession, bool) {
	if session, ok := s.sessionFromAPIKey(r); ok {
		return session, true
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, false
	}
	token := strings.TrimSpace(authHeader[7:])
	if token == "" {
		return nil, false
	}
	if session, ok := s.sessionFromJWT(token); ok {
		return session, true
	}

	s.sessionsMu.RLock()
	session, ok := s.sessions[token]
	s.sessionsMu.RUnlock()
	return session, ok
}

func (s *Server) storeSession(session *authSession) {
	s.sessionsMu.Lock()
	s.sessions[session.Token] = session
	s.sessionsMu.Unlock()
}

func (s *Server) deleteSession(token string) {
	s.sessionsMu.Lock()
	delete(s.sessions, token)
	s.sessionsMu.Unlock()
}

func (s *Server) invalidateSessionByToken(token string) {
	s.deleteSession(token)
}

func (s *Server) invalidateSessionByID(sessionID string) {
	s.sessionsMu.Lock()
	for token, session := range s.sessions {
		if session.SessionID == sessionID {
			delete(s.sessions, token)
		}
	}
	s.sessionsMu.Unlock()
	if sessionID != "" {
		if _, err := s.db.Exec("UPDATE sessions SET is_active = FALSE WHERE session_id = ?", sessionID); err != nil {
			s.logger.Warn("mark session inactive failed", zap.Error(err), zap.String("session_id", sessionID))
		}
	}
}

func (s *Server) tokenTTL() time.Duration {
	if s.jwtManager != nil && s.config.JWT.ExpirySeconds > 0 {
		return time.Duration(s.config.JWT.ExpirySeconds) * time.Second
	}
	if s.config.TokenExpiry <= 0 {
		return time.Hour
	}
	return time.Duration(s.config.TokenExpiry) * time.Second
}

func (s *Server) tokenType() string {
	if s.jwtManager != nil {
		return "jwt"
	}
	return "opaque"
}

func (s *Server) initAuthProviders() {
	if s.config.JWT.Enabled {
		secret := strings.TrimSpace(s.config.JWT.Secret)
		if secret == "" {
			secret = strings.TrimSpace(s.config.SessionSecret)
		}
		manager, err := authn.NewJWTManager(secret, s.config.JWT.Issuer, s.config.JWT.Audience)
		if err != nil {
			s.logger.Warn("JWT manager init failed; falling back to opaque tokens", zap.Error(err))
		} else {
			s.jwtManager = manager
		}
	}
	if s.config.LDAP.Enabled {
		s.ldapAuth = authn.NewLDAPAuthenticator(s.config.LDAP)
	}
	if s.config.OIDC.Enabled {
		s.oidcAuth = authn.NewOIDCAuthenticator(s.config.OIDC)
	}
	for _, keyCfg := range s.config.APIKeys {
		if !keyCfg.Enabled || strings.TrimSpace(keyCfg.Key) == "" {
			continue
		}
		s.apiKeys[keyCfg.Key] = apiKeyPrincipal{
			Subject: strings.TrimSpace(keyCfg.Subject),
			Role:    strings.TrimSpace(keyCfg.Role),
			Scopes:  append([]string{}, keyCfg.Scopes...),
		}
	}
}

func (s *Server) issueToken(session *authSession) (string, error) {
	if s.jwtManager == nil {
		return generateToken()
	}
	return s.jwtManager.Sign(authn.JWTClaims{
		Subject:   session.Username,
		Role:      session.Role,
		UserID:    session.UserID,
		SessionID: session.SessionID,
		HomeDir:   session.HomeDir,
		Scopes:    append([]string{}, session.Scopes...),
		ExpiresAt: session.ExpiresAt.Unix(),
	})
}

func (s *Server) sessionFromJWT(token string) (*authSession, bool) {
	if s.jwtManager == nil {
		return nil, false
	}
	claims, err := s.jwtManager.Parse(token)
	if err != nil {
		return nil, false
	}
	return &authSession{
		Token:     token,
		SessionID: claims.SessionID,
		UserID:    claims.UserID,
		Username:  claims.Subject,
		Role:      claims.Role,
		Scopes:    append([]string{}, claims.Scopes...),
		HomeDir:   claims.HomeDir,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
	}, true
}

func (s *Server) sessionFromAPIKey(r *http.Request) (*authSession, bool) {
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authHeader), "apikey ") {
			key = strings.TrimSpace(authHeader[7:])
		}
	}
	if key == "" || len(s.apiKeys) == 0 {
		return nil, false
	}
	for validKey, principal := range s.apiKeys {
		if subtle.ConstantTimeCompare([]byte(validKey), []byte(key)) == 1 {
			expiresAt := time.Now().Add(24 * time.Hour)
			return &authSession{
				Token:     "apikey:" + principal.Subject,
				Username:  principal.Subject,
				Role:      firstNonEmptyRole(principal.Role, "admin"),
				Scopes:    append([]string{}, principal.Scopes...),
				ExpiresAt: expiresAt,
			}, true
		}
	}
	return nil, false
}

func (s *Server) fileAccessContext(ctx context.Context, session *authSession) (*repository.User, storage.FileSystem, func(), error) {
	user, err := s.loadUser(ctx, session)
	if err != nil {
		return nil, nil, nil, err
	}
	fs, cleanup, err := buildUserFileSystem(user)
	if err != nil {
		return nil, nil, nil, err
	}
	return user, fs, cleanup, nil
}

func (s *Server) loadUser(ctx context.Context, session *authSession) (*repository.User, error) {
	if session == nil {
		return nil, fmt.Errorf("unauthorized")
	}
	if s.userRepo != nil {
		return s.userRepo.GetByID(ctx, session.UserID)
	}
	if s.db == nil {
		return nil, fmt.Errorf("user repository is not available")
	}

	user := &repository.User{}
	var filesystem sql.NullString
	var permissions sql.NullString
	var filters sql.NullString
	var quotas sql.NullString
	var bandwidthLimits sql.NullString
	var transferLimits sql.NullString
	var allowedProtocols sql.NullString
	var deniedProtocols sql.NullString
	var ipFilters sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		"SELECT id, username, status, password_hash, home_dir, filesystem, permissions, filters, quotas, bandwidth_limits, transfer_limits, max_sessions, allowed_protocols, denied_protocols, ip_filters, mfa_secret, mfa_enabled, expiration_date, description, created_at, updated_at FROM users WHERE id = ? LIMIT 1",
		session.UserID,
	).Scan(
		&user.ID, &user.Username, &user.Status, &user.PasswordHash, &user.HomeDir, &filesystem, &permissions, &filters,
		&quotas, &bandwidthLimits, &transferLimits, &user.MaxSessions, &allowedProtocols, &deniedProtocols,
		&ipFilters, &user.MFASecret, &user.MFAEnabled, &user.ExpirationDate, &user.Description, &user.CreatedAt, &user.UpdatedAt,
	); err != nil {
		return nil, err
	}

	user.Filesystem = rawJSONFromNullString(filesystem)
	user.Permissions = rawJSONFromNullString(permissions)
	user.Filters = rawJSONFromNullString(filters)
	user.Quotas = rawJSONFromNullString(quotas)
	user.BandwidthLimits = rawJSONFromNullString(bandwidthLimits)
	user.TransferLimits = rawJSONFromNullString(transferLimits)
	user.AllowedProtocols = rawJSONFromNullString(allowedProtocols)
	user.DeniedProtocols = rawJSONFromNullString(deniedProtocols)
	user.IPFilters = rawJSONFromNullString(ipFilters)
	return user, nil
}

func (s *Server) authorizeFileOperation(ctx context.Context, session *authSession, user *repository.User, r *http.Request, op policy.OperationType, filePath string, size int64) error {
	if s.policyEngine == nil {
		return nil
	}
	allowed, err := s.policyEngine.CanPerformOperation(ctx, policy.OperationRequest{
		UserID:    user.ID,
		Username:  session.Username,
		Protocol:  "http",
		ClientIP:  parseRemoteIP(s.clientIP(r)),
		Operation: op,
		FilePath:  filePath,
		FileSize:  size,
	})
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("operation %s is not allowed for %s", op, filePath)
	}
	return nil
}

func (s *Server) resolveVirtualPath(rawPath string) (string, string, error) {
	cleanVirtual := filepath.ToSlash(filepath.Clean("/" + strings.TrimSpace(rawPath)))
	if cleanVirtual == "." {
		cleanVirtual = "/"
	}
	return cleanVirtual, strings.TrimPrefix(cleanVirtual, "/"), nil
}

func removeAllFromFS(ctx context.Context, fs storage.FileSystem, storagePath string) error {
	info, err := fs.Stat(ctx, storagePath)
	if err != nil {
		return err
	}
	if info.IsDir {
		children, err := fs.ListDir(ctx, storagePath)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := removeAllFromFS(ctx, fs, storageChildPath(storagePath, child.Name)); err != nil {
				return err
			}
		}
		return fs.Rmdir(ctx, storagePath)
	}
	return fs.Delete(ctx, storagePath)
}

func buildUserFileSystem(user *repository.User) (storage.FileSystem, func(), error) {
	cfg, err := parseUserFileSystemConfig(user)
	if err != nil {
		return nil, nil, err
	}

	switch cfg.Type {
	case "", "local":
		basePath := stringConfigValue(cfg.Config, "base_path", user.HomeDir)
		if err := os.MkdirAll(basePath, 0o755); err != nil {
			return nil, nil, fmt.Errorf("failed to prepare local storage: %w", err)
		}
		return local.NewLocalFileSystem(basePath, boolConfigValue(cfg.Config, "chroot", true)), func() {}, nil
	case "encrypted":
		basePath := stringConfigValue(cfg.Config, "base_path", user.HomeDir)
		if err := os.MkdirAll(basePath, 0o755); err != nil {
			return nil, nil, fmt.Errorf("failed to prepare encrypted storage: %w", err)
		}
		fs, err := encrypted.NewEncryptedFileSystem(encrypted.Config{
			BasePath: basePath,
			KeyFile:  stringConfigValue(cfg.Config, "key_file", ""),
			Key:      stringConfigValue(cfg.Config, "key", ""),
		})
		if err != nil {
			return nil, nil, err
		}
		return fs, func() {}, nil
	case "httpfs":
		fs, err := httpfs.NewHTTPFsFileSystem(httpfs.Config{
			BaseURL: stringConfigValue(cfg.Config, "base_url", ""),
			APIKey:  stringConfigValue(cfg.Config, "api_key", ""),
			Timeout: intConfigValue(cfg.Config, "timeout", 30),
		})
		if err != nil {
			return nil, nil, err
		}
		return fs, func() {}, nil
	case "remotesftp":
		fs, err := remotesftp.NewRemoteSFTPFileSystem(remotesftp.Config{
			Host:       stringConfigValue(cfg.Config, "host", ""),
			Port:       intConfigValue(cfg.Config, "port", 22),
			Username:   stringConfigValue(cfg.Config, "username", ""),
			Password:   stringConfigValue(cfg.Config, "password", ""),
			PrivateKey: stringConfigValue(cfg.Config, "private_key", ""),
			HostKey:    stringConfigValue(cfg.Config, "host_key", ""),
			PathPrefix: stringConfigValue(cfg.Config, "path_prefix", ""),
			Timeout:    intConfigValue(cfg.Config, "timeout", 30),
		})
		if err != nil {
			return nil, nil, err
		}
		return fs, func() {
			_ = fs.Close()
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported filesystem type %q", cfg.Type)
	}
}

func parseUserFileSystemConfig(user *repository.User) (*storage.FileSystemConfig, error) {
	cfg := &storage.FileSystemConfig{
		Type:   "local",
		Config: map[string]interface{}{},
	}
	if len(user.Filesystem) == 0 {
		return cfg, nil
	}

	trimmed := strings.TrimSpace(string(user.Filesystem))
	if trimmed == "" {
		return cfg, nil
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		cfg.Type = strings.ToLower(trimmed)
		return cfg, nil
	}

	var direct storage.FileSystemConfig
	if err := json.Unmarshal(user.Filesystem, &direct); err == nil && (direct.Type != "" || len(direct.Config) > 0) {
		if direct.Type == "" {
			direct.Type = "local"
		}
		if direct.Config == nil {
			direct.Config = map[string]interface{}{}
		}
		direct.Type = strings.ToLower(strings.TrimSpace(direct.Type))
		return &direct, nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(user.Filesystem, &raw); err != nil {
		return nil, fmt.Errorf("invalid user filesystem config: %w", err)
	}
	cfg.Type = strings.ToLower(strings.TrimSpace(stringConfigValue(raw, "type", "local")))
	if nested, ok := raw["config"].(map[string]interface{}); ok {
		cfg.Config = nested
	} else {
		cfg.Config = raw
		delete(cfg.Config, "type")
	}
	return cfg, nil
}

func stringConfigValue(values map[string]interface{}, key, fallback string) string {
	if values == nil {
		return fallback
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return fallback
	}
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func boolConfigValue(values map[string]interface{}, key string, fallback bool) bool {
	if values == nil {
		return fallback
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return fallback
	}
	switch value := raw.(type) {
	case bool:
		return value
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return fallback
}

func intConfigValue(values map[string]interface{}, key string, fallback int) int {
	if values == nil {
		return fallback
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return fallback
	}
	switch value := raw.(type) {
	case int:
		return value
	case int32:
		return int(value)
	case int64:
		return int(value)
	case float64:
		return int(value)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return parsed
		}
	}
	return fallback
}

func storageChildPath(basePath, name string) string {
	if basePath == "" {
		return name
	}
	return pathpkg.Join(basePath, name)
}

func joinVirtualPath(basePath, name string) string {
	cleanBase := filepath.ToSlash(filepath.Clean("/" + strings.TrimSpace(basePath)))
	if cleanBase == "." || cleanBase == "/" {
		return "/" + name
	}
	return strings.TrimSuffix(cleanBase, "/") + "/" + name
}

func parseRemoteIP(raw string) net.IP {
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
		return ip
	}
	return net.IPv4(127, 0, 0, 1)
}

func rawJSONFromNullString(value sql.NullString) json.RawMessage {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	return json.RawMessage(value.String)
}

func (s *Server) normalizeHomeDir(username, requested string) (string, error) {
	if strings.Contains(username, string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid username")
	}
	candidate := strings.TrimSpace(requested)
	if candidate == "" || candidate == "/" || candidate == "/home" {
		candidate = filepath.Join("data", "users", username)
	}
	return filepath.Abs(candidate)
}

func (s *Server) processAuditQueue() {
	defer s.auditWg.Done()
	for fn := range s.auditQueue {
		fn()
	}
}

func (s *Server) enqueueAudit(fn func()) {
	select {
	case s.auditQueue <- fn:
	default:
		s.logger.Warn("audit queue full, dropping audit entry")
	}
}

func (s *Server) recordAudit(actorName, actorType, eventType, protocol, targetID, result, errMsg string) {
	if s.db == nil && s.auditRecorder == nil {
		return
	}
	eventID, err := generateToken()
	if err != nil {
		eventID = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	capturedID := eventID
	s.enqueueAudit(func() {
		if s.db != nil {
			if _, err := s.db.Exec(
				"INSERT INTO audit_logs (event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				capturedID, eventType, actorType, actorName, "resource", targetID, protocol, "", result, errMsg,
			); err != nil {
				s.logger.Warn("record audit failed", zap.Error(err), zap.String("event_type", eventType))
			}
		}
		if s.auditRecorder != nil {
			auditEventType := s.mapToAuditEventType(eventType, actorType)
			aType := audit.ActorUser
			if actorType == "admin" {
				aType = audit.ActorAdmin
			}
			tType := audit.TargetResource
			switch {
			case strings.Contains(eventType, "create_user"):
				tType = audit.TargetUser
			case strings.Contains(eventType, "update_user"):
				tType = audit.TargetUser
			case strings.Contains(eventType, "delete_user"):
				tType = audit.TargetUser
			case strings.Contains(eventType, "create_admin"):
				tType = audit.TargetAdmin
			case strings.Contains(eventType, "upload"):
				tType = audit.TargetFile
			case strings.Contains(eventType, "download"):
				tType = audit.TargetFile
			case strings.Contains(eventType, "delete"):
				tType = audit.TargetFile
			case strings.Contains(eventType, "rename"):
				tType = audit.TargetFile
			case strings.Contains(eventType, "mkdir"):
				tType = audit.TargetDirectory
			case strings.Contains(eventType, "config"):
				tType = audit.TargetConfig
			case strings.Contains(eventType, "backup"):
				tType = audit.TargetConfig
			case strings.Contains(eventType, "restore"):
				tType = audit.TargetConfig
			}
			_ = s.auditRecorder.Record(context.Background(), &audit.AuditEvent{
				EventType:    auditEventType,
				ActorType:    aType,
				ActorName:    actorName,
				TargetType:   tType,
				TargetID:     targetID,
				Protocol:     protocol,
				Result:       result,
				ErrorMessage: errMsg,
			})
		}
	})
}

func (s *Server) mapToAuditEventType(eventType, actorType string) audit.EventType {
	switch eventType {
	case "login", "login_ldap", "login_oidc":
		return audit.LoginSuccess
	case "create_user":
		return audit.AdminCreateUser
	case "update_user":
		return audit.AdminUpdateUser
	case "delete_user":
		return audit.AdminDeleteUser
	case "create_admin":
		return audit.AdminCreateUser
	case "update_admin":
		return audit.AdminUpdateUser
	case "delete_admin":
		return audit.AdminDeleteUser
	case "upload":
		return audit.FileUpload
	case "download":
		return audit.FileDownload
	case "delete":
		return audit.FileDelete
	case "rename":
		return audit.FileRename
	case "mkdir":
		return audit.DirCreate
	case "change_password", "forced_password_change":
		return audit.AdminUpdateUser
	case "config_change":
		return audit.ConfigChange
	case "backup":
		return audit.DataBackup
	case "restore":
		return audit.DataRestore
	default:
		return audit.APICall
	}
}

func (s *Server) clientIP(r *http.Request) string {
	forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	if forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Warn("write json failed", zap.Error(err))
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"message": message})
}

func parseIntOrDefault(raw string, defaultValue int) int {
	if raw == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return defaultValue
	}
	return value
}

// generateToken generates a random token for authentication
func generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Router returns the chi router for adding more routes
func (s *Server) Router() *chi.Mux {
	return s.router
}

// SetProtocolStatuses updates the protocol state reported by /status.
func (s *Server) SetProtocolStatuses(statuses map[string]bool) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()

	for name, enabled := range statuses {
		s.protocols[name] = enabled
	}
}

func (s *Server) SetHookManager(hm *hooks.HookManager) {
	s.hookManager = hm
}

func (s *Server) protocolEnabled(name string) bool {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()

	return s.protocols[name]
}

// spaHandler serves the SPA index.html for client-side routing
type spaHandler struct {
	staticPath string
	indexPath  string
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	indexPath := h.staticPath + "/" + h.indexPath
	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}
	http.NotFound(w, r)
}
