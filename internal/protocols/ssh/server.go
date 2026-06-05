package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/audit"
	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/defender"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/storage/local"
	"github.com/pkg/sftp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Server represents the SSH/SFTP/SCP server
type Server struct {
	config           config.SSHConfig
	authConfig       config.AuthConfig
	logger           *zap.Logger
	authService      *auth.AuthenticationService
	policyEngine     *policy.PolicyEngine
	userRepo         repository.UserRepository
	auditRepo        repository.AuditRepository
	auditRecorder    audit.AuditRecorder
	sessionRepo      repository.SessionRepository
	hookManager      *hooks.HookManager
	listener         net.Listener
	sshConfig        *ssh.ServerConfig
	certAuth         *auth.CertificateAuthenticator
	kbHandler        *auth.KeyboardInteractiveHandler
	multiStepTracker *auth.MultiStepAuthTracker
	geoIPFilter      *auth.GeoIPFilter
	passwordPolicy   *auth.PasswordPolicy
	totpAuth         *auth.TOTPAuthenticator
	defender         *defender.Defender
}

// NewServer creates a new SSH/SFTP server
func NewServer(
	cfg config.SSHConfig,
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
	}
}

// SetAuthConfig sets the authentication configuration
func (s *Server) SetAuthConfig(cfg config.AuthConfig) {
	s.authConfig = cfg
}

// SetPasswordPolicy sets the password policy
func (s *Server) SetPasswordPolicy(policy *auth.PasswordPolicy) {
	s.passwordPolicy = policy
}

// SetAuditRecorder sets the audit recorder for structured audit events
func (s *Server) SetAuditRecorder(recorder audit.AuditRecorder) {
	s.auditRecorder = recorder
}

func (s *Server) SetHookManager(hm *hooks.HookManager) {
	s.hookManager = hm
}

// SetDefender sets the defender service for brute-force protection
func (s *Server) SetDefender(d *defender.Defender) {
	s.defender = d
}

// Start starts the SSH/SFTP server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("SSH server is disabled")
		return nil
	}
	if !s.config.PasswordAuth && !s.config.PublicKeyAuth && !s.config.CertificateAuth {
		return fmt.Errorf("ssh server requires at least one enabled authentication method")
	}

	s.initAuthComponents()

	// Load host keys
	usingEphemeralHostKey := len(s.config.HostKeys) == 0
	hostKeys, err := s.loadHostKeys()
	if err != nil {
		return fmt.Errorf("failed to load host keys: %w", err)
	}
	if usingEphemeralHostKey {
		s.logger.Warn("SSH/SFTP server is using an ephemeral host key; configure ssh.host_keys for production")
	} else {
		s.logger.Info("SSH/SFTP server loaded persistent host keys", zap.Int("count", len(hostKeys)))
	}

	// Configure SSH server
	s.sshConfig = &ssh.ServerConfig{
		ServerVersion:               "SSH-2.0-SFTPxy",
		PasswordCallback:            s.passwordAuth,
		PublicKeyCallback:           s.publicKeyAuth,
		KeyboardInteractiveCallback: s.keyboardInteractiveAuth,
		MaxAuthTries:                6,
	}

	for _, key := range hostKeys {
		s.sshConfig.AddHostKey(key)
	}

	// Start listening
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.logger.Info("SSH/SFTP server started", zap.String("address", addr))

	go s.acceptConnections(ctx)

	return nil
}

func (s *Server) initAuthComponents() {
	if s.totpAuth == nil {
		s.totpAuth = auth.NewTOTPAuthenticator("SFTPxy")
	}

	if s.config.CertificateAuth && len(s.config.CAKeys) > 0 {
		caKeys, err := auth.LoadCAKeysFromFiles(s.config.CAKeys)
		if err != nil {
			s.logger.Error("Failed to load CA keys", zap.Error(err))
		} else {
			s.certAuth = auth.NewCertificateAuthenticator(s.userRepo, s.config.CertPrincipals)
			s.certAuth.TrustedCAKeys = caKeys
			s.logger.Info("SSH certificate authentication enabled", zap.Int("ca_keys", len(caKeys)))
		}
	}

	s.kbHandler = auth.NewKeyboardInteractiveHandler(s.userRepo, s.totpAuth, "SFTPxy")

	if s.authConfig.MultiStepAuth.Enabled {
		s.multiStepTracker = auth.NewMultiStepAuthTracker(s.authConfig.MultiStepAuth.TTLSeconds)
		s.logger.Info("SSH multi-step authentication enabled", zap.Strings("required_methods", s.authConfig.MultiStepAuth.RequiredMethods))
	}

	if s.authConfig.GeoIP.DBPath != "" || len(s.authConfig.GeoIP.AllowedCountries) > 0 || len(s.authConfig.GeoIP.DeniedCountries) > 0 {
		geoFilter, err := auth.NewGeoIPFilter(s.authConfig.GeoIP.DBPath, s.authConfig.GeoIP.AllowedCountries, s.authConfig.GeoIP.DeniedCountries)
		if err != nil {
			s.logger.Error("Failed to initialize GeoIP filter", zap.Error(err))
		} else {
			s.geoIPFilter = geoFilter
			s.logger.Info("SSH GeoIP filtering enabled")
		}
	}
}

// Shutdown gracefully shuts down the SSH server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		s.logger.Info("Shutting down SSH/SFTP server")
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptConnections(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("Failed to accept connection", zap.Error(err))
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientIP := remoteIP(conn.RemoteAddr())
	s.logger.Debug("New SSH connection", zap.String("remote", conn.RemoteAddr().String()))

	if s.hookManager != nil {
		s.hookManager.OnConnection(context.Background(), hooks.ConnectionEventPostConnect, &hooks.ConnectionPayload{
			Event:        hooks.ConnectionEventPostConnect,
			ConnectionID: fmt.Sprintf("ssh-%d", time.Now().UnixNano()),
			Protocol:     "sftp",
			ClientAddr:   clientIP.String(),
			Timestamp:    time.Now(),
		})
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logger.Warn("SSH handshake failed", zap.String("remote", conn.RemoteAddr().String()), zap.Error(err))
		return
	}

	defer sshConn.Close()

	s.logger.Info("SSH connection established",
		zap.String("user", sshConn.User()),
		zap.String("remote", conn.RemoteAddr().String()),
	)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			s.logger.Error("Failed to accept channel", zap.Error(err))
			continue
		}

		go s.handleSession(channel, requests, sshConn, clientIP)
	}
}

func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, sshConn *ssh.ServerConn, clientIP net.IP) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "subsystem":
			if len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				s.handleSFTP(channel, sshConn, clientIP)
				return
			}
			req.Reply(false, nil)
		case "exec":
			if !s.config.SCPEnabled {
				req.Reply(false, nil)
				return
			}
			req.Reply(true, nil)
			s.handleSCP(channel, req.Payload, sshConn, clientIP)
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) handleSFTP(channel ssh.Channel, sshConn *ssh.ServerConn, clientIP net.IP) {
	username := sshConn.User()

	// Get user info
	user, err := s.userRepo.GetByUsername(context.Background(), username)
	if err != nil {
		s.logger.Error("Failed to get user", zap.String("username", username), zap.Error(err))
		return
	}

	if err := os.MkdirAll(user.HomeDir, 0755); err != nil {
		s.logger.Error("Failed to prepare user home", zap.String("username", username), zap.Error(err))
		s.recordAudit(username, clientIP, "sftp_session", "failure", err.Error())
		return
	}

	filesystem := local.NewLocalFileSystem(user.HomeDir, true)
	if err := filesystem.HealthCheck(context.Background()); err != nil {
		s.logger.Error("SFTP filesystem health check failed", zap.String("username", username), zap.Error(err))
		s.recordAudit(username, clientIP, "sftp_session", "failure", err.Error())
		return
	}

	sessionID := newProtocolSessionID("sftp")
	if s.sessionRepo != nil {
		if err := s.sessionRepo.CreateSession(context.Background(), sessionID, user.ID, "sftp", clientIP.String()); err != nil {
			s.logger.Warn("Failed to create SFTP session record", zap.String("username", username), zap.Error(err))
		} else {
			defer func() {
				if err := s.sessionRepo.DeactivateSession(context.Background(), sessionID); err != nil {
					s.logger.Warn("Failed to deactivate SFTP session record", zap.String("username", username), zap.Error(err))
				}
			}()
		}
	}

	server := sftp.NewRequestServer(channel,
		newSFTPHandlers(s, user, clientIP),
		sftp.WithStartDirectory("/"),
	)
	s.recordAudit(username, clientIP, "sftp_session", "success", "")
	if s.userRepo != nil {
		s.userRepo.UpdateLastLogin(context.Background(), user.ID)
	}

	if err := server.Serve(); err != nil {
		if !errors.Is(err, io.EOF) {
			s.logger.Error("SFTP server error", zap.Error(err))
		}
	}
	_ = server.Close()
	s.logger.Debug("SFTP session ended", zap.String("user", username))
}

func (s *Server) handleSCP(channel ssh.Channel, payload []byte, sshConn *ssh.ServerConn, clientIP net.IP) {
	command := ""
	if len(payload) >= 4 {
		command = strings.TrimSpace(string(payload[4:]))
	}
	message := "SCP is not implemented in the minimal protocol closure\n"
	if command != "" {
		message = fmt.Sprintf("SCP command %q is not implemented in the minimal protocol closure\n", command)
	}
	_, _ = channel.Write([]byte(message))
	s.recordAudit(sshConn.User(), clientIP, "scp_exec", "failure", "scp not implemented")
	s.logger.Debug("SCP request rejected", zap.String("user", sshConn.User()), zap.String("command", command))
}

func (s *Server) passwordAuth(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	if !s.config.PasswordAuth {
		return nil, fmt.Errorf("password authentication disabled")
	}

	username := conn.User()
	clientIP := remoteIP(conn.RemoteAddr())

	if s.defender != nil && s.defender.IsBlocked(clientIP.String()) {
		s.logger.Warn("Authentication blocked by defender", zap.String("user", username), zap.String("ip", clientIP.String()))
		s.recordAudit(username, clientIP, "ssh_password_auth", "failure", "blocked by defender")
		return nil, fmt.Errorf("authentication blocked")
	}

	if err := s.checkGeoIP(clientIP, username); err != nil {
		return nil, err
	}

	s.logger.Debug("Password authentication attempt", zap.String("user", username))

	ctx := context.Background()
	result, err := s.authService.LoginUser(ctx, username, string(password))
	if err != nil || !result.Success {
		s.logger.Warn("Password authentication failed", zap.String("user", username), zap.String("ip", clientIP.String()))
		if s.defender != nil {
			s.defender.RecordFailure(clientIP.String(), "sftp")
		}
		s.recordAudit(username, clientIP, "ssh_password_auth", "failure", "authentication failed")
		return nil, fmt.Errorf("authentication failed")
	}

	if err := s.checkPasswordExpiry(result.User); err != nil {
		s.recordAudit(username, clientIP, "ssh_password_auth", "failure", err.Error())
		return nil, err
	}

	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(ctx, policy.AuthRequest{
			Username:   username,
			Protocol:   "sftp",
			ClientIP:   clientIP,
			AuthMethod: "password",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			s.recordAudit(username, clientIP, "ssh_password_auth", "failure", reason)
			return nil, errors.New(reason)
		}
	}

	if s.multiStepTracker != nil && s.isMultiStepRequired() {
		sessionID := s.sessionIDFromConn(conn)
		s.multiStepTracker.RecordPartialSuccess(sessionID, username, clientIP.String(), "password", s.authConfig.MultiStepAuth.RequiredMethods)
		s.recordAudit(username, clientIP, "ssh_password_auth", "partial", "additional authentication required")
		return nil, auth.ErrPartialAuthRequired
	}

	s.logger.Info("Password authentication successful", zap.String("user", username))
	s.recordAudit(username, clientIP, "ssh_password_auth", "success", "")

	if s.hookManager != nil {
		s.hookManager.OnConnection(context.Background(), hooks.ConnectionEventPostLogin, &hooks.ConnectionPayload{
			Event:        hooks.ConnectionEventPostLogin,
			ConnectionID: fmt.Sprintf("ssh-%d", time.Now().UnixNano()),
			Protocol:     "sftp",
			ClientAddr:   clientIP.String(),
			Username:     username,
			UserID:       result.User.ID,
			AuthMethod:   "password",
			Timestamp:    time.Now(),
		})
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":  fmt.Sprintf("%d", result.User.ID),
			"home-dir": result.User.HomeDir,
		},
	}, nil
}

func (s *Server) publicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()
	clientIP := remoteIP(conn.RemoteAddr())

	if s.defender != nil && s.defender.IsBlocked(clientIP.String()) {
		s.logger.Warn("Authentication blocked by defender", zap.String("user", username), zap.String("ip", clientIP.String()))
		s.recordAudit(username, clientIP, "ssh_publickey_auth", "failure", "blocked by defender")
		return nil, fmt.Errorf("authentication blocked")
	}

	if err := s.checkGeoIP(clientIP, username); err != nil {
		return nil, err
	}

	if cert, ok := auth.IsSSHCertificate(key); ok {
		if !s.config.CertificateAuth {
			return nil, fmt.Errorf("certificate authentication disabled")
		}
		return s.certificateAuth(conn, cert, username, clientIP)
	}

	if !s.config.PublicKeyAuth {
		return nil, fmt.Errorf("public key authentication disabled")
	}

	s.logger.Debug("Public key authentication attempt", zap.String("user", username))

	ctx := context.Background()
	authenticator := auth.NewPublicKeyAuthenticator(s.userRepo)
	user, err := authenticator.Authenticate(ctx, username, key)
	if err != nil {
		s.logger.Warn("Public key auth failed", zap.String("user", username), zap.Error(err))
		if s.defender != nil {
			s.defender.RecordFailure(clientIP.String(), "sftp")
		}
		s.recordAudit(username, clientIP, "ssh_publickey_auth", "failure", err.Error())
		return nil, fmt.Errorf("authentication failed")
	}

	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(ctx, policy.AuthRequest{
			Username:   username,
			Protocol:   "sftp",
			ClientIP:   clientIP,
			AuthMethod: "publickey",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			s.recordAudit(username, clientIP, "ssh_publickey_auth", "failure", reason)
			return nil, errors.New(reason)
		}
	}

	if s.multiStepTracker != nil && s.isMultiStepRequired() {
		sessionID := s.sessionIDFromConn(conn)
		s.multiStepTracker.RecordPartialSuccess(sessionID, username, clientIP.String(), "publickey", s.authConfig.MultiStepAuth.RequiredMethods)
		s.recordAudit(username, clientIP, "ssh_publickey_auth", "partial", "additional authentication required")
		return nil, auth.ErrPartialAuthRequired
	}

	s.logger.Info("Public key authentication successful", zap.String("user", username))
	s.recordAudit(username, clientIP, "ssh_publickey_auth", "success", "")

	if s.hookManager != nil {
		s.hookManager.OnConnection(context.Background(), hooks.ConnectionEventPostLogin, &hooks.ConnectionPayload{
			Event:        hooks.ConnectionEventPostLogin,
			ConnectionID: fmt.Sprintf("ssh-%d", time.Now().UnixNano()),
			Protocol:     "sftp",
			ClientAddr:   clientIP.String(),
			Username:     username,
			UserID:       user.ID,
			AuthMethod:   "publickey",
			Timestamp:    time.Now(),
		})
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":  fmt.Sprintf("%d", user.ID),
			"home-dir": user.HomeDir,
		},
	}, nil
}

func (s *Server) certificateAuth(conn ssh.ConnMetadata, cert *ssh.Certificate, username string, clientIP net.IP) (*ssh.Permissions, error) {
	if s.certAuth == nil {
		return nil, fmt.Errorf("certificate authentication not configured")
	}

	if s.defender != nil && s.defender.IsBlocked(clientIP.String()) {
		s.logger.Warn("Authentication blocked by defender", zap.String("user", username), zap.String("ip", clientIP.String()))
		s.recordAudit(username, clientIP, "ssh_cert_auth", "failure", "blocked by defender")
		return nil, fmt.Errorf("authentication blocked")
	}

	s.logger.Debug("Certificate authentication attempt", zap.String("user", username))

	user, err := s.certAuth.Authenticate(username, cert)
	if err != nil {
		s.logger.Warn("Certificate auth failed", zap.String("user", username), zap.Error(err))
		if s.defender != nil {
			s.defender.RecordFailure(clientIP.String(), "sftp")
		}
		s.recordAudit(username, clientIP, "ssh_cert_auth", "failure", err.Error())
		return nil, fmt.Errorf("authentication failed")
	}

	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(context.Background(), policy.AuthRequest{
			Username:   username,
			Protocol:   "sftp",
			ClientIP:   clientIP,
			AuthMethod: "certificate",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			s.recordAudit(username, clientIP, "ssh_cert_auth", "failure", reason)
			return nil, errors.New(reason)
		}
	}

	if s.multiStepTracker != nil && s.isMultiStepRequired() {
		sessionID := s.sessionIDFromConn(conn)
		s.multiStepTracker.RecordPartialSuccess(sessionID, username, clientIP.String(), "certificate", s.authConfig.MultiStepAuth.RequiredMethods)
		s.recordAudit(username, clientIP, "ssh_cert_auth", "partial", "additional authentication required")
		return nil, auth.ErrPartialAuthRequired
	}

	s.logger.Info("Certificate authentication successful", zap.String("user", username))
	s.recordAudit(username, clientIP, "ssh_cert_auth", "success", "")

	if s.hookManager != nil {
		s.hookManager.OnConnection(context.Background(), hooks.ConnectionEventPostLogin, &hooks.ConnectionPayload{
			Event:        hooks.ConnectionEventPostLogin,
			ConnectionID: fmt.Sprintf("ssh-%d", time.Now().UnixNano()),
			Protocol:     "sftp",
			ClientAddr:   clientIP.String(),
			Username:     username,
			UserID:       user.ID,
			AuthMethod:   "certificate",
			Timestamp:    time.Now(),
		})
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":  fmt.Sprintf("%d", user.ID),
			"home-dir": user.HomeDir,
		},
	}, nil
}

func (s *Server) keyboardInteractiveAuth(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	username := conn.User()
	clientIP := remoteIP(conn.RemoteAddr())

	if s.defender != nil && s.defender.IsBlocked(clientIP.String()) {
		s.logger.Warn("Authentication blocked by defender", zap.String("user", username), zap.String("ip", clientIP.String()))
		s.recordAudit(username, clientIP, "ssh_kbi_auth", "failure", "blocked by defender")
		return nil, fmt.Errorf("authentication blocked")
	}

	if err := s.checkGeoIP(clientIP, username); err != nil {
		return nil, err
	}

	if s.kbHandler == nil {
		return nil, fmt.Errorf("keyboard-interactive authentication not configured")
	}

	if s.multiStepTracker != nil {
		sessionID := s.sessionIDFromConn(conn)
		if s.multiStepTracker.HasPartialSuccess(sessionID, username) {
			user, err := s.kbHandler.AuthenticateTOTP(username, client)
			if err != nil {
				s.logger.Warn("Keyboard-interactive TOTP auth failed", zap.String("user", username), zap.Error(err))
				if s.defender != nil {
					s.defender.RecordFailure(clientIP.String(), "sftp")
				}
				s.recordAudit(username, clientIP, "ssh_kbi_auth", "failure", err.Error())
				return nil, fmt.Errorf("authentication failed")
			}

			s.multiStepTracker.RecordPartialSuccess(sessionID, username, clientIP.String(), "keyboard-interactive", s.authConfig.MultiStepAuth.RequiredMethods)

			if !s.multiStepTracker.IsAuthComplete(sessionID, username) {
				s.recordAudit(username, clientIP, "ssh_kbi_auth", "partial", "additional authentication required")
				return nil, auth.ErrPartialAuthRequired
			}

			s.multiStepTracker.ClearState(sessionID, username)
			s.logger.Info("Keyboard-interactive authentication successful (multi-step complete)", zap.String("user", username))
			s.recordAudit(username, clientIP, "ssh_kbi_auth", "success", "")

			return &ssh.Permissions{
				Extensions: map[string]string{
					"user-id":  fmt.Sprintf("%d", user.ID),
					"home-dir": user.HomeDir,
				},
			}, nil
		}
	}

	user, err := s.kbHandler.AuthenticateTOTP(username, client)
	if err != nil {
		s.logger.Warn("Keyboard-interactive auth failed", zap.String("user", username), zap.Error(err))
		if s.defender != nil {
			s.defender.RecordFailure(clientIP.String(), "sftp")
		}
		s.recordAudit(username, clientIP, "ssh_kbi_auth", "failure", err.Error())
		return nil, fmt.Errorf("authentication failed")
	}

	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(context.Background(), policy.AuthRequest{
			Username:   username,
			Protocol:   "sftp",
			ClientIP:   clientIP,
			AuthMethod: "keyboard-interactive",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			s.recordAudit(username, clientIP, "ssh_kbi_auth", "failure", reason)
			return nil, errors.New(reason)
		}
	}

	s.logger.Info("Keyboard-interactive authentication successful", zap.String("user", username))
	s.recordAudit(username, clientIP, "ssh_kbi_auth", "success", "")

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":  fmt.Sprintf("%d", user.ID),
			"home-dir": user.HomeDir,
		},
	}, nil
}

func (s *Server) checkGeoIP(clientIP net.IP, username string) error {
	if s.geoIPFilter == nil {
		return nil
	}
	allowed, country, err := s.geoIPFilter.CheckIP(clientIP)
	if err != nil {
		s.logger.Warn("GeoIP check failed", zap.String("ip", clientIP.String()), zap.Error(err))
		return nil
	}
	if !allowed {
		s.logger.Warn("GeoIP blocked", zap.String("ip", clientIP.String()), zap.String("country", country), zap.String("user", username))
		s.recordAudit(username, clientIP, "ssh_geoip_block", "failure", "blocked country: "+country)
		return auth.ErrGeoIPBlocked
	}
	return nil
}

func (s *Server) checkPasswordExpiry(user *repository.User) error {
	if s.authConfig.PasswordExpiresDays <= 0 {
		return nil
	}
	if !user.PasswordChangedAt.Valid || user.PasswordChangedAt.String == "" {
		return nil
	}
	changedAt, err := time.Parse(time.RFC3339, user.PasswordChangedAt.String)
	if err != nil {
		s.logger.Warn("Failed to parse password_changed_at", zap.String("value", user.PasswordChangedAt.String), zap.Error(err))
		return nil
	}
	expiry := changedAt.AddDate(0, 0, s.authConfig.PasswordExpiresDays)
	if time.Now().After(expiry) {
		return auth.ErrPasswordExpired
	}
	return nil
}

func (s *Server) isMultiStepRequired() bool {
	return s.authConfig.MultiStepAuth.Enabled && len(s.authConfig.MultiStepAuth.RequiredMethods) >= 2
}

func (s *Server) sessionIDFromConn(conn ssh.ConnMetadata) string {
	return fmt.Sprintf("%x-%s", conn.SessionID(), conn.User())
}

func (s *Server) loadHostKeys() ([]ssh.Signer, error) {
	var signers []ssh.Signer

	// Generate default host key if none configured
	if len(s.config.HostKeys) == 0 {
		// Generate an Ed25519 key for testing
		key, err := generateEd25519Key()
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)
		s.logger.Info("Generated default host key")
	} else {
		for _, keyPath := range s.config.HostKeys {
			keyBytes, err := os.ReadFile(keyPath)
			if err != nil {
				s.logger.Warn("Failed to read host key file", zap.String("path", keyPath), zap.Error(err))
				continue
			}
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil {
				s.logger.Warn("Failed to parse host key", zap.String("path", keyPath), zap.Error(err))
				continue
			}
			signers = append(signers, signer)
		}
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no valid host keys available")
	}

	return signers, nil
}

// generateEd25519Key generates a new Ed25519 key pair
func generateEd25519Key() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}
	return priv, nil
}

func (s *Server) recordAudit(username string, clientIP net.IP, eventType, result, errMsg string) {
	if s.auditRepo == nil && s.auditRecorder == nil {
		return
	}

	if s.auditRepo != nil {
		_, _ = s.auditRepo.CreateAuditLog(context.Background(), &repository.AuditLog{
			EventID:      fmt.Sprintf("ssh-%d", time.Now().UnixNano()),
			EventType:    eventType,
			ActorType:    "user",
			ActorName:    username,
			TargetType:   "protocol",
			TargetID:     "sftp",
			Protocol:     "sftp",
			ClientIP:     clientIP.String(),
			Result:       result,
			ErrorMessage: errMsg,
		})
	}

	if s.auditRecorder != nil {
		auditEventType := s.mapToAuditEventType(eventType, result)
		actorType := audit.ActorUser
		targetType := audit.TargetResource
		switch {
		case strings.Contains(eventType, "file_upload"):
			targetType = audit.TargetFile
		case strings.Contains(eventType, "file_download"):
			targetType = audit.TargetFile
		case strings.Contains(eventType, "file_delete"):
			targetType = audit.TargetFile
		case strings.Contains(eventType, "dir_create"):
			targetType = audit.TargetDirectory
		case strings.Contains(eventType, "dir_delete"):
			targetType = audit.TargetDirectory
		case strings.Contains(eventType, "ssh_command"):
			targetType = audit.TargetResource
		}
		_ = s.auditRecorder.Record(context.Background(), &audit.AuditEvent{
			EventType:    auditEventType,
			ActorType:    actorType,
			ActorName:    username,
			TargetType:   targetType,
			TargetID:     "sftp",
			Protocol:     "sftp",
			ClientIP:     clientIP.String(),
			Result:       result,
			ErrorMessage: errMsg,
		})
	}
}

func (s *Server) mapToAuditEventType(eventType, result string) audit.EventType {
	switch {
	case strings.Contains(eventType, "password_auth"):
		if result == "success" {
			return audit.LoginSuccess
		}
		return audit.LoginFailed
	case strings.Contains(eventType, "publickey_auth"):
		if result == "success" {
			return audit.LoginSuccess
		}
		return audit.LoginFailed
	case strings.Contains(eventType, "cert_auth"):
		if result == "success" {
			return audit.LoginSuccess
		}
		return audit.LoginFailed
	case strings.Contains(eventType, "kbi_auth"):
		if result == "success" {
			return audit.MFASuccess
		}
		return audit.MFAFailed
	case strings.Contains(eventType, "sftp_session"):
		if result == "success" {
			return audit.LoginSuccess
		}
		return audit.LoginFailed
	default:
		return audit.EventType(eventType)
	}
}

func remoteIP(addr net.Addr) net.IP {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	if ip := net.ParseIP(addr.String()); ip != nil {
		return ip
	}
	return net.IPv4(127, 0, 0, 1)
}

func newProtocolSessionID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
