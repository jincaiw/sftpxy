package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/defender"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/storage"
	"github.com/jincaiw/sftpxy/internal/storage/local"
	"go.uber.org/zap"
)

// Server represents the FTP/FTPS server
type Server struct {
	config       config.FTPConfig
	logger       *zap.Logger
	authService  *auth.AuthenticationService
	policyEngine *policy.PolicyEngine
	auditRepo    repository.AuditRepository
	sessionRepo  repository.SessionRepository
	userRepo     repository.UserRepository
	hookManager  *hooks.HookManager
	defender     *defender.Defender
	listener     net.Listener
	tlsConfig    *tls.Config
}

// SetHookManager sets the hook manager for file and connection events
func (s *Server) SetHookManager(hm *hooks.HookManager) {
	s.hookManager = hm
}

// SetDefender sets the brute-force defender
func (s *Server) SetDefender(d *defender.Defender) {
	s.defender = d
}

type connectionState struct {
	username        string
	user            *repository.User
	sessionID       string
	clientIP        net.IP
	secure          bool
	currentDir      string
	dataProtection  string
	passiveListener net.Listener
	renameFromPath  string
	fs              *local.LocalFileSystem
}

// NewServer creates a new FTP/FTPS server
func NewServer(
	cfg config.FTPConfig,
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

// Start starts the FTP server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("FTP server is disabled")
		return nil
	}
	if s.config.ListenPort < 0 || s.config.ListenPort > 65535 {
		return fmt.Errorf("ftp listen_port must be between 0 and 65535")
	}
	if s.config.PassivePortStart > 0 && s.config.PassivePortEnd > 0 && s.config.PassivePortEnd < s.config.PassivePortStart {
		return fmt.Errorf("ftp passive_port_end must be greater than or equal to passive_port_start")
	}
	if s.config.NATExternalAddress != "" && net.ParseIP(s.config.NATExternalAddress) == nil {
		return fmt.Errorf("ftp nat_external_address must be a valid IP address")
	}

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return err
	}
	s.tlsConfig = tlsConfig

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	listener, err := s.newListener(addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.logger.Info("FTP server started",
		zap.String("address", addr),
		zap.Bool("explicit_tls", s.config.ExplicitTLS),
		zap.Bool("implicit_tls", s.tlsConfig != nil && !s.config.ExplicitTLS),
	)

	go s.acceptConnections(ctx)

	return nil
}

// Shutdown gracefully shuts down the FTP server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.listener != nil {
		s.logger.Info("Shutting down FTP server")
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
				s.logger.Error("Failed to accept FTP connection", zap.Error(err))
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) newListener(addr string) (net.Listener, error) {
	if s.tlsConfig != nil && !s.config.ExplicitTLS {
		return tls.Listen("tcp4", addr, s.tlsConfig)
	}

	if s.config.ForceControlTLS && s.tlsConfig == nil {
		return nil, fmt.Errorf("force_control_tls requires TLS certificates")
	}

	if s.config.ForceDataTLS && s.tlsConfig == nil {
		return nil, fmt.Errorf("force_data_tls requires TLS certificates")
	}

	return net.Listen("tcp4", addr)
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	if s.config.TLSCertFile == "" && s.config.TLSKeyFile == "" {
		return nil, nil
	}

	if s.config.TLSCertFile == "" || s.config.TLSKeyFile == "" {
		return nil, fmt.Errorf("both ftp tls_cert_file and tls_key_file must be configured")
	}

	cert, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load FTP TLS certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (s *Server) handleConnection(conn net.Conn) {
	client := conn
	reader := bufio.NewReader(client)
	writer := bufio.NewWriter(client)
	state := &connectionState{
		clientIP:       remoteIP(conn.RemoteAddr()),
		secure:         isTLSConn(client),
		currentDir:     "/",
		dataProtection: "C",
	}
	defer func() {
		s.closePassiveListener(state)
		s.closeSession(state.sessionID)
		_ = client.Close()
	}()

	s.writeResponse(writer, 220, "SFTPxy FTP service ready")

	for {
		if s.config.IdleTimeout > 0 {
			_ = client.SetDeadline(time.Now().Add(time.Duration(s.config.IdleTimeout) * time.Second))
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		command, argument := splitCommand(line)
		switch command {
		case "AUTH":
			if strings.ToUpper(argument) != "TLS" {
				s.writeResponse(writer, 504, "Unsupported AUTH mechanism")
				continue
			}
			if s.tlsConfig == nil || !s.config.ExplicitTLS {
				s.writeResponse(writer, 534, "TLS is not available")
				continue
			}
			if state.secure {
				s.writeResponse(writer, 503, "TLS already active")
				continue
			}

			s.writeResponse(writer, 234, "AUTH TLS successful")

			tlsConn := tls.Server(client, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.logger.Warn("FTP TLS handshake failed", zap.Error(err))
				return
			}

			client = tlsConn
			reader = bufio.NewReader(client)
			writer = bufio.NewWriter(client)
			state.secure = true

		case "USER":
			state.username = argument
			if state.username == "" {
				s.writeResponse(writer, 501, "Username is required")
				continue
			}
			s.writeResponse(writer, 331, "Username accepted, send password")

		case "PASS":
			if state.username == "" {
				s.writeResponse(writer, 503, "Send USER first")
				continue
			}
			if s.config.ForceControlTLS && !state.secure {
				s.writeResponse(writer, 534, "TLS is required before authentication")
				s.recordAudit(state.username, state.clientIP, "failure", "TLS is required before authentication")
				continue
			}

			// Check defender before authentication
			if s.defender != nil && s.defender.IsBlocked(state.clientIP.String()) {
				s.writeResponse(writer, 530, "Access denied")
				s.recordAudit(state.username, state.clientIP, "failure", "IP is blocked by defender")
				continue
			}

			user, err := s.authenticateUser(context.Background(), state.username, argument, state.clientIP)
			if err != nil {
				s.logger.Warn("FTP authentication failed",
					zap.String("user", state.username),
					zap.String("ip", state.clientIP.String()),
					zap.Error(err),
				)
				// Record failure in defender
				if s.defender != nil {
					s.defender.RecordFailure(state.clientIP.String(), "ftp")
				}
				s.writeResponse(writer, 530, err.Error())
				continue
			}
			if state.sessionID != "" {
				s.closeSession(state.sessionID)
				state.sessionID = ""
			}
			state.sessionID = newProtocolSessionID("ftp")
			s.openSession(state.sessionID, user.ID, "ftp", state.clientIP.String())
			state.user = user

			// Cache filesystem instance after successful authentication
			fs, fsErr := s.userFileSystem(user)
			if fsErr != nil {
				s.logger.Error("Failed to initialize user filesystem",
					zap.String("user", user.Username),
					zap.Error(fsErr),
				)
			} else {
				state.fs = fs
			}

			s.logger.Info("FTP login successful",
				zap.String("user", user.Username),
				zap.String("ip", state.clientIP.String()),
				zap.Bool("secure", state.secure),
			)
			if s.userRepo != nil {
				s.userRepo.UpdateLastLogin(context.Background(), user.ID)
			}
			s.writeResponse(writer, 230, "Login successful")

		case "FEAT":
			s.writeRaw(writer, "211-Features:\r\n")
			if s.tlsConfig != nil && s.config.ExplicitTLS {
				s.writeRaw(writer, " AUTH TLS\r\n")
			}
			if s.tlsConfig != nil {
				s.writeRaw(writer, " PBSZ\r\n")
				s.writeRaw(writer, " PROT\r\n")
			}
			s.writeRaw(writer, " EPSV\r\n")
			s.writeRaw(writer, " PASV\r\n")
			s.writeRaw(writer, " UTF8\r\n")
			s.writeRaw(writer, " DELE\r\n")
			s.writeRaw(writer, " MKD\r\n")
			s.writeRaw(writer, " RMD\r\n")
			s.writeRaw(writer, " CDUP\r\n")
			s.writeRaw(writer, " RNFR\r\n")
			s.writeRaw(writer, " RNTO\r\n")
			s.writeRaw(writer, " ABOR\r\n")
			s.writeRaw(writer, "211 End\r\n")

		case "PBSZ":
			if !state.secure {
				s.writeResponse(writer, 503, "TLS is not active")
				continue
			}
			if argument != "0" {
				s.writeResponse(writer, 501, "PBSZ must be 0")
				continue
			}
			s.writeResponse(writer, 200, "PBSZ=0 successful")

		case "PROT":
			if !state.secure {
				s.writeResponse(writer, 503, "TLS is not active")
				continue
			}
			switch strings.ToUpper(argument) {
			case "C":
				if s.config.ForceDataTLS {
					s.writeResponse(writer, 534, "Data TLS is required")
					continue
				}
				state.dataProtection = "C"
				s.closePassiveListener(state)
				s.writeResponse(writer, 200, "Data channel protection set to Clear")
			case "P":
				state.dataProtection = "P"
				s.closePassiveListener(state)
				s.writeResponse(writer, 200, "Data channel protection set to Private")
			default:
				s.writeResponse(writer, 536, "Unsupported PROT level")
			}

		case "SYST":
			s.writeResponse(writer, 215, "UNIX Type: L8")
		case "TYPE", "PWD", "CWD":
			if !authenticated(s, writer, state.user) {
				continue
			}
			fs, err := s.getFileSystem(state)
			if err != nil {
				s.writeResponse(writer, 550, err.Error())
				continue
			}
			switch command {
			case "TYPE":
				s.writeResponse(writer, 200, "Type set")
			case "PWD":
				s.writeResponse(writer, 257, fmt.Sprintf("%q is the current directory", state.currentDir))
			case "CWD":
				targetPath := resolveFTPPath(state.currentDir, argument)
				info, statErr := fs.Stat(context.Background(), targetPath)
				if statErr != nil || !info.IsDir {
					s.writeResponse(writer, 550, "Directory not available")
					continue
				}
				state.currentDir = targetPath
				s.touchSession(state.sessionID)
				s.writeResponse(writer, 250, "Directory changed")
			}
		case "PASV", "EPSV":
			if !authenticated(s, writer, state.user) {
				continue
			}
			listener, err := s.openPassiveListener(state)
			if err != nil {
				s.writeResponse(writer, 425, err.Error())
				continue
			}
			tcpAddr, ok := listener.Addr().(*net.TCPAddr)
			if !ok {
				s.closePassiveListener(state)
				s.writeResponse(writer, 425, "Passive listener is unavailable")
				continue
			}
			if command == "EPSV" {
				s.writeResponse(writer, 229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", tcpAddr.Port))
				continue
			}
			hostIP := s.passiveAdvertiseIP(tcpAddr)
			if hostIP == nil {
				s.closePassiveListener(state)
				s.writeResponse(writer, 425, "Passive mode requires an IPv4 address")
				continue
			}
			octets := hostIP.To4()
			s.writeResponse(writer, 227, fmt.Sprintf(
				"Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
				octets[0], octets[1], octets[2], octets[3], tcpAddr.Port/256, tcpAddr.Port%256,
			))
		case "NOOP":
			s.writeResponse(writer, 200, "NOOP ok")
		case "QUIT":
			s.writeResponse(writer, 221, "Goodbye")
			return
		case "LIST", "NLST":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleListCommand(state, writer, command, argument)
		case "RETR":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleRetrieveCommand(state, writer, argument)
		case "STOR":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleStoreCommand(state, writer, argument)
		case "SIZE":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleSizeCommand(state, writer, argument)
		case "DELE":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleDeleCommand(state, writer, argument)
		case "MKD":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleMkdCommand(state, writer, argument)
		case "RMD":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleRmdCommand(state, writer, argument)
		case "CDUP":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleCdupCommand(state, writer)
		case "RNFR":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleRnfrCommand(state, writer, argument)
		case "RNTO":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.handleRntoCommand(state, writer, argument)
		case "ABOR":
			s.closePassiveListener(state)
			s.writeResponse(writer, 226, "Abort successful")
		case "MLSD", "MLST", "PORT", "EPRT", "APPE":
			if !authenticated(s, writer, state.user) {
				continue
			}
			s.writeResponse(writer, 502, "Command not implemented in minimal FTP mode")
		default:
			s.writeResponse(writer, 500, "Unsupported command")
		}
	}
}

func (s *Server) handleListCommand(state *connectionState, writer *bufio.Writer, command, argument string) {
	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)
	info, err := fs.Stat(context.Background(), targetPath)
	if err != nil {
		s.recordCommand(state.user.Username, command, targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "Path not available")
		return
	}

	var listing strings.Builder
	if info.IsDir {
		entries, listErr := fs.ListDir(context.Background(), targetPath)
		if listErr != nil {
			s.recordCommand(state.user.Username, command, targetPath, "failure", listErr.Error())
			s.writeResponse(writer, 550, "Directory is not available")
			return
		}
		for _, entry := range entries {
			if command == "NLST" {
				listing.WriteString(entry.Name)
				listing.WriteString("\r\n")
				continue
			}
			listing.WriteString(formatListEntry(entry))
		}
	} else if command == "NLST" {
		listing.WriteString(info.Name)
		listing.WriteString("\r\n")
	} else {
		listing.WriteString(formatListEntry(info))
	}

	err = s.handleDataTransfer(state, writer, command, targetPath, func(conn net.Conn) (int64, error) {
		written, writeErr := io.Copy(conn, strings.NewReader(listing.String()))
		return written, writeErr
	})
	if err != nil {
		s.recordCommand(state.user.Username, command, targetPath, "failure", err.Error())
		return
	}

	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, command, targetPath, "success", "")
}

func (s *Server) handleRetrieveCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for download
	if !s.checkOperationAllowed(state, policy.OpDownload, targetPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	// Pre-download hook
	if hookErr := s.fireFileEvent(hooks.FileEventPreDownload, state, targetPath, 0, false); hookErr != nil {
		s.writeResponse(writer, 550, hookErr.Error())
		return
	}

	file, err := fs.Open(context.Background(), targetPath)
	if err != nil {
		s.recordCommand(state.user.Username, "RETR", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "File is not available")
		return
	}
	defer file.Close()

	info, err := fs.Stat(context.Background(), targetPath)
	if err != nil {
		s.recordCommand(state.user.Username, "RETR", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "File metadata is not available")
		return
	}

	err = s.handleDataTransfer(state, writer, "RETR", targetPath, func(conn net.Conn) (int64, error) {
		return io.Copy(conn, file)
	})
	if err != nil {
		s.recordCommand(state.user.Username, "RETR", targetPath, "failure", err.Error())
		return
	}

	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, "RETR", targetPath, "success", "")
	s.recordTransfer(state, "download", targetPath, info.Size, info.Size, "success", "")

	// Post-download hook (async)
	s.fireFileEventAsync(hooks.FileEventDownload, state, targetPath, info.Size, false)
}

func (s *Server) handleStoreCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for upload
	if !s.checkOperationAllowed(state, policy.OpUpload, targetPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	// Pre-upload hook
	if hookErr := s.fireFileEvent(hooks.FileEventPreUpload, state, targetPath, 0, false); hookErr != nil {
		s.writeResponse(writer, 550, hookErr.Error())
		return
	}

	file, err := fs.Create(context.Background(), targetPath)
	if err != nil {
		s.recordCommand(state.user.Username, "STOR", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "Unable to create file")
		return
	}

	var bytesWritten int64
	err = s.handleDataTransfer(state, writer, "STOR", targetPath, func(conn net.Conn) (int64, error) {
		defer file.Close()
		written, copyErr := io.Copy(file, conn)
		bytesWritten = written
		return written, copyErr
	})
	if err != nil {
		s.recordCommand(state.user.Username, "STOR", targetPath, "failure", err.Error())
		s.recordTransfer(state, "upload", targetPath, 0, bytesWritten, "failure", err.Error())
		return
	}

	info, statErr := fs.Stat(context.Background(), targetPath)
	if statErr == nil {
		bytesWritten = info.Size
	}
	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, "STOR", targetPath, "success", "")
	s.recordTransfer(state, "upload", targetPath, bytesWritten, bytesWritten, "success", "")

	// Post-upload hook (async)
	s.fireFileEventAsync(hooks.FileEventUpload, state, targetPath, bytesWritten, false)
}

func (s *Server) handleSizeCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}
	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}
	targetPath := resolveFTPPath(state.currentDir, argument)
	info, err := fs.Stat(context.Background(), targetPath)
	if err != nil || info.IsDir {
		s.writeResponse(writer, 550, "File is not available")
		return
	}
	s.touchSession(state.sessionID)
	s.writeResponse(writer, 213, fmt.Sprintf("%d", info.Size))
}

func (s *Server) handleDataTransfer(state *connectionState, writer *bufio.Writer, command, _ string, transfer func(conn net.Conn) (int64, error)) error {
	if state.passiveListener == nil {
		s.writeResponse(writer, 425, "Use PASV or EPSV first")
		return errors.New("passive listener is not ready")
	}
	if s.config.ForceDataTLS && state.dataProtection != "P" {
		s.writeResponse(writer, 534, "PROT P is required for data transfers")
		return errors.New("data channel protection is required")
	}

	s.writeResponse(writer, 150, fmt.Sprintf("Opening data connection for %s", command))
	dataConn, err := s.acceptDataConn(state)
	if err != nil {
		s.writeResponse(writer, 425, "Unable to open data connection")
		return err
	}
	defer dataConn.Close()
	defer s.closePassiveListener(state)

	if s.config.IdleTimeout > 0 {
		_ = dataConn.SetDeadline(time.Now().Add(time.Duration(s.config.IdleTimeout) * time.Second))
	}

	if _, err := transfer(dataConn); err != nil {
		s.writeResponse(writer, 551, "Data transfer failed")
		return err
	}

	s.writeResponse(writer, 226, "Transfer complete")
	return nil
}

func (s *Server) openPassiveListener(state *connectionState) (net.Listener, error) {
	s.closePassiveListener(state)

	bindHost := s.passiveBindHost()
	if s.config.PassivePortStart > 0 && s.config.PassivePortEnd >= s.config.PassivePortStart {
		for port := s.config.PassivePortStart; port <= s.config.PassivePortEnd; port++ {
			listener, listenErr := s.listenPassiveAddress(state, fmt.Sprintf("%s:%d", bindHost, port))
			if listenErr == nil {
				state.passiveListener = listener
				return listener, nil
			}
		}
		return nil, fmt.Errorf("no passive ports available")
	}

	listener, err := s.listenPassiveAddress(state, net.JoinHostPort(bindHost, "0"))
	if err != nil {
		return nil, err
	}
	state.passiveListener = listener
	return listener, nil
}

func (s *Server) listenPassiveAddress(state *connectionState, addr string) (net.Listener, error) {
	if state.secure && state.dataProtection == "P" {
		if s.tlsConfig == nil {
			return nil, fmt.Errorf("data TLS is not configured")
		}
		return tls.Listen("tcp4", addr, s.tlsConfig)
	}
	return net.Listen("tcp4", addr)
}

func (s *Server) acceptDataConn(state *connectionState) (net.Conn, error) {
	type acceptResult struct {
		conn net.Conn
		err  error
	}

	resultCh := make(chan acceptResult, 1)
	go func(listener net.Listener) {
		conn, err := listener.Accept()
		resultCh <- acceptResult{conn: conn, err: err}
	}(state.passiveListener)

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-time.After(5 * time.Second):
		s.closePassiveListener(state)
		return nil, fmt.Errorf("timed out waiting for passive data connection")
	}
}

func (s *Server) closePassiveListener(state *connectionState) {
	if state == nil || state.passiveListener == nil {
		return
	}
	_ = state.passiveListener.Close()
	state.passiveListener = nil
}

func (s *Server) passiveBindHost() string {
	host := strings.TrimSpace(s.config.ListenAddress)
	if host == "" {
		return "0.0.0.0"
	}
	if host == "::" {
		return "0.0.0.0"
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "0.0.0.0"
		}
		return ip.To4().String()
	}
	return "0.0.0.0"
}

func (s *Server) passiveAdvertiseIP(tcpAddr *net.TCPAddr) net.IP {
	if external := strings.TrimSpace(s.config.NATExternalAddress); external != "" {
		return net.ParseIP(external).To4()
	}
	if tcpAddr != nil && tcpAddr.IP != nil && !tcpAddr.IP.IsUnspecified() {
		return tcpAddr.IP.To4()
	}
	if listenerAddr, ok := s.listener.Addr().(*net.TCPAddr); ok && listenerAddr.IP != nil {
		return listenerAddr.IP.To4()
	}
	return net.ParseIP("127.0.0.1").To4()
}

func (s *Server) userFileSystem(user *repository.User) (*local.LocalFileSystem, error) {
	if user == nil {
		return nil, fmt.Errorf("user is not authenticated")
	}
	if err := os.MkdirAll(user.HomeDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to prepare user home: %w", err)
	}
	fs := local.NewLocalFileSystem(user.HomeDir, true)
	if err := fs.HealthCheck(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to access user home: %w", err)
	}
	return fs, nil
}

func resolveFTPPath(currentDir, argument string) string {
	base := strings.TrimSpace(currentDir)
	if base == "" {
		base = "/"
	}
	trimmed := strings.TrimSpace(argument)
	if trimmed == "" {
		return base
	}

	if strings.HasPrefix(trimmed, "/") {
		return cleanFTPPath(trimmed)
	}
	return cleanFTPPath(path.Join(base, trimmed))
}

func cleanFTPPath(value string) string {
	cleaned := path.Clean("/" + strings.TrimPrefix(value, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func formatListEntry(info *storage.FileInfo) string {
	return fmt.Sprintf(
		"%s 1 ftp ftp %12d %s %s\r\n",
		info.Mode.String(),
		info.Size,
		info.ModTime.Format("Jan _2 15:04"),
		info.Name,
	)
}

func (s *Server) authenticateUser(ctx context.Context, username, password string, clientIP net.IP) (*repository.User, error) {
	result, err := s.authService.LoginUser(ctx, username, password)
	if err != nil || result == nil || !result.Success || result.User == nil {
		s.recordAudit(username, clientIP, "failure", "invalid credentials")
		return nil, fmt.Errorf("authentication failed")
	}

	if s.policyEngine != nil {
		if allowed, policyErr := s.policyEngine.CanAuthenticate(ctx, policy.AuthRequest{
			Username:   username,
			Protocol:   "ftp",
			ClientIP:   clientIP,
			AuthMethod: "password",
		}); policyErr != nil || !allowed {
			reason := "protocol access denied"
			if policyErr != nil {
				reason = policyErr.Error()
			}
			s.recordAudit(username, clientIP, "failure", reason)
			return nil, errors.New(reason)
		}
	}

	s.recordAudit(username, clientIP, "success", "")
	return result.User, nil
}

func (s *Server) recordAudit(username string, clientIP net.IP, result, errMsg string) {
	if s.auditRepo == nil {
		return
	}

	_, _ = s.auditRepo.CreateAuditLog(context.Background(), &repository.AuditLog{
		EventID:      fmt.Sprintf("ftp-%d", time.Now().UnixNano()),
		EventType:    "ftp_login",
		ActorType:    "user",
		ActorName:    username,
		TargetType:   "protocol",
		TargetID:     "ftp",
		Protocol:     "ftp",
		ClientIP:     clientIP.String(),
		Result:       result,
		ErrorMessage: errMsg,
	})
}

func (s *Server) writeResponse(writer *bufio.Writer, code int, message string) {
	s.writeRaw(writer, fmt.Sprintf("%d %s\r\n", code, message))
}

func (s *Server) writeRaw(writer *bufio.Writer, message string) {
	_, _ = writer.WriteString(message)
	_ = writer.Flush()
}

func splitCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}

	command, argument, found := strings.Cut(line, " ")
	if !found {
		return strings.ToUpper(command), ""
	}

	return strings.ToUpper(command), strings.TrimSpace(argument)
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

func isTLSConn(conn net.Conn) bool {
	_, ok := conn.(*tls.Conn)
	return ok
}

func newProtocolSessionID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func authenticated(s *Server, writer *bufio.Writer, user *repository.User) bool {
	if user != nil {
		return true
	}
	s.writeResponse(writer, 530, "Please login with USER and PASS")
	return false
}

func (s *Server) openSession(sessionID string, userID int64, protocol, clientIP string) {
	if s.sessionRepo == nil || sessionID == "" {
		return
	}
	if err := s.sessionRepo.CreateSession(context.Background(), sessionID, userID, protocol, clientIP); err != nil {
		s.logger.Warn("Failed to create FTP session record", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *Server) touchSession(sessionID string) {
	if s.sessionRepo == nil || sessionID == "" {
		return
	}
	if err := s.sessionRepo.TouchSession(context.Background(), sessionID); err != nil {
		s.logger.Warn("Failed to touch FTP session record", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *Server) closeSession(sessionID string) {
	if s.sessionRepo == nil || sessionID == "" {
		return
	}
	if err := s.sessionRepo.DeactivateSession(context.Background(), sessionID); err != nil {
		s.logger.Warn("Failed to deactivate FTP session record", zap.String("session_id", sessionID), zap.Error(err))
	}
}

func (s *Server) recordCommand(username, command, path, result, errMsg string) {
	if s.auditRepo == nil {
		return
	}
	_ = s.auditRepo.CreateCommandLog(context.Background(), command, username, "ftp", path, "", result, errMsg)
}

func (s *Server) recordTransfer(state *connectionState, operation, filePath string, fileSize, bytesTransferred int64, status, errMsg string) {
	if s.auditRepo == nil || state == nil {
		return
	}
	now := time.Now()
	_, _ = s.auditRepo.CreateTransferLog(context.Background(), &repository.TransferLog{
		Operation:        operation,
		Username:         state.username,
		Protocol:         "ftp",
		ConnectionID:     state.sessionID,
		LocalAddress:     s.listener.Addr().String(),
		RemoteAddress:    state.clientIP.String(),
		FilePath:         filePath,
		FileSize:         fileSize,
		BytesTransferred: bytesTransferred,
		StartTime:        now,
		EndTime:          now,
		Status:           status,
		Error:            errMsg,
		FTPMode:          "passive",
	})
}

// getFileSystem returns the cached filesystem from connectionState, or creates one if not cached
func (s *Server) getFileSystem(state *connectionState) (*local.LocalFileSystem, error) {
	if state.fs != nil {
		return state.fs, nil
	}
	return s.userFileSystem(state.user)
}

// checkOperationAllowed checks if the operation is allowed by the policy engine
func (s *Server) checkOperationAllowed(state *connectionState, op policy.OperationType, filePath string, fileSize int64) bool {
	if s.policyEngine == nil {
		return true
	}
	allowed, err := s.policyEngine.CanPerformOperation(context.Background(), policy.OperationRequest{
		UserID:    state.user.ID,
		Username:  state.user.Username,
		Protocol:  "ftp",
		ClientIP:  state.clientIP,
		Operation: op,
		FilePath:  filePath,
		FileSize:  fileSize,
	})
	if err != nil || !allowed {
		return false
	}
	return true
}

// fireFileEvent fires a synchronous file event hook
func (s *Server) fireFileEvent(event hooks.FileEvent, state *connectionState, filePath string, fileSize int64, isDir bool) error {
	if s.hookManager == nil {
		return nil
	}
	return s.hookManager.OnFileEvent(context.Background(), event, &hooks.FileEventPayload{
		Event:     event,
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		FileSize:  fileSize,
		Username:  state.user.Username,
		UserID:    state.user.ID,
		Protocol:  "ftp",
		ClientIP:  state.clientIP.String(),
		IsDir:     isDir,
		Timestamp: time.Now(),
	})
}

// fireFileEventAsync fires an asynchronous file event hook
func (s *Server) fireFileEventAsync(event hooks.FileEvent, state *connectionState, filePath string, fileSize int64, isDir bool) {
	if s.hookManager == nil {
		return
	}
	go func() {
		_ = s.hookManager.OnFileEvent(context.Background(), event, &hooks.FileEventPayload{
			Event:     event,
			FilePath:  filePath,
			FileName:  filepath.Base(filePath),
			FileSize:  fileSize,
			Username:  state.user.Username,
			UserID:    state.user.ID,
			Protocol:  "ftp",
			ClientIP:  state.clientIP.String(),
			IsDir:     isDir,
			Timestamp: time.Now(),
		})
	}()
}

// handleDeleCommand handles the DELE (delete file) command
func (s *Server) handleDeleCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for delete
	if !s.checkOperationAllowed(state, policy.OpDelete, targetPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	// Pre-delete hook
	if hookErr := s.fireFileEvent(hooks.FileEventPreDelete, state, targetPath, 0, false); hookErr != nil {
		s.writeResponse(writer, 550, hookErr.Error())
		return
	}

	if err := fs.Delete(context.Background(), targetPath); err != nil {
		s.recordCommand(state.user.Username, "DELE", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "Unable to delete file")
		return
	}

	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, "DELE", targetPath, "success", "")
	s.writeResponse(writer, 250, "File deleted")

	// Post-delete hook (async)
	s.fireFileEventAsync(hooks.FileEventDelete, state, targetPath, 0, false)
}

// handleMkdCommand handles the MKD (make directory) command
func (s *Server) handleMkdCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for mkdir
	if !s.checkOperationAllowed(state, policy.OpMkdir, targetPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	if err := fs.Mkdir(context.Background(), targetPath); err != nil {
		s.recordCommand(state.user.Username, "MKD", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "Unable to create directory")
		return
	}

	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, "MKD", targetPath, "success", "")
	s.writeResponse(writer, 257, fmt.Sprintf("%q created", targetPath))

	// Post-mkdir hook (async)
	s.fireFileEventAsync(hooks.FileEventMkdir, state, targetPath, 0, true)
}

// handleRmdCommand handles the RMD (remove directory) command
func (s *Server) handleRmdCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for delete (rmdir uses OpDelete)
	if !s.checkOperationAllowed(state, policy.OpDelete, targetPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	// Pre-delete hook
	if hookErr := s.fireFileEvent(hooks.FileEventPreDelete, state, targetPath, 0, true); hookErr != nil {
		s.writeResponse(writer, 550, hookErr.Error())
		return
	}

	if err := fs.Rmdir(context.Background(), targetPath); err != nil {
		s.recordCommand(state.user.Username, "RMD", targetPath, "failure", err.Error())
		s.writeResponse(writer, 550, "Unable to remove directory")
		return
	}

	s.touchSession(state.sessionID)
	s.recordCommand(state.user.Username, "RMD", targetPath, "success", "")
	s.writeResponse(writer, 250, "Directory removed")

	// Post-rmdir hook (async)
	s.fireFileEventAsync(hooks.FileEventRmdir, state, targetPath, 0, true)
}

// handleCdupCommand handles the CDUP (change to parent directory) command
func (s *Server) handleCdupCommand(state *connectionState, writer *bufio.Writer) {
	parentDir := path.Dir(state.currentDir)
	if parentDir == "." || parentDir == "" {
		parentDir = "/"
	}
	state.currentDir = parentDir
	s.touchSession(state.sessionID)
	s.writeResponse(writer, 250, "Directory changed to parent")
}

// handleRnfrCommand handles the RNFR (rename from) command - first step of rename
func (s *Server) handleRnfrCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Verify the source path exists
	_, statErr := fs.Stat(context.Background(), targetPath)
	if statErr != nil {
		s.writeResponse(writer, 550, "File or directory not found")
		return
	}

	state.renameFromPath = targetPath
	s.writeResponse(writer, 350, "Ready for RNTO")
}

// handleRntoCommand handles the RNTO (rename to) command - second step of rename
func (s *Server) handleRntoCommand(state *connectionState, writer *bufio.Writer, argument string) {
	if state.renameFromPath == "" {
		s.writeResponse(writer, 503, "Send RNFR first")
		return
	}

	if strings.TrimSpace(argument) == "" {
		s.writeResponse(writer, 501, "Path is required")
		return
	}

	fs, err := s.getFileSystem(state)
	if err != nil {
		s.writeResponse(writer, 550, err.Error())
		return
	}

	targetPath := resolveFTPPath(state.currentDir, argument)

	// Policy check for rename
	if !s.checkOperationAllowed(state, policy.OpRename, state.renameFromPath, 0) {
		s.writeResponse(writer, 550, "Permission denied")
		return
	}

	// Pre-rename hook
	if hookErr := s.fireFileEvent(hooks.FileEventRename, state, state.renameFromPath, 0, false); hookErr != nil {
		state.renameFromPath = ""
		s.writeResponse(writer, 550, hookErr.Error())
		return
	}

	if err := fs.Rename(context.Background(), state.renameFromPath, targetPath); err != nil {
		s.recordCommand(state.user.Username, "RNFR", state.renameFromPath, "failure", err.Error())
		state.renameFromPath = ""
		s.writeResponse(writer, 550, "Unable to rename")
		return
	}

	renameFrom := state.renameFromPath
	s.recordCommand(state.user.Username, "RNFR", renameFrom, "success", "")
	s.touchSession(state.sessionID)
	state.renameFromPath = ""
	s.writeResponse(writer, 250, "Renamed successfully")

	// Post-rename hook (async) - fire with newPath in NewPath field
	s.fireRenameEventAsync(state, renameFrom, targetPath)
}

// fireRenameEventAsync fires an async rename hook event with both old and new paths
func (s *Server) fireRenameEventAsync(state *connectionState, oldPath, newPath string) {
	if s.hookManager == nil {
		return
	}
	go func() {
		_ = s.hookManager.OnFileEvent(context.Background(), hooks.FileEventRename, &hooks.FileEventPayload{
			Event:     hooks.FileEventRename,
			FilePath:  oldPath,
			FileName:  filepath.Base(oldPath),
			NewPath:   newPath,
			Username:  state.user.Username,
			UserID:    state.user.ID,
			Protocol:  "ftp",
			ClientIP:  state.clientIP.String(),
			Timestamp: time.Now(),
		})
	}()
}
