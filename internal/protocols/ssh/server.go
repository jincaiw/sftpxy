package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/pkg/sftp"
	"github.com/sftpxy/sftpxy/internal/auth"
	"github.com/sftpxy/sftpxy/internal/config"
	"github.com/sftpxy/sftpxy/internal/policy"
	"github.com/sftpxy/sftpxy/internal/repository"
	"github.com/sftpxy/sftpxy/internal/storage/local"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Server represents the SSH/SFTP/SCP server
type Server struct {
	config       config.SSHConfig
	logger       *zap.Logger
	authService  *auth.AuthenticationService
	policyEngine *policy.PolicyEngine
	userRepo     repository.UserRepository
	listener     net.Listener
	sshConfig    *ssh.ServerConfig
}

// NewServer creates a new SSH/SFTP server
func NewServer(
	cfg config.SSHConfig,
	log *zap.Logger,
	authSvc *auth.AuthenticationService,
	policyEng *policy.PolicyEngine,
	userRepo repository.UserRepository,
) *Server {
	return &Server{
		config:       cfg,
		logger:       log,
		authService:  authSvc,
		policyEngine: policyEng,
		userRepo:     userRepo,
	}
}

// Start starts the SSH/SFTP server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("SSH server is disabled")
		return nil
	}

	// Load host keys
	hostKeys, err := s.loadHostKeys()
	if err != nil {
		return fmt.Errorf("failed to load host keys: %w", err)
	}

	// Configure SSH server
	s.sshConfig = &ssh.ServerConfig{
		ServerVersion:     "SSH-2.0-SFTPxy",
		PasswordCallback:  s.passwordAuth,
		PublicKeyCallback: s.publicKeyAuth,
		MaxAuthTries:      6,
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

	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP
	s.logger.Debug("New SSH connection", zap.String("remote", conn.RemoteAddr().String()))

	// Perform SSH handshake
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

	// Discard all global requests
	go ssh.DiscardRequests(reqs)

	// Handle channels
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
			if string(req.Payload[4:]) == "sftp" {
				req.Reply(true, nil)
				s.handleSFTP(channel, sshConn, clientIP)
				return
			}
		case "exec":
			req.Reply(true, nil)
			s.handleSCP(channel, req.Payload, sshConn, clientIP)
			return
		}
	}
}

func (s *Server) handleSFTP(channel ssh.Channel, sshConn *ssh.ServerConn, _ net.IP) {
	username := sshConn.User()

	// Get user info
	user, err := s.userRepo.GetByUsername(context.Background(), username)
	if err != nil {
		s.logger.Error("Failed to get user", zap.String("username", username), zap.Error(err))
		return
	}

	// Create filesystem
	_ = local.NewLocalFileSystem(user.HomeDir, true)

	// Setup SFTP handlers
	server, err := sftp.NewServer(channel,
		sftp.WithServerWorkingDirectory("/"),
	)
	if err != nil {
		s.logger.Error("Failed to create SFTP server", zap.Error(err))
		return
	}

	// Note: Full SFTP handler implementation requires custom Handlers
	// This is a simplified version
	if err := server.Serve(); err != nil {
		if err != io.EOF {
			s.logger.Error("SFTP server error", zap.Error(err))
		}
	}
	s.logger.Debug("SFTP session ended", zap.String("user", username))
}

func (s *Server) handleSCP(channel ssh.Channel, payload []byte, sshConn *ssh.ServerConn, _ net.IP) {
	// SCP implementation would parse the command and handle file transfers
	// Simplified for now
	s.logger.Debug("SCP request received", zap.String("user", sshConn.User()))
}

func (s *Server) passwordAuth(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP

	s.logger.Debug("Password authentication attempt", zap.String("user", username))

	ctx := context.Background()
	result, err := s.authService.LoginUser(ctx, username, string(password))
	if err != nil || !result.Success {
		s.logger.Warn("Password authentication failed", zap.String("user", username), zap.String("ip", clientIP.String()))
		return nil, fmt.Errorf("authentication failed")
	}

	s.logger.Info("Password authentication successful", zap.String("user", username))
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id": fmt.Sprintf("%d", result.User.ID),
		},
	}, nil
}

func (s *Server) publicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()

	s.logger.Debug("Public key authentication attempt", zap.String("user", username))

	// For now, accept any valid public key if user exists
	// In production, verify against stored keys
	ctx := context.Background()
	user, err := s.userRepo.GetByUsername(ctx, username)
	if err != nil {
		s.logger.Warn("Public key auth: user not found", zap.String("user", username))
		return nil, fmt.Errorf("user not found")
	}

	if user.Status != "active" {
		return nil, fmt.Errorf("user disabled")
	}

	s.logger.Info("Public key authentication successful", zap.String("user", username))
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id": fmt.Sprintf("%d", user.ID),
		},
	}, nil
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
