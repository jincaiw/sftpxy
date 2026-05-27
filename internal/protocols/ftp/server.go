package ftp

import (
	"context"
	"fmt"
	"net"

	"github.com/sftpxy/sftpxy/internal/auth"
	"github.com/sftpxy/sftpxy/internal/config"
	"github.com/sftpxy/sftpxy/internal/repository"
	"go.uber.org/zap"
)

// Server represents the FTP/FTPS server
type Server struct {
	config      config.FTPConfig
	logger      *zap.Logger
	authService *auth.AuthenticationService
	userRepo    repository.UserRepository
	listener    net.Listener
}

// NewServer creates a new FTP/FTPS server
func NewServer(
	cfg config.FTPConfig,
	log *zap.Logger,
	authSvc *auth.AuthenticationService,
	userRepo repository.UserRepository,
) *Server {
	return &Server{
		config:      cfg,
		logger:      log,
		authService: authSvc,
		userRepo:    userRepo,
	}
}

// Start starts the FTP server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("FTP server is disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	s.logger.Info("FTP server started (placeholder)", zap.String("address", addr))

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
			select {
			case <-ctx.Done():
				return
			default:
				s.logger.Error("Failed to accept FTP connection", zap.Error(err))
				continue
			}
		}
		conn.Close()
	}
}
