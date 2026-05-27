package webdav

import (
	"context"
	"fmt"
	"net/http"

	"github.com/sftpxy/sftpxy/internal/config"
	"go.uber.org/zap"
	"golang.org/x/net/webdav"
)

// Server represents the WebDAV server
type Server struct {
	config config.WebDAVConfig
	logger *zap.Logger
	server *http.Server
}

// NewServer creates a new WebDAV server
func NewServer(cfg config.WebDAVConfig, log *zap.Logger) *Server {
	return &Server{
		config: cfg,
		logger: log,
	}
}

// Start starts the WebDAV server
func (s *Server) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("WebDAV server is disabled")
		return nil
	}

	handler := &webdav.Handler{
		Prefix:     s.config.BasePath,
		FileSystem: webdav.Dir("/tmp/sftpxy-webdav"),
		LockSystem: webdav.NewMemLS(),
	}

	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	s.server = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	s.logger.Info("WebDAV server started", zap.String("address", addr))

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
