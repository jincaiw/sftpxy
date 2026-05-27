package httpd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sftpxy/sftpxy/internal/config"
	"go.uber.org/zap"
)

// Server represents the HTTP server
type Server struct {
	config config.HTTPDConfig
	router *chi.Mux
	server *http.Server
	logger *zap.Logger
}

// NewServer creates a new HTTP server
func NewServer(cfg config.HTTPDConfig, log *zap.Logger) *Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	s := &Server{
		config: cfg,
		router: r,
		logger: log,
	}

	// Setup routes
	s.setupRoutes()

	return s
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// Health check
	s.router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// API routes
	if s.config.RESTAPIEnabled {
		s.router.Route("/api/v1", func(r chi.Router) {
			r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"status":"running"}`))
			})
		})
	}

	// OpenAPI docs
	if s.config.OpenAPIEnabled {
		s.router.Get("/openapi", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"SFTPxy API","version":"1.0.0"}}`))
		})
	}

	// Metrics endpoint (redirect to telemetry)
	s.router.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://localhost:%d/metrics", s.config.ListenPort+10), http.StatusTemporaryRedirect)
	})
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Starting HTTP server", zap.String("address", addr))

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		s.logger.Info("Shutting down HTTP server")
		return s.server.Shutdown(ctx)
	}
	return nil
}

// Router returns the chi router for adding more routes
func (s *Server) Router() *chi.Mux {
	return s.router
}
