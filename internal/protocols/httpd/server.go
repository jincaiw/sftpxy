package httpd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sftpxy/sftpxy/internal/config"
	"go.uber.org/zap"
)

// Server represents the HTTP server
type Server struct {
	config    config.HTTPDConfig
	router    *chi.Mux
	server    *http.Server
	logger    *zap.Logger
	startTime time.Time
	version   string
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
		config:    cfg,
		router:    r,
		logger:    log,
		startTime: time.Now(),
		version:   "1.0.0",
	}

	// Setup routes
	s.setupRoutes()

	return s
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// Health check endpoint with detailed status
	s.router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		status := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"uptime":    time.Since(s.startTime).String(),
			"version":   s.version,
		}

		json.NewEncoder(w).Encode(status)
	})

	// Detailed system status endpoint
	s.router.Get("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		status := map[string]interface{}{
			"service": "SFTPxy",
			"version": s.version,
			"uptime":  time.Since(s.startTime).String(),
			"runtime": map[string]interface{}{
				"go_version":    runtime.Version(),
				"os":            runtime.GOOS,
				"arch":          runtime.GOARCH,
				"num_goroutine": runtime.NumGoroutine(),
				"num_cpu":       runtime.NumCPU(),
			},
			"memory": map[string]interface{}{
				"alloc_mb":       float64(m.Alloc) / 1024 / 1024,
				"total_alloc_mb": float64(m.TotalAlloc) / 1024 / 1024,
				"sys_mb":         float64(m.Sys) / 1024 / 1024,
				"num_gc":         m.NumGC,
				"heap_objects":   m.HeapObjects,
			},
			"protocols": map[string]interface{}{
				"ssh_enabled":    true,
				"ftp_enabled":    true,
				"webdav_enabled": true,
				"http_enabled":   true,
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		json.NewEncoder(w).Encode(status)
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
