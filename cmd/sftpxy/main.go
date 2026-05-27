package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sftpxy/sftpxy/internal/auth"
	"github.com/sftpxy/sftpxy/internal/config"
	"github.com/sftpxy/sftpxy/internal/database"
	"github.com/sftpxy/sftpxy/internal/events"
	"github.com/sftpxy/sftpxy/internal/logger"
	"github.com/sftpxy/sftpxy/internal/metrics"
	"github.com/sftpxy/sftpxy/internal/policy"
	"github.com/sftpxy/sftpxy/internal/protocols/ftp"
	"github.com/sftpxy/sftpxy/internal/protocols/httpd"
	sshd "github.com/sftpxy/sftpxy/internal/protocols/ssh"
	"github.com/sftpxy/sftpxy/internal/protocols/webdav"
	"github.com/sftpxy/sftpxy/internal/repository"
	"go.uber.org/zap"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logger.NewLogger(cfg.Common)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Info("Starting SFTPxy", zap.String("version", "0.1.0"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Database
	db, err := database.NewDB(cfg.DataProvider)
	if err != nil {
		log.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer db.Close()

	if err := db.HealthCheck(ctx); err != nil {
		log.Warn("Database health check failed", zap.Error(err))
	} else {
		log.Info("Database connected", zap.String("driver", db.Driver()))
	}

	// Repositories
	userRepo := repository.NewUserRepository(db)
	adminRepo := repository.NewAdminRepository(db)
	_ = repository.NewAuditRepository(db)

	// Auth & Policy
	authService := auth.NewAuthenticationService(userRepo, adminRepo)
	policyEngine := policy.NewPolicyEngine(userRepo)

	// Event Manager
	eventManager := events.NewManager(log, cfg.Commands.Whitelist)
	defer eventManager.Shutdown(ctx)

	// Metrics Collector
	metricsCollector := metrics.NewCollector(cfg.Telemetry, log)
	if err := metricsCollector.Start(ctx); err != nil {
		log.Warn("Failed to start metrics collector", zap.Error(err))
	}

	// SSH/SFTP Server
	sshServer := sshd.NewServer(cfg.SSH, log, authService, policyEngine, userRepo)
	if err := sshServer.Start(ctx); err != nil {
		log.Fatal("Failed to start SSH server", zap.Error(err))
	}

	// FTP Server
	ftpServer := ftp.NewServer(cfg.FTP, log, authService, userRepo)
	if err := ftpServer.Start(ctx); err != nil {
		log.Fatal("Failed to start FTP server", zap.Error(err))
	}

	// WebDAV Server
	webdavServer := webdav.NewServer(cfg.WebDAV, log)
	if err := webdavServer.Start(ctx); err != nil {
		log.Fatal("Failed to start WebDAV server", zap.Error(err))
	}

	// HTTP Server (WebAdmin/WebClient/API)
	httpServer := httpd.NewServer(cfg.HTTPD, log)
	if err := httpServer.Start(ctx); err != nil {
		log.Fatal("Failed to start HTTP server", zap.Error(err))
	}

	log.Info("SFTPxy is running",
		zap.Bool("ssh", cfg.SSH.Enabled),
		zap.Bool("ftp", cfg.FTP.Enabled),
		zap.Bool("webdav", cfg.WebDAV.Enabled),
		zap.Bool("http", cfg.HTTPD.Enabled),
		zap.Bool("telemetry", cfg.Telemetry.Enabled),
	)

	// Wait for signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Info("Shutting down", zap.String("signal", sig.String()))
	case <-ctx.Done():
		log.Info("Context cancelled")
	}

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30)
	defer shutdownCancel()

	sshServer.Shutdown(shutdownCtx)
	ftpServer.Shutdown(shutdownCtx)
	webdavServer.Shutdown(shutdownCtx)
	httpServer.Shutdown(shutdownCtx)
	metricsCollector.Shutdown(shutdownCtx)

	log.Info("SFTPxy stopped")
}
