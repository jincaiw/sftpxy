package metrics
package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sftpxy/sftpxy/internal/config"
	"go.uber.org/zap"
)

// Collector holds all Prometheus metrics
type Collector struct {
	config config.TelemetryConfig
	logger *zap.Logger
	server *http.Server

	// Transfer metrics
	UploadsTotal    *prometheus.CounterVec
	DownloadsTotal  *prometheus.CounterVec
	UploadBytes     *prometheus.CounterVec
	DownloadBytes   *prometheus.CounterVec
	TransferErrors  *prometheus.CounterVec

	// Connection metrics
	ActiveConnections *prometheus.GaugeVec
	AuthSuccess       *prometheus.CounterVec
	AuthFailure       *prometheus.CounterVec

	// HTTP metrics
	HTTPRequests    *prometheus.CounterVec
	HTTPDuration    *prometheus.HistogramVec

	// Event metrics
	EventExecutions *prometheus.CounterVec

	// Defender metrics
	BlockedIPs      prometheus.Gauge
	BlocksTotal     prometheus.Counter

	registry *prometheus.Registry
}

// NewCollector creates a new metrics collector
func NewCollector(cfg config.TelemetryConfig, log *zap.Logger) *Collector {
	registry := prometheus.NewRegistry()

	c := &Collector{
		config:   cfg,
		logger:   log.Named("metrics"),
		registry: registry,

		UploadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_uploads_total", Help: "Total uploads"},
			[]string{"protocol", "user"},
		),
		DownloadsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_downloads_total", Help: "Total downloads"},
			[]string{"protocol", "user"},
		),
		UploadBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_upload_bytes_total", Help: "Total upload bytes"},
			[]string{"protocol", "user"},
		),
		DownloadBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_download_bytes_total", Help: "Total download bytes"},
			[]string{"protocol", "user"},
		),
		TransferErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_transfer_errors_total", Help: "Total transfer errors"},
			[]string{"protocol", "error_type"},
		),
		ActiveConnections: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: "sftpxy_active_connections", Help: "Active connections"},
			[]string{"protocol"},
		),
		AuthSuccess: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_auth_success_total", Help: "Successful authentications"},
			[]string{"method"},
		),
		AuthFailure: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_auth_failure_total", Help: "Failed authentications"},
			[]string{"method", "reason"},
		),
		HTTPRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_http_requests_total", Help: "Total HTTP requests"},
			[]string{"method", "path", "status"},
		),
		HTTPDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: "sftpxy_http_duration_seconds", Help: "HTTP request duration"},
			[]string{"method", "path"},
		),
		EventExecutions: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_event_executions_total", Help: "Total event executions"},
			[]string{"rule", "action", "result"},
		),
		BlockedIPs: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_defender_blocked_ips", Help: "Currently blocked IPs"},
		),
		BlocksTotal: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sftpxy_defender_blocks_total", Help: "Total blocks"},
		),
	}

	// Register metrics
	registry.MustRegister(
		c.UploadsTotal, c.DownloadsTotal, c.UploadBytes, c.DownloadBytes,
		c.TransferErrors, c.ActiveConnections, c.AuthSuccess, c.AuthFailure,
		c.HTTPRequests, c.HTTPDuration, c.EventExecutions,
		c.BlockedIPs, c.BlocksTotal,
	)

	return c
}

// Start starts the telemetry server
func (c *Collector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		c.logger.Info("Telemetry server is disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", c.config.ListenAddress, c.config.ListenPort)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	c.server = &http.Server{Addr: addr, Handler: mux}

	c.logger.Info("Telemetry server started", zap.String("address", addr))

	go func() {
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			c.logger.Error("Telemetry server error", zap.Error(err))
		}
	}()

	return nil
}

// Shutdown shuts down the telemetry server
func (c *Collector) Shutdown(ctx context.Context) error {
	if c.server != nil {
		c.logger.Info("Shutting down telemetry server")
		return c.server.Shutdown(ctx)
	}
	return nil
}

// RecordUpload records an upload event
func (c *Collector) RecordUpload(protocol, user string, bytes int64) {
	c.UploadsTotal.WithLabelValues(protocol, user).Inc()
	c.UploadBytes.WithLabelValues(protocol, user).Add(float64(bytes))
}

// RecordDownload records a download event
func (c *Collector) RecordDownload(protocol, user string, bytes int64) {
	c.DownloadsTotal.WithLabelValues(protocol, user).Inc()
	c.DownloadBytes.WithLabelValues(protocol, user).Add(float64(bytes))
}

// RecordTransferError records a transfer error
func (c *Collector) RecordTransferError(protocol, errorType string) {
	c.TransferErrors.WithLabelValues(protocol, errorType).Inc()
}

// SetActiveConnections sets the active connection count
func (c *Collector) SetActiveConnections(protocol string, count int) {
	c.ActiveConnections.WithLabelValues(protocol).Set(float64(count))
}

// RecordAuthSuccess records a successful authentication
func (c *Collector) RecordAuthSuccess(method string) {
	c.AuthSuccess.WithLabelValues(method).Inc()
}

// RecordAuthFailure records a failed authentication
func (c *Collector) RecordAuthFailure(method, reason string) {
	c.AuthFailure.WithLabelValues(method, reason).Inc()
}

// RecordHTTPRequest records an HTTP request
func (c *Collector) RecordHTTPRequest(method, path, status string, duration float64) {
	c.HTTPRequests.WithLabelValues(method, path, status).Inc()
	c.HTTPDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordEventExecution records an event execution
func (c *Collector) RecordEventExecution(rule, action, result string) {
	c.EventExecutions.WithLabelValues(rule, action, result).Inc()
}

// SetBlockedIPs sets the blocked IP count
func (c *Collector) SetBlockedIPs(count int) {
	c.BlockedIPs.Set(float64(count))
}

// RecordBlock records a block event
func (c *Collector) RecordBlock() {
	c.BlocksTotal.Inc()
}
