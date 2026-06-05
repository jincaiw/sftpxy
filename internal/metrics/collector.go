package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

// Collector holds all Prometheus metrics
type Collector struct {
	config config.TelemetryConfig
	logger *zap.Logger
	server *http.Server

	// Transfer metrics
	UploadsTotal   *prometheus.CounterVec
	DownloadsTotal *prometheus.CounterVec
	UploadBytes    *prometheus.CounterVec
	DownloadBytes  *prometheus.CounterVec
	TransferErrors *prometheus.CounterVec

	// Connection metrics
	ActiveConnections *prometheus.GaugeVec
	AuthSuccess       *prometheus.CounterVec
	AuthFailure       *prometheus.CounterVec

	// HTTP metrics
	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec

	// Event metrics
	EventExecutions *prometheus.CounterVec
	ShareAccesses   *prometheus.CounterVec

	// Defender metrics
	BlockedIPs  prometheus.Gauge
	BlocksTotal prometheus.Counter

	// SSH command metrics
	SSHCommandsTotal *prometheus.CounterVec
	SSHCommandErrors *prometheus.CounterVec

	// Data provider metrics
	DataProviderAvailable prometheus.Gauge

	// Runtime metrics
	Goroutines        prometheus.Gauge
	OSThreads         prometheus.Gauge
	ProcessCPUSeconds prometheus.Gauge
	ProcessMemory     prometheus.Gauge
	ProcessOpenFDs    prometheus.Gauge
	ProcessStartTime  prometheus.Gauge

	registry      *prometheus.Registry
	runtimeCancel context.CancelFunc
	runtimeWg     sync.WaitGroup
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
		ShareAccesses: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_share_access_total", Help: "Total share access attempts"},
			[]string{"share_type", "result"},
		),
		BlockedIPs: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_defender_blocked_ips", Help: "Currently blocked IPs"},
		),
		BlocksTotal: prometheus.NewCounter(
			prometheus.CounterOpts{Name: "sftpxy_defender_blocks_total", Help: "Total blocks"},
		),
		SSHCommandsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_ssh_commands_total", Help: "Total SSH commands executed"},
			[]string{"command", "user"},
		),
		SSHCommandErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "sftpxy_ssh_command_errors_total", Help: "Total SSH command errors"},
			[]string{"command", "error_type"},
		),
		DataProviderAvailable: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_data_provider_available", Help: "Data provider availability (1=available, 0=unavailable)"},
		),
		Goroutines: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_goroutines", Help: "Number of goroutines"},
		),
		OSThreads: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_os_threads", Help: "Number of OS threads"},
		),
		ProcessCPUSeconds: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_process_cpu_seconds", Help: "Total CPU seconds consumed by the process"},
		),
		ProcessMemory: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_process_memory_bytes", Help: "Process memory allocation in bytes"},
		),
		ProcessOpenFDs: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_process_open_fds", Help: "Number of open file descriptors"},
		),
		ProcessStartTime: prometheus.NewGauge(
			prometheus.GaugeOpts{Name: "sftpxy_process_start_time_seconds", Help: "Process start time in unix seconds"},
		),
	}

	c.DataProviderAvailable.Set(1)
	c.ProcessStartTime.Set(float64(time.Now().Unix()))

	registry.MustRegister(
		c.UploadsTotal, c.DownloadsTotal, c.UploadBytes, c.DownloadBytes,
		c.TransferErrors, c.ActiveConnections, c.AuthSuccess, c.AuthFailure,
		c.HTTPRequests, c.HTTPDuration, c.EventExecutions, c.ShareAccesses,
		c.BlockedIPs, c.BlocksTotal,
		c.SSHCommandsTotal, c.SSHCommandErrors,
		c.DataProviderAvailable,
		c.Goroutines, c.OSThreads, c.ProcessCPUSeconds,
		c.ProcessMemory, c.ProcessOpenFDs, c.ProcessStartTime,
	)

	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return c
}

// Start starts the telemetry server
func (c *Collector) Start(ctx context.Context) error {
	if !c.config.Enabled {
		c.logger.Info("Telemetry server is disabled")
		return nil
	}

	if c.config.ListenPort <= 0 {
		c.logger.Info("Telemetry server port not configured, metrics available via admin HTTPD")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", c.config.ListenAddress, c.config.ListenPort)

	mux := http.NewServeMux()
	mux.Handle("/metrics", c.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	c.server = &http.Server{Addr: addr, Handler: mux}

	c.logger.Info("Telemetry server started", zap.String("address", addr))

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	go func() {
		if err := c.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			c.logger.Error("Telemetry server error", zap.Error(err))
		}
	}()

	return nil
}

// Handler returns the Prometheus HTTP handler backed by the collector registry.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}

// Shutdown shuts down the telemetry server
func (c *Collector) Shutdown(ctx context.Context) error {
	if c.runtimeCancel != nil {
		c.runtimeCancel()
		c.runtimeWg.Wait()
	}
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

// RecordShareAccess records a share access attempt.
func (c *Collector) RecordShareAccess(shareType, result string) {
	c.ShareAccesses.WithLabelValues(shareType, result).Inc()
}

// SetBlockedIPs sets the blocked IP count
func (c *Collector) SetBlockedIPs(count int) {
	c.BlockedIPs.Set(float64(count))
}

// RecordBlock records a block event
func (c *Collector) RecordBlock() {
	c.BlocksTotal.Inc()
}

// RecordSSHCommand records an SSH command execution
func (c *Collector) RecordSSHCommand(command, user string) {
	c.SSHCommandsTotal.WithLabelValues(command, user).Inc()
}

// RecordSSHCommandError records an SSH command error
func (c *Collector) RecordSSHCommandError(command, errorType string) {
	c.SSHCommandErrors.WithLabelValues(command, errorType).Inc()
}

// SetDataProviderAvailable sets the data provider availability gauge
func (c *Collector) SetDataProviderAvailable(available bool) {
	if available {
		c.DataProviderAvailable.Set(1)
	} else {
		c.DataProviderAvailable.Set(0)
	}
}

// CollectRuntimeMetrics starts a goroutine that periodically updates runtime gauges
func (c *Collector) CollectRuntimeMetrics() {
	ctx, cancel := context.WithCancel(context.Background())
	c.runtimeCancel = cancel

	c.runtimeWg.Add(1)
	go func() {
		defer c.runtimeWg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		c.updateRuntimeGauges()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.updateRuntimeGauges()
			}
		}
	}()
}

func (c *Collector) updateRuntimeGauges() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	c.Goroutines.Set(float64(runtime.NumGoroutine()))
	c.OSThreads.Set(float64(runtime.NumCgoCall()))

	var cpuUsage float64
	if usage, err := getProcessCPUSeconds(); err == nil {
		cpuUsage = usage
	}
	c.ProcessCPUSeconds.Set(cpuUsage)

	c.ProcessMemory.Set(float64(memStats.Alloc))

	if fds, err := getProcessOpenFDs(); err == nil {
		c.ProcessOpenFDs.Set(float64(fds))
	}
}

func getProcessCPUSeconds() (float64, error) {
	var ru runtime.MemStats
	runtime.ReadMemStats(&ru)
	_ = ru
	var rusage struct {
		Utime struct {
			Sec  int64
			Usec int64
		}
		Stime struct {
			Sec  int64
			Usec int64
		}
	}
	_, _, errno := syscall.Syscall(syscall.SYS_GETRUSAGE, 0, uintptr(unsafe.Pointer(&rusage)), 0)
	if errno != 0 {
		return 0, fmt.Errorf("getrusage failed: %d", errno)
	}
	cpuSec := float64(rusage.Utime.Sec+rusage.Stime.Sec) + float64(rusage.Utime.Usec+rusage.Stime.Usec)/1e6
	return cpuSec, nil
}

func getProcessOpenFDs() (int, error) {
	f, err := os.Open("/dev/fd")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return len(names), nil
}
