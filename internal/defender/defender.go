package defender

import (
	"context"
	"sync"
	"time"

	"github.com/jincaiw/sftpxy/internal/audit"
	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
)

// Config holds Defender configuration
type Config struct {
	MaxFailures   int           `json:"max_failures"`
	WindowMinutes int           `json:"window_minutes"`
	BlockDuration time.Duration `json:"block_duration"`
}

// DefaultConfig returns default Defender config
func DefaultConfig() Config {
	return Config{
		MaxFailures:   5,
		WindowMinutes: 10,
		BlockDuration: 30 * time.Minute,
	}
}

// FailureRecord tracks authentication failures
type FailureRecord struct {
	IP        string
	Protocol  string
	Timestamp time.Time
}

// Defender implements brute-force protection
type Defender struct {
	config           Config
	logger           *zap.Logger
	repo             repository.AuditRepository
	auditRecorder    audit.AuditRecorder
	failures         map[string][]FailureRecord
	mu               sync.RWMutex
	blockCache       map[string]time.Time // IP -> expiry
	metricsCollector MetricsCollector
}

// NewDefender creates a new Defender instance
func NewDefender(cfg Config, log *zap.Logger, repo repository.AuditRepository) *Defender {
	d := &Defender{
		config:     cfg,
		logger:     log.Named("defender"),
		repo:       repo,
		failures:   make(map[string][]FailureRecord),
		blockCache: make(map[string]time.Time),
	}

	// Start cleanup goroutine
	go d.cleanupLoop()

	return d
}

// RecordFailure records an authentication failure
func (d *Defender) RecordFailure(ip, protocol string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	d.failures[ip] = append(d.failures[ip], FailureRecord{
		IP:        ip,
		Protocol:  protocol,
		Timestamp: now,
	})

	// Clean old failures outside the window
	windowStart := now.Add(-time.Duration(d.config.WindowMinutes) * time.Minute)
	var recent []FailureRecord
	for _, f := range d.failures[ip] {
		if f.Timestamp.After(windowStart) {
			recent = append(recent, f)
		}
	}
	d.failures[ip] = recent

	// Check if threshold exceeded
	if len(recent) >= d.config.MaxFailures {
		d.blockIP(ip, protocol)
	}

	d.logger.Warn("Authentication failure recorded",
		zap.String("ip", ip),
		zap.String("protocol", protocol),
		zap.Int("count", len(recent)),
		zap.Int("threshold", d.config.MaxFailures),
	)
}

// IsBlocked checks if an IP is currently blocked
func (d *Defender) IsBlocked(ip string) bool {
	d.mu.RLock()
	if expiry, ok := d.blockCache[ip]; ok {
		if time.Now().Before(expiry) {
			d.mu.RUnlock()
			return true
		}
		d.mu.RUnlock()
		d.mu.Lock()
		delete(d.blockCache, ip)
		d.mu.Unlock()
		return false
	}
	d.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	block, err := d.repo.GetBlockedIP(ctx, ip)
	if err != nil {
		return false
	}

	if block.IsActive && time.Now().Before(block.ExpiresAt) {
		d.mu.Lock()
		d.blockCache[ip] = block.ExpiresAt
		d.mu.Unlock()
		return true
	}

	return false
}

// Unblock manually unblocks an IP
func (d *Defender) Unblock(ip string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.repo.UnblockIP(ctx, ip); err != nil {
		return err
	}

	delete(d.blockCache, ip)
	delete(d.failures, ip)

	if d.auditRecorder != nil {
		_ = d.auditRecorder.Record(context.Background(), &audit.AuditEvent{
			EventType:  audit.DefenderUnblock,
			ActorType:  audit.ActorAdmin,
			ActorName:  "admin",
			TargetType: audit.TargetIP,
			TargetID:   ip,
			Result:     "success",
		})
	}

	d.logger.Info("IP manually unblocked", zap.String("ip", ip))
	return nil
}

// GetBlockedIPs returns list of currently blocked IPs
func (d *Defender) GetBlockedIPs(limit, offset int) ([]*repository.BlockedIP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	blocks, err := d.repo.ListActiveBlocks(ctx, limit, offset)
	if err != nil {
		return nil, err
	}

	// Update metrics
	if d.metricsCollector != nil {
		d.metricsCollector.SetBlockedIPs(len(blocks))
	}

	return blocks, nil
}

// Internal methods

func (d *Defender) blockIP(ip, protocol string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expiresAt := time.Now().Add(d.config.BlockDuration)

	_, err := d.repo.AddBlockedIP(ctx, ip, protocol, "brute-force", expiresAt)
	if err != nil {
		d.logger.Error("Failed to add blocked IP", zap.String("ip", ip), zap.Error(err))
		return
	}

	d.blockCache[ip] = expiresAt
	d.failures[ip] = nil // Clear failure history

	d.logger.Warn("IP blocked due to brute-force",
		zap.String("ip", ip),
		zap.String("protocol", protocol),
		zap.Duration("duration", d.config.BlockDuration),
	)

	if d.auditRecorder != nil {
		_ = d.auditRecorder.Record(context.Background(), &audit.AuditEvent{
			EventType:  audit.DefenderBlock,
			ActorType:  audit.ActorSystem,
			ActorName:  "defender",
			TargetType: audit.TargetIP,
			TargetID:   ip,
			Protocol:   protocol,
			Result:     "success",
		})
	}

	// Update metrics
	if d.metricsCollector != nil {
		d.metricsCollector.RecordBlock()
		d.metricsCollector.SetBlockedIPs(len(d.blockCache))
	}
}

func (d *Defender) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.cleanup()
	}
}

func (d *Defender) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Clean expired blocks from cache
	for ip, expiry := range d.blockCache {
		if now.After(expiry) {
			delete(d.blockCache, ip)
		}
	}

	// Clean old failure records
	windowStart := now.Add(-time.Duration(d.config.WindowMinutes) * time.Minute)
	for ip, failures := range d.failures {
		var recent []FailureRecord
		for _, f := range failures {
			if f.Timestamp.After(windowStart) {
				recent = append(recent, f)
			}
		}
		if len(recent) == 0 {
			delete(d.failures, ip)
		} else {
			d.failures[ip] = recent
		}
	}

	// Clean expired blocks in database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d.repo.CleanExpiredBlocks(ctx)

	d.logger.Debug("Defender cleanup completed")
}

// SetMetricsCollector sets the metrics collector (optional)
func (d *Defender) SetMetricsCollector(mc MetricsCollector) {
	d.metricsCollector = mc
}

// SetAuditRecorder sets the audit recorder for structured audit events
func (d *Defender) SetAuditRecorder(recorder audit.AuditRecorder) {
	d.auditRecorder = recorder
}

// MetricsCollector interface for metrics
type MetricsCollector interface {
	SetBlockedIPs(count int)
	RecordBlock()
}
