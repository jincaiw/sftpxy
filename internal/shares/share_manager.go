package shares

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/audit"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// ShareType represents the type of share
type ShareType string

const (
	ShareTypeDownload ShareType = "download"
	ShareTypeUpload   ShareType = "upload"
)

// ShareRequest contains share creation parameters
type ShareRequest struct {
	UserID         int64
	Path           string
	ShareType      ShareType
	Password       string
	ExpiresAt      time.Time
	MaxDownloads   int
	MaxUploads     int
	IPRestrictions []string
}

// ShareInfo contains share information
type ShareInfo struct {
	ID             int64     `json:"id"`
	Token          string    `json:"token"`
	UserID         int64     `json:"user_id"`
	Username       string    `json:"username"`
	ShareType      ShareType `json:"share_type"`
	Path           string    `json:"path"`
	PasswordHash   string    `json:"-"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	MaxDownloads   int       `json:"max_downloads"`
	MaxUploads     int       `json:"max_uploads"`
	DownloadCount  int       `json:"download_count"`
	UploadCount    int       `json:"upload_count"`
	IPRestrictions string    `json:"ip_restrictions,omitempty"`
	IsActive       bool      `json:"is_active"`
	CreatedAt      time.Time `json:"created_at"`
}

// Manager manages share links
type Manager struct {
	shareRepo     repository.ShareRepository
	userRepo      repository.UserRepository
	auditRepo     repository.AuditRepository
	auditRecorder audit.AuditRecorder
	metrics       *metrics.Collector
	logger        *zap.Logger
}

// NewManager creates a new share manager
func NewManager(userRepo repository.UserRepository, log *zap.Logger) *Manager {
	return NewManagerWithDependencies(nil, userRepo, nil, nil, log)
}

// NewManagerWithDependencies creates a new share manager with persistence and auditing.
func NewManagerWithDependencies(
	shareRepo repository.ShareRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	metricsCollector *metrics.Collector,
	log *zap.Logger,
) *Manager {
	return &Manager{
		shareRepo: shareRepo,
		userRepo:  userRepo,
		auditRepo: auditRepo,
		metrics:   metricsCollector,
		logger:    log.Named("shares"),
	}
}

// SetAuditRecorder sets the audit recorder for structured audit events
func (m *Manager) SetAuditRecorder(recorder audit.AuditRecorder) {
	m.auditRecorder = recorder
}

// CreateShare creates a new share link
func (m *Manager) CreateShare(ctx context.Context, req ShareRequest) (*ShareInfo, error) {
	if m.shareRepo == nil {
		return nil, fmt.Errorf("share repository is not configured")
	}

	user, err := m.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve user: %w", err)
	}

	// Generate secure token
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Hash password if provided
	var passwordHash string
	if req.Password != "" {
		passwordHash, err = hashPassword(req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
	}

	repoShare := &repository.Share{
		Token:          token,
		UserID:         req.UserID,
		ShareType:      string(req.ShareType),
		Path:           req.Path,
		PasswordHash:   optionalString(passwordHash),
		ExpiresAt:      optionalTime(req.ExpiresAt),
		MaxDownloads:   optionalInt(req.MaxDownloads),
		MaxUploads:     optionalInt(req.MaxUploads),
		IPRestrictions: optionalString(strings.Join(req.IPRestrictions, ",")),
		IsActive:       true,
	}

	created, err := m.shareRepo.Create(ctx, repoShare)
	if err != nil {
		return nil, fmt.Errorf("failed to persist share: %w", err)
	}

	share := toShareInfo(created)
	share.Username = user.Username

	m.writeAudit(ctx, "share.create", user.Username, token, "success", "")
	m.logger.Info("Share created",
		zap.String("token", token),
		zap.Int64("user_id", req.UserID),
		zap.String("path", req.Path),
	)

	return share, nil
}

// GetShareByToken retrieves a share by its token
func (m *Manager) GetShareByToken(ctx context.Context, token string) (*ShareInfo, error) {
	if m.shareRepo == nil {
		return nil, fmt.Errorf("share repository is not configured")
	}

	share, err := m.shareRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return toShareInfo(share), nil
}

// RevokeShare deactivates a share
func (m *Manager) RevokeShare(ctx context.Context, shareID int64, userID int64) error {
	if m.shareRepo == nil {
		return fmt.Errorf("share repository is not configured")
	}

	share, err := m.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return err
	}
	if share.UserID != userID {
		return fmt.Errorf("share does not belong to user")
	}
	if err := m.shareRepo.Revoke(ctx, shareID); err != nil {
		return err
	}

	m.writeAudit(ctx, "share.revoke", share.Username, share.Token, "success", "")
	m.logger.Info("Share revoked", zap.Int64("id", shareID), zap.Int64("user_id", userID))
	return nil
}

// ListUserShares lists all shares for a user
func (m *Manager) ListUserShares(ctx context.Context, userID int64) ([]*ShareInfo, error) {
	if m.shareRepo == nil {
		return nil, fmt.Errorf("share repository is not configured")
	}

	records, err := m.shareRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	items := make([]*ShareInfo, 0, len(records))
	for _, record := range records {
		items = append(items, toShareInfo(record))
	}
	return items, nil
}

// ListAllShares lists all shares from all users
func (m *Manager) ListAllShares(ctx context.Context) ([]*ShareInfo, error) {
	if m.shareRepo == nil {
		return nil, fmt.Errorf("share repository is not configured")
	}

	records, err := m.shareRepo.ListAll(ctx)
	if err != nil {
		return nil, err
	}

	items := make([]*ShareInfo, 0, len(records))
	for _, record := range records {
		items = append(items, toShareInfo(record))
	}
	return items, nil
}

// DeleteShare deletes a share by ID (admin operation)
func (m *Manager) DeleteShare(ctx context.Context, shareID int64) error {
	if m.shareRepo == nil {
		return fmt.Errorf("share repository is not configured")
	}

	share, err := m.shareRepo.GetByID(ctx, shareID)
	if err != nil {
		return err
	}
	if err := m.shareRepo.Revoke(ctx, shareID); err != nil {
		return err
	}

	m.writeAudit(ctx, "share.delete", share.Username, share.Token, "success", "")
	m.logger.Info("Share deleted by admin", zap.Int64("id", shareID))
	return nil
}

// IncrementDownloadCount increments the download count for a share
func (m *Manager) IncrementDownloadCount(ctx context.Context, shareID int64) error {
	if m.shareRepo == nil {
		return fmt.Errorf("share repository is not configured")
	}
	return m.shareRepo.IncrementDownloadCount(ctx, shareID)
}

// IncrementUploadCount increments the upload count for a share
func (m *Manager) IncrementUploadCount(ctx context.Context, shareID int64) error {
	if m.shareRepo == nil {
		return fmt.Errorf("share repository is not configured")
	}
	return m.shareRepo.IncrementUploadCount(ctx, shareID)
}

// AccessShare validates a share access request and increments usage counters.
func (m *Manager) AccessShare(ctx context.Context, token, password, clientIP string) (*ShareInfo, error) {
	if m.shareRepo == nil {
		return nil, fmt.Errorf("share repository is not configured")
	}

	share, err := m.shareRepo.GetByToken(ctx, token)
	if err != nil {
		m.recordShareMetric("", "not_found")
		return nil, err
	}

	if !share.IsActive {
		m.recordShareMetric(share.ShareType, "inactive")
		return nil, fmt.Errorf("share is inactive")
	}
	if share.ExpiresAt.Valid && time.Now().After(share.ExpiresAt.Time) {
		m.recordShareMetric(share.ShareType, "expired")
		return nil, fmt.Errorf("share has expired")
	}
	if share.PasswordHash.Valid {
		if password == "" {
			m.recordShareMetric(share.ShareType, "password_required")
			return nil, fmt.Errorf("share password is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(share.PasswordHash.String), []byte(password)); err != nil {
			m.recordShareMetric(share.ShareType, "password_invalid")
			m.writeAudit(ctx, "share.access", share.Username, share.Token, "failed", "invalid password")
			return nil, fmt.Errorf("invalid share password")
		}
	}
	if share.IPRestrictions.Valid && strings.TrimSpace(share.IPRestrictions.String) != "" {
		allowed := false
		for _, candidate := range strings.Split(share.IPRestrictions.String, ",") {
			if strings.TrimSpace(candidate) == clientIP {
				allowed = true
				break
			}
		}
		if !allowed {
			m.recordShareMetric(share.ShareType, "ip_denied")
			m.writeAudit(ctx, "share.access", share.Username, share.Token, "failed", "client ip not allowed")
			return nil, fmt.Errorf("client ip is not allowed")
		}
	}

	switch ShareType(share.ShareType) {
	case ShareTypeDownload:
		if share.MaxDownloads.Valid && share.DownloadCount >= int(share.MaxDownloads.Int64) {
			m.recordShareMetric(share.ShareType, "limit_reached")
			return nil, fmt.Errorf("download limit reached")
		}
		if err := m.shareRepo.IncrementDownloadCount(ctx, share.ID); err != nil {
			return nil, err
		}
	case ShareTypeUpload:
		if share.MaxUploads.Valid && share.UploadCount >= int(share.MaxUploads.Int64) {
			m.recordShareMetric(share.ShareType, "limit_reached")
			return nil, fmt.Errorf("upload limit reached")
		}
		if err := m.shareRepo.IncrementUploadCount(ctx, share.ID); err != nil {
			return nil, err
		}
	}

	updated, err := m.shareRepo.GetByID(ctx, share.ID)
	if err != nil {
		return nil, err
	}

	m.recordShareMetric(updated.ShareType, "success")
	m.writeAudit(ctx, "share.access", updated.Username, updated.Token, "success", "")
	return toShareInfo(updated), nil
}

// Helper functions

func generateToken() (string, error) {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func optionalString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func optionalTime(value time.Time) sql.NullTime {
	if value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value, Valid: true}
}

func optionalInt(value int) sql.NullInt64 {
	if value <= 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(value), Valid: true}
}

func toShareInfo(share *repository.Share) *ShareInfo {
	info := &ShareInfo{
		ID:             share.ID,
		Token:          share.Token,
		UserID:         share.UserID,
		Username:       share.Username,
		ShareType:      ShareType(share.ShareType),
		Path:           share.Path,
		PasswordHash:   share.PasswordHash.String,
		MaxDownloads:   int(share.MaxDownloads.Int64),
		MaxUploads:     int(share.MaxUploads.Int64),
		DownloadCount:  share.DownloadCount,
		UploadCount:    share.UploadCount,
		IPRestrictions: share.IPRestrictions.String,
		IsActive:       share.IsActive,
		CreatedAt:      share.CreatedAt,
	}
	if share.ExpiresAt.Valid {
		info.ExpiresAt = share.ExpiresAt.Time
	}
	return info
}

func (m *Manager) writeAudit(ctx context.Context, eventType, actorName, targetID, result, errMsg string) {
	if m.auditRepo == nil && m.auditRecorder == nil {
		return
	}
	if m.auditRepo != nil {
		if _, err := m.auditRepo.CreateAuditLog(ctx, &repository.AuditLog{
			EventID:      fmt.Sprintf("share_%d", time.Now().UnixNano()),
			EventType:    eventType,
			ActorType:    "user",
			ActorName:    actorName,
			TargetType:   "share",
			TargetID:     targetID,
			Protocol:     "http",
			Result:       result,
			ErrorMessage: errMsg,
		}); err != nil {
			m.logger.Warn("failed to write share audit log", zap.Error(err))
		}
	}
	if m.auditRecorder != nil {
		auditEventType := m.mapToAuditEventType(eventType)
		_ = m.auditRecorder.Record(ctx, &audit.AuditEvent{
			EventType:    auditEventType,
			ActorType:    audit.ActorUser,
			ActorName:    actorName,
			TargetType:   audit.TargetShare,
			TargetID:     targetID,
			Protocol:     "http",
			Result:       result,
			ErrorMessage: errMsg,
		})
	}
}

func (m *Manager) mapToAuditEventType(eventType string) audit.EventType {
	switch eventType {
	case "share.create":
		return audit.ShareCreate
	case "share.modify":
		return audit.ShareModify
	case "share.revoke":
		return audit.ShareRevoke
	case "share.access":
		return audit.ShareAccess
	default:
		return audit.EventType(eventType)
	}
}

func (m *Manager) recordShareMetric(shareType, result string) {
	if m.metrics == nil {
		return
	}
	if shareType == "" {
		shareType = "unknown"
	}
	m.metrics.RecordShareAccess(shareType, result)
}
