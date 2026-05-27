package shares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/sftpxy/sftpxy/internal/repository"
	"go.uber.org/zap"
)

// ShareType represents the type of share
type ShareType string

const (
	ShareTypeDownload ShareType = "download"
	ShareTypeUpload   ShareType = "upload"
)

// ShareRequest contains share creation parameters
type ShareRequest struct {
	UserID        int64
	Path          string
	ShareType     ShareType
	Password      string
	ExpiresAt     time.Time
	MaxDownloads  int
	MaxUploads    int
	IPRestrictions []string
}

// ShareInfo contains share information
type ShareInfo struct {
	ID             int64
	Token          string
	UserID         int64
	Username       string
	ShareType      ShareType
	Path           string
	PasswordHash   string
	ExpiresAt      time.Time
	MaxDownloads   int
	MaxUploads     int
	DownloadCount  int
	UploadCount    int
	IPRestrictions string
	IsActive       bool
	CreatedAt      time.Time
}

// Manager manages share links
type Manager struct {
	userRepo repository.UserRepository
	logger   *zap.Logger
}

// NewManager creates a new share manager
func NewManager(userRepo repository.UserRepository, log *zap.Logger) *Manager {
	return &Manager{
		userRepo: userRepo,
		logger:   log.Named("shares"),
	}
}

// CreateShare creates a new share link
func (m *Manager) CreateShare(ctx context.Context, req ShareRequest) (*ShareInfo, error) {
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

	share := &ShareInfo{
		Token:          token,
		UserID:         req.UserID,
		ShareType:      req.ShareType,
		Path:           req.Path,
		PasswordHash:   passwordHash,
		ExpiresAt:      req.ExpiresAt,
		MaxDownloads:   req.MaxDownloads,
		MaxUploads:     req.MaxUploads,
		IPRestrictions: "",
		IsActive:       true,
	}

	m.logger.Info("Share created",
		zap.String("token", token),
		zap.Int64("user_id", req.UserID),
		zap.String("path", req.Path),
	)

	return share, nil
}

// GetShareByToken retrieves a share by its token
func (m *Manager) GetShareByToken(ctx context.Context, token string) (*ShareInfo, error) {
	// In production, query from database
	// For now, return placeholder
	return nil, fmt.Errorf("share not found: %s", token)
}

// RevokeShare deactivates a share
func (m *Manager) RevokeShare(ctx context.Context, shareID int64, userID int64) error {
	m.logger.Info("Share revoked", zap.Int64("id", shareID), zap.Int64("user_id", userID))
	return nil
}

// ListUserShares lists all shares for a user
func (m *Manager) ListUserShares(ctx context.Context, userID int64) ([]*ShareInfo, error) {
	return []*ShareInfo{}, nil
}

// IncrementDownloadCount increments the download count for a share
func (m *Manager) IncrementDownloadCount(ctx context.Context, shareID int64) error {
	return nil
}

// IncrementUploadCount increments the upload count for a share
func (m *Manager) IncrementUploadCount(ctx context.Context, shareID int64) error {
	return nil
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
	// Use bcrypt in production
	return password, nil
}
