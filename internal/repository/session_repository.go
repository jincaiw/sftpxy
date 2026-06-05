package repository

import (
	"context"

	"github.com/jincaiw/sftpxy/internal/database"
)

// SessionRepository defines persistence operations for active protocol sessions.
type SessionRepository interface {
	CreateSession(ctx context.Context, sessionID string, userID int64, protocol, clientIP string) error
	TouchSession(ctx context.Context, sessionID string) error
	DeactivateSession(ctx context.Context, sessionID string) error
}

type sessionRepository struct {
	db *database.DB
}

// NewSessionRepository creates a session repository backed by the sessions table.
func NewSessionRepository(db *database.DB) SessionRepository {
	return &sessionRepository{db: db}
}

func (r *sessionRepository) CreateSession(ctx context.Context, sessionID string, userID int64, protocol, clientIP string) error {
	_, err := r.db.ExecContext(
		ctx,
		"INSERT INTO sessions (session_id, user_id, protocol, client_ip, connected_at, last_activity_at, is_active) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)",
		sessionID, userID, protocol, clientIP,
	)
	return err
}

func (r *sessionRepository) TouchSession(ctx context.Context, sessionID string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE sessions SET last_activity_at = CURRENT_TIMESTAMP WHERE session_id = ? AND is_active = TRUE", sessionID)
	return err
}

func (r *sessionRepository) DeactivateSession(ctx context.Context, sessionID string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE sessions SET is_active = FALSE WHERE session_id = ?", sessionID)
	return err
}
