package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jincaiw/sftpxy/internal/database"
)

// Share represents a persisted share record.
type Share struct {
	ID             int64
	Token          string
	UserID         int64
	Username       string
	ShareType      string
	Path           string
	PasswordHash   sql.NullString
	ExpiresAt      sql.NullTime
	MaxDownloads   sql.NullInt64
	MaxUploads     sql.NullInt64
	DownloadCount  int
	UploadCount    int
	IPRestrictions sql.NullString
	IsActive       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ShareRepository defines the share persistence interface.
type ShareRepository interface {
	Create(ctx context.Context, share *Share) (*Share, error)
	GetByID(ctx context.Context, id int64) (*Share, error)
	GetByToken(ctx context.Context, token string) (*Share, error)
	ListByUserID(ctx context.Context, userID int64) ([]*Share, error)
	ListAll(ctx context.Context) ([]*Share, error)
	Revoke(ctx context.Context, id int64) error
	IncrementDownloadCount(ctx context.Context, id int64) error
	IncrementUploadCount(ctx context.Context, id int64) error
	CountActive(ctx context.Context) (int64, error)
}

type shareRepository struct {
	db *database.DB
}

// NewShareRepository creates a new ShareRepository.
func NewShareRepository(db *database.DB) ShareRepository {
	return &shareRepository{db: db}
}

func (r *shareRepository) Create(ctx context.Context, share *Share) (*Share, error) {
	query := `INSERT INTO shares (
		token, user_id, share_type, path, password_hash, expires_at,
		max_downloads, max_uploads, ip_restrictions, is_active
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		share.Token,
		share.UserID,
		share.ShareType,
		share.Path,
		nullStringValue(share.PasswordHash),
		nullTimeValue(share.ExpiresAt),
		nullIntValue(share.MaxDownloads),
		nullIntValue(share.MaxUploads),
		nullStringValue(share.IPRestrictions),
		share.IsActive,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return r.GetByID(ctx, id)
}

func (r *shareRepository) GetByID(ctx context.Context, id int64) (*Share, error) {
	return r.getOne(ctx, "s.id = ?", id)
}

func (r *shareRepository) GetByToken(ctx context.Context, token string) (*Share, error) {
	return r.getOne(ctx, "s.token = ?", token)
}

func (r *shareRepository) ListByUserID(ctx context.Context, userID int64) ([]*Share, error) {
	query := `SELECT
		s.id, s.token, s.user_id, COALESCE(u.username, ''), s.share_type, s.path,
		s.password_hash, s.expires_at, s.max_downloads, s.max_uploads,
		s.download_count, s.upload_count, s.ip_restrictions, s.is_active,
		s.created_at, s.updated_at
	FROM shares s
	LEFT JOIN users u ON u.id = s.user_id
	WHERE s.user_id = ?
	ORDER BY s.created_at DESC, s.id DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*Share
	for rows.Next() {
		share, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}

	return shares, rows.Err()
}

func (r *shareRepository) ListAll(ctx context.Context) ([]*Share, error) {
	query := `SELECT
		s.id, s.token, s.user_id, COALESCE(u.username, ''), s.share_type, s.path,
		s.password_hash, s.expires_at, s.max_downloads, s.max_uploads,
		s.download_count, s.upload_count, s.ip_restrictions, s.is_active,
		s.created_at, s.updated_at
	FROM shares s
	LEFT JOIN users u ON u.id = s.user_id
	ORDER BY s.created_at DESC, s.id DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*Share
	for rows.Next() {
		share, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}

	return shares, rows.Err()
}

func (r *shareRepository) Revoke(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE shares SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (r *shareRepository) IncrementDownloadCount(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE shares SET download_count = download_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (r *shareRepository) IncrementUploadCount(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE shares SET upload_count = upload_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (r *shareRepository) CountActive(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM shares WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
	).Scan(&count)
	return count, err
}

func (r *shareRepository) getOne(ctx context.Context, condition string, arg interface{}) (*Share, error) {
	query := fmt.Sprintf(`SELECT
		s.id, s.token, s.user_id, COALESCE(u.username, ''), s.share_type, s.path,
		s.password_hash, s.expires_at, s.max_downloads, s.max_uploads,
		s.download_count, s.upload_count, s.ip_restrictions, s.is_active,
		s.created_at, s.updated_at
	FROM shares s
	LEFT JOIN users u ON u.id = s.user_id
	WHERE %s
	LIMIT 1`, condition)

	row := r.db.QueryRowContext(ctx, query, arg)
	share, err := scanShare(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("share not found")
		}
		return nil, err
	}
	return share, nil
}

type shareScanner interface {
	Scan(dest ...interface{}) error
}

func scanShare(scanner shareScanner) (*Share, error) {
	var share Share
	var expiresAt sql.NullString
	var createdAt string
	var updatedAt string
	err := scanner.Scan(
		&share.ID,
		&share.Token,
		&share.UserID,
		&share.Username,
		&share.ShareType,
		&share.Path,
		&share.PasswordHash,
		&expiresAt,
		&share.MaxDownloads,
		&share.MaxUploads,
		&share.DownloadCount,
		&share.UploadCount,
		&share.IPRestrictions,
		&share.IsActive,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}
	if share.ExpiresAt, err = parseNullableTime(expiresAt); err != nil {
		return nil, err
	}
	if share.CreatedAt, err = parseRequiredTime(createdAt); err != nil {
		return nil, err
	}
	if share.UpdatedAt, err = parseRequiredTime(updatedAt); err != nil {
		return nil, err
	}
	return &share, nil
}

func nullStringValue(value sql.NullString) interface{} {
	if value.Valid {
		return value.String
	}
	return nil
}

func nullTimeValue(value sql.NullTime) interface{} {
	if value.Valid {
		return value.Time
	}
	return nil
}

func nullIntValue(value sql.NullInt64) interface{} {
	if value.Valid {
		return value.Int64
	}
	return nil
}

func parseNullableTime(value sql.NullString) (sql.NullTime, error) {
	if !value.Valid || value.String == "" {
		return sql.NullTime{}, nil
	}
	parsed, err := parseTimestamp(value.String)
	if err != nil {
		return sql.NullTime{}, err
	}
	return sql.NullTime{Time: parsed, Valid: true}, nil
}

func parseRequiredTime(value string) (time.Time, error) {
	return parseTimestamp(value)
}

func parseTimestamp(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("failed to parse timestamp %q", value)
}
