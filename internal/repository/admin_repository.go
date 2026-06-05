package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/jincaiw/sftpxy/internal/database"
)

// Admin represents an administrator in the system
type Admin struct {
	ID           int64           `json:"id"`
	Username     string          `json:"username"`
	PasswordHash string          `json:"-"`
	Status       string          `json:"status"`
	Permissions  json.RawMessage `json:"permissions,omitempty"`
	RoleID       sql.NullInt64   `json:"role_id,omitempty"`
	MFASecret    sql.NullString  `json:"mfa_secret,omitempty"`
	MFAEnabled   bool            `json:"mfa_enabled"`
	Filters      json.RawMessage `json:"filters,omitempty"`
	LastLoginAt  sql.NullString  `json:"last_login_at,omitempty"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

// AdminRepository defines the interface for admin data access
type AdminRepository interface {
	GetByUsername(ctx context.Context, username string) (*Admin, error)
	GetByID(ctx context.Context, id int64) (*Admin, error)
	Create(ctx context.Context, admin *Admin) (*Admin, error)
	Update(ctx context.Context, admin *Admin) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, limit, offset int) ([]*Admin, error)
	UpdateLastLogin(ctx context.Context, id int64) error
}

// adminRepository implements AdminRepository
type adminRepository struct {
	db *database.DB
}

// NewAdminRepository creates a new AdminRepository
func NewAdminRepository(db *database.DB) AdminRepository {
	return &adminRepository{db: db}
}

func (r *adminRepository) GetByUsername(ctx context.Context, username string) (*Admin, error) {
	query := "SELECT id, username, password_hash, status, permissions, role_id, mfa_secret, mfa_enabled, filters, last_login_at, created_at, updated_at FROM admins WHERE username = ? LIMIT 1"

	var admin Admin
	err := r.db.QueryRowContext(ctx, query, username).Scan(
		&admin.ID, &admin.Username, &admin.PasswordHash, &admin.Status,
		&admin.Permissions, &admin.RoleID, &admin.MFASecret, &admin.MFAEnabled,
		&admin.Filters, &admin.LastLoginAt, &admin.CreatedAt, &admin.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin not found: %s", username)
		}
		return nil, err
	}
	return &admin, nil
}

func (r *adminRepository) GetByID(ctx context.Context, id int64) (*Admin, error) {
	query := "SELECT id, username, password_hash, status, permissions, role_id, mfa_secret, mfa_enabled, filters, last_login_at, created_at, updated_at FROM admins WHERE id = ? LIMIT 1"

	var admin Admin
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&admin.ID, &admin.Username, &admin.PasswordHash, &admin.Status,
		&admin.Permissions, &admin.RoleID, &admin.MFASecret, &admin.MFAEnabled,
		&admin.Filters, &admin.LastLoginAt, &admin.CreatedAt, &admin.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("admin not found: %d", id)
		}
		return nil, err
	}
	return &admin, nil
}

func (r *adminRepository) Create(ctx context.Context, admin *Admin) (*Admin, error) {
	query := `INSERT INTO admins (username, password_hash, status, permissions, role_id, mfa_secret, mfa_enabled, filters)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query,
		admin.Username, admin.PasswordHash, admin.Status,
		admin.Permissions, admin.RoleID, admin.MFASecret,
		admin.MFAEnabled, admin.Filters,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	admin.ID = id
	return admin, nil
}

func (r *adminRepository) Update(ctx context.Context, admin *Admin) error {
	query := `UPDATE admins SET
		password_hash = ?, status = ?, permissions = ?, role_id = ?,
		mfa_secret = ?, mfa_enabled = ?, filters = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query,
		admin.PasswordHash, admin.Status, admin.Permissions,
		admin.RoleID, admin.MFASecret, admin.MFAEnabled,
		admin.Filters, admin.ID,
	)
	return err
}

func (r *adminRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM admins WHERE id = ?", id)
	return err
}

func (r *adminRepository) List(ctx context.Context, limit, offset int) ([]*Admin, error) {
	query := "SELECT id, username, password_hash, status, permissions, role_id, mfa_secret, mfa_enabled, filters, last_login_at, created_at, updated_at FROM admins ORDER BY id ASC LIMIT ? OFFSET ?"

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var admins []*Admin
	for rows.Next() {
		var admin Admin
		err := rows.Scan(
			&admin.ID, &admin.Username, &admin.PasswordHash, &admin.Status,
			&admin.Permissions, &admin.RoleID, &admin.MFASecret, &admin.MFAEnabled,
			&admin.Filters, &admin.LastLoginAt, &admin.CreatedAt, &admin.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		admins = append(admins, &admin)
	}
	return admins, rows.Err()
}

func (r *adminRepository) UpdateLastLogin(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE admins SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}
