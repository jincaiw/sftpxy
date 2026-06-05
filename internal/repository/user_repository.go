package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/jincaiw/sftpxy/internal/database"
)

// User represents a user in the system
type User struct {
	ID                  int64           `json:"id"`
	Username            string          `json:"username"`
	Email               sql.NullString  `json:"email,omitempty"`
	Status              string          `json:"status"`
	PasswordHash        sql.NullString  `json:"password_hash,omitempty"`
	PasswordChangedAt   sql.NullString  `json:"password_changed_at,omitempty"`
	HomeDir             string          `json:"home_dir"`
	Filesystem          json.RawMessage `json:"filesystem,omitempty"`
	Permissions         json.RawMessage `json:"permissions,omitempty"`
	Filters             json.RawMessage `json:"filters,omitempty"`
	Quotas              json.RawMessage `json:"quotas,omitempty"`
	BandwidthLimits     json.RawMessage `json:"bandwidth_limits,omitempty"`
	TransferLimits      json.RawMessage `json:"transfer_limits,omitempty"`
	ProtocolPermissions json.RawMessage `json:"protocol_permissions,omitempty"`
	MaxSessions         int             `json:"max_sessions"`
	AllowedProtocols    json.RawMessage `json:"allowed_protocols,omitempty"`
	DeniedProtocols     json.RawMessage `json:"denied_protocols,omitempty"`
	IPFilters           json.RawMessage `json:"ip_filters,omitempty"`
	MFASecret           sql.NullString  `json:"mfa_secret,omitempty"`
	MFAEnabled          bool            `json:"mfa_enabled"`
	ExpirationDate      sql.NullString  `json:"expiration_date,omitempty"`
	Description         sql.NullString  `json:"description,omitempty"`
	CreatedAt           string          `json:"created_at"`
	UpdatedAt           string          `json:"updated_at"`
}

// PublicKey represents an SSH public key
type PublicKey struct {
	ID        int64  `json:"id"`
	UserID    int64  `json:"user_id"`
	Label     string `json:"label"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// UserRepository defines the interface for user data access
type UserRepository interface {
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id int64) (*User, error)
	Create(ctx context.Context, user *User) (*User, error)
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id int64) error
	List(ctx context.Context, usernameFilter, statusFilter string, limit, offset int) ([]*User, error)
	Count(ctx context.Context) (int64, error)
	UpdateStatus(ctx context.Context, id int64, status string) error
	UpdateLastLogin(ctx context.Context, id int64) error

	// Public key operations
	GetPublicKeys(ctx context.Context, userID int64) ([]*PublicKey, error)
	AddPublicKey(ctx context.Context, userID int64, label, publicKey string) (*PublicKey, error)
	DeletePublicKey(ctx context.Context, id, userID int64) error
}

// userRepository implements UserRepository
type userRepository struct {
	db *database.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *database.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	query := "SELECT id, username, COALESCE(email, ''), status, password_hash, COALESCE(password_changed_at, ''), home_dir, filesystem, permissions, filters, quotas, bandwidth_limits, transfer_limits, protocol_permissions, max_sessions, allowed_protocols, denied_protocols, ip_filters, mfa_secret, mfa_enabled, expiration_date, description, created_at, updated_at FROM users WHERE username = ? LIMIT 1"

	user, err := scanUser(r.db.QueryRowContext(ctx, query, username))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %s", username)
		}
		return nil, err
	}
	return user, nil
}

func (r *userRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	query := "SELECT id, username, COALESCE(email, ''), status, password_hash, COALESCE(password_changed_at, ''), home_dir, filesystem, permissions, filters, quotas, bandwidth_limits, transfer_limits, protocol_permissions, max_sessions, allowed_protocols, denied_protocols, ip_filters, mfa_secret, mfa_enabled, expiration_date, description, created_at, updated_at FROM users WHERE id = ? LIMIT 1"

	user, err := scanUser(r.db.QueryRowContext(ctx, query, id))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %d", id)
		}
		return nil, err
	}
	return user, nil
}

func (r *userRepository) Create(ctx context.Context, user *User) (*User, error) {
	query := `INSERT INTO users (
		username, email, status, password_hash, password_changed_at, home_dir, filesystem,
		permissions, filters, quotas, bandwidth_limits,
		transfer_limits, protocol_permissions, max_sessions, allowed_protocols,
		denied_protocols, ip_filters, mfa_secret, mfa_enabled,
		expiration_date, description
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query,
		user.Username, user.Email, user.Status, user.PasswordHash, user.PasswordChangedAt, user.HomeDir,
		user.Filesystem, user.Permissions, user.Filters, user.Quotas,
		user.BandwidthLimits, user.TransferLimits, user.ProtocolPermissions, user.MaxSessions,
		user.AllowedProtocols, user.DeniedProtocols, user.IPFilters,
		user.MFASecret, user.MFAEnabled, user.ExpirationDate, user.Description,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	user.ID = id
	return user, nil
}

func (r *userRepository) Update(ctx context.Context, user *User) error {
	query := `UPDATE users SET
		email = ?, status = ?, home_dir = ?, filesystem = ?, permissions = ?,
		filters = ?, quotas = ?, bandwidth_limits = ?, transfer_limits = ?,
		protocol_permissions = ?, max_sessions = ?, allowed_protocols = ?, denied_protocols = ?,
		ip_filters = ?, mfa_secret = ?, mfa_enabled = ?,
		expiration_date = ?, description = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query,
		user.Email, user.Status, user.HomeDir, user.Filesystem, user.Permissions,
		user.Filters, user.Quotas, user.BandwidthLimits, user.TransferLimits,
		user.ProtocolPermissions, user.MaxSessions, user.AllowedProtocols, user.DeniedProtocols,
		user.IPFilters, user.MFASecret, user.MFAEnabled,
		user.ExpirationDate, user.Description, user.ID,
	)
	return err
}

func (r *userRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	return err
}

func (r *userRepository) List(ctx context.Context, usernameFilter, statusFilter string, limit, offset int) ([]*User, error) {
	query := "SELECT id, username, COALESCE(email, ''), status, password_hash, COALESCE(password_changed_at, ''), home_dir, filesystem, permissions, filters, quotas, bandwidth_limits, transfer_limits, protocol_permissions, max_sessions, allowed_protocols, denied_protocols, ip_filters, mfa_secret, mfa_enabled, expiration_date, description, created_at, updated_at FROM users WHERE 1=1"
	args := []interface{}{}

	if usernameFilter != "" {
		query += " AND username LIKE ?"
		args = append(args, "%"+usernameFilter+"%")
	}
	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}
	query += " ORDER BY id ASC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *userRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (r *userRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", status, id)
	return err
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	return err
}

func (r *userRepository) GetPublicKeys(ctx context.Context, userID int64) ([]*PublicKey, error) {
	query := "SELECT id, user_id, label, public_key, created_at, updated_at FROM public_keys WHERE user_id = ? ORDER BY created_at ASC"

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*PublicKey
	for rows.Next() {
		var key PublicKey
		err := rows.Scan(&key.ID, &key.UserID, &key.Label, &key.PublicKey, &key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			return nil, err
		}
		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

func (r *userRepository) AddPublicKey(ctx context.Context, userID int64, label, publicKey string) (*PublicKey, error) {
	query := "INSERT INTO public_keys (user_id, label, public_key) VALUES (?, ?, ?)"

	result, err := r.db.ExecContext(ctx, query, userID, label, publicKey)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		ID:        id,
		UserID:    userID,
		Label:     label,
		PublicKey: publicKey,
	}, nil
}

type userScanner interface {
	Scan(dest ...interface{}) error
}

func scanUser(scanner userScanner) (*User, error) {
	var user User
	var filesystem sql.NullString
	var permissions sql.NullString
	var filters sql.NullString
	var quotas sql.NullString
	var bandwidthLimits sql.NullString
	var transferLimits sql.NullString
	var protocolPermissions sql.NullString
	var allowedProtocols sql.NullString
	var deniedProtocols sql.NullString
	var ipFilters sql.NullString

	err := scanner.Scan(
		&user.ID, &user.Username, &user.Email, &user.Status, &user.PasswordHash,
		&user.PasswordChangedAt,
		&user.HomeDir, &filesystem, &permissions, &filters,
		&quotas, &bandwidthLimits, &transferLimits, &protocolPermissions,
		&user.MaxSessions, &allowedProtocols, &deniedProtocols,
		&ipFilters, &user.MFASecret, &user.MFAEnabled,
		&user.ExpirationDate, &user.Description, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	user.Filesystem = rawJSON(filesystem)
	user.Permissions = rawJSON(permissions)
	user.Filters = rawJSON(filters)
	user.Quotas = rawJSON(quotas)
	user.BandwidthLimits = rawJSON(bandwidthLimits)
	user.TransferLimits = rawJSON(transferLimits)
	user.ProtocolPermissions = rawJSON(protocolPermissions)
	user.AllowedProtocols = rawJSON(allowedProtocols)
	user.DeniedProtocols = rawJSON(deniedProtocols)
	user.IPFilters = rawJSON(ipFilters)
	return &user, nil
}

func rawJSON(value sql.NullString) json.RawMessage {
	if !value.Valid || value.String == "" {
		return nil
	}
	return json.RawMessage(value.String)
}

func (r *userRepository) DeletePublicKey(ctx context.Context, id, userID int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM public_keys WHERE id = ? AND user_id = ?", id, userID)
	return err
}
