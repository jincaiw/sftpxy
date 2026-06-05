package repository

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jincaiw/sftpxy/internal/database"
)

type Group struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Description  sql.NullString  `json:"description,omitempty"`
	Settings     json.RawMessage `json:"settings,omitempty"`
	UserSettings json.RawMessage `json:"user_settings,omitempty"`
	Priority     int64           `json:"priority"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
}

type GroupRepository interface {
	GetByID(ctx context.Context, id int64) (*Group, error)
	GetByUserID(ctx context.Context, userID int64) ([]*Group, error)
	List(ctx context.Context) ([]*Group, error)
	Create(ctx context.Context, group *Group) (*Group, error)
	Update(ctx context.Context, group *Group) error
	Delete(ctx context.Context, id int64) error
}

type groupRepository struct {
	db *database.DB
}

func NewGroupRepository(db *database.DB) GroupRepository {
	return &groupRepository{db: db}
}

func (r *groupRepository) GetByID(ctx context.Context, id int64) (*Group, error) {
	query := `SELECT id, name, COALESCE(description, ''), settings, user_settings, COALESCE(CAST(priority AS INTEGER), 0), created_at, updated_at FROM groups WHERE id = ? LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, id)
	return scanGroup(row)
}

func (r *groupRepository) GetByUserID(ctx context.Context, userID int64) ([]*Group, error) {
	query := `SELECT g.id, g.name, COALESCE(g.description, ''), g.settings, g.user_settings, COALESCE(CAST(g.priority AS INTEGER), 0), g.created_at, g.updated_at
		FROM groups g
		INNER JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.id ASC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		group, err := scanGroupRows(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (r *groupRepository) List(ctx context.Context) ([]*Group, error) {
	query := `SELECT id, name, COALESCE(description, ''), settings, user_settings, COALESCE(CAST(priority AS INTEGER), 0), created_at, updated_at FROM groups ORDER BY id ASC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		group, err := scanGroupRows(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (r *groupRepository) Create(ctx context.Context, group *Group) (*Group, error) {
	query := `INSERT INTO groups (name, description, settings, user_settings, priority) VALUES (?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query,
		group.Name, group.Description, group.Settings, group.UserSettings, group.Priority,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	group.ID = id
	return group, nil
}

func (r *groupRepository) Update(ctx context.Context, group *Group) error {
	query := `UPDATE groups SET name = ?, description = ?, settings = ?, user_settings = ?, priority = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query,
		group.Name, group.Description, group.Settings, group.UserSettings, group.Priority, group.ID,
	)
	return err
}

func (r *groupRepository) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM groups WHERE id = ?", id)
	return err
}

type groupScanner interface {
	Scan(dest ...interface{}) error
}

func scanGroup(scanner groupScanner) (*Group, error) {
	var group Group
	var settings sql.NullString
	var userSettings sql.NullString

	err := scanner.Scan(
		&group.ID, &group.Name, &group.Description,
		&settings, &userSettings, &group.Priority,
		&group.CreatedAt, &group.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	group.Settings = rawJSON(settings)
	group.UserSettings = rawJSON(userSettings)
	return &group, nil
}

func scanGroupRows(rows *sql.Rows) (*Group, error) {
	var group Group
	var settings sql.NullString
	var userSettings sql.NullString

	err := rows.Scan(
		&group.ID, &group.Name, &group.Description,
		&settings, &userSettings, &group.Priority,
		&group.CreatedAt, &group.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	group.Settings = rawJSON(settings)
	group.UserSettings = rawJSON(userSettings)
	return &group, nil
}
