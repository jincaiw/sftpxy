package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/database"
)

// EventRuleRecord represents a persisted event rule.
type EventRuleRecord struct {
	ID          int64
	Name        string
	Description sql.NullString
	TriggerType string
	Conditions  json.RawMessage
	IsActive    bool
	Schedule    sql.NullString
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// EventActionRecord represents a persisted action bound to a rule.
type EventActionRecord struct {
	ID         int64
	RuleID     int64
	ActionType string
	Config     json.RawMessage
	OrderIndex int
	CreatedAt  time.Time
}

// EventHistoryRecord represents an action execution history entry.
type EventHistoryRecord struct {
	ID           int64     `json:"id"`
	RuleID       int64     `json:"rule_id"`
	ActionID     int64     `json:"action_id"`
	EventType    string    `json:"event_type"`
	Payload      string    `json:"payload"`
	Result       string    `json:"result"`
	ErrorMessage string    `json:"error_message"`
	ExecutedAt   time.Time `json:"executed_at"`
}

// EventRepository defines the event persistence interface.
type EventRepository interface {
	CreateRule(ctx context.Context, rule *EventRuleRecord) (*EventRuleRecord, error)
	UpdateRule(ctx context.Context, rule *EventRuleRecord) (*EventRuleRecord, error)
	DeleteRule(ctx context.Context, id int64) error
	GetRuleByID(ctx context.Context, id int64) (*EventRuleRecord, error)
	CreateAction(ctx context.Context, action *EventActionRecord) (*EventActionRecord, error)
	DeleteActionsByRuleID(ctx context.Context, ruleID int64) error
	GetActionsByRuleID(ctx context.Context, ruleID int64) ([]*EventActionRecord, error)
	UpdateRuleActions(ctx context.Context, ruleID int64, actions []*EventActionRecord) error
	ListRules(ctx context.Context) ([]*EventRuleRecord, error)
	ListActionsByRuleIDs(ctx context.Context, ruleIDs []int64) ([]*EventActionRecord, error)
	CreateHistory(ctx context.Context, history *EventHistoryRecord) (*EventHistoryRecord, error)
	ListHistory(ctx context.Context, eventType, result string, limit, offset int) ([]*EventHistoryRecord, error)
	CountHistory(ctx context.Context, eventType, result string) (int64, error)
}

type eventRepository struct {
	db *database.DB
}

// NewEventRepository creates a new EventRepository.
func NewEventRepository(db *database.DB) EventRepository {
	return &eventRepository{db: db}
}

func (r *eventRepository) CreateRule(ctx context.Context, rule *EventRuleRecord) (*EventRuleRecord, error) {
	query := `INSERT INTO event_rules (name, description, trigger_type, conditions, is_active, schedule)
	VALUES (?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		rule.Name,
		rule.Description,
		rule.TriggerType,
		rule.Conditions,
		rule.IsActive,
		rule.Schedule,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, name, description, trigger_type, conditions, is_active, schedule, created_at, updated_at
		FROM event_rules WHERE id = ?`,
		id,
	)

	var record EventRuleRecord
	if err := row.Scan(
		&record.ID,
		&record.Name,
		&record.Description,
		&record.TriggerType,
		&record.Conditions,
		&record.IsActive,
		&record.Schedule,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *eventRepository) UpdateRule(ctx context.Context, rule *EventRuleRecord) (*EventRuleRecord, error) {
	query := `UPDATE event_rules SET name = ?, description = ?, trigger_type = ?, conditions = ?, is_active = ?, schedule = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?`

	_, err := r.db.ExecContext(
		ctx,
		query,
		rule.Name,
		rule.Description,
		rule.TriggerType,
		rule.Conditions,
		rule.IsActive,
		rule.Schedule,
		rule.ID,
	)
	if err != nil {
		return nil, err
	}

	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, name, description, trigger_type, conditions, is_active, schedule, created_at, updated_at
		FROM event_rules WHERE id = ?`,
		rule.ID,
	)

	var record EventRuleRecord
	if err := row.Scan(
		&record.ID,
		&record.Name,
		&record.Description,
		&record.TriggerType,
		&record.Conditions,
		&record.IsActive,
		&record.Schedule,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *eventRepository) DeleteRule(ctx context.Context, id int64) error {
	query := `DELETE FROM event_rules WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *eventRepository) CreateAction(ctx context.Context, action *EventActionRecord) (*EventActionRecord, error) {
	query := `INSERT INTO event_actions (rule_id, action_type, action_config, order_index)
	VALUES (?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		action.RuleID,
		action.ActionType,
		action.Config,
		action.OrderIndex,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, rule_id, action_type, action_config, order_index, created_at
		FROM event_actions WHERE id = ?`,
		id,
	)

	var record EventActionRecord
	if err := row.Scan(
		&record.ID,
		&record.RuleID,
		&record.ActionType,
		&record.Config,
		&record.OrderIndex,
		&record.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *eventRepository) DeleteActionsByRuleID(ctx context.Context, ruleID int64) error {
	query := `DELETE FROM event_actions WHERE rule_id = ?`
	_, err := r.db.ExecContext(ctx, query, ruleID)
	return err
}

func (r *eventRepository) GetRuleByID(ctx context.Context, id int64) (*EventRuleRecord, error) {
	query := `SELECT id, name, description, trigger_type, conditions, is_active, schedule, created_at, updated_at
	FROM event_rules WHERE id = ?`
	row := r.db.QueryRowContext(ctx, query, id)
	var record EventRuleRecord
	if err := row.Scan(
		&record.ID,
		&record.Name,
		&record.Description,
		&record.TriggerType,
		&record.Conditions,
		&record.IsActive,
		&record.Schedule,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *eventRepository) GetActionsByRuleID(ctx context.Context, ruleID int64) ([]*EventActionRecord, error) {
	query := `SELECT id, rule_id, action_type, action_config, order_index, created_at
	FROM event_actions WHERE rule_id = ? ORDER BY order_index ASC, id ASC`
	rows, err := r.db.QueryContext(ctx, query, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*EventActionRecord
	for rows.Next() {
		var record EventActionRecord
		if err := rows.Scan(
			&record.ID,
			&record.RuleID,
			&record.ActionType,
			&record.Config,
			&record.OrderIndex,
			&record.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, &record)
	}
	return records, rows.Err()
}

func (r *eventRepository) UpdateRuleActions(ctx context.Context, ruleID int64, actions []*EventActionRecord) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM event_actions WHERE rule_id = ?", ruleID); err != nil {
		tx.Rollback()
		return err
	}
	for _, action := range actions {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO event_actions (rule_id, action_type, action_config, order_index) VALUES (?, ?, ?, ?)",
			ruleID, action.ActionType, action.Config, action.OrderIndex,
		)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (r *eventRepository) ListRules(ctx context.Context) ([]*EventRuleRecord, error) {
	query := `SELECT id, name, description, trigger_type, conditions, is_active, schedule, created_at, updated_at
	FROM event_rules
	ORDER BY id ASC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*EventRuleRecord
	for rows.Next() {
		var record EventRuleRecord
		if err := rows.Scan(
			&record.ID,
			&record.Name,
			&record.Description,
			&record.TriggerType,
			&record.Conditions,
			&record.IsActive,
			&record.Schedule,
			&record.CreatedAt,
			&record.UpdatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, &record)
	}

	return records, rows.Err()
}

func (r *eventRepository) ListActionsByRuleIDs(ctx context.Context, ruleIDs []int64) ([]*EventActionRecord, error) {
	if len(ruleIDs) == 0 {
		return []*EventActionRecord{}, nil
	}

	placeholders := make([]string, 0, len(ruleIDs))
	args := make([]interface{}, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		placeholders = append(placeholders, "?")
		args = append(args, ruleID)
	}

	query := fmt.Sprintf(`SELECT id, rule_id, action_type, action_config, order_index, created_at
	FROM event_actions
	WHERE rule_id IN (%s)
	ORDER BY rule_id ASC, order_index ASC, id ASC`, strings.Join(placeholders, ","))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*EventActionRecord
	for rows.Next() {
		var record EventActionRecord
		if err := rows.Scan(
			&record.ID,
			&record.RuleID,
			&record.ActionType,
			&record.Config,
			&record.OrderIndex,
			&record.CreatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, &record)
	}

	return records, rows.Err()
}

func (r *eventRepository) CreateHistory(ctx context.Context, history *EventHistoryRecord) (*EventHistoryRecord, error) {
	query := `INSERT INTO event_history (rule_id, action_id, event_type, payload, result, error_message)
	VALUES (?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		history.RuleID,
		history.ActionID,
		history.EventType,
		history.Payload,
		history.Result,
		nullableString(history.ErrorMessage),
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	row := r.db.QueryRowContext(
		ctx,
		`SELECT id, rule_id, action_id, event_type, payload, result, COALESCE(error_message, ''), executed_at
		FROM event_history WHERE id = ?`,
		id,
	)

	var record EventHistoryRecord
	if err := row.Scan(
		&record.ID,
		&record.RuleID,
		&record.ActionID,
		&record.EventType,
		&record.Payload,
		&record.Result,
		&record.ErrorMessage,
		&record.ExecutedAt,
	); err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *eventRepository) ListHistory(ctx context.Context, eventType, result string, limit, offset int) ([]*EventHistoryRecord, error) {
	query := `SELECT id, rule_id, action_id, event_type, payload, result, COALESCE(error_message, ''), executed_at
	FROM event_history
	WHERE 1=1`
	args := []interface{}{}

	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if result != "" {
		query += " AND result = ?"
		args = append(args, result)
	}

	query += " ORDER BY executed_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*EventHistoryRecord
	for rows.Next() {
		var item EventHistoryRecord
		if err := rows.Scan(
			&item.ID,
			&item.RuleID,
			&item.ActionID,
			&item.EventType,
			&item.Payload,
			&item.Result,
			&item.ErrorMessage,
			&item.ExecutedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, &item)
	}

	return items, rows.Err()
}

func (r *eventRepository) CountHistory(ctx context.Context, eventType, result string) (int64, error) {
	query := "SELECT COUNT(*) FROM event_history WHERE 1=1"
	args := []interface{}{}

	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if result != "" {
		query += " AND result = ?"
		args = append(args, result)
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
