package repository

import (
	"context"
	"time"

	"github.com/jincaiw/sftpxy/internal/database"
)

// AuditLog represents an audit event
type AuditLog struct {
	ID           int64     `json:"id"`
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	ActorType    string    `json:"actor_type"`
	ActorName    string    `json:"actor_name"`
	TargetType   string    `json:"target_type"`
	TargetID     string    `json:"target_id"`
	Protocol     string    `json:"protocol"`
	ClientIP     string    `json:"client_ip"`
	Result       string    `json:"result"`
	ErrorMessage string    `json:"error_message"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuditFilter holds all 12 query filter criteria from PRD 17.5
type AuditFilter struct {
	FromTime       time.Time
	ToTime         time.Time
	Username       string
	Admin          string
	ClientIP       string
	Protocol       string
	EventType      string
	FilePath       string
	Status         string
	ErrorCode      string
	ConnectionID   string
	EventRuleID    string
	StorageBackend string
}

// TransferLog represents a file transfer log entry
type TransferLog struct {
	ID               int64     `json:"id"`
	Operation        string    `json:"operation"`
	Username         string    `json:"username"`
	Protocol         string    `json:"protocol"`
	ConnectionID     string    `json:"connection_id"`
	LocalAddress     string    `json:"local_address"`
	RemoteAddress    string    `json:"remote_address"`
	FilePath         string    `json:"file_path"`
	FileSize         int64     `json:"file_size"`
	BytesTransferred int64     `json:"bytes_transferred"`
	StartTime        time.Time `json:"start_time"`
	EndTime          time.Time `json:"end_time"`
	DurationMs       int       `json:"duration_ms"`
	Status           string    `json:"status"`
	Error            string    `json:"error"`
	FTPMode          string    `json:"ftp_mode"`
	CreatedAt        time.Time `json:"created_at"`
}

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Protocol  string    `json:"protocol"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
}

// AuditRepository defines the interface for audit data access
type AuditRepository interface {
	// Audit logs
	CreateAuditLog(ctx context.Context, log *AuditLog) (*AuditLog, error)
	ListAuditLogs(ctx context.Context, eventType, actorName, clientIP, protocol, result string, limit, offset int) ([]*AuditLog, error)
	ListAuditLogsFiltered(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditLog, error)
	CountAuditLogs(ctx context.Context) (int64, error)

	// Transfer logs
	CreateTransferLog(ctx context.Context, log *TransferLog) (*TransferLog, error)
	ListTransferLogs(ctx context.Context, username, protocol, operation, status string, limit, offset int) ([]*TransferLog, error)

	// Command logs
	CreateCommandLog(ctx context.Context, command, username, protocol, path, newPath, result, errMsg string) error

	// HTTP logs
	CreateHTTPLog(ctx context.Context, method, path string, statusCode int, username, clientIP, userAgent string, responseTimeMs, requestSize, responseSize int, authMethod, errMsg string) error

	// Defender blocklist
	AddBlockedIP(ctx context.Context, ip, protocol, reason string, expiresAt time.Time) (*BlockedIP, error)
	GetBlockedIP(ctx context.Context, ip string) (*BlockedIP, error)
	UnblockIP(ctx context.Context, ip string) error
	ListActiveBlocks(ctx context.Context, limit, offset int) ([]*BlockedIP, error)
	CleanExpiredBlocks(ctx context.Context) error
}

// auditRepository implements AuditRepository
type auditRepository struct {
	db *database.DB
}

// NewAuditRepository creates a new AuditRepository
func NewAuditRepository(db *database.DB) AuditRepository {
	return &auditRepository{db: db}
}

func (r *auditRepository) CreateAuditLog(ctx context.Context, log *AuditLog) (*AuditLog, error) {
	query := `INSERT INTO audit_logs (event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query,
		log.EventID, log.EventType, log.ActorType, log.ActorName,
		log.TargetType, log.TargetID, log.Protocol, log.ClientIP,
		log.Result, log.ErrorMessage,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	log.ID = id
	return log, nil
}

func (r *auditRepository) ListAuditLogs(ctx context.Context, eventType, actorName, clientIP, protocol, result string, limit, offset int) ([]*AuditLog, error) {
	query := "SELECT id, event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message, created_at FROM audit_logs WHERE 1=1"
	args := []interface{}{}

	if eventType != "" {
		query += " AND event_type = ?"
		args = append(args, eventType)
	}
	if actorName != "" {
		query += " AND actor_name = ?"
		args = append(args, actorName)
	}
	if clientIP != "" {
		query += " AND client_ip = ?"
		args = append(args, clientIP)
	}
	if protocol != "" {
		query += " AND protocol = ?"
		args = append(args, protocol)
	}
	if result != "" {
		query += " AND result = ?"
		args = append(args, result)
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		err := rows.Scan(
			&log.ID, &log.EventID, &log.EventType, &log.ActorType,
			&log.ActorName, &log.TargetType, &log.TargetID, &log.Protocol,
			&log.ClientIP, &log.Result, &log.ErrorMessage, &log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &log)
	}
	return logs, rows.Err()
}

func (r *auditRepository) CountAuditLogs(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_logs").Scan(&count)
	return count, err
}

func (r *auditRepository) ListAuditLogsFiltered(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditLog, error) {
	query := "SELECT id, event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message, created_at FROM audit_logs WHERE 1=1"
	args := []interface{}{}

	if filter == nil {
		filter = &AuditFilter{}
	}

	if !filter.FromTime.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, filter.FromTime)
	}
	if !filter.ToTime.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, filter.ToTime)
	}
	if filter.Username != "" {
		query += " AND actor_name = ? AND actor_type = 'user'"
		args = append(args, filter.Username)
	}
	if filter.Admin != "" {
		query += " AND actor_name = ? AND actor_type = 'admin'"
		args = append(args, filter.Admin)
	}
	if filter.ClientIP != "" {
		query += " AND client_ip = ?"
		args = append(args, filter.ClientIP)
	}
	if filter.Protocol != "" {
		query += " AND protocol = ?"
		args = append(args, filter.Protocol)
	}
	if filter.EventType != "" {
		query += " AND event_type = ?"
		args = append(args, filter.EventType)
	}
	if filter.FilePath != "" {
		query += " AND target_id LIKE ?"
		args = append(args, "%"+filter.FilePath+"%")
	}
	if filter.Status != "" {
		query += " AND result = ?"
		args = append(args, filter.Status)
	}
	if filter.ErrorCode != "" {
		query += " AND error_message LIKE ?"
		args = append(args, "%"+filter.ErrorCode+"%")
	}
	if filter.ConnectionID != "" {
		query += " AND target_id = ?"
		args = append(args, filter.ConnectionID)
	}
	if filter.EventRuleID != "" {
		query += " AND target_id = ?"
		args = append(args, filter.EventRuleID)
	}
	if filter.StorageBackend != "" {
		query += " AND protocol = ?"
		args = append(args, filter.StorageBackend)
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		err := rows.Scan(
			&log.ID, &log.EventID, &log.EventType, &log.ActorType,
			&log.ActorName, &log.TargetType, &log.TargetID, &log.Protocol,
			&log.ClientIP, &log.Result, &log.ErrorMessage, &log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &log)
	}
	return logs, rows.Err()
}

func (r *auditRepository) CreateTransferLog(ctx context.Context, log *TransferLog) (*TransferLog, error) {
	query := `INSERT INTO transfer_logs (operation, username, protocol, connection_id, local_address, remote_address, file_path, file_size, bytes_transferred, start_time, end_time, duration_ms, status, error, ftp_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(ctx, query,
		log.Operation, log.Username, log.Protocol, log.ConnectionID,
		log.LocalAddress, log.RemoteAddress, log.FilePath, log.FileSize,
		log.BytesTransferred, log.StartTime, log.EndTime, log.DurationMs,
		log.Status, log.Error, log.FTPMode,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	log.ID = id
	return log, nil
}

func (r *auditRepository) ListTransferLogs(ctx context.Context, username, protocol, operation, status string, limit, offset int) ([]*TransferLog, error) {
	query := "SELECT id, operation, username, protocol, connection_id, local_address, remote_address, file_path, file_size, bytes_transferred, start_time, end_time, duration_ms, status, error, ftp_mode, created_at FROM transfer_logs WHERE 1=1"
	args := []interface{}{}

	if username != "" {
		query += " AND username = ?"
		args = append(args, username)
	}
	if protocol != "" {
		query += " AND protocol = ?"
		args = append(args, protocol)
	}
	if operation != "" {
		query += " AND operation = ?"
		args = append(args, operation)
	}
	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*TransferLog
	for rows.Next() {
		var log TransferLog
		err := rows.Scan(
			&log.ID, &log.Operation, &log.Username, &log.Protocol,
			&log.ConnectionID, &log.LocalAddress, &log.RemoteAddress,
			&log.FilePath, &log.FileSize, &log.BytesTransferred,
			&log.StartTime, &log.EndTime, &log.DurationMs, &log.Status,
			&log.Error, &log.FTPMode, &log.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		logs = append(logs, &log)
	}
	return logs, rows.Err()
}

func (r *auditRepository) CreateCommandLog(ctx context.Context, command, username, protocol, path, newPath, result, errMsg string) error {
	query := "INSERT INTO command_logs (command, username, protocol, path, new_path, result, error) VALUES (?, ?, ?, ?, ?, ?, ?)"
	_, err := r.db.ExecContext(ctx, query, command, username, protocol, path, newPath, result, errMsg)
	return err
}

func (r *auditRepository) CreateHTTPLog(ctx context.Context, method, path string, statusCode int, username, clientIP, userAgent string, responseTimeMs, requestSize, responseSize int, authMethod, errMsg string) error {
	query := `INSERT INTO http_logs (method, path, status_code, username, client_ip, user_agent, response_time_ms, request_size, response_size, auth_method, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := r.db.ExecContext(ctx, query, method, path, statusCode, username, clientIP, userAgent, responseTimeMs, requestSize, responseSize, authMethod, errMsg)
	return err
}

func (r *auditRepository) AddBlockedIP(ctx context.Context, ip, protocol, reason string, expiresAt time.Time) (*BlockedIP, error) {
	query := "INSERT INTO defender_blocklist (ip, protocol, reason, expires_at) VALUES (?, ?, ?, ?)"

	result, err := r.db.ExecContext(ctx, query, ip, protocol, reason, expiresAt)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &BlockedIP{
		ID:        id,
		IP:        ip,
		Protocol:  protocol,
		Reason:    reason,
		ExpiresAt: expiresAt,
		IsActive:  true,
	}, nil
}

func (r *auditRepository) GetBlockedIP(ctx context.Context, ip string) (*BlockedIP, error) {
	query := "SELECT id, ip, protocol, reason, blocked_at, expires_at, is_active FROM defender_blocklist WHERE ip = ? AND is_active = TRUE LIMIT 1"

	var block BlockedIP
	err := r.db.QueryRowContext(ctx, query, ip).Scan(
		&block.ID, &block.IP, &block.Protocol, &block.Reason,
		&block.BlockedAt, &block.ExpiresAt, &block.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return &block, nil
}

func (r *auditRepository) UnblockIP(ctx context.Context, ip string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE defender_blocklist SET is_active = FALSE WHERE ip = ?", ip)
	return err
}

func (r *auditRepository) ListActiveBlocks(ctx context.Context, limit, offset int) ([]*BlockedIP, error) {
	query := "SELECT id, ip, protocol, reason, blocked_at, expires_at, is_active FROM defender_blocklist WHERE is_active = TRUE ORDER BY blocked_at DESC LIMIT ? OFFSET ?"

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []*BlockedIP
	for rows.Next() {
		var block BlockedIP
		err := rows.Scan(
			&block.ID, &block.IP, &block.Protocol, &block.Reason,
			&block.BlockedAt, &block.ExpiresAt, &block.IsActive,
		)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, &block)
	}
	return blocks, rows.Err()
}

func (r *auditRepository) CleanExpiredBlocks(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "UPDATE defender_blocklist SET is_active = FALSE WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND is_active = TRUE")
	return err
}
