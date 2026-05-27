-- name: CreateAuditLog :one
INSERT INTO audit_logs (
    event_id, event_type, actor_type, actor_name,
    target_type, target_id, protocol, client_ip,
    result, error_message
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: ListAuditLogs :many
SELECT * FROM audit_logs
WHERE (? = '' OR event_type = ?)
AND (? = '' OR actor_name = ?)
AND (? = '' OR client_ip = ?)
AND (? = '' OR protocol = ?)
AND (? = '' OR result = ?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CountAuditLogs :one
SELECT COUNT(*) FROM audit_logs;

-- name: CreateTransferLog :one
INSERT INTO transfer_logs (
    operation, username, protocol, connection_id,
    local_address, remote_address, file_path, file_size,
    bytes_transferred, start_time, end_time, duration_ms,
    status, error, ftp_mode
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: ListTransferLogs :many
SELECT * FROM transfer_logs
WHERE (? = '' OR username = ?)
AND (? = '' OR protocol = ?)
AND (? = '' OR operation = ?)
AND (? = '' OR status = ?)
ORDER BY created_at DESC
LIMIT ? OFFSET ?;

-- name: CreateCommandLog :one
INSERT INTO command_logs (command, username, protocol, path, new_path, result, error)
VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: CreateHTTPLog :one
INSERT INTO http_logs (
    method, path, status_code, username, client_ip,
    user_agent, response_time_ms, request_size, response_size,
    auth_method, error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: AddBlockedIP :one
INSERT INTO defender_blocklist (ip, protocol, reason, expires_at)
VALUES (?, ?, ?, ?) RETURNING *;

-- name: GetBlockedIP :one
SELECT * FROM defender_blocklist WHERE ip = ? AND is_active = TRUE LIMIT 1;

-- name: UnblockIP :exec
UPDATE defender_blocklist SET is_active = FALSE WHERE ip = ?;

-- name: ListActiveBlocks :many
SELECT * FROM defender_blocklist WHERE is_active = TRUE ORDER BY blocked_at DESC LIMIT ? OFFSET ?;

-- name: CleanExpiredBlocks :exec
UPDATE defender_blocklist SET is_active = FALSE WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND is_active = TRUE;
