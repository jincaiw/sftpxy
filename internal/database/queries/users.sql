-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ? LIMIT 1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ? LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (
    username, status, password_hash, home_dir, filesystem,
    permissions, filters, quotas, bandwidth_limits,
    transfer_limits, max_sessions, allowed_protocols,
    denied_protocols, ip_filters, mfa_secret, mfa_enabled,
    expiration_date, description
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
) RETURNING *;

-- name: UpdateUser :exec
UPDATE users SET
    status = COALESCE(NULLIF(?, ''), status),
    password_hash = COALESCE(NULLIF(?, ''), password_hash),
    home_dir = COALESCE(NULLIF(?, ''), home_dir),
    filesystem = COALESCE(NULLIF(?, ''), filesystem),
    permissions = COALESCE(NULLIF(?, ''), permissions),
    filters = COALESCE(NULLIF(?, ''), filters),
    quotas = COALESCE(NULLIF(?, ''), quotas),
    bandwidth_limits = COALESCE(NULLIF(?, ''), bandwidth_limits),
    transfer_limits = COALESCE(NULLIF(?, ''), transfer_limits),
    max_sessions = COALESCE(NULLIF(?, 0), max_sessions),
    allowed_protocols = COALESCE(NULLIF(?, ''), allowed_protocols),
    denied_protocols = COALESCE(NULLIF(?, ''), denied_protocols),
    ip_filters = COALESCE(NULLIF(?, ''), ip_filters),
    mfa_secret = COALESCE(NULLIF(?, ''), mfa_secret),
    mfa_enabled = COALESCE(?, mfa_enabled),
    expiration_date = COALESCE(NULLIF(?, ''), expiration_date),
    description = COALESCE(NULLIF(?, ''), description),
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users
WHERE (? = '' OR username LIKE ?)
AND (? = '' OR status = ?)
ORDER BY id ASC
LIMIT ? OFFSET ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;

-- name: UpdateUserStatus :exec
UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: GetPublicKeysByUserID :many
SELECT * FROM public_keys WHERE user_id = ? ORDER BY created_at ASC;

-- name: AddPublicKey :one
INSERT INTO public_keys (user_id, label, public_key) VALUES (?, ?, ?) RETURNING *;

-- name: DeletePublicKey :exec
DELETE FROM public_keys WHERE id = ? AND user_id = ?;
