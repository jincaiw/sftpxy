-- name: GetAdminByUsername :one
SELECT * FROM admins WHERE username = ? LIMIT 1;

-- name: GetAdminByID :one
SELECT * FROM admins WHERE id = ? LIMIT 1;

-- name: CreateAdmin :one
INSERT INTO admins (username, password_hash, status, permissions, role_id, mfa_secret, mfa_enabled, filters)
VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: UpdateAdmin :exec
UPDATE admins SET
    password_hash = COALESCE(NULLIF(?, ''), password_hash),
    status = COALESCE(NULLIF(?, ''), status),
    permissions = COALESCE(NULLIF(?, ''), permissions),
    role_id = COALESCE(NULLIF(?, 0), role_id),
    mfa_secret = COALESCE(NULLIF(?, ''), mfa_secret),
    mfa_enabled = COALESCE(?, mfa_enabled),
    filters = COALESCE(NULLIF(?, ''), filters),
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: DeleteAdmin :exec
DELETE FROM admins WHERE id = ?;

-- name: ListAdmins :many
SELECT * FROM admins ORDER BY id ASC LIMIT ? OFFSET ?;

-- name: UpdateAdminLastLogin :exec
UPDATE admins SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?;
