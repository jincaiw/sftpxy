-- name: GetShareByToken :one
SELECT * FROM shares WHERE token = ? LIMIT 1;

-- name: GetSharesByUserID :many
SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC;

-- name: CreateShare :one
INSERT INTO shares (
    token, user_id, share_type, path, password_hash,
    expires_at, max_downloads, max_uploads, ip_restrictions
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *;

-- name: UpdateShareDownloadCount :exec
UPDATE shares SET download_count = download_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateShareUploadCount :exec
UPDATE shares SET upload_count = upload_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeactivateShare :exec
UPDATE shares SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: DeleteShare :exec
DELETE FROM shares WHERE id = ?;

-- name: ListActiveShares :many
SELECT * FROM shares WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: ExpireOldShares :exec
UPDATE shares SET is_active = FALSE WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND is_active = TRUE;
