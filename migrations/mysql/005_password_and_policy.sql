-- +goose Up
ALTER TABLE users ADD COLUMN password_changed_at TEXT;
ALTER TABLE users ADD COLUMN protocol_permissions TEXT;
ALTER TABLE groups ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE users DROP COLUMN password_changed_at;
ALTER TABLE users DROP COLUMN protocol_permissions;
ALTER TABLE groups DROP COLUMN priority;
