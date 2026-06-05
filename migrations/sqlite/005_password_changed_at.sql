-- +goose Up
ALTER TABLE users ADD COLUMN password_changed_at TEXT;

-- +goose Down
-- SQLite does not support dropping columns in-place for this schema version.
