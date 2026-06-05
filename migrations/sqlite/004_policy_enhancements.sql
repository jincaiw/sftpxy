-- +goose Up
ALTER TABLE users ADD COLUMN protocol_permissions TEXT;
ALTER TABLE groups ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- +goose Down
-- SQLite does not support dropping columns in-place for this schema version.
