-- +goose Up
ALTER TABLE users ADD COLUMN email TEXT;

-- +goose Down
-- SQLite does not support dropping a column in-place for this schema version.
