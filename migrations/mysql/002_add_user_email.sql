-- +goose Up
ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL AFTER username;

-- +goose Down
ALTER TABLE users DROP COLUMN email;
