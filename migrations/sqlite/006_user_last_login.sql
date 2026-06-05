-- +goose Up
ALTER TABLE users ADD COLUMN last_login_at DATETIME;
