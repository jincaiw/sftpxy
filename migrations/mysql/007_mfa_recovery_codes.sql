-- +goose Up
ALTER TABLE users ADD COLUMN mfa_recovery_codes TEXT;
