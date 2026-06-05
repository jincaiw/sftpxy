package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/jincaiw/sftpxy/internal/auth"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	dbPath := filepath.Join(root, "data", "e2e", "sftpxy.db")
	homeDir := filepath.Join(root, "data", "e2e", "home", "testuser")
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, "existing.txt"), []byte("hello from e2e\n"), 0o644); err != nil {
		panic(err)
	}

	adminHash, hashErr := auth.HashPassword("admin-pass")
	if hashErr != nil {
		panic(hashErr)
	}
	userHash, userHashErr := auth.HashPassword("testuser-pass")
	if userHashErr != nil {
		panic(userHashErr)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	adminStmt := `
INSERT INTO admins (username, password_hash, status, permissions)
VALUES (?, ?, 'active', '["*"]')
ON CONFLICT(username) DO UPDATE SET
	password_hash = excluded.password_hash,
	status = excluded.status,
	permissions = excluded.permissions,
	updated_at = CURRENT_TIMESTAMP
`
	if _, err := db.Exec(adminStmt, "admin", adminHash); err != nil {
		panic(err)
	}

	userStmt := `
INSERT INTO users (username, email, status, password_hash, home_dir, filesystem, permissions, mfa_enabled, max_sessions)
VALUES (?, ?, 'active', ?, ?, ?, ?, FALSE, 5)
ON CONFLICT(username) DO UPDATE SET
	email = excluded.email,
	status = excluded.status,
	password_hash = excluded.password_hash,
	home_dir = excluded.home_dir,
	filesystem = excluded.filesystem,
	permissions = excluded.permissions,
	mfa_enabled = excluded.mfa_enabled,
	max_sessions = excluded.max_sessions,
	updated_at = CURRENT_TIMESTAMP
`
	if _, err := db.Exec(userStmt, "testuser", "testuser@example.com", userHash, homeDir, "local", "full"); err != nil {
		panic(err)
	}

	fmt.Println("seeded e2e admin and testuser")
}
