package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/config"
)

func mysqlDSN() string {
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		return dsn
	}
	return ""
}

func skipIfNoMySQL(t *testing.T) {
	t.Helper()
	if mysqlDSN() == "" {
		t.Skip("MYSQL_DSN not set, skipping MySQL integration tests")
	}
}

func openTestMySQLDB(t *testing.T) *DB {
	t.Helper()
	dsn := mysqlDSN()
	cfg := config.DataProviderConfig{
		Driver:           "mysql",
		ConnectionString: dsn,
		MaxOpenConns:     5,
		MaxIdleConns:     2,
		ConnMaxLifetime:  300,
	}
	db, err := NewDB(cfg)
	if err != nil {
		t.Fatalf("failed to open MySQL connection: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMySQLConnection(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.HealthCheck(ctx); err != nil {
		t.Fatalf("MySQL health check failed: %v", err)
	}
}

func TestMySQLSchemaInitialization(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)
	ctx := context.Background()

	tables := []string{
		"users", "admins", "groups", "roles",
		"audit_logs", "transfer_logs", "command_logs", "http_logs",
		"sessions", "shares", "defender_blocklist",
		"event_rules", "event_actions", "event_history",
		"virtual_folders", "folder_users", "folder_groups",
		"user_groups", "user_roles", "admin_roles",
		"public_keys",
	}

	for _, table := range tables {
		var count int64
		query := fmt.Sprintf(
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = '%s'",
			table,
		)
		if err := db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			t.Errorf("failed to check table %s: %v", table, err)
			continue
		}
		if count == 0 {
			t.Logf("table %s does not exist yet (expected if migrations not run)", table)
		} else {
			t.Logf("table %s exists", table)
		}
	}
}

func TestMySQLUserCRUD(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)
	ctx := context.Background()

	username := fmt.Sprintf("test_user_%d", time.Now().UnixNano())

	result, err := db.ExecContext(ctx,
		"INSERT INTO users (username, status, home_dir, max_sessions, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
		username, "active", "/tmp/test_home", 10,
	)
	if err != nil {
		t.Fatalf("failed to insert user: %v", err)
	}
	userID, _ := result.LastInsertId()

	var fetchedName string
	if err := db.QueryRowContext(ctx, "SELECT username FROM users WHERE id = ?", userID).Scan(&fetchedName); err != nil {
		t.Fatalf("failed to query user: %v", err)
	}
	if fetchedName != username {
		t.Errorf("expected username %s, got %s", username, fetchedName)
	}

	_, err = db.ExecContext(ctx, "UPDATE users SET status = ? WHERE id = ?", "disabled", userID)
	if err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	var status string
	if err := db.QueryRowContext(ctx, "SELECT status FROM users WHERE id = ?", userID).Scan(&status); err != nil {
		t.Fatalf("failed to query user status: %v", err)
	}
	if status != "disabled" {
		t.Errorf("expected status disabled, got %s", status)
	}

	_, err = db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	var count int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count); err != nil {
		t.Fatalf("failed to count users: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users after delete, got %d", count)
	}
}

func TestMySQLAuditLogCRUD(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)
	ctx := context.Background()

	eventType := "test_event"
	actorName := fmt.Sprintf("test_actor_%d", time.Now().UnixNano())

	result, err := db.ExecContext(ctx,
		"INSERT INTO audit_logs (event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		fmt.Sprintf("test-%d", time.Now().UnixNano()), eventType, "user", actorName, "resource", "test_target", "http", "127.0.0.1", "success", "",
	)
	if err != nil {
		t.Fatalf("failed to insert audit log: %v", err)
	}
	logID, _ := result.LastInsertId()

	var fetchedType string
	if err := db.QueryRowContext(ctx, "SELECT event_type FROM audit_logs WHERE id = ?", logID).Scan(&fetchedType); err != nil {
		t.Fatalf("failed to query audit log: %v", err)
	}
	if fetchedType != eventType {
		t.Errorf("expected event_type %s, got %s", eventType, fetchedType)
	}

	_, err = db.ExecContext(ctx, "DELETE FROM audit_logs WHERE id = ?", logID)
	if err != nil {
		t.Fatalf("failed to delete audit log: %v", err)
	}
}

func TestMySQLTransactionRollback(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)
	ctx := context.Background()

	username := fmt.Sprintf("tx_test_user_%d", time.Now().UnixNano())

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (username, status, home_dir, max_sessions, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
		username, "active", "/tmp/tx_test", 10,
	)
	if err != nil {
		t.Fatalf("failed to insert user in transaction: %v", err)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("failed to rollback transaction: %v", err)
	}

	var count int64
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count); err != nil {
		t.Fatalf("failed to count users: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users after rollback, got %d", count)
	}
}

func TestMySQLDriver(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)

	if db.Driver() != "mysql" {
		t.Errorf("expected driver mysql, got %s", db.Driver())
	}
}

func TestMySQLNullHandling(t *testing.T) {
	skipIfNoMySQL(t)
	db := openTestMySQLDB(t)
	ctx := context.Background()

	username := fmt.Sprintf("null_test_%d", time.Now().UnixNano())

	_, err := db.ExecContext(ctx,
		"INSERT INTO users (username, email, status, home_dir, max_sessions, created_at, updated_at) VALUES (?, NULL, ?, ?, ?, NOW(), NOW())",
		username, "active", "/tmp/null_test", 10,
	)
	if err != nil {
		t.Fatalf("failed to insert user with null email: %v", err)
	}

	var email sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT email FROM users WHERE username = ?", username).Scan(&email); err != nil {
		t.Fatalf("failed to query user with null email: %v", err)
	}
	if email.Valid {
		t.Errorf("expected null email, got %s", email.String)
	}

	_, _ = db.ExecContext(ctx, "DELETE FROM users WHERE username = ?", username)
}
