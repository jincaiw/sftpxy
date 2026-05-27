package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/sftpxy/sftpxy/internal/config"
	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB with additional functionality
type DB struct {
	*sql.DB
	driver string
}

// NewDB creates a new database connection
func NewDB(cfg config.DataProviderConfig) (*DB, error) {
	var db *sql.DB
	var err error

	switch cfg.Driver {
	case "sqlite":
		db, err = openSQLite(cfg.ConnectionString)
	case "mysql":
		db, err = openMySQL(cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second)
	}

	return &DB{
		DB:     db,
		driver: cfg.Driver,
	}, nil
}

// openSQLite opens a SQLite database
func openSQLite(dsn string) (*sql.DB, error) {
	// Add query parameters for SQLite
	dsnWithParams := dsn + "?_journal_mode=WAL&_foreign_keys=ON"
	return sql.Open("sqlite", dsnWithParams)
}

// openMySQL opens a MySQL database
func openMySQL(cfg config.DataProviderConfig) (*sql.DB, error) {
	// Build MySQL DSN
	dsn := cfg.ConnectionString
	if cfg.SSLMode != "" {
		dsn += "&tls=" + cfg.SSLMode
	}
	return sql.Open("mysql", dsn)
}

// HealthCheck checks if the database is accessible
func (db *DB) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return db.PingContext(ctx)
}

// Driver returns the database driver name
func (db *DB) Driver() string {
	return db.driver
}

// Close closes the database connection
func (db *DB) Close() error {
	if db.DB != nil {
		return db.DB.Close()
	}
	return nil
}
