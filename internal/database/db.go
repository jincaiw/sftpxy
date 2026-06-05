package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jincaiw/sftpxy/internal/config"
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

	if cfg.Driver == "sqlite" {
		db.SetMaxOpenConns(2)
		db.SetMaxIdleConns(2)
	} else {
		if cfg.MaxOpenConns > 0 {
			db.SetMaxOpenConns(cfg.MaxOpenConns)
		}
		if cfg.MaxIdleConns > 0 {
			db.SetMaxIdleConns(cfg.MaxIdleConns)
		}
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
	if filePath := sqliteFilePath(dsn); filePath != "" {
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create sqlite directory: %w", err)
		}
	}

	dsnWithParams := appendSQLitePragmas(dsn,
		"journal_mode(WAL)",
		"foreign_keys(ON)",
		"busy_timeout(15000)",
	)
	db, err := sql.Open("sqlite", dsnWithParams)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	return db, nil
}

// openMySQL opens a MySQL database
func openMySQL(cfg config.DataProviderConfig) (*sql.DB, error) {
	dsn := cfg.ConnectionString
	if cfg.SSLMode != "" {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		dsn += separator + "tls=" + cfg.SSLMode
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

func sqliteFilePath(dsn string) string {
	base := dsn
	if idx := strings.Index(base, "?"); idx >= 0 {
		base = base[:idx]
	}
	base = strings.TrimPrefix(base, "file:")
	base = strings.TrimSpace(base)

	if base == "" || base == ":memory:" || strings.Contains(base, "mode=memory") {
		return ""
	}

	return filepath.Clean(base)
}

func appendSQLitePragmas(dsn string, pragmas ...string) string {
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}

	params := make([]string, 0, len(pragmas))
	for _, pragma := range pragmas {
		if strings.TrimSpace(pragma) == "" {
			continue
		}
		params = append(params, "_pragma="+url.QueryEscape(pragma))
	}
	if len(params) == 0 {
		return dsn
	}
	return dsn + separator + strings.Join(params, "&")
}
