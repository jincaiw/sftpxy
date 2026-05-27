package storage

import (
	"context"
	"io"
	"os"
	"time"
)

// FileInfo contains information about a file or directory
type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
	Sys     interface{}
}

// FileSystem defines the interface for all storage backends
type FileSystem interface {
	// File operations
	Open(ctx context.Context, path string) (io.ReadCloser, error)
	Create(ctx context.Context, path string) (io.WriteCloser, error)
	Stat(ctx context.Context, path string) (*FileInfo, error)
	Delete(ctx context.Context, path string) error
	Rename(ctx context.Context, oldPath, newPath string) error
	Mkdir(ctx context.Context, path string) error
	Rmdir(ctx context.Context, path string) error
	ListDir(ctx context.Context, path string) ([]*FileInfo, error)

	// Metadata operations
	Chmod(ctx context.Context, path string, mode os.FileMode) error
	Chown(ctx context.Context, path string, uid, gid int) error
	Chtimes(ctx context.Context, path string, atime, mtime time.Time) error
	Truncate(ctx context.Context, path string, size int64) error
	Symlink(ctx context.Context, oldPath, newPath string) error
	Copy(ctx context.Context, src, dst string) error

	// Quota
	GetUsage(ctx context.Context) (int64, error)

	// Health
	HealthCheck(ctx context.Context) error

	// Type returns the filesystem type name
	Type() string
}

// FileSystemConfig contains configuration for creating a filesystem
type FileSystemConfig struct {
	Type   string                 `json:"type"`   // local, encrypted, remotesftp, httpfs
	Config map[string]interface{} `json:"config"` // Backend-specific configuration
}

// Factory creates FileSystem instances based on configuration
type Factory interface {
	CreateFileSystem(ctx context.Context, config *FileSystemConfig) (FileSystem, error)
}
