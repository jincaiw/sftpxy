package local

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sftpxy/sftpxy/internal/storage"
)

// LocalFileSystem implements FileSystem for local disk storage
type LocalFileSystem struct {
	basePath string
	chroot   bool
}

// NewLocalFileSystem creates a new local filesystem
func NewLocalFileSystem(basePath string, chroot bool) *LocalFileSystem {
	return &LocalFileSystem{
		basePath: basePath,
		chroot:   chroot,
	}
}

// sanitizePath ensures the path is within the base path
func (fs *LocalFileSystem) sanitizePath(path string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(path)

	// If chroot is enabled, ensure path doesn't escape base
	if fs.chroot {
		fullPath := filepath.Join(fs.basePath, cleanPath)
		absPath, err := filepath.Abs(fullPath)
		if err != nil {
			return "", fmt.Errorf("invalid path: %w", err)
		}
		absBase, err := filepath.Abs(fs.basePath)
		if err != nil {
			return "", fmt.Errorf("invalid base path: %w", err)
		}
		if !strings.HasPrefix(absPath, absBase) {
			return "", fmt.Errorf("path escapes chroot: %s", path)
		}
		return absPath, nil
	}

	return filepath.Join(fs.basePath, cleanPath), nil
}

// Open opens a file for reading
func (fs *LocalFileSystem) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	return file, nil
}

// Create creates a new file for writing
func (fs *LocalFileSystem) Create(ctx context.Context, path string) (io.WriteCloser, error) {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	// Ensure parent directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Create temp file first for atomic write
	tempFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Return a wrapper that renames on close
	return &atomicWriter{
		file:     tempFile,
		tempPath: tempFile.Name(),
		finalPath: fullPath,
	}, nil
}

// atomicWriter wraps a temp file and renames it on close
type atomicWriter struct {
	file      *os.File
	tempPath  string
	finalPath string
	closed    bool
}

func (aw *atomicWriter) Write(p []byte) (n int, err error) {
	return aw.file.Write(p)
}

func (aw *atomicWriter) Close() error {
	if aw.closed {
		return nil
	}
	aw.closed = true

	// Close the temp file first
	if err := aw.file.Close(); err != nil {
		os.Remove(aw.tempPath)
		return err
	}

	// Rename temp file to final path (atomic operation)
	if err := os.Rename(aw.tempPath, aw.finalPath); err != nil {
		os.Remove(aw.tempPath)
		return fmt.Errorf("failed to finalize write: %w", err)
	}

	return nil
}

// Stat returns file information
func (fs *LocalFileSystem) Stat(ctx context.Context, path string) (*storage.FileInfo, error) {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &storage.FileInfo{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
		Sys:     info.Sys(),
	}, nil
}

// Delete removes a file
func (fs *LocalFileSystem) Delete(ctx context.Context, path string) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}

// Rename renames a file or directory
func (fs *LocalFileSystem) Rename(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := fs.sanitizePath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := fs.sanitizePath(newPath)
	if err != nil {
		return err
	}

	if err := os.Rename(oldFullPath, newFullPath); err != nil {
		return fmt.Errorf("failed to rename: %w", err)
	}
	return nil
}

// Mkdir creates a directory
func (fs *LocalFileSystem) Mkdir(ctx context.Context, path string) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// Rmdir removes an empty directory
func (fs *LocalFileSystem) Rmdir(ctx context.Context, path string) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to remove directory: %w", err)
	}
	return nil
}

// ListDir lists directory contents
func (fs *LocalFileSystem) ListDir(ctx context.Context, path string) ([]*storage.FileInfo, error) {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []*storage.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, &storage.FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
			Sys:     info.Sys(),
		})
	}

	return files, nil
}

// Chmod changes file permissions
func (fs *LocalFileSystem) Chmod(ctx context.Context, path string, mode os.FileMode) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Chmod(fullPath, mode); err != nil {
		return fmt.Errorf("failed to chmod: %w", err)
	}
	return nil
}

// Chown changes file ownership (not fully supported on all platforms)
func (fs *LocalFileSystem) Chown(ctx context.Context, path string, uid, gid int) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Chown(fullPath, uid, gid); err != nil {
		return fmt.Errorf("failed to chown: %w", err)
	}
	return nil
}

// Chtimes changes file access and modification times
func (fs *LocalFileSystem) Chtimes(ctx context.Context, path string, atime, mtime time.Time) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Chtimes(fullPath, atime, mtime); err != nil {
		return fmt.Errorf("failed to chtimes: %w", err)
	}
	return nil
}

// Truncate truncates a file to a specified size
func (fs *LocalFileSystem) Truncate(ctx context.Context, path string, size int64) error {
	fullPath, err := fs.sanitizePath(path)
	if err != nil {
		return err
	}

	if err := os.Truncate(fullPath, size); err != nil {
		return fmt.Errorf("failed to truncate: %w", err)
	}
	return nil
}

// Symlink creates a symbolic link
func (fs *LocalFileSystem) Symlink(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := fs.sanitizePath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := fs.sanitizePath(newPath)
	if err != nil {
		return err
	}

	if err := os.Symlink(oldFullPath, newFullPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}
	return nil
}

// Copy copies a file
func (fs *LocalFileSystem) Copy(ctx context.Context, src, dst string) error {
	srcFullPath, err := fs.sanitizePath(src)
	if err != nil {
		return err
	}
	dstFullPath, err := fs.sanitizePath(dst)
	if err != nil {
		return err
	}

	srcFile, err := os.Open(srcFullPath)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstFullPath)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}

	return nil
}

// GetUsage returns the total size of files in the filesystem
func (fs *LocalFileSystem) GetUsage(ctx context.Context) (int64, error) {
	var size int64
	err := filepath.Walk(fs.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return size, nil
}

// HealthCheck checks if the filesystem is accessible
func (fs *LocalFileSystem) HealthCheck(ctx context.Context) error {
	_, err := os.Stat(fs.basePath)
	if err != nil {
		return fmt.Errorf("base path not accessible: %w", err)
	}
	return nil
}

// Type returns the filesystem type
func (fs *LocalFileSystem) Type() string {
	return "local"
}
