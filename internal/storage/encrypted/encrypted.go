package encrypted

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jincaiw/sftpxy/internal/storage"
)

// EncryptedFileSystem wraps a local filesystem with encryption
type EncryptedFileSystem struct {
	baseFS   *storage.FileSystem
	key      []byte
	basePath string
}

// Config holds encryption configuration
type Config struct {
	BasePath string `json:"base_path"`
	KeyFile  string `json:"key_file"`
	Key      string `json:"key"` // Base64 encoded key (optional, overrides KeyFile)
}

// NewEncryptedFileSystem creates a new encrypted filesystem
func NewEncryptedFileSystem(cfg Config) (*EncryptedFileSystem, error) {
	var key []byte
	var err error

	if cfg.Key != "" {
		// Use provided base64 key
		key, err = base64.StdEncoding.DecodeString(cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid key: %w", err)
		}
	} else if cfg.KeyFile != "" {
		// Read key from file
		keyData, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file: %w", err)
		}
		key = keyData
	} else {
		return nil, fmt.Errorf("either key or key_file must be specified")
	}

	// Ensure key is 32 bytes for AES-256
	if len(key) < 32 {
		// Derive 32-byte key using HKDF
		h := sha256.New()
		h.Write(key)
		key = h.Sum(nil)
	}

	return &EncryptedFileSystem{
		key:      key[:32],
		basePath: cfg.BasePath,
	}, nil
}

func (efs *EncryptedFileSystem) sanitizePath(path string) (string, error) {
	return storage.ResolveLocalPath(efs.basePath, path)
}

// encryptData encrypts plaintext using AES-GCM
func (efs *EncryptedFileSystem) encryptData(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(efs.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptData decrypts ciphertext using AES-GCM
func (efs *EncryptedFileSystem) decryptData(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(efs.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Open opens a file for reading and decrypts it
func (efs *EncryptedFileSystem) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	// Read encrypted data
	encryptedData, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Decrypt
	plaintext, err := efs.decryptData(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return io.NopCloser(&encryptedReader{data: plaintext}), nil
}

// encryptedReader implements io.ReadCloser for decrypted data
type encryptedReader struct {
	data   []byte
	offset int
}

func (er *encryptedReader) Read(p []byte) (n int, err error) {
	if er.offset >= len(er.data) {
		return 0, io.EOF
	}
	n = copy(p, er.data[er.offset:])
	er.offset += n
	return n, nil
}

func (er *encryptedReader) Close() error {
	return nil
}

// Create creates a new file, encrypts data before writing
func (efs *EncryptedFileSystem) Create(ctx context.Context, path string) (io.WriteCloser, error) {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return nil, err
	}

	// Ensure parent directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	return &encryptedWriter{
		path:   fullPath,
		buffer: make([]byte, 0),
		fs:     efs,
	}, nil
}

type encryptedWriter struct {
	path   string
	buffer []byte
	fs     *EncryptedFileSystem
	closed bool
}

func (ew *encryptedWriter) Write(p []byte) (n int, err error) {
	ew.buffer = append(ew.buffer, p...)
	return len(p), nil
}

func (ew *encryptedWriter) Close() error {
	if ew.closed {
		return nil
	}
	ew.closed = true

	// Encrypt the buffer
	encrypted, err := ew.fs.encryptData(ew.buffer)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	// Write to file
	if err := os.WriteFile(ew.path, encrypted, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// Stat returns file information (size is encrypted size)
func (efs *EncryptedFileSystem) Stat(ctx context.Context, path string) (*storage.FileInfo, error) {
	fullPath, err := efs.sanitizePath(path)
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

// Delete removes an encrypted file
func (efs *EncryptedFileSystem) Delete(ctx context.Context, path string) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Remove(fullPath)
}

// Rename renames an encrypted file
func (efs *EncryptedFileSystem) Rename(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := efs.sanitizePath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := efs.sanitizePath(newPath)
	if err != nil {
		return err
	}
	return os.Rename(oldFullPath, newFullPath)
}

// Mkdir creates a directory
func (efs *EncryptedFileSystem) Mkdir(ctx context.Context, path string) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.MkdirAll(fullPath, 0755)
}

// Rmdir removes an empty directory
func (efs *EncryptedFileSystem) Rmdir(ctx context.Context, path string) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Remove(fullPath)
}

// ListDir lists directory contents
func (efs *EncryptedFileSystem) ListDir(ctx context.Context, path string) ([]*storage.FileInfo, error) {
	fullPath, err := efs.sanitizePath(path)
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
func (efs *EncryptedFileSystem) Chmod(ctx context.Context, path string, mode os.FileMode) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Chmod(fullPath, mode)
}

// Chown changes file ownership
func (efs *EncryptedFileSystem) Chown(ctx context.Context, path string, uid, gid int) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Chown(fullPath, uid, gid)
}

// Chtimes changes file times
func (efs *EncryptedFileSystem) Chtimes(ctx context.Context, path string, atime, mtime time.Time) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Chtimes(fullPath, atime, mtime)
}

// Truncate truncates a file
func (efs *EncryptedFileSystem) Truncate(ctx context.Context, path string, size int64) error {
	fullPath, err := efs.sanitizePath(path)
	if err != nil {
		return err
	}
	return os.Truncate(fullPath, size)
}

// Symlink creates a symbolic link
func (efs *EncryptedFileSystem) Symlink(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := efs.sanitizePath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := efs.sanitizePath(newPath)
	if err != nil {
		return err
	}
	return os.Symlink(oldFullPath, newFullPath)
}

// Copy copies an encrypted file
func (efs *EncryptedFileSystem) Copy(ctx context.Context, src, dst string) error {
	srcFullPath, err := efs.sanitizePath(src)
	if err != nil {
		return err
	}
	dstFullPath, err := efs.sanitizePath(dst)
	if err != nil {
		return err
	}

	srcData, err := os.ReadFile(srcFullPath)
	if err != nil {
		return fmt.Errorf("failed to read source: %w", err)
	}

	return os.WriteFile(dstFullPath, srcData, 0644)
}

// GetUsage returns total size of encrypted files
func (efs *EncryptedFileSystem) GetUsage(ctx context.Context) (int64, error) {
	var size int64
	err := filepath.Walk(efs.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

// HealthCheck checks if the filesystem is accessible
func (efs *EncryptedFileSystem) HealthCheck(ctx context.Context) error {
	_, err := os.Stat(efs.basePath)
	if err != nil {
		return fmt.Errorf("base path not accessible: %w", err)
	}
	return nil
}

// Type returns the filesystem type
func (efs *EncryptedFileSystem) Type() string {
	return "encrypted"
}
