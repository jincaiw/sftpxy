package remotesftp

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	pathpkg "path"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/internal/storage"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// RemoteSFTPFileSystem implements FileSystem for remote SFTP storage
type RemoteSFTPFileSystem struct {
	client     *sftp.Client
	sshClient  *ssh.Client
	host       string
	port       int
	username   string
	password   string
	privateKey string
	pathPrefix string
	timeout    time.Duration
}

// Config holds RemoteSFTP configuration
type Config struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"` // Path to private key file
	HostKey    string `json:"host_key"`    // SSH public key or SHA256 fingerprint
	PathPrefix string `json:"path_prefix"`
	Timeout    int    `json:"timeout"` // Seconds
}

// NewRemoteSFTPFileSystem creates a new remote SFTP filesystem
func NewRemoteSFTPFileSystem(cfg Config) (*RemoteSFTPFileSystem, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}

	// Create SSH config
	sshConfig := &ssh.ClientConfig{
		User:    cfg.Username,
		Auth:    []ssh.AuthMethod{},
		Timeout: time.Duration(cfg.Timeout) * time.Second,
	}
	hostKeyCallback, err := buildHostKeyCallback(cfg.HostKey)
	if err != nil {
		return nil, err
	}
	sshConfig.HostKeyCallback = hostKeyCallback

	// Add authentication methods
	if cfg.Password != "" {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(cfg.Password))
	}

	if cfg.PrivateKey != "" {
		key, err := loadPrivateKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(key))
	}

	if len(sshConfig.Auth) == 0 {
		return nil, fmt.Errorf("no authentication method specified")
	}

	// Connect to SSH server
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	sshClient, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %w", err)
	}

	// Create SFTP client
	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		sshClient.Close()
		return nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}

	return &RemoteSFTPFileSystem{
		client:     sftpClient,
		sshClient:  sshClient,
		host:       cfg.Host,
		port:       cfg.Port,
		username:   cfg.Username,
		password:   cfg.Password,
		privateKey: cfg.PrivateKey,
		pathPrefix: cfg.PathPrefix,
		timeout:    time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

func buildHostKeyCallback(expected string) (ssh.HostKeyCallback, error) {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil, fmt.Errorf("remote sftp host_key verification must be configured")
	}

	if strings.HasPrefix(expected, "ssh-") {
		expectedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expected))
		if err != nil {
			return nil, fmt.Errorf("failed to parse remote sftp host_key: %w", err)
		}
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			if string(key.Marshal()) != string(expectedKey.Marshal()) {
				return fmt.Errorf("remote sftp host key mismatch for %s", hostname)
			}
			return nil
		}, nil
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		actualFingerprint := ssh.FingerprintSHA256(key)
		if actualFingerprint != expected {
			return fmt.Errorf("remote sftp host key fingerprint mismatch for %s: got %s", hostname, actualFingerprint)
		}
		return nil
	}, nil
}

// loadPrivateKey loads an SSH private key from file
func loadPrivateKey(path string) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

// fullPath returns the full path with prefix and rejects prefix escapes.
func (fs *RemoteSFTPFileSystem) fullPath(path string) (string, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		cleanPath = "."
	}
	cleanPath = strings.TrimLeft(cleanPath, "/")
	cleanPath = pathpkg.Clean(cleanPath)
	if cleanPath == "." {
		cleanPath = ""
	}
	if fs.pathPrefix == "" {
		return cleanPath, nil
	}

	cleanPrefix := pathpkg.Clean("/" + strings.TrimSpace(fs.pathPrefix))
	fullPath := pathpkg.Join(cleanPrefix, cleanPath)
	if cleanPrefix != "/" && fullPath != cleanPrefix && !strings.HasPrefix(fullPath, cleanPrefix+"/") {
		return "", fmt.Errorf("path escapes remote prefix")
	}
	return fullPath, nil
}

// Open opens a file for reading
func (fs *RemoteSFTPFileSystem) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return nil, err
	}

	file, err := fs.client.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	return file, nil
}

// Create creates a new file for writing
func (fs *RemoteSFTPFileSystem) Create(ctx context.Context, path string) (io.WriteCloser, error) {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return nil, err
	}

	// Ensure parent directory exists
	dir := pathpkg.Dir(fullPath)
	if err := fs.client.MkdirAll(dir); err != nil {
		// Ignore error if directory already exists
	}

	file, err := fs.client.Create(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	return file, nil
}

// Stat returns file information
func (fs *RemoteSFTPFileSystem) Stat(ctx context.Context, path string) (*storage.FileInfo, error) {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return nil, err
	}

	info, err := fs.client.Stat(fullPath)
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
func (fs *RemoteSFTPFileSystem) Delete(ctx context.Context, path string) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.Remove(fullPath)
}

// Rename renames a file or directory
func (fs *RemoteSFTPFileSystem) Rename(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := fs.fullPath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := fs.fullPath(newPath)
	if err != nil {
		return err
	}
	return fs.client.Rename(oldFullPath, newFullPath)
}

// Mkdir creates a directory
func (fs *RemoteSFTPFileSystem) Mkdir(ctx context.Context, path string) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.MkdirAll(fullPath)
}

// Rmdir removes an empty directory
func (fs *RemoteSFTPFileSystem) Rmdir(ctx context.Context, path string) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.RemoveDirectory(fullPath)
}

// ListDir lists directory contents
func (fs *RemoteSFTPFileSystem) ListDir(ctx context.Context, path string) ([]*storage.FileInfo, error) {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return nil, err
	}

	entries, err := fs.client.ReadDir(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []*storage.FileInfo
	for _, entry := range entries {
		files = append(files, &storage.FileInfo{
			Name:    entry.Name(),
			Size:    entry.Size(),
			Mode:    entry.Mode(),
			ModTime: entry.ModTime(),
			IsDir:   entry.IsDir(),
			Sys:     entry.Sys(),
		})
	}

	return files, nil
}

// Chmod changes file permissions
func (fs *RemoteSFTPFileSystem) Chmod(ctx context.Context, path string, mode os.FileMode) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.Chmod(fullPath, mode)
}

// Chown changes file ownership (may not be supported by all SFTP servers)
func (fs *RemoteSFTPFileSystem) Chown(ctx context.Context, path string, uid, gid int) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.Chown(fullPath, uid, gid)
}

// Chtimes changes file times
func (fs *RemoteSFTPFileSystem) Chtimes(ctx context.Context, path string, atime, mtime time.Time) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.Chtimes(fullPath, atime, mtime)
}

// Truncate truncates a file
func (fs *RemoteSFTPFileSystem) Truncate(ctx context.Context, path string, size int64) error {
	fullPath, err := fs.fullPath(path)
	if err != nil {
		return err
	}
	return fs.client.Truncate(fullPath, size)
}

// Symlink creates a symbolic link (may not be supported)
func (fs *RemoteSFTPFileSystem) Symlink(ctx context.Context, oldPath, newPath string) error {
	oldFullPath, err := fs.fullPath(oldPath)
	if err != nil {
		return err
	}
	newFullPath, err := fs.fullPath(newPath)
	if err != nil {
		return err
	}
	return fs.client.Symlink(oldFullPath, newFullPath)
}

// Copy copies a file (downloads and re-uploads)
func (fs *RemoteSFTPFileSystem) Copy(ctx context.Context, src, dst string) error {
	srcFullPath, err := fs.fullPath(src)
	if err != nil {
		return err
	}
	dstFullPath, err := fs.fullPath(dst)
	if err != nil {
		return err
	}

	// Open source file
	srcFile, err := fs.client.Open(srcFullPath)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := fs.client.Create(dstFullPath)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer dstFile.Close()

	// Copy data
	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetUsage returns total size of files (may be expensive on remote)
func (fs *RemoteSFTPFileSystem) GetUsage(ctx context.Context) (int64, error) {
	// For remote SFTP, we return -1 to indicate unknown
	// Calculating total usage would require walking the entire tree
	return -1, nil
}

// HealthCheck checks if the connection is alive
func (fs *RemoteSFTPFileSystem) HealthCheck(ctx context.Context) error {
	// Try to get current directory as a health check
	_, err := fs.client.Getwd()
	if err != nil {
		return fmt.Errorf("connection not healthy: %w", err)
	}
	return nil
}

// Type returns the filesystem type
func (fs *RemoteSFTPFileSystem) Type() string {
	return "remotesftp"
}

// Close closes the connections
func (fs *RemoteSFTPFileSystem) Close() error {
	if fs.client != nil {
		fs.client.Close()
	}
	if fs.sshClient != nil {
		fs.sshClient.Close()
	}
	return nil
}
