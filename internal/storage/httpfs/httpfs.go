package httpfs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sftpxy/sftpxy/internal/storage"
)

// HTTPFsFileSystem implements FileSystem using external HTTP API
type HTTPFsFileSystem struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	timeout    time.Duration
}

// Config holds HTTPFs configuration
type Config struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	Timeout int    `json:"timeout"` // Seconds
}

// NewHTTPFsFileSystem creates a new HTTP filesystem
func NewHTTPFsFileSystem(cfg Config) (*HTTPFsFileSystem, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}

	return &HTTPFsFileSystem{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
		timeout: time.Duration(cfg.Timeout) * time.Second,
	}, nil
}

// httpRequest performs an HTTP request with authentication
func (hfs *HTTPFsFileSystem) httpRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := hfs.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication header
	if hfs.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+hfs.apiKey)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := hfs.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check for error responses
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp, nil
}

// Open opens a file for reading
func (hfs *HTTPFsFileSystem) Open(ctx context.Context, path string) (io.ReadCloser, error) {
	resp, err := hfs.httpRequest(ctx, "GET", "/files"+path, nil)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// Create creates a new file for writing
func (hfs *HTTPFsFileSystem) Create(ctx context.Context, path string) (io.WriteCloser, error) {
	return &httpWriter{
		hfs:  hfs,
		path: path,
		ctx:  ctx,
	}, nil
}

type httpWriter struct {
	hfs     *HTTPFsFileSystem
	path    string
	ctx     context.Context
	buffer  bytes.Buffer
	closed  bool
}

func (hw *httpWriter) Write(p []byte) (n int, err error) {
	return hw.buffer.Write(p)
}

func (hw *httpWriter) Close() error {
	if hw.closed {
		return nil
	}
	hw.closed = true

	// Upload the file content
	resp, err := hw.hfs.httpRequest(hw.ctx, "PUT", "/files"+hw.path, &hw.buffer)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Stat returns file information
func (hfs *HTTPFsFileSystem) Stat(ctx context.Context, path string) (*storage.FileInfo, error) {
	resp, err := hfs.httpRequest(ctx, "GET", "/stat"+path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var statInfo struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		Mode    uint32    `json:"mode"`
		ModTime time.Time `json:"mod_time"`
		IsDir   bool      `json:"is_dir"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&statInfo); err != nil {
		return nil, fmt.Errorf("failed to decode stat response: %w", err)
	}

	return &storage.FileInfo{
		Name:    statInfo.Name,
		Size:    statInfo.Size,
		Mode:    os.FileMode(statInfo.Mode),
		ModTime: statInfo.ModTime,
		IsDir:   statInfo.IsDir,
		Sys:     nil,
	}, nil
}

// Delete removes a file
func (hfs *HTTPFsFileSystem) Delete(ctx context.Context, path string) error {
	resp, err := hfs.httpRequest(ctx, "DELETE", "/files"+path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Rename renames a file or directory
func (hfs *HTTPFsFileSystem) Rename(ctx context.Context, oldPath, newPath string) error {
	body := map[string]string{"new_path": newPath}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/rename"+oldPath, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Mkdir creates a directory
func (hfs *HTTPFsFileSystem) Mkdir(ctx context.Context, path string) error {
	resp, err := hfs.httpRequest(ctx, "POST", "/dirs"+path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Rmdir removes an empty directory
func (hfs *HTTPFsFileSystem) Rmdir(ctx context.Context, path string) error {
	resp, err := hfs.httpRequest(ctx, "DELETE", "/dirs"+path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListDir lists directory contents
func (hfs *HTTPFsFileSystem) ListDir(ctx context.Context, path string) ([]*storage.FileInfo, error) {
	resp, err := hfs.httpRequest(ctx, "GET", "/list"+path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var items []struct {
		Name    string    `json:"name"`
		Size    int64     `json:"size"`
		Mode    uint32    `json:"mode"`
		ModTime time.Time `json:"mod_time"`
		IsDir   bool      `json:"is_dir"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("failed to decode list response: %w", err)
	}

	var files []*storage.FileInfo
	for _, item := range items {
		files = append(files, &storage.FileInfo{
			Name:    item.Name,
			Size:    item.Size,
			Mode:    os.FileMode(item.Mode),
			ModTime: item.ModTime,
			IsDir:   item.IsDir,
			Sys:     nil,
		})
	}

	return files, nil
}

// Chmod changes file permissions
func (hfs *HTTPFsFileSystem) Chmod(ctx context.Context, path string, mode os.FileMode) error {
	body := map[string]interface{}{"mode": uint32(mode)}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/chmod"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Chown changes file ownership
func (hfs *HTTPFsFileSystem) Chown(ctx context.Context, path string, uid, gid int) error {
	body := map[string]interface{}{"uid": uid, "gid": gid}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/chown"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Chtimes changes file times
func (hfs *HTTPFsFileSystem) Chtimes(ctx context.Context, path string, atime, mtime time.Time) error {
	body := map[string]interface{}{
		"atime": atime.Format(time.RFC3339),
		"mtime": mtime.Format(time.RFC3339),
	}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/chtimes"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Truncate truncates a file
func (hfs *HTTPFsFileSystem) Truncate(ctx context.Context, path string, size int64) error {
	body := map[string]interface{}{"size": size}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/truncate"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Symlink creates a symbolic link
func (hfs *HTTPFsFileSystem) Symlink(ctx context.Context, oldPath, newPath string) error {
	body := map[string]string{"target": oldPath}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/symlink"+newPath, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Copy copies a file
func (hfs *HTTPFsFileSystem) Copy(ctx context.Context, src, dst string) error {
	body := map[string]string{"source": src, "destination": dst}
	bodyBytes, _ := json.Marshal(body)

	resp, err := hfs.httpRequest(ctx, "POST", "/copy", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// GetUsage returns total size of files
func (hfs *HTTPFsFileSystem) GetUsage(ctx context.Context) (int64, error) {
	resp, err := hfs.httpRequest(ctx, "GET", "/usage", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var usage struct {
		Size int64 `json:"size"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&usage); err != nil {
		return 0, fmt.Errorf("failed to decode usage: %w", err)
	}

	return usage.Size, nil
}

// HealthCheck checks if the HTTP filesystem is accessible
func (hfs *HTTPFsFileSystem) HealthCheck(ctx context.Context) error {
	resp, err := hfs.httpRequest(ctx, "GET", "/health", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Type returns the filesystem type
func (hfs *HTTPFsFileSystem) Type() string {
	return "httpfs"
}
