package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type HookType string

const (
	HookTypeHTTP    HookType = "http"
	HookTypeCommand HookType = "command"
)

type HookAuthResult struct {
	Authenticated bool               `json:"authenticated"`
	UserConfig    *DynamicUserConfig `json:"user_config,omitempty"`
	ErrorReason   string             `json:"error_reason,omitempty"`
}

type DynamicUserConfig struct {
	StorageBackend string            `json:"storage_backend,omitempty"`
	Permissions    map[string]bool   `json:"permissions,omitempty"`
	Quota          *QuotaConfig      `json:"quota,omitempty"`
	Protocols      []string          `json:"protocols,omitempty"`
	Groups         []string          `json:"groups,omitempty"`
	Roles          []string          `json:"roles,omitempty"`
	HomeDir        string            `json:"home_dir,omitempty"`
	Extra          map[string]string `json:"extra,omitempty"`
}

type QuotaConfig struct {
	MaxSize     int64 `json:"max_size,omitempty"`
	MaxFiles    int64 `json:"max_files,omitempty"`
	MaxUpload   int64 `json:"max_upload,omitempty"`
	MaxDownload int64 `json:"max_download,omitempty"`
}

type AuthHook struct {
	Type     HookType      `mapstructure:"type"`
	Endpoint string        `mapstructure:"endpoint"`
	Command  string        `mapstructure:"command"`
	Timeout  time.Duration `mapstructure:"timeout"`
	CacheTTL time.Duration `mapstructure:"cache_ttl"`

	logger *zap.Logger
	cache  map[string]*cacheEntry
	mu     sync.RWMutex
}

type cacheEntry struct {
	result    *HookAuthResult
	expiresAt time.Time
}

func NewAuthHook(cfg *AuthHook, log *zap.Logger) *AuthHook {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 0
	}
	h := &AuthHook{
		Type:     cfg.Type,
		Endpoint: cfg.Endpoint,
		Command:  cfg.Command,
		Timeout:  cfg.Timeout,
		CacheTTL: cfg.CacheTTL,
		logger:   log.Named("auth_hook"),
		cache:    make(map[string]*cacheEntry),
	}
	return h
}

func (h *AuthHook) Authenticate(ctx context.Context, username, password string) (*HookAuthResult, error) {
	if h.CacheTTL > 0 {
		h.mu.RLock()
		if entry, ok := h.cache[username]; ok && time.Now().Before(entry.expiresAt) {
			h.mu.RUnlock()
			h.logger.Debug("auth hook cache hit", zap.String("username", username))
			return entry.result, nil
		}
		h.mu.RUnlock()
	}

	h.logger.Debug("auth hook invoked", zap.String("username", username), zap.String("type", string(h.Type)))

	var result *HookAuthResult
	var err error

	switch h.Type {
	case HookTypeHTTP:
		result, err = h.authenticateHTTP(ctx, username, password)
	case HookTypeCommand:
		result, err = h.authenticateCommand(ctx, username, password)
	default:
		return nil, fmt.Errorf("unsupported auth hook type: %s", h.Type)
	}

	if err != nil {
		h.logger.Error("auth hook failed", zap.String("username", username), zap.Error(err))
		return &HookAuthResult{Authenticated: false, ErrorReason: err.Error()}, err
	}

	if h.CacheTTL > 0 && result.Authenticated {
		h.mu.Lock()
		h.cache[username] = &cacheEntry{
			result:    result,
			expiresAt: time.Now().Add(h.CacheTTL),
		}
		h.mu.Unlock()
	}

	return result, nil
}

func (h *AuthHook) authenticateHTTP(ctx context.Context, username, password string) (*HookAuthResult, error) {
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &HookAuthResult{Authenticated: false, ErrorReason: fmt.Sprintf("external auth returned %d", resp.StatusCode)}, nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var result HookAuthResult
		if err := json.Unmarshal(respBody, &result); err != nil {
			return &HookAuthResult{Authenticated: true}, nil
		}
		return &result, nil
	}

	return nil, fmt.Errorf("external auth returned status %d: %s", resp.StatusCode, string(respBody))
}

func (h *AuthHook) authenticateCommand(ctx context.Context, username, password string) (*HookAuthResult, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, h.Command, username, password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return &HookAuthResult{Authenticated: false, ErrorReason: err.Error()}, nil
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return &HookAuthResult{Authenticated: true}, nil
	}

	var result HookAuthResult
	if err := json.Unmarshal(output, &result); err != nil {
		if trimmed == "true" || trimmed == "1" || trimmed == "ok" {
			return &HookAuthResult{Authenticated: true}, nil
		}
		return &HookAuthResult{Authenticated: false, ErrorReason: "invalid command output"}, nil
	}
	return &result, nil
}

type DynamicUserHook struct {
	Type     HookType      `mapstructure:"type"`
	Endpoint string        `mapstructure:"endpoint"`
	Command  string        `mapstructure:"command"`
	Timeout  time.Duration `mapstructure:"timeout"`

	logger *zap.Logger
}

func NewDynamicUserHook(cfg DynamicUserHook, log *zap.Logger) *DynamicUserHook {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &DynamicUserHook{
		Type:     cfg.Type,
		Endpoint: cfg.Endpoint,
		Command:  cfg.Command,
		Timeout:  cfg.Timeout,
		logger:   log.Named("dynamic_user_hook"),
	}
}

func (h *DynamicUserHook) GetDynamicConfig(ctx context.Context, username string) (*DynamicUserConfig, error) {
	h.logger.Debug("dynamic user hook invoked", zap.String("username", username))

	switch h.Type {
	case HookTypeHTTP:
		return h.getHTTPConfig(ctx, username)
	case HookTypeCommand:
		return h.getCommandConfig(ctx, username)
	default:
		return nil, fmt.Errorf("unsupported dynamic user hook type: %s", h.Type)
	}
}

func (h *DynamicUserHook) getHTTPConfig(ctx context.Context, username string) (*DynamicUserConfig, error) {
	reqCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	url := strings.TrimRight(h.Endpoint, "/") + "/" + username
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("dynamic user hook returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}

	var config DynamicUserConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("failed to parse dynamic user config: %w", err)
	}
	return &config, nil
}

func (h *DynamicUserHook) getCommandConfig(ctx context.Context, username string) (*DynamicUserConfig, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, h.Command, username)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return nil, nil
	}

	var config DynamicUserConfig
	if err := json.Unmarshal(output, &config); err != nil {
		return nil, fmt.Errorf("failed to parse dynamic user config: %w", err)
	}
	return &config, nil
}

func MergeDynamicConfig(base *DynamicUserConfig, overlay *DynamicUserConfig) *DynamicUserConfig {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	merged := &DynamicUserConfig{
		StorageBackend: base.StorageBackend,
		HomeDir:        base.HomeDir,
	}

	if overlay.StorageBackend != "" {
		merged.StorageBackend = overlay.StorageBackend
	}
	if overlay.HomeDir != "" {
		merged.HomeDir = overlay.HomeDir
	}

	merged.Permissions = make(map[string]bool)
	for k, v := range base.Permissions {
		merged.Permissions[k] = v
	}
	for k, v := range overlay.Permissions {
		merged.Permissions[k] = v
	}

	if overlay.Quota != nil {
		merged.Quota = overlay.Quota
	} else {
		merged.Quota = base.Quota
	}

	if len(overlay.Protocols) > 0 {
		merged.Protocols = overlay.Protocols
	} else {
		merged.Protocols = base.Protocols
	}

	if len(overlay.Groups) > 0 {
		merged.Groups = overlay.Groups
	} else {
		merged.Groups = base.Groups
	}

	if len(overlay.Roles) > 0 {
		merged.Roles = overlay.Roles
	} else {
		merged.Roles = base.Roles
	}

	merged.Extra = make(map[string]string)
	for k, v := range base.Extra {
		merged.Extra[k] = v
	}
	for k, v := range overlay.Extra {
		merged.Extra[k] = v
	}

	return merged
}

type FileEvent string

const (
	FileEventPreUpload   FileEvent = "pre-upload"
	FileEventUpload      FileEvent = "upload"
	FileEventPreDownload FileEvent = "pre-download"
	FileEventDownload    FileEvent = "download"
	FileEventPreDelete   FileEvent = "pre-delete"
	FileEventDelete      FileEvent = "delete"
	FileEventRename      FileEvent = "rename"
	FileEventMkdir       FileEvent = "mkdir"
	FileEventRmdir       FileEvent = "rmdir"
)

type FileEventHook struct {
	Event    FileEvent     `mapstructure:"event"`
	Type     HookType      `mapstructure:"type"`
	Endpoint string        `mapstructure:"endpoint"`
	Command  string        `mapstructure:"command"`
	Timeout  time.Duration `mapstructure:"timeout"`

	logger *zap.Logger
}

type FileEventPayload struct {
	Event     FileEvent `json:"event"`
	FilePath  string    `json:"file_path"`
	FileName  string    `json:"file_name"`
	FileSize  int64     `json:"file_size"`
	Username  string    `json:"username"`
	UserID    int64     `json:"user_id"`
	Protocol  string    `json:"protocol"`
	ClientIP  string    `json:"client_ip"`
	NewPath   string    `json:"new_path,omitempty"`
	IsDir     bool      `json:"is_dir,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func NewFileEventHook(cfg FileEventHook, log *zap.Logger) *FileEventHook {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &FileEventHook{
		Event:    cfg.Event,
		Type:     cfg.Type,
		Endpoint: cfg.Endpoint,
		Command:  cfg.Command,
		Timeout:  cfg.Timeout,
		logger:   log.Named("file_event_hook"),
	}
}

func (h *FileEventHook) Execute(ctx context.Context, payload *FileEventPayload) error {
	h.logger.Debug("file event hook invoked",
		zap.String("event", string(h.Event)),
		zap.String("path", payload.FilePath),
		zap.String("user", payload.Username),
	)

	switch h.Type {
	case HookTypeHTTP:
		return h.executeHTTP(ctx, payload)
	case HookTypeCommand:
		return h.executeCommand(ctx, payload)
	default:
		return fmt.Errorf("unsupported file event hook type: %s", h.Type)
	}
}

func (h *FileEventHook) executeHTTP(ctx context.Context, payload *FileEventPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPxy-File-Event", string(h.Event))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("file event hook vetoed: %s", strings.TrimSpace(string(respBody)))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("file event hook returned status %d", resp.StatusCode)
	}

	return nil
}

func (h *FileEventHook) executeCommand(ctx context.Context, payload *FileEventPayload) error {
	cmdCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, h.Command, string(h.Event), payload.FilePath, payload.Username)
	cmd.Env = append(cmd.Env,
		"SFTPXY_FILE_EVENT="+string(h.Event),
		"SFTPXY_FILE_PATH="+payload.FilePath,
		"SFTPXY_FILE_NAME="+payload.FileName,
		"SFTPXY_USERNAME="+payload.Username,
		"SFTPXY_PROTOCOL="+payload.Protocol,
		"SFTPXY_CLIENT_IP="+payload.ClientIP,
	)
	if payload.FileSize > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SFTPXY_FILE_SIZE=%d", payload.FileSize))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("file event hook command failed: %w, output: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

type ConnectionEvent string

const (
	ConnectionEventPostConnect    ConnectionEvent = "post-connect"
	ConnectionEventPostLogin      ConnectionEvent = "post-login"
	ConnectionEventPostDisconnect ConnectionEvent = "post-disconnect"
)

type ConnectionHook struct {
	Event    ConnectionEvent `mapstructure:"event"`
	Type     HookType        `mapstructure:"type"`
	Endpoint string          `mapstructure:"endpoint"`
	Command  string          `mapstructure:"command"`
	Timeout  time.Duration   `mapstructure:"timeout"`

	logger *zap.Logger
}

type ConnectionPayload struct {
	Event        ConnectionEvent `json:"event"`
	ConnectionID string          `json:"connection_id"`
	Protocol     string          `json:"protocol"`
	ClientAddr   string          `json:"client_addr"`
	Username     string          `json:"username,omitempty"`
	UserID       int64           `json:"user_id,omitempty"`
	AuthMethod   string          `json:"auth_method,omitempty"`
	Timestamp    time.Time       `json:"timestamp"`
}

func NewConnectionHook(cfg ConnectionHook, log *zap.Logger) *ConnectionHook {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &ConnectionHook{
		Event:    cfg.Event,
		Type:     cfg.Type,
		Endpoint: cfg.Endpoint,
		Command:  cfg.Command,
		Timeout:  cfg.Timeout,
		logger:   log.Named("connection_hook"),
	}
}

func (h *ConnectionHook) Execute(ctx context.Context, payload *ConnectionPayload) error {
	h.logger.Debug("connection hook invoked",
		zap.String("event", string(h.Event)),
		zap.String("connection_id", payload.ConnectionID),
		zap.String("username", payload.Username),
	)

	switch h.Type {
	case HookTypeHTTP:
		return h.executeHTTP(ctx, payload)
	case HookTypeCommand:
		return h.executeCommand(ctx, payload)
	default:
		return fmt.Errorf("unsupported connection hook type: %s", h.Type)
	}
}

func (h *ConnectionHook) executeHTTP(ctx context.Context, payload *ConnectionPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	reqCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, h.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPxy-Connection-Event", string(h.Event))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("connection hook returned status %d", resp.StatusCode)
	}

	return nil
}

func (h *ConnectionHook) executeCommand(ctx context.Context, payload *ConnectionPayload) error {
	cmdCtx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, h.Command, string(h.Event), payload.ConnectionID, payload.Protocol)
	cmd.Env = append(cmd.Env,
		"SFTPXY_CONNECTION_EVENT="+string(h.Event),
		"SFTPXY_CONNECTION_ID="+payload.ConnectionID,
		"SFTPXY_PROTOCOL="+payload.Protocol,
		"SFTPXY_CLIENT_ADDR="+payload.ClientAddr,
	)
	if payload.Username != "" {
		cmd.Env = append(cmd.Env, "SFTPXY_USERNAME="+payload.Username)
	}
	if payload.AuthMethod != "" {
		cmd.Env = append(cmd.Env, "SFTPXY_AUTH_METHOD="+payload.AuthMethod)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("connection hook command failed: %w, output: %s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

type HookManager struct {
	mu              sync.RWMutex
	AuthHook        *AuthHook
	DynamicUserHook *DynamicUserHook
	FileEventHooks  []*FileEventHook
	ConnectionHooks []*ConnectionHook
	logger          *zap.Logger
}

func NewHookManager(log *zap.Logger) *HookManager {
	return &HookManager{
		logger: log.Named("hook_manager"),
	}
}

func (hm *HookManager) SetAuthHook(hook *AuthHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.AuthHook = hook
}

func (hm *HookManager) SetDynamicUserHook(hook *DynamicUserHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.DynamicUserHook = hook
}

func (hm *HookManager) AddFileEventHook(hook *FileEventHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.FileEventHooks = append(hm.FileEventHooks, hook)
}

func (hm *HookManager) AddConnectionHook(hook *ConnectionHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.ConnectionHooks = append(hm.ConnectionHooks, hook)
}

func (hm *HookManager) Authenticate(ctx context.Context, username, password string) (*HookAuthResult, error) {
	hm.mu.RLock()
	hook := hm.AuthHook
	hm.mu.RUnlock()
	if hook == nil {
		return nil, fmt.Errorf("auth hook not configured")
	}
	return hook.Authenticate(ctx, username, password)
}

func (hm *HookManager) GetDynamicConfig(ctx context.Context, username string) (*DynamicUserConfig, error) {
	hm.mu.RLock()
	hook := hm.DynamicUserHook
	hm.mu.RUnlock()
	if hook == nil {
		return nil, nil
	}
	return hook.GetDynamicConfig(ctx, username)
}

func (hm *HookManager) OnFileEvent(ctx context.Context, event FileEvent, payload *FileEventPayload) error {
	hm.mu.RLock()
	hooks := make([]*FileEventHook, len(hm.FileEventHooks))
	copy(hooks, hm.FileEventHooks)
	hm.mu.RUnlock()

	var firstErr error
	for _, hook := range hooks {
		if hook.Event != event {
			continue
		}
		if err := hook.Execute(ctx, payload); err != nil {
			hm.logger.Error("file event hook failed",
				zap.String("event", string(event)),
				zap.String("hook_type", string(hook.Type)),
				zap.Error(err),
			)
			if strings.HasPrefix(err.Error(), "file event hook vetoed") {
				return err
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (hm *HookManager) OnConnection(ctx context.Context, event ConnectionEvent, payload *ConnectionPayload) {
	hm.mu.RLock()
	hooks := make([]*ConnectionHook, len(hm.ConnectionHooks))
	copy(hooks, hm.ConnectionHooks)
	hm.mu.RUnlock()

	for _, hook := range hooks {
		if hook.Event != event {
			continue
		}
		if err := hook.Execute(ctx, payload); err != nil {
			hm.logger.Error("connection hook failed",
				zap.String("event", string(event)),
				zap.String("hook_type", string(hook.Type)),
				zap.Error(err),
			)
		}
	}
}
