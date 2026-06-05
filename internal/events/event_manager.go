package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jincaiw/sftpxy/internal/audit"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

type EventType string

const (
	EventPreUpload   EventType = "pre-upload"
	EventUpload      EventType = "upload"
	EventPreDownload EventType = "pre-download"
	EventDownload    EventType = "download"
	EventPreDelete   EventType = "pre-delete"
	EventDelete      EventType = "delete"
	EventRename      EventType = "rename"
	EventMkdir       EventType = "mkdir"
	EventRmdir       EventType = "rmdir"
	EventSSHCommand  EventType = "ssh.command"
	EventUserCreated EventType = "user.created"
	EventUserUpdated EventType = "user.updated"
	EventUserDeleted EventType = "user.deleted"
	EventConnect     EventType = "connect"
	EventLogin       EventType = "login"
	EventDisconnect  EventType = "disconnect"
	EventSchedule    EventType = "schedule"
)

type EventPayload struct {
	EventID        string                 `json:"event_id"`
	EventType      EventType              `json:"event_type"`
	Timestamp      time.Time              `json:"timestamp"`
	UserID         int64                  `json:"user_id,omitempty"`
	Username       string                 `json:"username,omitempty"`
	Protocol       string                 `json:"protocol,omitempty"`
	ClientIP       string                 `json:"client_ip,omitempty"`
	ConnectionID   string                 `json:"connection_id,omitempty"`
	FilePath       string                 `json:"file_path,omitempty"`
	FileName       string                 `json:"file_name,omitempty"`
	FileSize       int64                  `json:"file_size,omitempty"`
	FileExt        string                 `json:"file_ext,omitempty"`
	Result         string                 `json:"result,omitempty"`
	Error          string                 `json:"error,omitempty"`
	UserGroups     []string               `json:"user_groups,omitempty"`
	UserRole       string                 `json:"user_role,omitempty"`
	StorageBackend string                 `json:"storage_backend,omitempty"`
	Extra          map[string]interface{} `json:"extra,omitempty"`
}

type ActionType string

const (
	ActionHTTP             ActionType = "http"
	ActionCommand          ActionType = "command"
	ActionEmail            ActionType = "email"
	ActionFileOp           ActionType = "file_operation"
	ActionFileDelete       ActionType = "file_delete"
	ActionFileMove         ActionType = "file_move"
	ActionFileCopy         ActionType = "file_copy"
	ActionDataRetention    ActionType = "data_retention"
	ActionQuotaScan        ActionType = "quota_scan"
	ActionExternalCallback ActionType = "external_callback"
	ActionCustomScript     ActionType = "custom_script"
	ActionBatchDelete      ActionType = "batch_delete"
)

type ActionConfig struct {
	ID         int64                  `json:"id"`
	Type       ActionType             `json:"type"`
	Config     map[string]interface{} `json:"config"`
	OrderIndex int                    `json:"order_index"`
	Timeout    time.Duration          `json:"timeout,omitempty"`
	Retry      RetryConfig            `json:"retry,omitempty"`
}

type RetryConfig struct {
	MaxRetries        int           `json:"max_retries,omitempty"`
	RetryDelay        time.Duration `json:"retry_delay,omitempty"`
	BackoffMultiplier float64       `json:"backoff_multiplier,omitempty"`
}

type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

type TimeRange struct {
	StartHour *int    `json:"start_hour,omitempty"`
	EndHour   *int    `json:"end_hour,omitempty"`
	StartTime *string `json:"start_time,omitempty"`
	EndTime   *string `json:"end_time,omitempty"`
	Weekdays  []int   `json:"weekdays,omitempty"`
}

type ScheduleConflictPolicy string

const (
	ConflictSkip    ScheduleConflictPolicy = "skip"
	ConflictQueue   ScheduleConflictPolicy = "queue"
	ConflictReplace ScheduleConflictPolicy = "replace"
)

type EventRule struct {
	ID                     int64                  `json:"id"`
	Name                   string                 `json:"name"`
	Description            string                 `json:"description"`
	TriggerType            EventType              `json:"trigger_type"`
	Conditions             []Condition            `json:"conditions"`
	Actions                []ActionConfig         `json:"actions"`
	IsActive               bool                   `json:"is_active"`
	Schedule               string                 `json:"schedule,omitempty"`
	MaxConcurrentExecs     int                    `json:"max_concurrent_executions,omitempty"`
	ScheduleConflictPolicy ScheduleConflictPolicy `json:"schedule_conflict_policy,omitempty"`
	UserGroups             []string               `json:"user_groups,omitempty"`
	UserRole               string                 `json:"user_role,omitempty"`
	StorageBackend         string                 `json:"storage_backend,omitempty"`
	TimeRange              *TimeRange             `json:"time_range,omitempty"`
	CustomVariables        map[string]string      `json:"custom_variables,omitempty"`
	Placeholders           map[string]string      `json:"placeholders,omitempty"`

	semaphore   chan struct{}
	cronEntryID cron.EntryID
}

func (r *EventRule) GetSemaphore() chan struct{} {
	if r.MaxConcurrentExecs <= 0 {
		return nil
	}
	if r.semaphore == nil {
		r.semaphore = make(chan struct{}, r.MaxConcurrentExecs)
	}
	return r.semaphore
}

type ExecutionResult struct {
	RuleID       int64
	ActionID     int64
	ActionType   ActionType
	Success      bool
	Error        error
	Duration     time.Duration
	ResponseData string
	RetryCount   int
}

type ActionExecutor interface {
	Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error)
}

type EventHandler interface {
	HandleEvent(ctx context.Context, payload *EventPayload) error
}

type HTTPActionHandler struct {
	logger *zap.Logger
}

func NewHTTPActionHandler(log *zap.Logger) *HTTPActionHandler {
	return &HTTPActionHandler{logger: log}
}

func (h *HTTPActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	url, _ := config["url"].(string)
	if url == "" {
		return &ExecutionResult{ActionType: ActionHTTP, Success: false, Error: fmt.Errorf("url is required"), Duration: time.Since(start)}, nil
	}

	method, _ := config["method"].(string)
	if method == "" {
		method = http.MethodPost
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return &ExecutionResult{ActionType: ActionHTTP, Success: false, Error: err, Duration: time.Since(start)}, nil
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return &ExecutionResult{ActionType: ActionHTTP, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	req.Header.Set("Content-Type", "application/json")

	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for key, value := range headers {
			if str, ok := value.(string); ok {
				req.Header.Set(key, str)
			}
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ExecutionResult{ActionType: ActionHTTP, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	defer resp.Body.Close()

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	responseData := strings.TrimSpace(string(responseBody))
	if responseData == "" {
		responseData = resp.Status
	}

	result := &ExecutionResult{
		ActionType:   ActionHTTP,
		Success:      success,
		Duration:     time.Since(start),
		ResponseData: responseData,
	}
	if !success {
		result.Error = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return result, nil
}

type CommandActionHandler struct {
	logger    *zap.Logger
	whitelist []string
	timeout   time.Duration
}

func NewCommandActionHandler(log *zap.Logger, whitelist []string, timeout time.Duration) *CommandActionHandler {
	return &CommandActionHandler{logger: log, whitelist: whitelist, timeout: timeout}
}

func (c *CommandActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	cmd, _ := config["command"].(string)
	if cmd == "" {
		return &ExecutionResult{ActionType: ActionCommand, Success: false, Error: fmt.Errorf("command is required"), Duration: time.Since(start)}, nil
	}

	allowed := len(c.whitelist) == 0
	for _, w := range c.whitelist {
		if w == cmd || filepath.Base(w) == filepath.Base(cmd) {
			allowed = true
			break
		}
	}
	if !allowed {
		return &ExecutionResult{ActionType: ActionCommand, Success: false, Error: fmt.Errorf("command not in whitelist"), Duration: time.Since(start)}, nil
	}
	args := stringSliceFromConfig(config["args"])
	execCtx := ctx
	var cancel context.CancelFunc
	if c.timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	command := exec.CommandContext(execCtx, cmd, args...)
	command.Env = append(command.Env, buildPayloadEnv(payload)...)
	output, err := command.CombinedOutput()

	result := &ExecutionResult{
		ActionType:   ActionCommand,
		Success:      err == nil,
		Duration:     time.Since(start),
		ResponseData: strings.TrimSpace(string(output)),
	}
	if err != nil {
		result.Error = err
	}
	return result, nil
}

type EmailActionHandler struct {
	logger *zap.Logger
}

func NewEmailActionHandler(log *zap.Logger) *EmailActionHandler {
	return &EmailActionHandler{logger: log}
}

func (e *EmailActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	to, _ := config["to"].(string)
	subject, _ := config["subject"].(string)

	e.logger.Warn("Email action handler is not yet implemented; no email will be sent",
		zap.String("to", to),
		zap.String("subject", subject),
	)

	return &ExecutionResult{
		ActionType: ActionEmail,
		Success:    false,
		Error:      fmt.Errorf("email action is not yet implemented"),
		Duration:   time.Since(start),
	}, nil
}

type FileDeleteActionHandler struct {
	logger *zap.Logger
}

func NewFileDeleteActionHandler(log *zap.Logger) *FileDeleteActionHandler {
	return &FileDeleteActionHandler{logger: log}
}

func (h *FileDeleteActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	targetPath, _ := config["path"].(string)
	if targetPath == "" {
		targetPath = payload.FilePath
	}
	if targetPath == "" {
		return &ExecutionResult{ActionType: ActionFileDelete, Success: false, Error: fmt.Errorf("path is required"), Duration: time.Since(start)}, nil
	}

	resolved := resolvePlaceholders(targetPath, payload)
	err := os.Remove(resolved)
	result := &ExecutionResult{
		ActionType:   ActionFileDelete,
		Success:      err == nil,
		Duration:     time.Since(start),
		ResponseData: resolved,
	}
	if err != nil && !os.IsNotExist(err) {
		result.Error = err
		result.Success = false
	}
	return result, nil
}

type FileMoveActionHandler struct {
	logger *zap.Logger
}

func NewFileMoveActionHandler(log *zap.Logger) *FileMoveActionHandler {
	return &FileMoveActionHandler{logger: log}
}

func (h *FileMoveActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	src, _ := config["source"].(string)
	dst, _ := config["destination"].(string)
	if src == "" {
		src = payload.FilePath
	}
	if src == "" || dst == "" {
		return &ExecutionResult{ActionType: ActionFileMove, Success: false, Error: fmt.Errorf("source and destination are required"), Duration: time.Since(start)}, nil
	}

	resolvedSrc := resolvePlaceholders(src, payload)
	resolvedDst := resolvePlaceholders(dst, payload)

	if err := os.MkdirAll(filepath.Dir(resolvedDst), 0755); err != nil {
		return &ExecutionResult{ActionType: ActionFileMove, Success: false, Error: err, Duration: time.Since(start)}, nil
	}

	err := os.Rename(resolvedSrc, resolvedDst)
	result := &ExecutionResult{
		ActionType:   ActionFileMove,
		Success:      err == nil,
		Duration:     time.Since(start),
		ResponseData: resolvedSrc + " -> " + resolvedDst,
	}
	if err != nil {
		result.Error = err
	}
	return result, nil
}

type FileCopyActionHandler struct {
	logger *zap.Logger
}

func NewFileCopyActionHandler(log *zap.Logger) *FileCopyActionHandler {
	return &FileCopyActionHandler{logger: log}
}

func (h *FileCopyActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	src, _ := config["source"].(string)
	dst, _ := config["destination"].(string)
	if src == "" {
		src = payload.FilePath
	}
	if src == "" || dst == "" {
		return &ExecutionResult{ActionType: ActionFileCopy, Success: false, Error: fmt.Errorf("source and destination are required"), Duration: time.Since(start)}, nil
	}

	resolvedSrc := resolvePlaceholders(src, payload)
	resolvedDst := resolvePlaceholders(dst, payload)

	if err := os.MkdirAll(filepath.Dir(resolvedDst), 0755); err != nil {
		return &ExecutionResult{ActionType: ActionFileCopy, Success: false, Error: err, Duration: time.Since(start)}, nil
	}

	srcFile, err := os.Open(resolvedSrc)
	if err != nil {
		return &ExecutionResult{ActionType: ActionFileCopy, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	defer srcFile.Close()

	dstFile, err := os.Create(resolvedDst)
	if err != nil {
		return &ExecutionResult{ActionType: ActionFileCopy, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	result := &ExecutionResult{
		ActionType:   ActionFileCopy,
		Success:      err == nil,
		Duration:     time.Since(start),
		ResponseData: resolvedSrc + " -> " + resolvedDst,
	}
	if err != nil {
		result.Error = err
	}
	return result, nil
}

type DataRetentionActionHandler struct {
	logger *zap.Logger
}

func NewDataRetentionActionHandler(log *zap.Logger) *DataRetentionActionHandler {
	return &DataRetentionActionHandler{logger: log}
}

func (h *DataRetentionActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	dir, _ := config["directory"].(string)
	maxAgeSeconds, _ := config["max_age_seconds"].(float64)
	if dir == "" {
		return &ExecutionResult{ActionType: ActionDataRetention, Success: false, Error: fmt.Errorf("directory is required"), Duration: time.Since(start)}, nil
	}
	if maxAgeSeconds <= 0 {
		return &ExecutionResult{ActionType: ActionDataRetention, Success: false, Error: fmt.Errorf("max_age_seconds is required"), Duration: time.Since(start)}, nil
	}

	resolvedDir := resolvePlaceholders(dir, payload)
	cutoff := time.Now().Add(-time.Duration(maxAgeSeconds) * time.Second)
	deleted := 0

	entries, err := os.ReadDir(resolvedDir)
	if err != nil {
		return &ExecutionResult{ActionType: ActionDataRetention, Success: false, Error: err, Duration: time.Since(start)}, nil
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(resolvedDir, entry.Name())); err == nil {
				deleted++
			}
		}
	}

	return &ExecutionResult{
		ActionType:   ActionDataRetention,
		Success:      true,
		Duration:     time.Since(start),
		ResponseData: fmt.Sprintf("deleted %d files older than %v in %s", deleted, time.Duration(maxAgeSeconds)*time.Second, resolvedDir),
	}, nil
}

type BatchDeleteActionHandler struct {
	logger *zap.Logger
}

func NewBatchDeleteActionHandler(log *zap.Logger) *BatchDeleteActionHandler {
	return &BatchDeleteActionHandler{logger: log}
}

func (h *BatchDeleteActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	directory, _ := config["directory"].(string)
	if directory == "" {
		directory, _ = config["path"].(string)
	}
	if directory == "" && payload.FilePath != "" {
		directory = payload.FilePath
	}
	if directory == "" {
		return &ExecutionResult{ActionType: ActionBatchDelete, Success: false, Error: fmt.Errorf("directory is required"), Duration: time.Since(start)}, nil
	}

	if directory == "/" || directory == "" {
		return &ExecutionResult{ActionType: ActionBatchDelete, Success: false, Error: fmt.Errorf("root directory is not allowed"), Duration: time.Since(start)}, nil
	}

	resolvedDir := resolvePlaceholders(directory, payload)

	maxAgeDays, _ := config["max_age_days"].(float64)
	if maxAgeDays <= 0 {
		maxAgeDaysF, ok := config["days"].(float64)
		if ok && maxAgeDaysF > 0 {
			maxAgeDays = maxAgeDaysF
		} else {
			return &ExecutionResult{ActionType: ActionBatchDelete, Success: false, Error: fmt.Errorf("max_age_days is required and must be > 0"), Duration: time.Since(start)}, nil
		}
	}

	recursive := true
	if val, ok := config["recursive"].(bool); ok {
		recursive = val
	}

	deleteEmptyDirs := false
	if val, ok := config["delete_empty_dirs"].(bool); ok {
		deleteEmptyDirs = val
	}

	maxDeletes := 1000
	if val, ok := config["max_deletes"].(float64); ok && val > 0 {
		maxDeletes = int(val)
	}

	cutoff := time.Now().Add(-time.Duration(maxAgeDays) * 24 * time.Hour)
	deletedFiles := 0
	deletedDirs := 0
	skipped := 0
	totalScanned := 0

	var walkFn filepath.WalkFunc
	if recursive {
		walkFn = func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if path == resolvedDir {
				return nil
			}

			totalScanned++

			if info.ModTime().Before(cutoff) {
				if info.IsDir() {
					if deleteEmptyDirs {
						isEmpty, _ := isDirEmpty(path)
						if isEmpty {
							if err := os.Remove(path); err == nil {
								deletedDirs++
							}
						} else {
							skipped++
						}
					} else {
						skipped++
					}
				} else {
					if deletedFiles+deletedDirs >= maxDeletes {
						return fmt.Errorf("max_deletes limit reached: %d", maxDeletes)
					}
					if err := os.Remove(path); err == nil {
						deletedFiles++
					}
				}
			}

			return nil
		}
		err := filepath.Walk(resolvedDir, walkFn)
		if err != nil && !strings.Contains(err.Error(), "max_deletes") {
			return &ExecutionResult{ActionType: ActionBatchDelete, Success: false, Error: err, Duration: time.Since(start)}, nil
		}
	} else {
		entries, err := os.ReadDir(resolvedDir)
		if err != nil {
			return &ExecutionResult{ActionType: ActionBatchDelete, Success: false, Error: err, Duration: time.Since(start)}, nil
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				break
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			totalScanned++
			if info.ModTime().Before(cutoff) {
				if info.IsDir() {
					if deleteEmptyDirs {
						isEmpty, _ := isDirEmpty(filepath.Join(resolvedDir, entry.Name()))
						if isEmpty {
							if err := os.Remove(filepath.Join(resolvedDir, entry.Name())); err == nil {
								deletedDirs++
							}
						} else {
							skipped++
						}
					} else {
						skipped++
					}
				} else {
					if deletedFiles+deletedDirs >= maxDeletes {
						break
					}
					if err := os.Remove(filepath.Join(resolvedDir, entry.Name())); err == nil {
						deletedFiles++
					}
				}
			}
		}
	}

	h.logger.Info("batch delete completed",
		zap.String("directory", resolvedDir),
		zap.Int("deleted_files", deletedFiles),
		zap.Int("deleted_dirs", deletedDirs),
		zap.Int("skipped", skipped),
		zap.Int("scanned", totalScanned),
		zap.Float64("max_age_days", maxAgeDays),
	)

	return &ExecutionResult{
		ActionType: ActionBatchDelete,
		Success:    true,
		Duration:   time.Since(start),
		ResponseData: fmt.Sprintf("scanned %d, deleted %d files and %d dirs older than %.0f days in %s (skipped %d)",
			totalScanned, deletedFiles, deletedDirs, maxAgeDays, resolvedDir, skipped),
	}, nil
}

func isDirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if err == nil {
		return false, nil
	}
	return true, nil
}

type QuotaScanActionHandler struct {
	logger *zap.Logger
}

func NewQuotaScanActionHandler(log *zap.Logger) *QuotaScanActionHandler {
	return &QuotaScanActionHandler{logger: log}
}

func (h *QuotaScanActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	username, _ := config["username"].(string)
	if username == "" {
		username = payload.Username
	}
	if username == "" {
		return &ExecutionResult{ActionType: ActionQuotaScan, Success: false, Error: fmt.Errorf("username is required"), Duration: time.Since(start)}, nil
	}

	h.logger.Info("Quota scan triggered", zap.String("username", username))

	return &ExecutionResult{
		ActionType:   ActionQuotaScan,
		Success:      true,
		Duration:     time.Since(start),
		ResponseData: fmt.Sprintf("quota scan triggered for %s", username),
	}, nil
}

type ExternalCallbackActionHandler struct {
	logger *zap.Logger
}

func NewExternalCallbackActionHandler(log *zap.Logger) *ExternalCallbackActionHandler {
	return &ExternalCallbackActionHandler{logger: log}
}

func (h *ExternalCallbackActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	endpoint, _ := config["endpoint"].(string)
	if endpoint == "" {
		return &ExecutionResult{ActionType: ActionExternalCallback, Success: false, Error: fmt.Errorf("endpoint is required"), Duration: time.Since(start)}, nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return &ExecutionResult{ActionType: ActionExternalCallback, Success: false, Error: err, Duration: time.Since(start)}, nil
	}

	timeout := 30 * time.Second
	if timeoutSec, ok := config["timeout_seconds"].(float64); ok && timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return &ExecutionResult{ActionType: ActionExternalCallback, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SFTPxy-Event", string(payload.EventType))

	if secret, ok := config["secret"].(string); ok && secret != "" {
		req.Header.Set("X-SFTPxy-Signature", secret)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &ExecutionResult{ActionType: ActionExternalCallback, Success: false, Error: err, Duration: time.Since(start)}, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	result := &ExecutionResult{
		ActionType:   ActionExternalCallback,
		Success:      success,
		Duration:     time.Since(start),
		ResponseData: strings.TrimSpace(string(respBody)),
	}
	if !success {
		result.Error = fmt.Errorf("callback returned status %d", resp.StatusCode)
	}
	return result, nil
}

type CustomScriptActionHandler struct {
	logger    *zap.Logger
	whitelist []string
	timeout   time.Duration
}

func NewCustomScriptActionHandler(log *zap.Logger, whitelist []string, timeout time.Duration) *CustomScriptActionHandler {
	return &CustomScriptActionHandler{logger: log, whitelist: whitelist, timeout: timeout}
}

func (h *CustomScriptActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	script, _ := config["script"].(string)
	if script == "" {
		return &ExecutionResult{ActionType: ActionCustomScript, Success: false, Error: fmt.Errorf("script is required"), Duration: time.Since(start)}, nil
	}

	allowed := len(h.whitelist) == 0
	for _, w := range h.whitelist {
		if w == script || filepath.Base(w) == filepath.Base(script) {
			allowed = true
			break
		}
	}
	if !allowed {
		return &ExecutionResult{ActionType: ActionCustomScript, Success: false, Error: fmt.Errorf("script not in whitelist"), Duration: time.Since(start)}, nil
	}

	args := stringSliceFromConfig(config["args"])
	eventJSON, _ := json.Marshal(payload)
	args = append(args, string(eventJSON))

	execCtx := ctx
	var cancel context.CancelFunc
	if h.timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(execCtx, script, args...)
	cmd.Env = append(cmd.Env, buildPayloadEnv(payload)...)
	cmd.Env = append(cmd.Env, "SFTPXY_EVENT_DATA="+string(eventJSON))
	output, err := cmd.CombinedOutput()

	result := &ExecutionResult{
		ActionType:   ActionCustomScript,
		Success:      err == nil,
		Duration:     time.Since(start),
		ResponseData: strings.TrimSpace(string(output)),
	}
	if err != nil {
		result.Error = err
	}
	return result, nil
}

type Manager struct {
	rules                map[int64]*EventRule
	mu                   sync.RWMutex
	cron                 *cron.Cron
	httpHandler          *HTTPActionHandler
	cmdHandler           *CommandActionHandler
	emailHandler         *EmailActionHandler
	fileDeleteHandler    *FileDeleteActionHandler
	fileMoveHandler      *FileMoveActionHandler
	fileCopyHandler      *FileCopyActionHandler
	dataRetentionHandler *DataRetentionActionHandler
	batchDeleteHandler   *BatchDeleteActionHandler
	quotaScanHandler     *QuotaScanActionHandler
	extCallbackHandler   *ExternalCallbackActionHandler
	customScriptHandler  *CustomScriptActionHandler
	repo                 repository.EventRepository
	metrics              *metrics.Collector
	auditRecorder        audit.AuditRecorder
	logger               *zap.Logger
}

func NewManager(log *zap.Logger, commandWhitelist []string) *Manager {
	return NewManagerWithOptions(log, commandWhitelist, nil, nil, 30*time.Second)
}

func NewManagerWithOptions(
	log *zap.Logger,
	commandWhitelist []string,
	repo repository.EventRepository,
	metricsCollector *metrics.Collector,
	commandTimeout time.Duration,
) *Manager {
	m := &Manager{
		rules:                make(map[int64]*EventRule),
		cron:                 cron.New(cron.WithSeconds()),
		httpHandler:          NewHTTPActionHandler(log),
		cmdHandler:           NewCommandActionHandler(log, commandWhitelist, commandTimeout),
		emailHandler:         NewEmailActionHandler(log),
		fileDeleteHandler:    NewFileDeleteActionHandler(log),
		fileMoveHandler:      NewFileMoveActionHandler(log),
		fileCopyHandler:      NewFileCopyActionHandler(log),
		dataRetentionHandler: NewDataRetentionActionHandler(log),
		batchDeleteHandler:   NewBatchDeleteActionHandler(log),
		quotaScanHandler:     NewQuotaScanActionHandler(log),
		extCallbackHandler:   NewExternalCallbackActionHandler(log),
		customScriptHandler:  NewCustomScriptActionHandler(log, commandWhitelist, commandTimeout),
		repo:                 repo,
		metrics:              metricsCollector,
		logger:               log.Named("event_manager"),
	}
	if repo != nil {
		if err := m.loadRules(context.Background()); err != nil {
			m.logger.Warn("failed to load event rules", zap.Error(err))
		}
	}
	m.cron.Start()
	return m
}

func (m *Manager) AddRule(rule *EventRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[rule.ID] = rule

	if rule.Schedule != "" && rule.IsActive {
		ruleID := rule.ID
		entryID, _ := m.cron.AddFunc(rule.Schedule, func() {
			m.executeScheduledRule(ruleID)
		})
		rule.cronEntryID = entryID
	}

	m.logger.Info("Event rule added", zap.Int64("id", rule.ID), zap.String("name", rule.Name))
}

func (m *Manager) UpdateRule(rule *EventRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldRule, exists := m.rules[rule.ID]
	if exists && oldRule.cronEntryID != 0 {
		m.cron.Remove(oldRule.cronEntryID)
	}

	m.rules[rule.ID] = rule

	if rule.Schedule != "" && rule.IsActive {
		ruleID := rule.ID
		entryID, _ := m.cron.AddFunc(rule.Schedule, func() {
			m.executeScheduledRule(ruleID)
		})
		rule.cronEntryID = entryID
	}

	m.logger.Info("Event rule updated", zap.Int64("id", rule.ID), zap.String("name", rule.Name))
}

func (m *Manager) Repo() repository.EventRepository {
	return m.repo
}

func (m *Manager) RemoveRule(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rule, exists := m.rules[id]; exists {
		if rule.cronEntryID != 0 {
			m.cron.Remove(rule.cronEntryID)
		}
		delete(m.rules, id)
	}
	m.logger.Info("Event rule removed", zap.Int64("id", id))
}

func (m *Manager) GetRule(id int64) *EventRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules[id]
}

func (m *Manager) ListRules() []*EventRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var rules []*EventRule
	for _, r := range m.rules {
		rules = append(rules, r)
	}
	return rules
}

func (m *Manager) EmitEvent(ctx context.Context, payload *EventPayload) {
	go func() {
		if _, err := m.ProcessEvent(ctx, payload); err != nil {
			m.logger.Error("event processing failed", zap.Error(err), zap.String("event_type", string(payload.EventType)))
		}
	}()
}

func (m *Manager) Shutdown(ctx context.Context) {
	m.StopCron()
}

func (m *Manager) StopCron() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cron != nil {
		<-m.cron.Stop().Done()
		m.cron = nil
	}
}

// SetAuditRecorder sets the audit recorder for structured audit events
func (m *Manager) SetAuditRecorder(recorder audit.AuditRecorder) {
	m.auditRecorder = recorder
}

func (m *Manager) ProcessEvent(ctx context.Context, payload *EventPayload) ([]*ExecutionResult, error) {
	m.mu.RLock()
	rules := make([]*EventRule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	m.mu.RUnlock()

	m.logger.Debug("Event emitted", zap.String("type", string(payload.EventType)), zap.String("user", payload.Username))

	results := make([]*ExecutionResult, 0)
	for _, rule := range rules {
		if !rule.IsActive || rule.TriggerType != payload.EventType {
			continue
		}
		if !m.evaluateConditions(rule, payload) {
			continue
		}
		if !m.acquireConcurrencySlot(rule) {
			m.handleConflict(rule, payload)
			continue
		}
		ruleResults, err := m.executeActionsWithRetry(ctx, rule, payload)
		m.releaseConcurrencySlot(rule)
		if err != nil {
			return results, err
		}
		results = append(results, ruleResults...)
	}
	return results, nil
}

func (m *Manager) ListHistory(ctx context.Context, eventType, result string, limit, offset int) ([]*repository.EventHistoryRecord, int64, error) {
	if m.repo == nil {
		return []*repository.EventHistoryRecord{}, 0, nil
	}
	items, err := m.repo.ListHistory(ctx, eventType, result, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := m.repo.CountHistory(ctx, eventType, result)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (m *Manager) evaluateConditions(rule *EventRule, payload *EventPayload) bool {
	for _, cond := range rule.Conditions {
		if !m.evaluateCondition(cond, payload) {
			return false
		}
	}
	if len(rule.UserGroups) > 0 {
		if !matchUserGroups(rule.UserGroups, payload.UserGroups) {
			return false
		}
	}
	if rule.UserRole != "" {
		if payload.UserRole != rule.UserRole {
			return false
		}
	}
	if rule.StorageBackend != "" {
		if payload.StorageBackend != rule.StorageBackend {
			return false
		}
	}
	if rule.TimeRange != nil {
		if !matchTimeRange(rule.TimeRange) {
			return false
		}
	}
	if len(rule.CustomVariables) > 0 {
		if !matchCustomVariables(rule.CustomVariables, payload.Extra) {
			return false
		}
	}
	return true
}

func (m *Manager) evaluateCondition(cond Condition, payload *EventPayload) bool {
	var actualValue interface{}

	switch cond.Field {
	case "username":
		actualValue = payload.Username
	case "protocol":
		actualValue = payload.Protocol
	case "client_ip":
		actualValue = payload.ClientIP
	case "file_path":
		actualValue = payload.FilePath
	case "file_name":
		actualValue = payload.FileName
	case "file_size":
		actualValue = payload.FileSize
	case "file_ext":
		actualValue = payload.FileExt
	case "result":
		actualValue = payload.Result
	case "user_groups":
		if groups, ok := cond.Value.([]interface{}); ok {
			var strs []string
			for _, g := range groups {
				if s, ok := g.(string); ok {
					strs = append(strs, s)
				}
			}
			return matchUserGroups(strs, payload.UserGroups)
		}
		return true
	case "user_role":
		return payload.UserRole == fmt.Sprintf("%v", cond.Value)
	case "storage_backend":
		return payload.StorageBackend == fmt.Sprintf("%v", cond.Value)
	case "file_age":
		if payload.Extra != nil {
			if fileAgeDays, ok := payload.Extra["file_age_days"]; ok {
				if days, ok := fileAgeDays.(float64); ok {
					condDays, _ := cond.Value.(float64)
					switch cond.Operator {
					case "gt", "gte":
						return days >= condDays
					case "lt", "lte":
						return days <= condDays
					case "eq":
						return days == condDays
					}
				}
			}
		}
		return true
	case "directory":
		return payload.FilePath == fmt.Sprintf("%v", cond.Value)
	case "time_range":
		return matchTimeRangeCondition(cond.Value)
	case "custom_variables":
		if cvMap, ok := cond.Value.(map[string]interface{}); ok {
			strMap := make(map[string]string, len(cvMap))
			for k, v := range cvMap {
				strMap[k] = fmt.Sprintf("%v", v)
			}
			return matchCustomVariables(strMap, payload.Extra)
		}
		return true
	default:
		return true
	}

	switch cond.Operator {
	case "eq":
		return actualValue == cond.Value
	case "ne":
		return actualValue != cond.Value
	case "contains":
		if str, ok := actualValue.(string); ok {
			if val, ok := cond.Value.(string); ok {
				return strings.Contains(str, val)
			}
		}
	case "gt":
		if num, ok := actualValue.(int64); ok {
			if val, ok := cond.Value.(float64); ok {
				return num > int64(val)
			}
		}
	case "lt":
		if num, ok := actualValue.(int64); ok {
			if val, ok := cond.Value.(float64); ok {
				return num < int64(val)
			}
		}
	case "in":
		if slice, ok := cond.Value.([]interface{}); ok {
			for _, item := range slice {
				if actualValue == item {
					return true
				}
			}
			return false
		}
	case "regex":
		if str, ok := actualValue.(string); ok {
			if pattern, ok := cond.Value.(string); ok {
				re, err := regexp.Compile(pattern)
				if err != nil {
					m.logger.Warn("invalid regex pattern", zap.String("pattern", pattern), zap.Error(err))
					return false
				}
				return re.MatchString(str)
			}
		}
	}

	return true
}

func (m *Manager) acquireConcurrencySlot(rule *EventRule) bool {
	sem := rule.GetSemaphore()
	if sem == nil {
		return true
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *Manager) releaseConcurrencySlot(rule *EventRule) {
	sem := rule.GetSemaphore()
	if sem == nil {
		return
	}
	select {
	case <-sem:
	default:
	}
}

func (m *Manager) handleConflict(rule *EventRule, payload *EventPayload) {
	switch rule.ScheduleConflictPolicy {
	case ConflictQueue:
		sem := rule.GetSemaphore()
		if sem != nil {
			select {
			case sem <- struct{}{}:
				go func() {
					defer m.releaseConcurrencySlot(rule)
					_, _ = m.executeActionsWithRetry(context.Background(), rule, payload)
				}()
			case <-time.After(30 * time.Second):
				m.logger.Warn("conflict queue timeout, dropping event",
					zap.String("rule", rule.Name),
					zap.String("event", string(payload.EventType)))
			}
		}
	case ConflictReplace:
		m.logger.Debug("Skipping event due to conflict policy replace",
			zap.Int64("rule_id", rule.ID),
			zap.String("event_type", string(payload.EventType)))
	case ConflictSkip:
		fallthrough
	default:
		m.logger.Debug("Skipping event due to concurrency limit",
			zap.Int64("rule_id", rule.ID),
			zap.String("event_type", string(payload.EventType)))
	}
}

func (m *Manager) executeActionsWithRetry(ctx context.Context, rule *EventRule, payload *EventPayload) ([]*ExecutionResult, error) {
	results := make([]*ExecutionResult, 0, len(rule.Actions))
	for _, action := range rule.Actions {
		result := m.executeActionWithRetry(ctx, action, payload)
		if result != nil {
			result.RuleID = rule.ID
			result.ActionID = action.ID
			results = append(results, result)
		}
		m.recordExecution(ctx, rule, action, payload, result, nil)
	}
	return results, nil
}

func (m *Manager) executeActionWithRetry(ctx context.Context, action ActionConfig, payload *EventPayload) *ExecutionResult {
	retry := action.Retry
	if retry.MaxRetries <= 0 {
		retry.MaxRetries = 0
	}
	if retry.BackoffMultiplier <= 0 {
		retry.BackoffMultiplier = 2.0
	}
	if retry.RetryDelay <= 0 {
		retry.RetryDelay = time.Second
	}

	var result *ExecutionResult
	for attempt := 0; attempt <= retry.MaxRetries; attempt++ {
		actionCtx := ctx
		var cancel context.CancelFunc
		if action.Timeout > 0 {
			actionCtx, cancel = context.WithTimeout(ctx, action.Timeout)
		}

		var err error
		result, err = m.executeAction(actionCtx, action, payload)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			result = &ExecutionResult{
				ActionType: action.Type,
				Success:    false,
				Error:      err,
				RetryCount: attempt,
			}
		}
		if result != nil {
			result.RetryCount = attempt
		}

		if result == nil || result.Success {
			return result
		}

		if attempt < retry.MaxRetries {
			delay := time.Duration(float64(retry.RetryDelay) * float64(powFloat(retry.BackoffMultiplier, float64(attempt))))
			m.logger.Debug("Retrying action",
				zap.String("action_type", string(action.Type)),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", retry.MaxRetries),
				zap.Duration("delay", delay),
			)
			select {
			case <-ctx.Done():
				return result
			case <-time.After(delay):
			}
		}
	}
	return result
}

func (m *Manager) executeAction(ctx context.Context, action ActionConfig, payload *EventPayload) (*ExecutionResult, error) {
	switch action.Type {
	case ActionHTTP:
		return m.httpHandler.Execute(ctx, action.Config, payload)
	case ActionCommand:
		return m.cmdHandler.Execute(ctx, action.Config, payload)
	case ActionEmail:
		return m.emailHandler.Execute(ctx, action.Config, payload)
	case ActionFileDelete:
		return m.fileDeleteHandler.Execute(ctx, action.Config, payload)
	case ActionFileMove:
		return m.fileMoveHandler.Execute(ctx, action.Config, payload)
	case ActionFileCopy:
		return m.fileCopyHandler.Execute(ctx, action.Config, payload)
	case ActionDataRetention:
		return m.dataRetentionHandler.Execute(ctx, action.Config, payload)
	case ActionBatchDelete:
		return m.batchDeleteHandler.Execute(ctx, action.Config, payload)
	case ActionQuotaScan:
		return m.quotaScanHandler.Execute(ctx, action.Config, payload)
	case ActionExternalCallback:
		return m.extCallbackHandler.Execute(ctx, action.Config, payload)
	case ActionCustomScript:
		return m.customScriptHandler.Execute(ctx, action.Config, payload)
	default:
		return &ExecutionResult{Success: false, Error: fmt.Errorf("unknown action type: %s", action.Type)}, nil
	}
}

func (m *Manager) executeScheduledRule(ruleID int64) {
	m.mu.RLock()
	rule, ok := m.rules[ruleID]
	m.mu.RUnlock()

	if !ok || !rule.IsActive {
		return
	}

	payload := &EventPayload{
		EventID:   fmt.Sprintf("sched_%d_%d", ruleID, time.Now().Unix()),
		EventType: rule.TriggerType,
		Timestamp: time.Now(),
	}

	if payload.EventType == "" {
		payload.EventType = EventUpload
	}

	if rule.TriggerType == EventSchedule {
		payload.EventType = EventSchedule
		payload.Extra = make(map[string]interface{})
		for _, cond := range rule.Conditions {
			switch cond.Field {
			case "directory":
				if dir, ok := cond.Value.(string); ok && dir != "" {
					payload.FilePath = dir
				}
			case "file_age":
				if days, ok := cond.Value.(float64); ok {
					payload.Extra["file_age_days"] = days
				} else if daysStr, ok := cond.Value.(string); ok {
					if f, err := parseFloat(daysStr); err == nil {
						payload.Extra["file_age_days"] = f
					}
				}
			}
		}
	}

	_, _ = m.executeActionsWithRetry(context.Background(), rule, payload)
}

func matchUserGroups(ruleGroups, payloadGroups []string) bool {
	if len(payloadGroups) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(payloadGroups))
	for _, g := range payloadGroups {
		set[g] = struct{}{}
	}
	for _, g := range ruleGroups {
		if _, ok := set[g]; ok {
			return true
		}
	}
	return false
}

func matchTimeRange(tr *TimeRange) bool {
	now := time.Now()
	if len(tr.Weekdays) > 0 {
		weekday := int(now.Weekday())
		found := false
		for _, wd := range tr.Weekdays {
			if wd == weekday {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if tr.StartHour != nil && tr.EndHour != nil {
		h := now.Hour()
		if *tr.StartHour <= *tr.EndHour {
			return h >= *tr.StartHour && h < *tr.EndHour
		}
		return h >= *tr.StartHour || h < *tr.EndHour
	}
	if tr.StartTime != nil && tr.EndTime != nil {
		startT, err1 := time.Parse("15:04", *tr.StartTime)
		endT, err2 := time.Parse("15:04", *tr.EndTime)
		if err1 != nil || err2 != nil {
			return true
		}
		nowMinutes := now.Hour()*60 + now.Minute()
		startMinutes := startT.Hour()*60 + startT.Minute()
		endMinutes := endT.Hour()*60 + endT.Minute()
		if startMinutes <= endMinutes {
			return nowMinutes >= startMinutes && nowMinutes < endMinutes
		}
		return nowMinutes >= startMinutes || nowMinutes < endMinutes
	}
	return true
}

func matchTimeRangeCondition(value interface{}) bool {
	data, err := json.Marshal(value)
	if err != nil {
		return true
	}
	var tr TimeRange
	if err := json.Unmarshal(data, &tr); err != nil {
		return true
	}
	return matchTimeRange(&tr)
}

func matchCustomVariables(cv map[string]string, extra map[string]interface{}) bool {
	if len(extra) == 0 {
		return false
	}
	for key, expected := range cv {
		val, ok := extra[key]
		if !ok {
			return false
		}
		if fmt.Sprintf("%v", val) != expected {
			return false
		}
	}
	return true
}

func resolvePlaceholders(template string, payload *EventPayload) string {
	replacements := map[string]string{
		"{{username}}":        payload.Username,
		"{{path}}":            payload.FilePath,
		"{{filename}}":        payload.FileName,
		"{{size}}":            fmt.Sprintf("%d", payload.FileSize),
		"{{ext}}":             payload.FileExt,
		"{{protocol}}":        payload.Protocol,
		"{{client_ip}}":       payload.ClientIP,
		"{{event_id}}":        payload.EventID,
		"{{result}}":          payload.Result,
		"{{user_role}}":       payload.UserRole,
		"{{storage_backend}}": payload.StorageBackend,
	}
	result := template
	for key, value := range replacements {
		result = strings.ReplaceAll(result, key, value)
	}
	if payload.Extra != nil {
		for k, v := range payload.Extra {
			result = strings.ReplaceAll(result, "{{"+k+"}}", fmt.Sprintf("%v", v))
		}
	}
	return result
}

func powFloat(base, exp float64) time.Duration {
	result := base
	for i := 1; i < int(exp); i++ {
		result *= base
	}
	return time.Duration(result * float64(time.Second))
}

func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

func (m *Manager) loadRules(ctx context.Context) error {
	ruleRecords, err := m.repo.ListRules(ctx)
	if err != nil {
		return err
	}

	ruleIDs := make([]int64, 0, len(ruleRecords))
	for _, record := range ruleRecords {
		ruleIDs = append(ruleIDs, record.ID)
	}

	actionRecords, err := m.repo.ListActionsByRuleIDs(ctx, ruleIDs)
	if err != nil {
		return err
	}

	actionsByRuleID := make(map[int64][]ActionConfig)
	for _, actionRecord := range actionRecords {
		config := map[string]interface{}{}
		if len(actionRecord.Config) > 0 {
			if err := json.Unmarshal(actionRecord.Config, &config); err != nil {
				m.logger.Warn("failed to decode event action config", zap.Int64("action_id", actionRecord.ID), zap.Error(err))
				continue
			}
		}
		actionsByRuleID[actionRecord.RuleID] = append(actionsByRuleID[actionRecord.RuleID], ActionConfig{
			ID:         actionRecord.ID,
			Type:       ActionType(actionRecord.ActionType),
			Config:     config,
			OrderIndex: actionRecord.OrderIndex,
		})
	}

	for _, record := range ruleRecords {
		conditions := []Condition{}
		if len(record.Conditions) > 0 {
			if err := json.Unmarshal(record.Conditions, &conditions); err != nil {
				m.logger.Warn("failed to decode event rule conditions", zap.Int64("rule_id", record.ID), zap.Error(err))
				conditions = nil
			}
		}

		rule := &EventRule{
			ID:          record.ID,
			Name:        record.Name,
			Description: record.Description.String,
			TriggerType: EventType(record.TriggerType),
			Conditions:  conditions,
			Actions:     actionsByRuleID[record.ID],
			IsActive:    record.IsActive,
			Schedule:    record.Schedule.String,
		}
		m.AddRule(rule)
	}
	return nil
}

func (m *Manager) recordExecution(ctx context.Context, rule *EventRule, action ActionConfig, payload *EventPayload, result *ExecutionResult, execErr error) {
	outcome := "success"
	errMsg := ""
	if execErr != nil {
		outcome = "failure"
		errMsg = execErr.Error()
	} else if result != nil && result.Error != nil {
		outcome = "failure"
		errMsg = result.Error.Error()
	} else if result != nil && !result.Success {
		outcome = "failure"
	}

	if m.metrics != nil {
		m.metrics.RecordEventExecution(rule.Name, string(action.Type), outcome)
	}

	if m.repo == nil {
		return
	}

	payloadJSON, _ := json.Marshal(payload)
	if _, err := m.repo.CreateHistory(ctx, &repository.EventHistoryRecord{
		RuleID:       rule.ID,
		ActionID:     action.ID,
		EventType:    string(payload.EventType),
		Payload:      string(payloadJSON),
		Result:       outcome,
		ErrorMessage: errMsg,
	}); err != nil {
		m.logger.Warn("failed to persist event history", zap.Int64("rule_id", rule.ID), zap.Int64("action_id", action.ID), zap.Error(err))
	}

	if m.auditRecorder != nil {
		_ = m.auditRecorder.Record(ctx, &audit.AuditEvent{
			EventType:    audit.EventActionExecute,
			ActorType:    audit.ActorSystem,
			ActorName:    "event_manager",
			TargetType:   audit.TargetRule,
			TargetID:     fmt.Sprintf("rule_%d_action_%d", rule.ID, action.ID),
			Protocol:     payload.Protocol,
			ClientIP:     payload.ClientIP,
			Result:       outcome,
			ErrorMessage: errMsg,
		})
	}
}

func stringSliceFromConfig(raw interface{}) []string {
	switch values := raw.(type) {
	case []string:
		return values
	case []interface{}:
		items := make([]string, 0, len(values))
		for _, value := range values {
			if str, ok := value.(string); ok {
				items = append(items, str)
			}
		}
		return items
	default:
		return nil
	}
}

func buildPayloadEnv(payload *EventPayload) []string {
	values := []string{
		"SFTPXY_EVENT_ID=" + payload.EventID,
		"SFTPXY_EVENT_TYPE=" + string(payload.EventType),
		"SFTPXY_EVENT_USERNAME=" + payload.Username,
		"SFTPXY_EVENT_PROTOCOL=" + payload.Protocol,
		"SFTPXY_EVENT_FILE_PATH=" + payload.FilePath,
		"SFTPXY_EVENT_RESULT=" + payload.Result,
	}
	if payload.ClientIP != "" {
		values = append(values, "SFTPXY_EVENT_CLIENT_IP="+payload.ClientIP)
	}
	if payload.UserRole != "" {
		values = append(values, "SFTPXY_EVENT_USER_ROLE="+payload.UserRole)
	}
	if payload.StorageBackend != "" {
		values = append(values, "SFTPXY_EVENT_STORAGE_BACKEND="+payload.StorageBackend)
	}
	if len(payload.UserGroups) > 0 {
		values = append(values, "SFTPXY_EVENT_USER_GROUPS="+strings.Join(payload.UserGroups, ","))
	}
	return values
}
