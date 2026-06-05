package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
)

type Permission struct {
	Path       string `json:"path"`
	List       bool   `json:"list"`
	Download   bool   `json:"download"`
	Upload     bool   `json:"upload"`
	Overwrite  bool   `json:"overwrite"`
	Delete     bool   `json:"delete"`
	Rename     bool   `json:"rename"`
	CreateDirs bool   `json:"create_dirs"`
	Chmod      bool   `json:"chmod"`
}

type QuotaConfig struct {
	MaxSize      int64 `json:"max_size"`
	MaxFiles     int64 `json:"max_files"`
	CurrentSize  int64 `json:"current_size"`
	CurrentFiles int64 `json:"current_files"`
}

type BandwidthLimit struct {
	UploadBytesPerSec   int64 `json:"upload_bytes_per_sec"`
	DownloadBytesPerSec int64 `json:"download_bytes_per_sec"`
}

type TransferLimit struct {
	MaxUploadBytes   int64     `json:"max_upload_bytes"`
	MaxDownloadBytes int64     `json:"max_download_bytes"`
	CurrentUpload    int64     `json:"current_upload"`
	CurrentDownload  int64     `json:"current_download"`
	ResetPeriod      string    `json:"reset_period"`
	LastReset        time.Time `json:"last_reset"`
}

type IPFilter struct {
	AllowList []string `json:"allow_list"`
	DenyList  []string `json:"deny_list"`
}

type OperationType string

const (
	OpList     OperationType = "list"
	OpDownload OperationType = "download"
	OpUpload   OperationType = "upload"
	OpDelete   OperationType = "delete"
	OpRename   OperationType = "rename"
	OpMkdir    OperationType = "mkdir"
	OpRmdir    OperationType = "rmdir"
	OpChmod    OperationType = "chmod"
	OpChown    OperationType = "chown"
	OpChtimes  OperationType = "chtimes"
	OpTruncate OperationType = "truncate"
	OpCopy     OperationType = "copy"
	OpSymlink  OperationType = "symlink"
)

type FileFilter struct {
	AllowedPatterns     []string `json:"allowed_patterns"`
	DeniedPatterns      []string `json:"denied_patterns"`
	MaxFileSize         int64    `json:"max_file_size"`
	AllowedExtensions   []string `json:"allowed_extensions"`
	DeniedExtensions    []string `json:"denied_extensions"`
	MinFileSize         int64    `json:"min_file_size"`
	HiddenPatterns      []string `json:"hidden_patterns"`
	DeniedUploadNames   []string `json:"denied_upload_names"`
	DeniedDownloadNames []string `json:"denied_download_names"`
}

type TimeBasedBandwidthRule struct {
	BandwidthLimit
	StartHour int   `json:"start_hour"`
	EndHour   int   `json:"end_hour"`
	Days      []int `json:"days"`
}

type ExtendedBandwidthLimit struct {
	BandwidthLimit
	ProtocolLimits map[string]BandwidthLimit `json:"protocol_limits,omitempty"`
	TimeBased      []TimeBasedBandwidthRule  `json:"time_based,omitempty"`
}

type ProtocolPermissions map[string][]Permission

type GroupSettings struct {
	Priority                int64                     `json:"priority"`
	Permissions             []Permission              `json:"permissions,omitempty"`
	ProtocolPermissions     ProtocolPermissions       `json:"protocol_permissions,omitempty"`
	BandwidthLimits         BandwidthLimit            `json:"bandwidth_limits,omitempty"`
	ProtocolBandwidthLimits map[string]BandwidthLimit `json:"protocol_bandwidth_limits,omitempty"`
	TimeBasedBandwidth      []TimeBasedBandwidthRule  `json:"time_based_bandwidth,omitempty"`
	Quota                   QuotaConfig               `json:"quota,omitempty"`
	TransferLimit           TransferLimit             `json:"transfer_limit,omitempty"`
	AllowedProtocols        []string                  `json:"allowed_protocols,omitempty"`
	DeniedProtocols         []string                  `json:"denied_protocols,omitempty"`
}

type QuotaAlertConfig struct {
	Threshold float64 `json:"threshold"`
}

type EventNotifier interface {
	Notify(ctx context.Context, eventType string, payload map[string]interface{})
}

type Group struct {
	ID           int64           `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	Settings     json.RawMessage `json:"settings,omitempty"`
	UserSettings json.RawMessage `json:"user_settings,omitempty"`
	Priority     int64           `json:"priority"`
}

type GroupRepository interface {
	GetByUserID(ctx context.Context, userID int64) ([]*Group, error)
	GetByID(ctx context.Context, id int64) (*Group, error)
}

type PolicyEngineOption func(*PolicyEngine)

func WithGroupRepo(repo GroupRepository) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.groupRepo = repo
	}
}

func WithEventNotifier(notifier EventNotifier) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.eventNotifier = notifier
	}
}

func WithQuotaAlert(config QuotaAlertConfig) PolicyEngineOption {
	return func(pe *PolicyEngine) {
		pe.quotaAlert = config
	}
}

type PolicyEngine struct {
	userRepo      repository.UserRepository
	groupRepo     GroupRepository
	eventNotifier EventNotifier
	quotaAlert    QuotaAlertConfig
}

func NewPolicyEngine(userRepo repository.UserRepository, opts ...PolicyEngineOption) *PolicyEngine {
	pe := &PolicyEngine{userRepo: userRepo}
	for _, opt := range opts {
		opt(pe)
	}
	return pe
}

type AuthRequest struct {
	Username   string
	Protocol   string
	ClientIP   net.IP
	AuthMethod string
}

func (pe *PolicyEngine) CanAuthenticate(ctx context.Context, req AuthRequest) (bool, error) {
	user, err := pe.userRepo.GetByUsername(ctx, req.Username)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	if user.Status != "active" {
		return false, fmt.Errorf("user is disabled")
	}

	if user.ExpirationDate.Valid && user.ExpirationDate.String != "" {
		expiry, err := time.Parse(time.RFC3339, user.ExpirationDate.String)
		if err == nil && time.Now().After(expiry) {
			return false, fmt.Errorf("user has expired")
		}
	}

	if len(user.AllowedProtocols) > 0 {
		var allowed []string
		json.Unmarshal(user.AllowedProtocols, &allowed)
		if !contains(allowed, req.Protocol) {
			return false, fmt.Errorf("protocol %s not allowed for user", req.Protocol)
		}
	}

	if len(user.DeniedProtocols) > 0 {
		var denied []string
		json.Unmarshal(user.DeniedProtocols, &denied)
		if contains(denied, req.Protocol) {
			return false, fmt.Errorf("protocol %s denied for user", req.Protocol)
		}
	}

	if len(user.IPFilters) > 0 {
		var ipFilter IPFilter
		json.Unmarshal(user.IPFilters, &ipFilter)
		if !pe.isIPAllowed(req.ClientIP, ipFilter) {
			return false, fmt.Errorf("IP %s not allowed", req.ClientIP)
		}
	}

	return true, nil
}

type OperationRequest struct {
	UserID    int64
	Username  string
	Protocol  string
	ClientIP  net.IP
	Operation OperationType
	FilePath  string
	FileSize  int64
}

func (pe *PolicyEngine) CanPerformOperation(ctx context.Context, req OperationRequest) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	if user.Status != "active" {
		return false, fmt.Errorf("user is disabled")
	}

	permissions, err := parsePermissions(user.Permissions)
	if err != nil {
		return false, fmt.Errorf("invalid permissions config: %w", err)
	}

	var protoPerms ProtocolPermissions
	if len(user.ProtocolPermissions) > 0 {
		json.Unmarshal(user.ProtocolPermissions, &protoPerms)
	}

	if !pe.hasPermissionWithProtocol(permissions, protoPerms, req.Operation, req.FilePath, req.Protocol) {
		return false, fmt.Errorf("permission denied for %s on %s", req.Operation, req.FilePath)
	}

	if len(user.Filters) > 0 {
		var filter FileFilter
		if err := json.Unmarshal(user.Filters, &filter); err == nil {
			if !passesFileFilterStruct(&filter, req.FilePath, req.FileSize, req.Operation) {
				return false, fmt.Errorf("file filtered: %s", req.FilePath)
			}
		} else {
			var rawFilters map[string]interface{}
			if json.Unmarshal(user.Filters, &rawFilters) == nil {
				if !passesFileFilterMap(rawFilters, req.FilePath, req.FileSize) {
					return false, fmt.Errorf("file filtered: %s", req.FilePath)
				}
			}
		}
	}

	if req.Operation == OpUpload {
		if len(user.Quotas) > 0 {
			var quota QuotaConfig
			json.Unmarshal(user.Quotas, &quota)
			if quota.MaxSize > 0 && quota.CurrentSize+req.FileSize > quota.MaxSize {
				return false, fmt.Errorf("quota exceeded")
			}
		}
	}

	if len(user.TransferLimits) > 0 {
		var limit TransferLimit
		json.Unmarshal(user.TransferLimits, &limit)
		if !checkTransferLimit(limit, req) {
			return false, fmt.Errorf("transfer limit exceeded")
		}
	}

	return true, nil
}

func (pe *PolicyEngine) CheckQuota(ctx context.Context, userID int64, size int64) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.Quotas) == 0 {
		return true, nil
	}

	var quota QuotaConfig
	json.Unmarshal(user.Quotas, &quota)

	if quota.MaxSize > 0 && quota.CurrentSize+size > quota.MaxSize {
		pe.emitQuotaWarning(ctx, user, quota.CurrentSize+size, quota.MaxSize)
		return false, fmt.Errorf("storage quota exceeded: current=%d, adding=%d, max=%d",
			quota.CurrentSize, size, quota.MaxSize)
	}

	if quota.MaxFiles > 0 && quota.CurrentFiles+1 > quota.MaxFiles {
		return false, fmt.Errorf("file count quota exceeded")
	}

	if pe.quotaAlert.Threshold > 0 && quota.MaxSize > 0 {
		usageRatio := float64(quota.CurrentSize+size) / float64(quota.MaxSize)
		if usageRatio >= pe.quotaAlert.Threshold {
			pe.emitQuotaWarning(ctx, user, quota.CurrentSize+size, quota.MaxSize)
		}
	}

	return true, nil
}

func (pe *PolicyEngine) GetBandwidthLimit(ctx context.Context, userID int64, direction string) (int64, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return 0, err
	}

	if len(user.BandwidthLimits) == 0 {
		return 0, nil
	}

	var limit BandwidthLimit
	json.Unmarshal(user.BandwidthLimits, &limit)

	if direction == "upload" {
		return limit.UploadBytesPerSec, nil
	}
	return limit.DownloadBytesPerSec, nil
}

func (pe *PolicyEngine) GetEffectiveBandwidthLimit(ctx context.Context, userID int64, protocol string) (BandwidthLimit, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return BandwidthLimit{}, err
	}

	var userLimit ExtendedBandwidthLimit
	if len(user.BandwidthLimits) > 0 {
		json.Unmarshal(user.BandwidthLimits, &userLimit)
	}

	var groupLimit BandwidthLimit
	var groupProtoLimits map[string]BandwidthLimit
	if pe.groupRepo != nil {
		groups, gErr := pe.groupRepo.GetByUserID(ctx, userID)
		if gErr == nil && len(groups) > 0 {
			merged := mergeGroupSettings(groups)
			groupLimit = merged.BandwidthLimits
			groupProtoLimits = merged.ProtocolBandwidthLimits
		}
	}

	return pe.getEffectiveBandwidthLimit(userLimit, groupLimit, groupProtoLimits, protocol, time.Now()), nil
}

func (pe *PolicyEngine) IsIPAllowed(ctx context.Context, userID int64, ip net.IP, protocol string) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.IPFilters) == 0 {
		return true, nil
	}

	var ipFilter IPFilter
	json.Unmarshal(user.IPFilters, &ipFilter)

	return pe.isIPAllowed(ip, ipFilter), nil
}

func (pe *PolicyEngine) IsProtocolAllowed(ctx context.Context, userID int64, protocol string) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.AllowedProtocols) > 0 {
		var allowed []string
		json.Unmarshal(user.AllowedProtocols, &allowed)
		if !contains(allowed, protocol) {
			return false, nil
		}
	}

	if len(user.DeniedProtocols) > 0 {
		var denied []string
		json.Unmarshal(user.DeniedProtocols, &denied)
		if contains(denied, protocol) {
			return false, nil
		}
	}

	return true, nil
}

func (pe *PolicyEngine) IsFileHidden(ctx context.Context, userID int64, filePath string) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.Filters) == 0 {
		return false, nil
	}

	var filter FileFilter
	if err := json.Unmarshal(user.Filters, &filter); err != nil {
		return false, nil
	}

	fileName := path.Base(filePath)
	for _, pattern := range filter.HiddenPatterns {
		if matchPattern(pattern, fileName) || matchPattern(pattern, filePath) {
			return true, nil
		}
	}

	return false, nil
}

func (pe *PolicyEngine) CheckTransferLimit(ctx context.Context, userID int64, req OperationRequest) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.TransferLimits) == 0 {
		return true, nil
	}

	var limit TransferLimit
	json.Unmarshal(user.TransferLimits, &limit)

	if !checkTransferLimit(limit, req) {
		return false, fmt.Errorf("transfer limit exceeded")
	}

	return true, nil
}

func (pe *PolicyEngine) ResetTransferLimit(ctx context.Context, userID int64) error {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if len(user.TransferLimits) == 0 {
		return nil
	}

	var limit TransferLimit
	json.Unmarshal(user.TransferLimits, &limit)
	limit.CurrentUpload = 0
	limit.CurrentDownload = 0
	limit.LastReset = time.Now()

	updated, _ := json.Marshal(limit)
	user.TransferLimits = updated
	return pe.userRepo.Update(ctx, user)
}

func (pe *PolicyEngine) MergeGroupSettings(groups []*Group) GroupSettings {
	return mergeGroupSettings(groups)
}

func (pe *PolicyEngine) hasPermissionWithProtocol(defaultPerms []Permission, protoPerms ProtocolPermissions, op OperationType, filePath string, protocol string) bool {
	if protoPerms != nil && protocol != "" {
		if perms, ok := protoPerms[protocol]; ok && len(perms) > 0 {
			return hasPermission(perms, op, filePath)
		}
	}

	if len(defaultPerms) > 0 {
		return hasPermission(defaultPerms, op, filePath)
	}

	return true
}

func (pe *PolicyEngine) getEffectiveBandwidthLimit(userLimit ExtendedBandwidthLimit, groupLimit BandwidthLimit, groupProtoLimits map[string]BandwidthLimit, protocol string, now time.Time) BandwidthLimit {
	var candidates []BandwidthLimit

	if userLimit.UploadBytesPerSec > 0 || userLimit.DownloadBytesPerSec > 0 {
		candidates = append(candidates, userLimit.BandwidthLimit)
	}

	if groupLimit.UploadBytesPerSec > 0 || groupLimit.DownloadBytesPerSec > 0 {
		candidates = append(candidates, groupLimit)
	}

	if protocol != "" {
		if pl, ok := userLimit.ProtocolLimits[protocol]; ok && (pl.UploadBytesPerSec > 0 || pl.DownloadBytesPerSec > 0) {
			candidates = append(candidates, pl)
		}
		if groupProtoLimits != nil {
			if pl, ok := groupProtoLimits[protocol]; ok && (pl.UploadBytesPerSec > 0 || pl.DownloadBytesPerSec > 0) {
				candidates = append(candidates, pl)
			}
		}
	}

	for _, rule := range userLimit.TimeBased {
		if isTimeBasedRuleActive(rule, now) {
			candidates = append(candidates, rule.BandwidthLimit)
		}
	}

	if len(candidates) == 0 {
		return BandwidthLimit{}
	}

	effective := candidates[0]
	for _, c := range candidates[1:] {
		if c.UploadBytesPerSec > 0 && (effective.UploadBytesPerSec == 0 || c.UploadBytesPerSec < effective.UploadBytesPerSec) {
			effective.UploadBytesPerSec = c.UploadBytesPerSec
		}
		if c.DownloadBytesPerSec > 0 && (effective.DownloadBytesPerSec == 0 || c.DownloadBytesPerSec < effective.DownloadBytesPerSec) {
			effective.DownloadBytesPerSec = c.DownloadBytesPerSec
		}
	}

	return effective
}

func isTimeBasedRuleActive(rule TimeBasedBandwidthRule, now time.Time) bool {
	if len(rule.Days) > 0 {
		dayMatch := false
		weekday := int(now.Weekday())
		for _, d := range rule.Days {
			if d == weekday {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}

	hour := now.Hour()
	if rule.StartHour <= rule.EndHour {
		return hour >= rule.StartHour && hour < rule.EndHour
	}
	return hour >= rule.StartHour || hour < rule.EndHour
}

func mergeGroupSettings(groups []*Group) GroupSettings {
	if len(groups) == 0 {
		return GroupSettings{}
	}

	type groupWithSettings struct {
		settings GroupSettings
	}

	var items []groupWithSettings
	for _, g := range groups {
		var gs GroupSettings
		if len(g.Settings) > 0 {
			json.Unmarshal(g.Settings, &gs)
		}
		gs.Priority = g.Priority
		items = append(items, groupWithSettings{settings: gs})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].settings.Priority > items[j].settings.Priority
	})

	result := GroupSettings{
		Permissions:             []Permission{},
		AllowedProtocols:        []string{},
		DeniedProtocols:         []string{},
		ProtocolBandwidthLimits: map[string]BandwidthLimit{},
		ProtocolPermissions:     ProtocolPermissions{},
		TimeBasedBandwidth:      []TimeBasedBandwidthRule{},
	}

	quotaSet := false
	bwSet := false
	tlSet := false

	for _, item := range items {
		gs := item.settings

		result.Permissions = append(result.Permissions, gs.Permissions...)

		for proto, perms := range gs.ProtocolPermissions {
			result.ProtocolPermissions[proto] = append(result.ProtocolPermissions[proto], perms...)
		}

		if !bwSet && (gs.BandwidthLimits.UploadBytesPerSec > 0 || gs.BandwidthLimits.DownloadBytesPerSec > 0) {
			result.BandwidthLimits = gs.BandwidthLimits
			bwSet = true
		}

		for proto, limit := range gs.ProtocolBandwidthLimits {
			if _, exists := result.ProtocolBandwidthLimits[proto]; !exists {
				result.ProtocolBandwidthLimits[proto] = limit
			}
		}

		result.TimeBasedBandwidth = append(result.TimeBasedBandwidth, gs.TimeBasedBandwidth...)

		if !quotaSet && (gs.Quota.MaxSize > 0 || gs.Quota.MaxFiles > 0) {
			result.Quota = gs.Quota
			quotaSet = true
		}

		if !tlSet && (gs.TransferLimit.MaxUploadBytes > 0 || gs.TransferLimit.MaxDownloadBytes > 0) {
			result.TransferLimit = gs.TransferLimit
			tlSet = true
		}

		result.AllowedProtocols = append(result.AllowedProtocols, gs.AllowedProtocols...)
		result.DeniedProtocols = append(result.DeniedProtocols, gs.DeniedProtocols...)
	}

	return result
}

func checkTransferLimit(limit TransferLimit, req OperationRequest) bool {
	limit = maybeResetTransferLimit(limit)

	if req.Operation == OpUpload && limit.MaxUploadBytes > 0 {
		if limit.CurrentUpload+req.FileSize > limit.MaxUploadBytes {
			return false
		}
	}

	if req.Operation == OpDownload && limit.MaxDownloadBytes > 0 {
		if limit.CurrentDownload+req.FileSize > limit.MaxDownloadBytes {
			return false
		}
	}

	return true
}

func maybeResetTransferLimit(limit TransferLimit) TransferLimit {
	if limit.ResetPeriod == "" || limit.ResetPeriod == "none" {
		return limit
	}

	now := time.Now()
	needsReset := false

	switch limit.ResetPeriod {
	case "daily":
		if !limit.LastReset.IsZero() {
			y1, m1, d1 := limit.LastReset.Date()
			y2, m2, d2 := now.Date()
			needsReset = y1 != y2 || m1 != m2 || d1 != d2
		} else {
			needsReset = true
		}
	case "monthly":
		if !limit.LastReset.IsZero() {
			y1, m1, _ := limit.LastReset.Date()
			y2, m2, _ := now.Date()
			needsReset = y1 != y2 || m1 != m2
		} else {
			needsReset = true
		}
	}

	if needsReset {
		limit.CurrentUpload = 0
		limit.CurrentDownload = 0
		limit.LastReset = now
	}

	return limit
}

func (pe *PolicyEngine) emitQuotaWarning(ctx context.Context, user *repository.User, currentUsage int64, quotaLimit int64) {
	if pe.eventNotifier == nil {
		return
	}

	pe.eventNotifier.Notify(ctx, "quota_warning", map[string]interface{}{
		"user_id":       user.ID,
		"username":      user.Username,
		"current_usage": currentUsage,
		"quota_limit":   quotaLimit,
		"threshold":     pe.quotaAlert.Threshold,
	})
}

func passesFileFilterMap(filters map[string]interface{}, filePath string, size int64) bool {
	if allowedPatterns, ok := filters["allowed_patterns"].([]interface{}); ok {
		matched := false
		for _, p := range allowedPatterns {
			if pattern, ok := p.(string); ok {
				if matchPattern(pattern, filePath) {
					matched = true
					break
				}
			}
		}
		if !matched && len(allowedPatterns) > 0 {
			return false
		}
	}

	if deniedPatterns, ok := filters["denied_patterns"].([]interface{}); ok {
		for _, p := range deniedPatterns {
			if pattern, ok := p.(string); ok {
				if matchPattern(pattern, filePath) {
					return false
				}
			}
		}
	}

	if maxSize, ok := filters["max_file_size"].(float64); ok {
		if size > int64(maxSize) {
			return false
		}
	}

	return true
}

func passesFileFilterStruct(filter *FileFilter, filePath string, size int64, op OperationType) bool {
	if len(filter.AllowedPatterns) > 0 {
		matched := false
		for _, pattern := range filter.AllowedPatterns {
			if matchPattern(pattern, filePath) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	for _, pattern := range filter.DeniedPatterns {
		if matchPattern(pattern, filePath) {
			return false
		}
	}

	if filter.MaxFileSize > 0 && size > filter.MaxFileSize {
		return false
	}

	if len(filter.AllowedExtensions) > 0 {
		ext := strings.ToLower(path.Ext(filePath))
		found := false
		for _, allowed := range filter.AllowedExtensions {
			if strings.ToLower(allowed) == ext {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.DeniedExtensions) > 0 {
		ext := strings.ToLower(path.Ext(filePath))
		for _, denied := range filter.DeniedExtensions {
			if strings.ToLower(denied) == ext {
				return false
			}
		}
	}

	if filter.MinFileSize > 0 && size > 0 && size < filter.MinFileSize {
		return false
	}

	fileName := path.Base(filePath)

	if op == OpUpload && len(filter.DeniedUploadNames) > 0 {
		for _, pattern := range filter.DeniedUploadNames {
			if matchPattern(pattern, fileName) || matchPattern(pattern, filePath) {
				return false
			}
		}
	}

	if op == OpDownload && len(filter.DeniedDownloadNames) > 0 {
		for _, pattern := range filter.DeniedDownloadNames {
			if matchPattern(pattern, fileName) || matchPattern(pattern, filePath) {
				return false
			}
		}
	}

	return true
}

type QuotaScanner struct {
	userRepo repository.UserRepository
}

func NewQuotaScanner(userRepo repository.UserRepository) *QuotaScanner {
	return &QuotaScanner{userRepo: userRepo}
}

type QuotaScanResult struct {
	UsedBytes int64
	UsedFiles int64
}

func (qs *QuotaScanner) ScanUserQuota(ctx context.Context, userID string) (int64, int64, error) {
	var userIDInt int64
	_, err := fmt.Sscanf(userID, "%d", &userIDInt)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid user ID: %s", userID)
	}

	user, err := qs.userRepo.GetByID(ctx, userIDInt)
	if err != nil {
		return 0, 0, err
	}

	return qs.scanDirectory(user.HomeDir)
}

func (qs *QuotaScanner) ScanPath(homeDir string) (int64, int64, error) {
	return qs.scanDirectory(homeDir)
}

func (qs *QuotaScanner) scanDirectory(root string) (int64, int64, error) {
	var totalSize int64
	var totalFiles int64

	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		totalSize += info.Size()
		totalFiles++
		return nil
	})

	if err != nil {
		return 0, 0, err
	}

	return totalSize, totalFiles, nil
}

func (qs *QuotaScanner) CompareAndUpdateQuota(ctx context.Context, userID string) (bool, error) {
	var userIDInt int64
	_, err := fmt.Sscanf(userID, "%d", &userIDInt)
	if err != nil {
		return false, fmt.Errorf("invalid user ID: %s", userID)
	}

	user, err := qs.userRepo.GetByID(ctx, userIDInt)
	if err != nil {
		return false, err
	}

	usedBytes, usedFiles, err := qs.scanDirectory(user.HomeDir)
	if err != nil {
		return false, err
	}

	if len(user.Quotas) == 0 {
		return false, nil
	}

	var quota QuotaConfig
	json.Unmarshal(user.Quotas, &quota)

	if quota.CurrentSize != usedBytes || quota.CurrentFiles != usedFiles {
		quota.CurrentSize = usedBytes
		quota.CurrentFiles = usedFiles
		updated, _ := json.Marshal(quota)
		user.Quotas = updated
		return true, qs.userRepo.Update(ctx, user)
	}

	return false, nil
}

type TransferLimitManager struct {
	userRepo repository.UserRepository
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	mu       sync.Mutex
}

func NewTransferLimitManager(userRepo repository.UserRepository, interval time.Duration) *TransferLimitManager {
	return &TransferLimitManager{
		userRepo: userRepo,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

func (m *TransferLimitManager) Start() {
	go m.run()
}

func (m *TransferLimitManager) Stop() {
	close(m.stopCh)
	<-m.doneCh
}

func (m *TransferLimitManager) ResetUser(ctx context.Context, userID int64) error {
	user, err := m.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if len(user.TransferLimits) == 0 {
		return nil
	}
	var limit TransferLimit
	json.Unmarshal(user.TransferLimits, &limit)
	limit.CurrentUpload = 0
	limit.CurrentDownload = 0
	limit.LastReset = time.Now()
	updated, _ := json.Marshal(limit)
	user.TransferLimits = updated
	return m.userRepo.Update(ctx, user)
}

func (m *TransferLimitManager) run() {
	defer close(m.doneCh)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.resetExpiredLimits(context.Background())
		}
	}
}

func (m *TransferLimitManager) resetExpiredLimits(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	offset := 0
	batchSize := 100

	for {
		users, err := m.userRepo.List(ctx, "", "", batchSize, offset)
		if err != nil {
			return
		}
		if len(users) == 0 {
			break
		}

		for _, user := range users {
			if len(user.TransferLimits) == 0 {
				continue
			}
			var limit TransferLimit
			json.Unmarshal(user.TransferLimits, &limit)
			resetLimit := maybeResetTransferLimit(limit)
			if resetLimit.CurrentUpload != limit.CurrentUpload || resetLimit.CurrentDownload != limit.CurrentDownload {
				updated, _ := json.Marshal(resetLimit)
				user.TransferLimits = updated
				m.userRepo.Update(ctx, user)
			}
		}

		if len(users) < batchSize {
			break
		}
		offset += batchSize
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) isIPAllowed(ip net.IP, filter IPFilter) bool {
	for _, deniedCIDR := range filter.DenyList {
		_, cidr, err := net.ParseCIDR(deniedCIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return false
		}
	}

	if len(filter.AllowList) == 0 {
		return true
	}

	for _, allowedCIDR := range filter.AllowList {
		_, cidr, err := net.ParseCIDR(allowedCIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func hasPermission(permissions []Permission, op OperationType, filePath string) bool {
	var matchedPerm *Permission

	for i := range permissions {
		p := &permissions[i]
		if pathMatches(p.Path, filePath) {
			if matchedPerm == nil || len(p.Path) > len(matchedPerm.Path) {
				matchedPerm = p
			}
		}
	}

	if matchedPerm == nil {
		return false
	}

	switch op {
	case OpList:
		return matchedPerm.List
	case OpDownload:
		return matchedPerm.Download
	case OpUpload:
		return matchedPerm.Upload
	case OpDelete:
		return matchedPerm.Delete
	case OpRename:
		return matchedPerm.Rename
	case OpMkdir, OpRmdir:
		return matchedPerm.CreateDirs
	case OpChmod:
		return matchedPerm.Chmod
	default:
		return false
	}
}

func pathMatches(pattern, filePath string) bool {
	if pattern == "/" || pattern == "" {
		return true
	}
	return strings.HasPrefix(filePath, pattern)
}

func parsePermissions(raw json.RawMessage) ([]Permission, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		switch strings.ToLower(trimmed) {
		case "full":
			return []Permission{fullAccessPermission("/")}, nil
		case "read":
			return []Permission{readOnlyPermission("/")}, nil
		default:
			return nil, fmt.Errorf("unsupported legacy permissions value %q", trimmed)
		}
	}

	var permissions []Permission
	if err := json.Unmarshal(raw, &permissions); err == nil {
		return permissions, nil
	}

	var single Permission
	if err := json.Unmarshal(raw, &single); err == nil {
		if single.Path == "" {
			single.Path = "/"
		}
		return []Permission{single}, nil
	}

	return nil, fmt.Errorf("unsupported permissions format")
}

func fullAccessPermission(filePath string) Permission {
	return Permission{
		Path:       filePath,
		List:       true,
		Download:   true,
		Upload:     true,
		Overwrite:  true,
		Delete:     true,
		Rename:     true,
		CreateDirs: true,
		Chmod:      true,
	}
}

func readOnlyPermission(filePath string) Permission {
	return Permission{
		Path:     filePath,
		List:     true,
		Download: true,
	}
}

func matchPattern(pattern, filePath string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(filePath, prefix+"/")
	}
	if strings.HasPrefix(pattern, "*.") {
		ext := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(filePath, ext)
	}
	if strings.Contains(pattern, "*") {
		if matched, _ := path.Match(pattern, path.Base(filePath)); matched {
			return true
		}
		if matched, _ := path.Match(pattern, filePath); matched {
			return true
		}
	}
	return filePath == pattern
}
