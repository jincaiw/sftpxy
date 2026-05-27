package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sftpxy/sftpxy/internal/repository"
)

// Permission represents a file permission
type Permission struct {
	Path       string   `json:"path"`
	List       bool     `json:"list"`
	Download   bool     `json:"download"`
	Upload     bool     `json:"upload"`
	Overwrite  bool     `json:"overwrite"`
	Delete     bool     `json:"delete"`
	Rename     bool     `json:"rename"`
	CreateDirs bool     `json:"create_dirs"`
	Chmod      bool     `json:"chmod"`
}

// QuotaConfig represents quota settings
type QuotaConfig struct {
	MaxSize     int64 `json:"max_size"`      // Max storage in bytes
	MaxFiles    int64 `json:"max_files"`     // Max file count
	CurrentSize int64 `json:"current_size"`  // Current usage
	CurrentFiles int64 `json:"current_files"` // Current file count
}

// BandwidthLimit represents bandwidth limits
type BandwidthLimit struct {
	UploadBytesPerSec   int64 `json:"upload_bytes_per_sec"`
	DownloadBytesPerSec int64 `json:"download_bytes_per_sec"`
}

// TransferLimit represents transfer limits
type TransferLimit struct {
	MaxUploadBytes   int64 `json:"max_upload_bytes"`
	MaxDownloadBytes int64 `json:"max_download_bytes"`
	CurrentUpload    int64 `json:"current_upload"`
	CurrentDownload  int64 `json:"current_download"`
	ResetPeriod      string `json:"reset_period"` // daily, monthly
	LastReset        time.Time `json:"last_reset"`
}

// IPFilter represents IP filtering rules
type IPFilter struct {
	AllowList []string `json:"allow_list"`
	DenyList  []string `json:"deny_list"`
}

// OperationType represents the type of file operation
type OperationType string

const (
	OpList      OperationType = "list"
	OpDownload  OperationType = "download"
	OpUpload    OperationType = "upload"
	OpDelete    OperationType = "delete"
	OpRename    OperationType = "rename"
	OpMkdir     OperationType = "mkdir"
	OpRmdir     OperationType = "rmdir"
	OpChmod     OperationType = "chmod"
	OpChown     OperationType = "chown"
	OpChtimes   OperationType = "chtimes"
	OpTruncate  OperationType = "truncate"
	OpCopy      OperationType = "copy"
	OpSymlink   OperationType = "symlink"
)

// PolicyEngine provides unified policy control for all protocols
type PolicyEngine struct {
	userRepo repository.UserRepository
}

// NewPolicyEngine creates a new PolicyEngine
func NewPolicyEngine(userRepo repository.UserRepository) *PolicyEngine {
	return &PolicyEngine{userRepo: userRepo}
}

// AuthRequest contains authentication request information
type AuthRequest struct {
	Username string
	Protocol string
	ClientIP net.IP
	AuthMethod string // password, publickey, mfa
}

// CanAuthenticate checks if a user can authenticate
func (pe *PolicyEngine) CanAuthenticate(ctx context.Context, req AuthRequest) (bool, error) {
	user, err := pe.userRepo.GetByUsername(ctx, req.Username)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	// Check user status
	if user.Status != "active" {
		return false, fmt.Errorf("user is disabled")
	}

	// Check expiration
	if user.ExpirationDate.Valid && user.ExpirationDate.String != "" {
		expiry, err := time.Parse(time.RFC3339, user.ExpirationDate.String)
		if err == nil && time.Now().After(expiry) {
			return false, fmt.Errorf("user has expired")
		}
	}

	// Check protocol allowance
	if len(user.AllowedProtocols) > 0 {
		var allowed []string
		json.Unmarshal(user.AllowedProtocols, &allowed)
		if !contains(allowed, req.Protocol) {
			return false, fmt.Errorf("protocol %s not allowed for user", req.Protocol)
		}
	}

	// Check denied protocols
	if len(user.DeniedProtocols) > 0 {
		var denied []string
		json.Unmarshal(user.DeniedProtocols, &denied)
		if contains(denied, req.Protocol) {
			return false, fmt.Errorf("protocol %s denied for user", req.Protocol)
		}
	}

	// Check IP filter
	if len(user.IPFilters) > 0 {
		var ipFilter IPFilter
		json.Unmarshal(user.IPFilters, &ipFilter)
		if !pe.isIPAllowed(req.ClientIP, ipFilter) {
			return false, fmt.Errorf("IP %s not allowed", req.ClientIP)
		}
	}

	return true, nil
}

// OperationRequest contains file operation request information
type OperationRequest struct {
	UserID     int64
	Username   string
	Protocol   string
	ClientIP   net.IP
	Operation  OperationType
	FilePath   string
	FileSize   int64
}

// CanPerformOperation checks if a user can perform a file operation
func (pe *PolicyEngine) CanPerformOperation(ctx context.Context, req OperationRequest) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return false, fmt.Errorf("user not found: %w", err)
	}

	// Check user status
	if user.Status != "active" {
		return false, fmt.Errorf("user is disabled")
	}

	// Check permissions
	if len(user.Permissions) > 0 {
		var permissions []Permission
		json.Unmarshal(user.Permissions, &permissions)
		if !pe.hasPermission(permissions, req.Operation, req.FilePath) {
			return false, fmt.Errorf("permission denied for %s on %s", req.Operation, req.FilePath)
		}
	}

	// Check file filters
	if len(user.Filters) > 0 {
		var filters map[string]interface{}
		json.Unmarshal(user.Filters, &filters)
		if !pe.passesFileFilter(filters, req.FilePath, req.FileSize) {
			return false, fmt.Errorf("file filtered: %s", req.FilePath)
		}
	}

	// Check quota for uploads
	if req.Operation == OpUpload {
		if len(user.Quotas) > 0 {
			var quota QuotaConfig
			json.Unmarshal(user.Quotas, &quota)
			if quota.MaxSize > 0 && quota.CurrentSize+req.FileSize > quota.MaxSize {
				return false, fmt.Errorf("quota exceeded")
			}
		}
	}

	return true, nil
}

// CheckQuota checks if an upload would exceed quota
func (pe *PolicyEngine) CheckQuota(ctx context.Context, userID int64, size int64) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.Quotas) == 0 {
		return true, nil // No quota configured
	}

	var quota QuotaConfig
	json.Unmarshal(user.Quotas, &quota)

	if quota.MaxSize > 0 && quota.CurrentSize+size > quota.MaxSize {
		return false, fmt.Errorf("storage quota exceeded: current=%d, adding=%d, max=%d",
			quota.CurrentSize, size, quota.MaxSize)
	}

	if quota.MaxFiles > 0 && quota.CurrentFiles+1 > quota.MaxFiles {
		return false, fmt.Errorf("file count quota exceeded")
	}

	return true, nil
}

// GetBandwidthLimit returns the bandwidth limit for a user
func (pe *PolicyEngine) GetBandwidthLimit(ctx context.Context, userID int64, direction string) (int64, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return 0, err
	}

	if len(user.BandwidthLimits) == 0 {
		return 0, nil // No limit
	}

	var limit BandwidthLimit
	json.Unmarshal(user.BandwidthLimits, &limit)

	if direction == "upload" {
		return limit.UploadBytesPerSec, nil
	}
	return limit.DownloadBytesPerSec, nil
}

// IsIPAllowed checks if an IP is allowed for a user
func (pe *PolicyEngine) IsIPAllowed(ctx context.Context, userID int64, ip net.IP, protocol string) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	if len(user.IPFilters) == 0 {
		return true, nil // No IP filter configured
	}

	var ipFilter IPFilter
	json.Unmarshal(user.IPFilters, &ipFilter)

	return pe.isIPAllowed(ip, ipFilter), nil
}

// IsProtocolAllowed checks if a protocol is allowed for a user
func (pe *PolicyEngine) IsProtocolAllowed(ctx context.Context, userID int64, protocol string) (bool, error) {
	user, err := pe.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false, err
	}

	// Check allowed protocols
	if len(user.AllowedProtocols) > 0 {
		var allowed []string
		json.Unmarshal(user.AllowedProtocols, &allowed)
		if !contains(allowed, protocol) {
			return false, nil
		}
	}

	// Check denied protocols
	if len(user.DeniedProtocols) > 0 {
		var denied []string
		json.Unmarshal(user.DeniedProtocols, &denied)
		if contains(denied, protocol) {
			return false, nil
		}
	}

	return true, nil
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) isIPAllowed(ip net.IP, filter IPFilter) bool {
	// Check deny list first
	for _, deniedCIDR := range filter.DenyList {
		_, cidr, err := net.ParseCIDR(deniedCIDR)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return false
		}
	}

	// If allow list is empty, allow by default
	if len(filter.AllowList) == 0 {
		return true
	}

	// Check allow list
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

func (pe *PolicyEngine) hasPermission(permissions []Permission, op OperationType, path string) bool {
	// Find the most specific permission for the path
	var matchedPerm *Permission

	for i := range permissions {
		p := &permissions[i]
		if pathMatches(p.Path, path) {
			if matchedPerm == nil || len(p.Path) > len(matchedPerm.Path) {
				matchedPerm = p
			}
		}
	}

	if matchedPerm == nil {
		return false // Default deny if no permission matches
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

func pathMatches(pattern, path string) bool {
	if pattern == "/" || pattern == "" {
		return true
	}
	return strings.HasPrefix(path, pattern)
}

func (pe *PolicyEngine) passesFileFilter(filters map[string]interface{}, path string, size int64) bool {
	// Check allowed patterns
	if allowedPatterns, ok := filters["allowed_patterns"].([]interface{}); ok {
		matched := false
		for _, p := range allowedPatterns {
			if pattern, ok := p.(string); ok {
				if matchPattern(pattern, path) {
					matched = true
					break
				}
			}
		}
		if !matched && len(allowedPatterns) > 0 {
			return false
		}
	}

	// Check denied patterns
	if deniedPatterns, ok := filters["denied_patterns"].([]interface{}); ok {
		for _, p := range deniedPatterns {
			if pattern, ok := p.(string); ok {
				if matchPattern(pattern, path) {
					return false
				}
			}
		}
	}

	// Check max file size
	if maxSize, ok := filters["max_file_size"].(float64); ok {
		if size > int64(maxSize) {
			return false
		}
	}

	return true
}

func matchPattern(pattern, path string) bool {
	// Simple glob-like pattern matching
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/")
	}
	if strings.HasPrefix(pattern, "*.") {
		ext := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(path, ext)
	}
	return path == pattern
}
