package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
)

type fakeUserRepo struct {
	byID       map[int64]*repository.User
	byUsername map[string]*repository.User
}

func (r *fakeUserRepo) GetByUsername(_ context.Context, username string) (*repository.User, error) {
	if user, ok := r.byUsername[username]; ok {
		copied := *user
		return &copied, nil
	}
	return nil, sql.ErrNoRows
}

func (r *fakeUserRepo) GetByID(_ context.Context, id int64) (*repository.User, error) {
	if user, ok := r.byID[id]; ok {
		copied := *user
		return &copied, nil
	}
	return nil, sql.ErrNoRows
}

func (r *fakeUserRepo) Create(context.Context, *repository.User) (*repository.User, error) {
	return nil, nil
}
func (r *fakeUserRepo) Update(context.Context, *repository.User) error { return nil }
func (r *fakeUserRepo) Delete(context.Context, int64) error            { return nil }
func (r *fakeUserRepo) List(context.Context, string, string, int, int) ([]*repository.User, error) {
	return nil, nil
}
func (r *fakeUserRepo) Count(context.Context) (int64, error)              { return 0, nil }
func (r *fakeUserRepo) UpdateStatus(context.Context, int64, string) error { return nil }
func (r *fakeUserRepo) GetPublicKeys(context.Context, int64) ([]*repository.PublicKey, error) {
	return nil, nil
}
func (r *fakeUserRepo) AddPublicKey(context.Context, int64, string, string) (*repository.PublicKey, error) {
	return nil, nil
}
func (r *fakeUserRepo) DeletePublicKey(context.Context, int64, int64) error { return nil }
func (r *fakeUserRepo) UpdateLastLogin(context.Context, int64) error        { return nil }

type fakeGroupRepo struct {
	byUserID map[int64][]*Group
	byID     map[int64]*Group
}

func (r *fakeGroupRepo) GetByUserID(_ context.Context, userID int64) ([]*Group, error) {
	if groups, ok := r.byUserID[userID]; ok {
		return groups, nil
	}
	return nil, nil
}

func (r *fakeGroupRepo) GetByID(_ context.Context, id int64) (*Group, error) {
	if group, ok := r.byID[id]; ok {
		return group, nil
	}
	return nil, sql.ErrNoRows
}

type fakeEventNotifier struct {
	events []struct {
		eventType string
		payload   map[string]interface{}
	}
}

func (f *fakeEventNotifier) Notify(_ context.Context, eventType string, payload map[string]interface{}) {
	f.events = append(f.events, struct {
		eventType string
		payload   map[string]interface{}
	}{eventType: eventType, payload: payload})
}

func TestCanAuthenticateRejectsExpiredDeniedProtocolAndForeignIP(t *testing.T) {
	t.Parallel()

	expiredAt := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	user := &repository.User{
		ID:               7,
		Username:         "alice",
		Status:           "active",
		AllowedProtocols: mustJSON(t, []string{"sftp", "webdav"}),
		DeniedProtocols:  mustJSON(t, []string{"ftp"}),
		IPFilters: mustJSON(t, IPFilter{
			AllowList: []string{"10.0.0.0/24"},
			DenyList:  []string{"10.0.0.128/25"},
		}),
		ExpirationDate: sql.NullString{String: expiredAt, Valid: true},
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byUsername: map[string]*repository.User{"alice": user},
		byID:       map[int64]*repository.User{7: user},
	})

	allowed, err := engine.CanAuthenticate(context.Background(), AuthRequest{
		Username: "alice",
		Protocol: "sftp",
		ClientIP: mustIP(t, "10.0.0.10"),
	})
	if err == nil || !strings.Contains(err.Error(), "expired") || allowed {
		t.Fatalf("expected expired rejection, allowed=%v err=%v", allowed, err)
	}

	user.ExpirationDate = sql.NullString{}
	allowed, err = engine.CanAuthenticate(context.Background(), AuthRequest{
		Username: "alice",
		Protocol: "ftp",
		ClientIP: mustIP(t, "10.0.0.10"),
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed") || allowed {
		t.Fatalf("expected allowed protocol rejection before deny-list pass-through, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanAuthenticate(context.Background(), AuthRequest{
		Username: "alice",
		Protocol: "webdav",
		ClientIP: mustIP(t, "10.0.0.200"),
	})
	if err == nil || !strings.Contains(err.Error(), "not allowed") || allowed {
		t.Fatalf("expected IP rejection, allowed=%v err=%v", allowed, err)
	}
}

func TestCanPerformOperationUsesMostSpecificPermissionAndQuota(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       42,
		Username: "alice",
		Status:   "active",
		Permissions: mustJSON(t, []Permission{
			{Path: "/", Upload: false, Download: true},
			{Path: "/uploads", Upload: true},
		}),
		Quotas: mustJSON(t, QuotaConfig{
			MaxSize:     100,
			CurrentSize: 90,
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{42: user},
	})

	allowed, err := engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    42,
		Operation: OpUpload,
		FilePath:  "/uploads/report.txt",
		FileSize:  5,
	})
	if err != nil || !allowed {
		t.Fatalf("expected most specific /uploads permission to allow upload, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    42,
		Operation: OpUpload,
		FilePath:  "/private/report.txt",
		FileSize:  5,
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") || allowed {
		t.Fatalf("expected root permission to deny upload outside /uploads, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    42,
		Operation: OpUpload,
		FilePath:  "/uploads/big.bin",
		FileSize:  15,
	})
	if err == nil || !strings.Contains(err.Error(), "quota exceeded") || allowed {
		t.Fatalf("expected quota rejection, allowed=%v err=%v", allowed, err)
	}
}

func TestCanPerformOperationAcceptsLegacyFullPermissionsString(t *testing.T) {
	repo := &fakeUserRepo{
		byID: map[int64]*repository.User{
			1: {
				ID:          1,
				Username:    "legacy",
				Status:      "active",
				Permissions: json.RawMessage("full"),
			},
		},
	}

	engine := NewPolicyEngine(repo)
	allowed, err := engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    1,
		Username:  "legacy",
		Protocol:  "http",
		ClientIP:  net.ParseIP("127.0.0.1"),
		Operation: OpList,
		FilePath:  "/",
	})
	if err != nil {
		t.Fatalf("CanPerformOperation returned error: %v", err)
	}
	if !allowed {
		t.Fatalf("expected legacy full permission to allow root list")
	}
}

func TestCheckQuotaCountsSizeAndFileLimit(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       100,
		Username: "bob",
		Status:   "active",
		Quotas: mustJSON(t, QuotaConfig{
			MaxSize:      50,
			CurrentSize:  45,
			MaxFiles:     3,
			CurrentFiles: 3,
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{100: user},
	})

	allowed, err := engine.CheckQuota(context.Background(), 100, 10)
	if err == nil || !strings.Contains(err.Error(), "storage quota exceeded") || allowed {
		t.Fatalf("expected storage quota rejection, allowed=%v err=%v", allowed, err)
	}

	user.Quotas = mustJSON(t, QuotaConfig{
		MaxSize:      100,
		CurrentSize:  45,
		MaxFiles:     3,
		CurrentFiles: 3,
	})
	allowed, err = engine.CheckQuota(context.Background(), 100, 1)
	if err == nil || !strings.Contains(err.Error(), "file count quota exceeded") || allowed {
		t.Fatalf("expected file count quota rejection, allowed=%v err=%v", allowed, err)
	}
}

func TestPerProtocolPermissions(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       200,
		Username: "proto_user",
		Status:   "active",
		Permissions: mustJSON(t, []Permission{
			{Path: "/", Upload: false, Download: true},
		}),
		ProtocolPermissions: mustJSON(t, ProtocolPermissions{
			"sftp": {{Path: "/", Upload: true, Download: true}},
			"ftp":  {{Path: "/", Upload: false, Download: false}},
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{200: user},
	})

	allowed, err := engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    200,
		Operation: OpUpload,
		FilePath:  "/data/file.txt",
		Protocol:  "sftp",
	})
	if err != nil || !allowed {
		t.Fatalf("expected sftp protocol permission to allow upload, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    200,
		Operation: OpUpload,
		FilePath:  "/data/file.txt",
		Protocol:  "webdav",
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") || allowed {
		t.Fatalf("expected default permission to deny upload for webdav, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    200,
		Operation: OpDownload,
		FilePath:  "/data/file.txt",
		Protocol:  "ftp",
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") || allowed {
		t.Fatalf("expected ftp protocol permission to deny download, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    200,
		Operation: OpDownload,
		FilePath:  "/data/file.txt",
		Protocol:  "webdav",
	})
	if err != nil || !allowed {
		t.Fatalf("expected default permission to allow download for webdav, allowed=%v err=%v", allowed, err)
	}
}

func TestFileExtensionFilters(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       300,
		Username: "filter_user",
		Status:   "active",
		Permissions: mustJSON(t, []Permission{
			{Path: "/", Upload: true, Download: true},
		}),
		Filters: mustJSON(t, FileFilter{
			AllowedExtensions:   []string{".txt", ".pdf"},
			DeniedExtensions:    []string{".exe", ".bat"},
			MinFileSize:         10,
			MaxFileSize:         10000,
			DeniedUploadNames:   []string{"*.tmp"},
			DeniedDownloadNames: []string{"*.secret"},
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{300: user},
	})

	allowed, err := engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/report.txt",
		FileSize:  100,
	})
	if err != nil || !allowed {
		t.Fatalf("expected .txt upload to be allowed, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/virus.exe",
		FileSize:  100,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected .exe upload to be denied by denied_extensions, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/image.png",
		FileSize:  100,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected .png upload to be denied by allowed_extensions, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/tiny.txt",
		FileSize:  5,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected small file to be denied by min_file_size, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/huge.txt",
		FileSize:  20000,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected large file to be denied by max_file_size, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpUpload,
		FilePath:  "/docs/cache.tmp",
		FileSize:  100,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected .tmp upload to be denied by denied_upload_names, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    300,
		Operation: OpDownload,
		FilePath:  "/docs/keys.secret",
		FileSize:  100,
	})
	if err == nil || !strings.Contains(err.Error(), "file filtered") || allowed {
		t.Fatalf("expected .secret download to be denied by denied_download_names, allowed=%v err=%v", allowed, err)
	}
}

func TestHiddenPatterns(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       310,
		Username: "hidden_user",
		Status:   "active",
		Filters: mustJSON(t, FileFilter{
			HiddenPatterns: []string{".*", "*.bak"},
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{310: user},
	})

	hidden, err := engine.IsFileHidden(context.Background(), 310, "/docs/.env")
	if err != nil || !hidden {
		t.Fatalf("expected .env to be hidden, hidden=%v err=%v", hidden, err)
	}

	hidden, err = engine.IsFileHidden(context.Background(), 310, "/docs/backup.bak")
	if err != nil || !hidden {
		t.Fatalf("expected .bak to be hidden, hidden=%v err=%v", hidden, err)
	}

	hidden, err = engine.IsFileHidden(context.Background(), 310, "/docs/report.txt")
	if err != nil || hidden {
		t.Fatalf("expected report.txt to NOT be hidden, hidden=%v err=%v", hidden, err)
	}
}

func TestTransferLimitReset(t *testing.T) {
	t.Parallel()

	yesterday := time.Now().Add(-25 * time.Hour)

	limit := TransferLimit{
		MaxUploadBytes:   1000,
		MaxDownloadBytes: 2000,
		CurrentUpload:    500,
		CurrentDownload:  1000,
		ResetPeriod:      "daily",
		LastReset:        yesterday,
	}

	reset := maybeResetTransferLimit(limit)
	if reset.CurrentUpload != 0 || reset.CurrentDownload != 0 {
		t.Fatalf("expected daily reset to zero counters, got upload=%d download=%d", reset.CurrentUpload, reset.CurrentDownload)
	}

	limit.ResetPeriod = "none"
	reset = maybeResetTransferLimit(limit)
	if reset.CurrentUpload != 500 || reset.CurrentDownload != 1000 {
		t.Fatalf("expected none period to keep counters, got upload=%d download=%d", reset.CurrentUpload, reset.CurrentDownload)
	}

	limit.ResetPeriod = "monthly"
	limit.LastReset = time.Now().Add(-32 * 24 * time.Hour)
	reset = maybeResetTransferLimit(limit)
	if reset.CurrentUpload != 0 || reset.CurrentDownload != 0 {
		t.Fatalf("expected monthly reset to zero counters, got upload=%d download=%d", reset.CurrentUpload, reset.CurrentDownload)
	}

	todayLimit := TransferLimit{
		MaxUploadBytes: 1000,
		CurrentUpload:  500,
		ResetPeriod:    "daily",
		LastReset:      time.Now().Truncate(time.Hour),
	}
	reset = maybeResetTransferLimit(todayLimit)
	if reset.CurrentUpload != 500 {
		t.Fatalf("expected same-day to keep counters, got upload=%d", reset.CurrentUpload)
	}
}

func TestTransferLimitCheckInOperation(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       400,
		Username: "transfer_user",
		Status:   "active",
		Permissions: mustJSON(t, []Permission{
			{Path: "/", Upload: true, Download: true},
		}),
		TransferLimits: mustJSON(t, TransferLimit{
			MaxUploadBytes:   100,
			CurrentUpload:    90,
			MaxDownloadBytes: 200,
			CurrentDownload:  50,
			ResetPeriod:      "none",
			LastReset:        time.Now(),
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{
		byID: map[int64]*repository.User{400: user},
	})

	allowed, err := engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    400,
		Operation: OpUpload,
		FilePath:  "/data/file.bin",
		FileSize:  20,
	})
	if err == nil || !strings.Contains(err.Error(), "transfer limit exceeded") || allowed {
		t.Fatalf("expected upload transfer limit exceeded, allowed=%v err=%v", allowed, err)
	}

	allowed, err = engine.CanPerformOperation(context.Background(), OperationRequest{
		UserID:    400,
		Operation: OpDownload,
		FilePath:  "/data/file.bin",
		FileSize:  50,
	})
	if err != nil || !allowed {
		t.Fatalf("expected download within limit to be allowed, allowed=%v err=%v", allowed, err)
	}
}

func TestQuotaAlerting(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       500,
		Username: "alert_user",
		Status:   "active",
		Quotas: mustJSON(t, QuotaConfig{
			MaxSize:     1000,
			CurrentSize: 850,
		}),
	}

	notifier := &fakeEventNotifier{}
	engine := NewPolicyEngine(
		&fakeUserRepo{byID: map[int64]*repository.User{500: user}},
		WithEventNotifier(notifier),
		WithQuotaAlert(QuotaAlertConfig{Threshold: 0.9}),
	)

	allowed, err := engine.CheckQuota(context.Background(), 500, 100)
	if err != nil || !allowed {
		t.Fatalf("expected quota to be allowed, allowed=%v err=%v", allowed, err)
	}

	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 quota warning event, got %d", len(notifier.events))
	}
	if notifier.events[0].eventType != "quota_warning" {
		t.Fatalf("expected event type quota_warning, got %s", notifier.events[0].eventType)
	}
	if notifier.events[0].payload["username"] != "alert_user" {
		t.Fatalf("expected username alert_user, got %v", notifier.events[0].payload["username"])
	}
}

func TestQuotaAlertingOnExceeded(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       501,
		Username: "exceeded_user",
		Status:   "active",
		Quotas: mustJSON(t, QuotaConfig{
			MaxSize:     100,
			CurrentSize: 90,
		}),
	}

	notifier := &fakeEventNotifier{}
	engine := NewPolicyEngine(
		&fakeUserRepo{byID: map[int64]*repository.User{501: user}},
		WithEventNotifier(notifier),
		WithQuotaAlert(QuotaAlertConfig{Threshold: 0.9}),
	)

	allowed, err := engine.CheckQuota(context.Background(), 501, 20)
	if err == nil || allowed {
		t.Fatalf("expected quota exceeded, allowed=%v err=%v", allowed, err)
	}

	if len(notifier.events) != 1 {
		t.Fatalf("expected 1 quota warning event on exceeded, got %d", len(notifier.events))
	}
}

func TestQuotaScanner(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("hello world"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("short"), 0644)
	os.MkdirAll(filepath.Join(tmpDir, "sub"), 0755)
	os.WriteFile(filepath.Join(tmpDir, "sub", "file3.txt"), []byte("nested content here"), 0644)

	user := &repository.User{
		ID:       600,
		Username: "scan_user",
		Status:   "active",
		HomeDir:  tmpDir,
		Quotas: mustJSON(t, QuotaConfig{
			MaxSize:      10000,
			CurrentSize:  999,
			MaxFiles:     100,
			CurrentFiles: 999,
		}),
	}

	scanner := NewQuotaScanner(&fakeUserRepo{
		byID: map[int64]*repository.User{600: user},
	})

	usedBytes, usedFiles, err := scanner.ScanUserQuota(context.Background(), "600")
	if err != nil {
		t.Fatalf("ScanUserQuota returned error: %v", err)
	}
	if usedFiles != 3 {
		t.Fatalf("expected 3 files, got %d", usedFiles)
	}
	if usedBytes <= 0 {
		t.Fatalf("expected positive usedBytes, got %d", usedBytes)
	}

	updated, err := scanner.CompareAndUpdateQuota(context.Background(), "600")
	if err != nil {
		t.Fatalf("CompareAndUpdateQuota returned error: %v", err)
	}
	if !updated {
		t.Fatalf("expected quota to be updated since stored values differ from actual")
	}
}

func TestMultiGroupPriority(t *testing.T) {
	t.Parallel()

	highGroup := &Group{
		ID:       1,
		Name:     "premium",
		Priority: 100,
		Settings: mustJSON(t, GroupSettings{
			Priority:        100,
			BandwidthLimits: BandwidthLimit{UploadBytesPerSec: 5000, DownloadBytesPerSec: 10000},
			Quota:           QuotaConfig{MaxSize: 1000000},
			Permissions: []Permission{
				{Path: "/premium", Upload: true, Download: true},
			},
			AllowedProtocols: []string{"sftp", "webdav"},
		}),
	}

	lowGroup := &Group{
		ID:       2,
		Name:     "basic",
		Priority: 10,
		Settings: mustJSON(t, GroupSettings{
			Priority:        10,
			BandwidthLimits: BandwidthLimit{UploadBytesPerSec: 1000, DownloadBytesPerSec: 2000},
			Quota:           QuotaConfig{MaxSize: 500000},
			Permissions: []Permission{
				{Path: "/basic", Upload: true, Download: true},
			},
			AllowedProtocols: []string{"sftp"},
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{})
	merged := engine.MergeGroupSettings([]*Group{lowGroup, highGroup})

	if merged.BandwidthLimits.UploadBytesPerSec != 5000 {
		t.Fatalf("expected high priority group bandwidth 5000, got %d", merged.BandwidthLimits.UploadBytesPerSec)
	}
	if merged.Quota.MaxSize != 1000000 {
		t.Fatalf("expected high priority group quota 1000000, got %d", merged.Quota.MaxSize)
	}

	if len(merged.Permissions) != 2 {
		t.Fatalf("expected 2 permissions (union), got %d", len(merged.Permissions))
	}

	protoSet := make(map[string]bool)
	for _, p := range merged.AllowedProtocols {
		protoSet[p] = true
	}
	if !protoSet["sftp"] || !protoSet["webdav"] {
		t.Fatalf("expected union of protocols {sftp, webdav}, got %v", merged.AllowedProtocols)
	}
}

func TestEffectiveBandwidthLimit(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       700,
		Username: "bw_user",
		Status:   "active",
		BandwidthLimits: mustJSON(t, ExtendedBandwidthLimit{
			BandwidthLimit: BandwidthLimit{UploadBytesPerSec: 5000, DownloadBytesPerSec: 10000},
			ProtocolLimits: map[string]BandwidthLimit{
				"sftp": {UploadBytesPerSec: 3000, DownloadBytesPerSec: 6000},
			},
			TimeBased: []TimeBasedBandwidthRule{
				{
					BandwidthLimit: BandwidthLimit{UploadBytesPerSec: 1000, DownloadBytesPerSec: 2000},
					StartHour:      9,
					EndHour:        17,
					Days:           []int{1, 2, 3, 4, 5},
				},
			},
		}),
	}

	group := &Group{
		ID:       10,
		Name:     "limited_group",
		Priority: 50,
		Settings: mustJSON(t, GroupSettings{
			Priority:        50,
			BandwidthLimits: BandwidthLimit{UploadBytesPerSec: 2000, DownloadBytesPerSec: 4000},
			ProtocolBandwidthLimits: map[string]BandwidthLimit{
				"ftp": {UploadBytesPerSec: 500, DownloadBytesPerSec: 1000},
			},
		}),
	}

	engine := NewPolicyEngine(
		&fakeUserRepo{byID: map[int64]*repository.User{700: user}},
		WithGroupRepo(&fakeGroupRepo{
			byUserID: map[int64][]*Group{700: {group}},
			byID:     map[int64]*Group{10: group},
		}),
	)

	result, err := engine.GetEffectiveBandwidthLimit(context.Background(), 700, "sftp")
	if err != nil {
		t.Fatalf("GetEffectiveBandwidthLimit returned error: %v", err)
	}

	if result.UploadBytesPerSec > 3000 {
		t.Fatalf("expected effective upload <= min(user_sftp=3000, group=2000), got %d", result.UploadBytesPerSec)
	}
	if result.DownloadBytesPerSec > 6000 {
		t.Fatalf("expected effective download <= min(user_sftp=6000, group=4000), got %d", result.DownloadBytesPerSec)
	}
}

func TestTimeBasedBandwidthRule(t *testing.T) {
	rule := TimeBasedBandwidthRule{
		BandwidthLimit: BandwidthLimit{UploadBytesPerSec: 1000},
		StartHour:      9,
		EndHour:        17,
		Days:           []int{1, 2, 3, 4, 5},
	}

	monday10am := time.Date(2025, 1, 6, 10, 0, 0, 0, time.UTC)
	if !isTimeBasedRuleActive(rule, monday10am) {
		t.Fatalf("expected rule to be active on Monday 10am")
	}

	monday8am := time.Date(2025, 1, 6, 8, 0, 0, 0, time.UTC)
	if isTimeBasedRuleActive(rule, monday8am) {
		t.Fatalf("expected rule to be inactive on Monday 8am (before start)")
	}

	sunday10am := time.Date(2025, 1, 5, 10, 0, 0, 0, time.UTC)
	if isTimeBasedRuleActive(rule, sunday10am) {
		t.Fatalf("expected rule to be inactive on Sunday (not in days)")
	}

	ruleNoDays := TimeBasedBandwidthRule{
		BandwidthLimit: BandwidthLimit{UploadBytesPerSec: 1000},
		StartHour:      22,
		EndHour:        6,
	}

	night11pm := time.Date(2025, 1, 6, 23, 0, 0, 0, time.UTC)
	if !isTimeBasedRuleActive(ruleNoDays, night11pm) {
		t.Fatalf("expected overnight rule to be active at 11pm")
	}

	morning3am := time.Date(2025, 1, 6, 3, 0, 0, 0, time.UTC)
	if !isTimeBasedRuleActive(ruleNoDays, morning3am) {
		t.Fatalf("expected overnight rule to be active at 3am")
	}

	noon := time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)
	if isTimeBasedRuleActive(ruleNoDays, noon) {
		t.Fatalf("expected overnight rule to be inactive at noon")
	}
}

func TestResetTransferLimitViaEngine(t *testing.T) {
	t.Parallel()

	user := &repository.User{
		ID:       800,
		Username: "reset_user",
		Status:   "active",
		TransferLimits: mustJSON(t, TransferLimit{
			MaxUploadBytes:   1000,
			CurrentUpload:    800,
			MaxDownloadBytes: 2000,
			CurrentDownload:  1500,
			ResetPeriod:      "daily",
			LastReset:        time.Now().Add(-25 * time.Hour),
		}),
	}

	repo := &fakeUserRepo{
		byID: map[int64]*repository.User{800: user},
	}
	engine := NewPolicyEngine(repo)

	err := engine.ResetTransferLimit(context.Background(), 800)
	if err != nil {
		t.Fatalf("ResetTransferLimit returned error: %v", err)
	}
}

func TestPassesFileFilterStruct(t *testing.T) {
	filter := &FileFilter{
		AllowedExtensions: []string{".txt", ".pdf"},
		DeniedExtensions:  []string{".exe"},
		MinFileSize:       100,
		MaxFileSize:       10000,
	}

	if !passesFileFilterStruct(filter, "/docs/report.txt", 500, OpUpload) {
		t.Fatalf("expected .txt file within size range to pass")
	}

	if passesFileFilterStruct(filter, "/docs/virus.exe", 500, OpUpload) {
		t.Fatalf("expected .exe file to be denied by denied_extensions")
	}

	if passesFileFilterStruct(filter, "/docs/image.png", 500, OpUpload) {
		t.Fatalf("expected .png file to be denied by allowed_extensions")
	}

	if passesFileFilterStruct(filter, "/docs/tiny.txt", 50, OpUpload) {
		t.Fatalf("expected file below min_file_size to be denied")
	}

	if passesFileFilterStruct(filter, "/docs/huge.txt", 20000, OpUpload) {
		t.Fatalf("expected file above max_file_size to be denied")
	}

	if !passesFileFilterStruct(filter, "/docs/report.txt", 500, OpDownload) {
		t.Fatalf("expected .txt download to pass allowed_extensions check")
	}
}

func TestPassesFileFilterMap(t *testing.T) {
	filters := map[string]interface{}{
		"allowed_patterns": []interface{}{"/docs/*"},
		"denied_patterns":  []interface{}{"*.bak"},
		"max_file_size":    float64(10000),
	}

	if !passesFileFilterMap(filters, "/docs/report.txt", 500) {
		t.Fatalf("expected file matching allowed_patterns to pass")
	}

	if passesFileFilterMap(filters, "/other/report.txt", 500) {
		t.Fatalf("expected file not matching allowed_patterns to be denied")
	}

	if passesFileFilterMap(filters, "/docs/backup.bak", 500) {
		t.Fatalf("expected file matching denied_patterns to be denied")
	}

	if passesFileFilterMap(filters, "/docs/big.txt", 20000) {
		t.Fatalf("expected file exceeding max_file_size to be denied")
	}
}

func TestMergeGroupSettingsEmpty(t *testing.T) {
	result := mergeGroupSettings(nil)
	if result.Priority != 0 {
		t.Fatalf("expected zero priority for nil groups, got %d", result.Priority)
	}

	result = mergeGroupSettings([]*Group{})
	if len(result.Permissions) != 0 {
		t.Fatalf("expected no permissions for empty groups, got %d", len(result.Permissions))
	}
}

func TestMergeGroupSettingsProtocolBandwidthLimits(t *testing.T) {
	group1 := &Group{
		ID:       1,
		Name:     "group1",
		Priority: 10,
		Settings: mustJSON(t, GroupSettings{
			Priority: 10,
			ProtocolBandwidthLimits: map[string]BandwidthLimit{
				"sftp": {UploadBytesPerSec: 1000, DownloadBytesPerSec: 2000},
			},
		}),
	}

	group2 := &Group{
		ID:       2,
		Name:     "group2",
		Priority: 5,
		Settings: mustJSON(t, GroupSettings{
			Priority: 5,
			ProtocolBandwidthLimits: map[string]BandwidthLimit{
				"ftp":  {UploadBytesPerSec: 500, DownloadBytesPerSec: 1000},
				"sftp": {UploadBytesPerSec: 3000, DownloadBytesPerSec: 6000},
			},
		}),
	}

	engine := NewPolicyEngine(&fakeUserRepo{})
	merged := engine.MergeGroupSettings([]*Group{group1, group2})

	sftpLimit, ok := merged.ProtocolBandwidthLimits["sftp"]
	if !ok {
		t.Fatalf("expected sftp protocol bandwidth limit to exist")
	}
	if sftpLimit.UploadBytesPerSec != 1000 {
		t.Fatalf("expected first group's sftp limit to win (higher priority), got %d", sftpLimit.UploadBytesPerSec)
	}

	ftpLimit, ok := merged.ProtocolBandwidthLimits["ftp"]
	if !ok {
		t.Fatalf("expected ftp protocol bandwidth limit to exist")
	}
	if ftpLimit.UploadBytesPerSec != 500 {
		t.Fatalf("expected ftp limit from second group, got %d", ftpLimit.UploadBytesPerSec)
	}
}

func TestNewPolicyEngineWithOptions(t *testing.T) {
	repo := &fakeUserRepo{}
	notifier := &fakeEventNotifier{}
	groupRepo := &fakeGroupRepo{}

	engine := NewPolicyEngine(repo,
		WithEventNotifier(notifier),
		WithGroupRepo(groupRepo),
		WithQuotaAlert(QuotaAlertConfig{Threshold: 0.85}),
	)

	if engine.eventNotifier == nil {
		t.Fatalf("expected eventNotifier to be set")
	}
	if engine.groupRepo == nil {
		t.Fatalf("expected groupRepo to be set")
	}
	if engine.quotaAlert.Threshold != 0.85 {
		t.Fatalf("expected quota alert threshold 0.85, got %f", engine.quotaAlert.Threshold)
	}
}

func TestNewPolicyEngineBackwardCompatible(t *testing.T) {
	repo := &fakeUserRepo{}
	engine := NewPolicyEngine(repo)

	if engine.userRepo == nil {
		t.Fatalf("expected userRepo to be set")
	}
	if engine.groupRepo != nil {
		t.Fatalf("expected groupRepo to be nil by default")
	}
	if engine.eventNotifier != nil {
		t.Fatalf("expected eventNotifier to be nil by default")
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	return data
}

func mustIP(t *testing.T, raw string) net.IP {
	t.Helper()

	ip := net.ParseIP(raw)
	if ip == nil {
		t.Fatalf("failed to parse IP %q", raw)
	}
	return ip
}
