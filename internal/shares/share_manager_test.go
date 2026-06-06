package shares

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type fakeShareRepo struct {
	nextID          int64
	byID            map[int64]*repository.Share
	byToken         map[string]*repository.Share
	createInput     *repository.Share
	downloadIncrIDs []int64
	uploadIncrIDs   []int64
}

func newFakeShareRepo() *fakeShareRepo {
	return &fakeShareRepo{
		nextID:  1,
		byID:    make(map[int64]*repository.Share),
		byToken: make(map[string]*repository.Share),
	}
}

func (r *fakeShareRepo) Create(_ context.Context, share *repository.Share) (*repository.Share, error) {
	r.createInput = cloneShare(share)
	created := cloneShare(share)
	created.ID = r.nextID
	r.nextID++
	now := time.Now().UTC()
	created.CreatedAt = now
	created.UpdatedAt = now
	r.byID[created.ID] = created
	r.byToken[created.Token] = created
	return cloneShare(created), nil
}

func (r *fakeShareRepo) GetByID(_ context.Context, id int64) (*repository.Share, error) {
	share, ok := r.byID[id]
	if !ok {
		return nil, errors.New("share not found")
	}
	return cloneShare(share), nil
}

func (r *fakeShareRepo) GetByToken(_ context.Context, token string) (*repository.Share, error) {
	share, ok := r.byToken[token]
	if !ok {
		return nil, errors.New("share not found")
	}
	return cloneShare(share), nil
}

func (r *fakeShareRepo) ListByUserID(_ context.Context, userID int64) ([]*repository.Share, error) {
	var shares []*repository.Share
	for _, share := range r.byID {
		if share.UserID == userID {
			shares = append(shares, cloneShare(share))
		}
	}
	return shares, nil
}

func (r *fakeShareRepo) Revoke(_ context.Context, id int64) error {
	share, ok := r.byID[id]
	if !ok {
		return errors.New("share not found")
	}
	share.IsActive = false
	return nil
}

func (r *fakeShareRepo) IncrementDownloadCount(_ context.Context, id int64) error {
	share, ok := r.byID[id]
	if !ok {
		return errors.New("share not found")
	}
	share.DownloadCount++
	r.downloadIncrIDs = append(r.downloadIncrIDs, id)
	return nil
}

func (r *fakeShareRepo) IncrementUploadCount(_ context.Context, id int64) error {
	share, ok := r.byID[id]
	if !ok {
		return errors.New("share not found")
	}
	share.UploadCount++
	r.uploadIncrIDs = append(r.uploadIncrIDs, id)
	return nil
}

func (r *fakeShareRepo) CountActive(_ context.Context) (int64, error) {
	var count int64
	for _, share := range r.byID {
		if share.IsActive {
			count++
		}
	}
	return count, nil
}

func (r *fakeShareRepo) ListAll(_ context.Context) ([]*repository.Share, error) {
	var shares []*repository.Share
	for _, share := range r.byID {
		shares = append(shares, cloneShare(share))
	}
	return shares, nil
}

type fakeUserRepo struct {
	users map[int64]*repository.User
}

func (r *fakeUserRepo) GetByUsername(_ context.Context, username string) (*repository.User, error) {
	for _, user := range r.users {
		if user.Username == username {
			return cloneUser(user), nil
		}
	}
	return nil, errors.New("user not found")
}

func (r *fakeUserRepo) GetByID(_ context.Context, id int64) (*repository.User, error) {
	user, ok := r.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return cloneUser(user), nil
}

func (r *fakeUserRepo) Create(_ context.Context, user *repository.User) (*repository.User, error) {
	return cloneUser(user), nil
}

func (r *fakeUserRepo) Update(context.Context, *repository.User) error { return nil }
func (r *fakeUserRepo) Delete(context.Context, int64) error            { return nil }
func (r *fakeUserRepo) List(context.Context, string, string, int, int) ([]*repository.User, error) {
	return nil, nil
}
func (r *fakeUserRepo) Count(context.Context) (int64, error)              { return int64(len(r.users)), nil }
func (r *fakeUserRepo) UpdateStatus(context.Context, int64, string) error { return nil }
func (r *fakeUserRepo) GetPublicKeys(context.Context, int64) ([]*repository.PublicKey, error) {
	return nil, nil
}
func (r *fakeUserRepo) AddPublicKey(context.Context, int64, string, string) (*repository.PublicKey, error) {
	return nil, nil
}
func (r *fakeUserRepo) DeletePublicKey(context.Context, int64, int64) error { return nil }
func (r *fakeUserRepo) UpdateLastLogin(context.Context, int64) error        { return nil }

type fakeAuditRepo struct {
	logs []*repository.AuditLog
}

func (r *fakeAuditRepo) CreateAuditLog(_ context.Context, log *repository.AuditLog) (*repository.AuditLog, error) {
	copied := *log
	r.logs = append(r.logs, &copied)
	return &copied, nil
}

func (r *fakeAuditRepo) ListAuditLogs(context.Context, string, string, string, string, string, int, int) ([]*repository.AuditLog, error) {
	return nil, nil
}
func (r *fakeAuditRepo) ListAuditLogsFiltered(context.Context, *repository.AuditFilter, int, int) ([]*repository.AuditLog, error) {
	return nil, nil
}
func (r *fakeAuditRepo) CountAuditLogs(context.Context) (int64, error) {
	return int64(len(r.logs)), nil
}
func (r *fakeAuditRepo) CreateTransferLog(context.Context, *repository.TransferLog) (*repository.TransferLog, error) {
	return nil, nil
}
func (r *fakeAuditRepo) ListTransferLogs(context.Context, string, string, string, string, int, int) ([]*repository.TransferLog, error) {
	return nil, nil
}
func (r *fakeAuditRepo) CreateCommandLog(context.Context, string, string, string, string, string, string, string) error {
	return nil
}
func (r *fakeAuditRepo) CreateHTTPLog(context.Context, string, string, int, string, string, string, int, int, int, string, string) error {
	return nil
}
func (r *fakeAuditRepo) AddBlockedIP(context.Context, string, string, string, time.Time) (*repository.BlockedIP, error) {
	return nil, nil
}
func (r *fakeAuditRepo) GetBlockedIP(context.Context, string) (*repository.BlockedIP, error) {
	return nil, nil
}
func (r *fakeAuditRepo) UnblockIP(context.Context, string) error { return nil }
func (r *fakeAuditRepo) ListActiveBlocks(context.Context, int, int) ([]*repository.BlockedIP, error) {
	return nil, nil
}
func (r *fakeAuditRepo) CleanExpiredBlocks(context.Context) error { return nil }

func TestCreateSharePersistsSecurityControls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	shareRepo := newFakeShareRepo()
	userRepo := &fakeUserRepo{
		users: map[int64]*repository.User{
			7: {ID: 7, Username: "alice", Status: "active"},
		},
	}
	auditRepo := &fakeAuditRepo{}
	manager := NewManagerWithDependencies(shareRepo, userRepo, auditRepo, nil, zap.NewNop())

	expiresAt := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	info, err := manager.CreateShare(ctx, ShareRequest{
		UserID:         7,
		Path:           "/docs/report.pdf",
		ShareType:      ShareTypeDownload,
		Password:       "secret-123",
		ExpiresAt:      expiresAt,
		MaxDownloads:   3,
		IPRestrictions: []string{"10.0.0.1", "10.0.0.2"},
	})
	if err != nil {
		t.Fatalf("CreateShare returned error: %v", err)
	}

	if info.Username != "alice" {
		t.Fatalf("expected username alice, got %q", info.Username)
	}
	if info.Token == "" {
		t.Fatal("expected generated token")
	}
	if shareRepo.createInput == nil {
		t.Fatal("expected repository create input to be captured")
	}
	if shareRepo.createInput.PasswordHash.String == "" || !shareRepo.createInput.PasswordHash.Valid {
		t.Fatal("expected password hash to be persisted")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(shareRepo.createInput.PasswordHash.String), []byte("secret-123")); err != nil {
		t.Fatalf("expected stored password hash to match original password: %v", err)
	}
	if got := shareRepo.createInput.IPRestrictions.String; got != "10.0.0.1,10.0.0.2" {
		t.Fatalf("expected persisted IP restrictions, got %q", got)
	}
	if !shareRepo.createInput.ExpiresAt.Valid || !shareRepo.createInput.ExpiresAt.Time.Equal(expiresAt) {
		t.Fatalf("expected expires_at %v, got %+v", expiresAt, shareRepo.createInput.ExpiresAt)
	}
	if len(auditRepo.logs) != 1 || auditRepo.logs[0].EventType != "share.create" || auditRepo.logs[0].Result != "success" {
		t.Fatalf("expected successful share.create audit log, got %+v", auditRepo.logs)
	}
}

func TestAccessShareRejectsInvalidPasswordAndAllowedIPMismatch(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("secret-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword returned error: %v", err)
	}

	shareRepo := newFakeShareRepo()
	shareRepo.byID[1] = &repository.Share{
		ID:             1,
		Token:          "share-token",
		UserID:         7,
		Username:       "alice",
		ShareType:      string(ShareTypeDownload),
		Path:           "/docs/report.pdf",
		PasswordHash:   sql.NullString{String: string(passwordHash), Valid: true},
		IPRestrictions: sql.NullString{String: "10.0.0.1,10.0.0.2", Valid: true},
		IsActive:       true,
	}
	shareRepo.byToken["share-token"] = shareRepo.byID[1]

	auditRepo := &fakeAuditRepo{}
	manager := NewManagerWithDependencies(shareRepo, &fakeUserRepo{}, auditRepo, nil, zap.NewNop())

	if _, err := manager.AccessShare(ctx, "share-token", "wrong-password", "10.0.0.1"); err == nil || !strings.Contains(err.Error(), "invalid share password") {
		t.Fatalf("expected invalid password error, got %v", err)
	}
	if len(shareRepo.downloadIncrIDs) != 0 {
		t.Fatalf("expected no download increments on invalid password, got %+v", shareRepo.downloadIncrIDs)
	}
	if len(auditRepo.logs) != 1 || auditRepo.logs[0].Result != "failed" || !strings.Contains(auditRepo.logs[0].ErrorMessage, "invalid password") {
		t.Fatalf("expected failed audit log for invalid password, got %+v", auditRepo.logs)
	}

	if _, err := manager.AccessShare(ctx, "share-token", "secret-123", "10.0.0.99"); err == nil || !strings.Contains(err.Error(), "client ip is not allowed") {
		t.Fatalf("expected client IP rejection, got %v", err)
	}
	if len(shareRepo.downloadIncrIDs) != 0 {
		t.Fatalf("expected no download increments on IP rejection, got %+v", shareRepo.downloadIncrIDs)
	}
	if len(auditRepo.logs) != 2 || auditRepo.logs[1].Result != "failed" || !strings.Contains(auditRepo.logs[1].ErrorMessage, "client ip not allowed") {
		t.Fatalf("expected failed audit log for IP rejection, got %+v", auditRepo.logs)
	}
}

func TestAccessShareDoesNotIncrementDownloadCountAndAuditsSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	shareRepo := newFakeShareRepo()
	shareRepo.byID[1] = &repository.Share{
		ID:            1,
		Token:         "download-token",
		UserID:        7,
		Username:      "alice",
		ShareType:     string(ShareTypeDownload),
		Path:          "/docs/report.pdf",
		MaxDownloads:  sql.NullInt64{Int64: 2, Valid: true},
		DownloadCount: 1,
		IsActive:      true,
	}
	shareRepo.byToken["download-token"] = shareRepo.byID[1]

	auditRepo := &fakeAuditRepo{}
	manager := NewManagerWithDependencies(shareRepo, &fakeUserRepo{}, auditRepo, nil, zap.NewNop())

	info, err := manager.AccessShare(ctx, "download-token", "", "")
	if err != nil {
		t.Fatalf("AccessShare returned error: %v", err)
	}

	if len(shareRepo.downloadIncrIDs) != 0 {
		t.Fatalf("expected access to avoid download increments, got %+v", shareRepo.downloadIncrIDs)
	}
	if info.DownloadCount != 1 {
		t.Fatalf("expected unchanged download count 1, got %d", info.DownloadCount)
	}
	if len(auditRepo.logs) != 1 || auditRepo.logs[0].EventType != "share.access" || auditRepo.logs[0].Result != "success" {
		t.Fatalf("expected successful share.access audit log, got %+v", auditRepo.logs)
	}
}

func cloneShare(share *repository.Share) *repository.Share {
	if share == nil {
		return nil
	}
	copied := *share
	return &copied
}

func cloneUser(user *repository.User) *repository.User {
	if user == nil {
		return nil
	}
	copied := *user
	return &copied
}
