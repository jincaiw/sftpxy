package webdav

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/testutil"
	"go.uber.org/zap"
)

func TestWebDAVAuthPathMappingAndPolicy(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}
	permissions, err := json.Marshal([]policy.Permission{
		{
			Path:       "/",
			List:       true,
			Download:   true,
			Upload:     true,
			CreateDirs: true,
		},
	})
	if err != nil {
		t.Fatalf("marshal permissions failed: %v", err)
	}

	user := &repository.User{
		ID:           1,
		Username:     "alice",
		Status:       "active",
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		HomeDir:      t.TempDir(),
		Permissions:  permissions,
	}
	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
	}
	auditRepo := &testutil.RecordingAuditRepo{}
	sessionRepo := &testutil.RecordingSessionRepo{}

	server := newTestServer(t, config.WebDAVConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		BasePath:      "/dav",
	}, userRepo, auditRepo, sessionRepo)

	baseURL := "http://" + server.listener.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}

	unauthReq, _ := http.NewRequest(http.MethodGet, baseURL+"/dav/readme.txt", nil)
	unauthResp, err := client.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauthenticated request failed: %v", err)
	}
	defer unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want %d", unauthResp.StatusCode, http.StatusUnauthorized)
	}

	badPathReq, _ := http.NewRequest(http.MethodGet, baseURL+"/dav-other/readme.txt", nil)
	badPathReq.SetBasicAuth("alice", "secret-pass")
	badPathResp, err := client.Do(badPathReq)
	if err != nil {
		t.Fatalf("out-of-base-path request failed: %v", err)
	}
	defer badPathResp.Body.Close()
	if badPathResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected status for path outside base path: %d", badPathResp.StatusCode)
	}

	mkcolReq, _ := http.NewRequest("MKCOL", baseURL+"/dav/docs", nil)
	mkcolReq.SetBasicAuth("alice", "secret-pass")
	mkcolResp, err := client.Do(mkcolReq)
	if err != nil {
		t.Fatalf("mkcol request failed: %v", err)
	}
	defer mkcolResp.Body.Close()
	if mkcolResp.StatusCode != http.StatusCreated && mkcolResp.StatusCode != http.StatusMethodNotAllowed {
		body, _ := io.ReadAll(mkcolResp.Body)
		t.Fatalf("mkcol status = %d, want 201/405, body=%s", mkcolResp.StatusCode, string(body))
	}

	putReq, _ := http.NewRequest(http.MethodPut, baseURL+"/dav/docs/readme.txt", bytes.NewBufferString("hello via webdav"))
	putReq.SetBasicAuth("alice", "secret-pass")
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("put request failed: %v", err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("put status = %d, want 201/204, body=%s", putResp.StatusCode, string(body))
	}

	getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/dav/docs/readme.txt", nil)
	getReq.SetBasicAuth("alice", "secret-pass")
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("get request failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("read get body failed: %v", err)
	}
	if string(body) != "hello via webdav" {
		t.Fatalf("get body = %q, want %q", string(body), "hello via webdav")
	}

	deleteReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/dav/docs/readme.txt", nil)
	deleteReq.SetBasicAuth("alice", "secret-pass")
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("delete request failed: %v", err)
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("delete status = %d, want %d, body=%s", deleteResp.StatusCode, http.StatusForbidden, strings.TrimSpace(string(body)))
	}

	if len(auditRepo.AuditLogs) == 0 {
		t.Fatalf("expected webdav audit logs to be recorded")
	}
	waitForInactiveSessions(t, sessionRepo, "webdav")
}

func TestStartRejectsUnsupportedClientCert(t *testing.T) {
	t.Parallel()

	server := NewServer(
		config.WebDAVConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    30084,
			ClientCert:    true,
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		policy.NewPolicyEngine(&testutil.StubUserRepo{}),
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("expected unsupported webdav client certificate auth to fail")
	}
}

func TestStartRejectsInvalidBasePath(t *testing.T) {
	t.Parallel()

	server := NewServer(
		config.WebDAVConfig{
			Enabled:       true,
			ListenAddress: "127.0.0.1",
			ListenPort:    30084,
			BasePath:      "dav",
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		policy.NewPolicyEngine(&testutil.StubUserRepo{}),
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("expected invalid webdav base path to fail")
	}
}

func TestWebDAVTLSPathSupportsAuthenticatedAccess(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}
	permissions, err := json.Marshal([]policy.Permission{
		{
			Path:       "/",
			List:       true,
			Download:   true,
			Upload:     true,
			CreateDirs: true,
		},
	})
	if err != nil {
		t.Fatalf("marshal permissions failed: %v", err)
	}

	user := &repository.User{
		ID:           2,
		Username:     "tls-user",
		Status:       "active",
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		HomeDir:      t.TempDir(),
		Permissions:  permissions,
	}
	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
	}

	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := testutil.GenerateSelfSignedCertificate(certFile, keyFile); err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	server := newTestServer(t, config.WebDAVConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		BasePath:      "/dav",
		TLSCertFile:   certFile,
		TLSKeyFile:    keyFile,
	}, userRepo, &testutil.RecordingAuditRepo{}, &testutil.RecordingSessionRepo{})

	baseURL := "https://" + server.listener.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	putReq, _ := http.NewRequest(http.MethodPut, baseURL+"/dav/secure.txt", bytes.NewBufferString("hello via tls webdav"))
	putReq.SetBasicAuth("tls-user", "secret-pass")
	putResp, err := client.Do(putReq)
	if err != nil {
		t.Fatalf("put request failed: %v", err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusCreated && putResp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(putResp.Body)
		t.Fatalf("put status = %d, want 201/204, body=%s", putResp.StatusCode, string(body))
	}

	getReq, _ := http.NewRequest(http.MethodGet, baseURL+"/dav/secure.txt", nil)
	getReq.SetBasicAuth("tls-user", "secret-pass")
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("get request failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Fatalf("read get body failed: %v", err)
	}
	if string(body) != "hello via tls webdav" {
		t.Fatalf("get body = %q, want %q", string(body), "hello via tls webdav")
	}
}

func newTestServer(t *testing.T, cfg config.WebDAVConfig, userRepo *testutil.StubUserRepo, auditRepo *testutil.RecordingAuditRepo, sessionRepo *testutil.RecordingSessionRepo) *Server {
	t.Helper()

	authService := auth.NewAuthenticationService(userRepo, &testutil.StubAdminRepo{})
	server := NewServer(cfg, zap.NewNop(), authService, policy.NewPolicyEngine(userRepo), userRepo, auditRepo, sessionRepo)

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start webdav server failed: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	})
	return server
}

func waitForInactiveSessions(t *testing.T, sessionRepo *testutil.RecordingSessionRepo, protocol string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(sessionRepo.Sessions) > 0 {
			allInactive := true
			for _, session := range sessionRepo.Sessions {
				if session.Protocol == protocol && session.Active {
					allInactive = false
					break
				}
			}
			if allInactive {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected %s sessions to be deactivated", protocol)
}
