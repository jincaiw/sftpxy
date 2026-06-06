package httpd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	authn "github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/database"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/shares"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func TestAdminAPIContract(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	adminToken := loginAdmin(t, server)

	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/users", adminToken, map[string]interface{}{
		"username":       "alice",
		"email":          "alice@example.com",
		"password":       "alice-pass",
		"home_directory": filepath.Join(t.TempDir(), "alice-home"),
		"status":         "active",
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create user status = %d, want %d", createResp.StatusCode, http.StatusOK)
	}

	usersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", adminToken, nil)
	if usersResp.StatusCode != http.StatusOK {
		t.Fatalf("list users status = %d, want %d", usersResp.StatusCode, http.StatusOK)
	}

	var users []map[string]interface{}
	decodeJSON(t, usersResp.Body, &users)
	if len(users) != 1 {
		t.Fatalf("user count = %d, want 1", len(users))
	}
	if users[0]["username"] != "alice" {
		t.Fatalf("username = %v, want alice", users[0]["username"])
	}
	if users[0]["email"] != "alice@example.com" {
		t.Fatalf("email = %v, want alice@example.com", users[0]["email"])
	}
	if users[0]["home_directory"] == "" {
		t.Fatalf("home_directory should not be empty")
	}

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/users/1", adminToken, map[string]interface{}{
		"email":  "alice+updated@example.com",
		"status": "disabled",
	})
	if updateResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("update user status = %d, want %d, body: %s", updateResp.StatusCode, http.StatusOK, string(bodyBytes))
	}

	usersResp = doJSONRequest(t, server, http.MethodGet, "/api/v1/users", adminToken, nil)
	if usersResp.StatusCode != http.StatusOK {
		t.Fatalf("list users after update status = %d, want %d", usersResp.StatusCode, http.StatusOK)
	}
	decodeJSON(t, usersResp.Body, &users)
	if users[0]["email"] != "alice+updated@example.com" {
		t.Fatalf("updated email = %v, want alice+updated@example.com", users[0]["email"])
	}
	if users[0]["status"] != "disabled" {
		t.Fatalf("updated status = %v, want disabled", users[0]["status"])
	}

	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&auditCount); err != nil {
		t.Fatalf("count audit logs failed: %v", err)
	}
	if auditCount == 0 {
		t.Fatalf("expected audit logs to be recorded")
	}

	logsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/logs?page=1&limit=10", adminToken, nil)
	if logsResp.StatusCode != http.StatusOK {
		t.Fatalf("get logs status = %d, want %d", logsResp.StatusCode, http.StatusOK)
	}

	var logsPayload struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	decodeJSON(t, logsResp.Body, &logsPayload)
	if logsPayload.Total == 0 || len(logsPayload.Items) == 0 {
		t.Fatalf("expected logs payload to contain items, got total=%d items=%d", logsPayload.Total, len(logsPayload.Items))
	}
}

func TestUserFileAPIContract(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "bob-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "bob", "bob-pass", userHome)

	userToken := loginUser(t, server, "bob", "bob-pass")

	folderResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/files/folder", userToken, map[string]string{
		"path": "/docs",
	})
	if folderResp.StatusCode != http.StatusOK {
		t.Fatalf("create folder status = %d, want %d", folderResp.StatusCode, http.StatusOK)
	}

	uploadResp := uploadFileRequest(t, server, userToken, "/docs", "readme.txt", "hello from test")
	if uploadResp.StatusCode != http.StatusOK {
		t.Fatalf("upload file status = %d, want %d", uploadResp.StatusCode, http.StatusOK)
	}
	uploadedPath := filepath.Join(userHome, "docs", "readme.txt")
	uploadedBody, err := os.ReadFile(uploadedPath)
	if err != nil {
		t.Fatalf("uploaded file should exist on disk at %s: %v", uploadedPath, err)
	}
	if string(uploadedBody) != "hello from test" {
		t.Fatalf("uploaded file body = %q, want %q", string(uploadedBody), "hello from test")
	}

	listResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/files?path=/docs", userToken, nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list files status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	var files []map[string]interface{}
	decodeJSON(t, listResp.Body, &files)
	if len(files) != 1 || files[0]["name"] != "readme.txt" {
		t.Fatalf("unexpected files payload: %+v", files)
	}

	downloadResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/files/download?path=/docs/readme.txt", userToken, nil)
	if downloadResp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want %d", downloadResp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		t.Fatalf("read download body failed: %v", err)
	}
	if string(body) != "hello from test" {
		t.Fatalf("download body = %q, want %q", string(body), "hello from test")
	}

	renameResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/files/rename", userToken, map[string]string{
		"old_path": "/docs/readme.txt",
		"new_path": "/docs/guide.txt",
	})
	if renameResp.StatusCode != http.StatusOK {
		t.Fatalf("rename status = %d, want %d", renameResp.StatusCode, http.StatusOK)
	}

	deleteResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/files?path=/docs/guide.txt", userToken, nil)
	if deleteResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want %d", deleteResp.StatusCode, http.StatusOK)
	}

	adminToken := loginAdmin(t, server)
	connectionsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/connections", adminToken, nil)
	if connectionsResp.StatusCode != http.StatusOK {
		t.Fatalf("get connections status = %d, want %d", connectionsResp.StatusCode, http.StatusOK)
	}

	var connections []map[string]interface{}
	decodeJSON(t, connectionsResp.Body, &connections)
	if len(connections) < 1 {
		t.Fatalf("connection count = %d, want at least 1", len(connections))
	}
	connectionID := ""
	for _, connection := range connections {
		if connection["username"] == "bob" && connection["principal"] == "user" {
			connectionID, _ = connection["id"].(string)
			break
		}
	}
	if connectionID == "" {
		t.Fatalf("user connection id should not be empty: %+v", connections)
	}

	disconnectResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/connections/"+connectionID, adminToken, nil)
	if disconnectResp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect status = %d, want %d", disconnectResp.StatusCode, http.StatusOK)
	}
}

func TestUserProfileAPIContract(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "dave-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "dave", "dave-pass", userHome)

	secret, err := authn.NewTOTPAuthenticator("SFTPxy").GenerateSecret()
	if err != nil {
		t.Fatalf("generate dave MFA secret failed: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET quotas = ?, mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", `{"max_size":1048576,"current_size":512}`, secret, "dave"); err != nil {
		t.Fatalf("seed user quota failed: %v", err)
	}
	var userID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "dave").Scan(&userID); err != nil {
		t.Fatalf("load user id failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO public_keys (user_id, label, public_key) VALUES (?, ?, ?)", userID, "workstation", "ssh-ed25519 AAAATEST dave@workstation"); err != nil {
		t.Fatalf("seed public key failed: %v", err)
	}

	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate login MFA code failed: %v", err)
	}
	loginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "dave",
		"password": "dave-pass",
		"mfa_code": validCode,
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("user login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	var loginPayload map[string]interface{}
	decodeJSON(t, loginResp.Body, &loginPayload)
	userToken, _ := loginPayload["token"].(string)
	if userToken == "" {
		t.Fatalf("user token should not be empty")
	}

	profileResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/profile", userToken, nil)
	if profileResp.StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d, want %d", profileResp.StatusCode, http.StatusOK)
	}

	var profile map[string]interface{}
	decodeJSON(t, profileResp.Body, &profile)
	if profile["username"] != "dave" {
		t.Fatalf("username = %v, want dave", profile["username"])
	}
	quota, ok := profile["quota"].(map[string]interface{})
	if !ok || quota["configured"] != true {
		t.Fatalf("expected configured quota in profile response, got %+v", profile["quota"])
	}
	publicKeys, ok := profile["public_keys"].([]interface{})
	if !ok || len(publicKeys) != 1 {
		t.Fatalf("expected one public key, got %+v", profile["public_keys"])
	}

	changePasswordResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/profile/password", userToken, map[string]string{
		"current_password": "dave-pass",
		"new_password":     "dave-pass-2",
	})
	if changePasswordResp.StatusCode != http.StatusOK {
		t.Fatalf("change password status = %d, want %d", changePasswordResp.StatusCode, http.StatusOK)
	}

	reloginCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate relogin MFA code failed: %v", err)
	}
	reloginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "dave",
		"password": "dave-pass-2",
		"mfa_code": reloginCode,
	})
	if reloginResp.StatusCode != http.StatusOK {
		t.Fatalf("relogin status = %d, want %d", reloginResp.StatusCode, http.StatusOK)
	}
}

func TestUserFileAPIUsesFilesystemConfigAndPolicy(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "erin-home")
	storageHome := filepath.Join(t.TempDir(), "erin-storage")
	if err := os.MkdirAll(filepath.Join(storageHome, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir storage home failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storageHome, "docs", "report.txt"), []byte("from-storage-backend"), 0o644); err != nil {
		t.Fatalf("seed storage file failed: %v", err)
	}
	seedUser(t, db, "erin", "erin-pass", userHome)

	filesystemConfig, err := json.Marshal(map[string]interface{}{
		"type": "local",
		"config": map[string]interface{}{
			"base_path": storageHome,
			"chroot":    true,
		},
	})
	if err != nil {
		t.Fatalf("marshal filesystem config failed: %v", err)
	}
	permissions, err := json.Marshal([]map[string]interface{}{
		{
			"path":        "/docs",
			"list":        true,
			"download":    true,
			"upload":      false,
			"overwrite":   false,
			"delete":      false,
			"rename":      false,
			"create_dirs": false,
			"chmod":       false,
		},
	})
	if err != nil {
		t.Fatalf("marshal permissions failed: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET filesystem = ?, permissions = ? WHERE username = ?", string(filesystemConfig), string(permissions), "erin"); err != nil {
		t.Fatalf("update user filesystem/policy failed: %v", err)
	}

	userToken := loginUser(t, server, "erin", "erin-pass")

	listResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/files?path=/docs", userToken, nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list files status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	var files []map[string]interface{}
	decodeJSON(t, listResp.Body, &files)
	if len(files) != 1 || files[0]["name"] != "report.txt" {
		t.Fatalf("unexpected files payload: %+v", files)
	}

	downloadResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/files/download?path=/docs/report.txt", userToken, nil)
	if downloadResp.StatusCode != http.StatusOK {
		t.Fatalf("download status = %d, want %d", downloadResp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		t.Fatalf("read download body failed: %v", err)
	}
	if string(body) != "from-storage-backend" {
		t.Fatalf("download body = %q, want %q", string(body), "from-storage-backend")
	}

	uploadResp := uploadFileRequest(t, server, userToken, "/docs", "blocked.txt", "should fail")
	if uploadResp.StatusCode != http.StatusForbidden {
		respBody, _ := io.ReadAll(uploadResp.Body)
		t.Fatalf("upload status = %d, want %d, body=%s", uploadResp.StatusCode, http.StatusForbidden, string(respBody))
	}
	if _, err := os.Stat(filepath.Join(storageHome, "docs", "blocked.txt")); !os.IsNotExist(err) {
		t.Fatalf("blocked upload should not create target file, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(userHome, "docs", "report.txt")); !os.IsNotExist(err) {
		t.Fatalf("webclient should not read from home_dir when filesystem override is configured, got err=%v", err)
	}
}

func TestUserFileAPIAcceptsLegacyFilesystemString(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "legacy-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userHome, "existing.txt"), []byte("legacy-home-file"), 0o644); err != nil {
		t.Fatalf("seed user home file failed: %v", err)
	}
	seedUser(t, db, "legacy", "legacy-pass", userHome)

	if _, err := db.Exec("UPDATE users SET filesystem = ? WHERE username = ?", "local", "legacy"); err != nil {
		t.Fatalf("set legacy filesystem failed: %v", err)
	}

	userToken := loginUser(t, server, "legacy", "legacy-pass")

	listResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/files?path=/", userToken, nil)
	if listResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listResp.Body)
		t.Fatalf("list files status = %d, want %d, body=%s", listResp.StatusCode, http.StatusOK, string(body))
	}

	var files []map[string]interface{}
	decodeJSON(t, listResp.Body, &files)
	if len(files) != 1 || files[0]["name"] != "existing.txt" {
		t.Fatalf("unexpected files payload for legacy filesystem config: %+v", files)
	}
}

func TestShareAndObservabilityContract(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "carol-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "carol", "carol-pass", userHome)

	userToken := loginUser(t, server, "carol", "carol-pass")
	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares", userToken, map[string]interface{}{
		"path":          "/docs/report.txt",
		"share_type":    "download",
		"password":      "secret",
		"max_downloads": 1,
	})
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create share status = %d, want %d, body=%s", createResp.StatusCode, http.StatusCreated, string(body))
	}

	var share map[string]interface{}
	decodeJSON(t, createResp.Body, &share)
	token, _ := share["token"].(string)
	if token == "" {
		t.Fatalf("share token should not be empty")
	}

	listResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/shares", userToken, nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list shares status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	accessResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares/access/"+token, "", map[string]string{
		"password": "secret",
	})
	if accessResp.StatusCode != http.StatusOK {
		t.Fatalf("access share status = %d, want %d", accessResp.StatusCode, http.StatusOK)
	}

	adminToken := loginAdmin(t, server)
	emitResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/events/emit", adminToken, map[string]interface{}{
		"event_type": "login",
		"username":   "carol",
		"protocol":   "http",
		"result":     "success",
	})
	if emitResp.StatusCode != http.StatusOK {
		t.Fatalf("emit event status = %d, want %d", emitResp.StatusCode, http.StatusOK)
	}

	historyResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/events/history?page=1&limit=10", adminToken, nil)
	if historyResp.StatusCode != http.StatusOK {
		t.Fatalf("event history status = %d, want %d", historyResp.StatusCode, http.StatusOK)
	}

	var historyPayload struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	decodeJSON(t, historyResp.Body, &historyPayload)
	if historyPayload.Total == 0 {
		t.Fatalf("expected event history to contain items")
	}

	metricsResp := doJSONRequest(t, server, http.MethodGet, "/metrics", "", nil)
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", metricsResp.StatusCode, http.StatusOK)
	}
	metricsBody, err := io.ReadAll(metricsResp.Body)
	if err != nil {
		t.Fatalf("read metrics body failed: %v", err)
	}
	metricsText := string(metricsBody)
	if !strings.Contains(metricsText, "sftpxy_event_executions_total") {
		t.Fatalf("metrics should contain event executions counter")
	}
	if !strings.Contains(metricsText, "sftpxy_share_access_total") {
		t.Fatalf("metrics should contain share access counter")
	}

	healthResp := doJSONRequest(t, server, http.MethodGet, "/health", "", nil)
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", healthResp.StatusCode, http.StatusOK)
	}

	statusResp := doJSONRequest(t, server, http.MethodGet, "/status", "", nil)
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status endpoint status = %d, want %d", statusResp.StatusCode, http.StatusOK)
	}

	revokeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares/"+toStringID(t, share["id"])+"/revoke", userToken, nil)
	if revokeResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke share status = %d, want %d", revokeResp.StatusCode, http.StatusOK)
	}

	failedAccessResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares/access/"+token, "", map[string]string{
		"password": "secret",
	})
	if failedAccessResp.StatusCode == http.StatusOK {
		t.Fatalf("expected revoked share access to fail")
	}
}

func TestCreateShareRespectsDownloadPolicy(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "frank-home")
	if err := os.MkdirAll(filepath.Join(userHome, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userHome, "docs", "report.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatalf("seed file failed: %v", err)
	}
	seedUser(t, db, "frank", "frank-pass", userHome)

	permissions, err := json.Marshal([]map[string]interface{}{
		{
			"path":        "/docs",
			"list":        true,
			"download":    false,
			"upload":      false,
			"overwrite":   false,
			"delete":      false,
			"rename":      false,
			"create_dirs": false,
			"chmod":       false,
		},
	})
	if err != nil {
		t.Fatalf("marshal permissions failed: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET permissions = ? WHERE username = ?", string(permissions), "frank"); err != nil {
		t.Fatalf("update permissions failed: %v", err)
	}

	userToken := loginUser(t, server, "frank", "frank-pass")
	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares", userToken, map[string]interface{}{
		"path":       "/docs/report.txt",
		"share_type": "download",
	})
	if createResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create share status = %d, want %d, body=%s", createResp.StatusCode, http.StatusForbidden, string(body))
	}
}

func TestShareDownloadIncrementsCountOnce(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "gina-home")
	if err := os.MkdirAll(filepath.Join(userHome, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(userHome, "docs", "report.txt"), []byte("download me"), 0o644); err != nil {
		t.Fatalf("seed file failed: %v", err)
	}
	seedUser(t, db, "gina", "gina-pass", userHome)

	userToken := loginUser(t, server, "gina", "gina-pass")
	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/shares", userToken, map[string]interface{}{
		"path":          "/docs/report.txt",
		"share_type":    "download",
		"password":      "secret",
		"max_downloads": 2,
	})
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create share status = %d, want %d, body=%s", createResp.StatusCode, http.StatusCreated, string(body))
	}

	var share map[string]interface{}
	decodeJSON(t, createResp.Body, &share)
	token, _ := share["token"].(string)
	if token == "" {
		t.Fatal("expected share token")
	}

	downloadResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/shares/download/"+token+"?password=secret", "", nil)
	if downloadResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(downloadResp.Body)
		t.Fatalf("download status = %d, want %d, body=%s", downloadResp.StatusCode, http.StatusOK, string(body))
	}

	var downloadCount int
	if err := db.QueryRow("SELECT download_count FROM shares WHERE token = ?", token).Scan(&downloadCount); err != nil {
		t.Fatalf("load download count failed: %v", err)
	}
	if downloadCount != 1 {
		t.Fatalf("download_count = %d, want 1", downloadCount)
	}
}

func TestUserLoginRequiresValidMFACode(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "mfa-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "mfa-user", "mfa-pass", userHome)

	secret, err := authn.NewTOTPAuthenticator("SFTPxy").GenerateSecret()
	if err != nil {
		t.Fatalf("generate user MFA secret failed: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", secret, "mfa-user"); err != nil {
		t.Fatalf("enable user MFA failed: %v", err)
	}

	missingCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "mfa-user",
		"password": "mfa-pass",
	})
	if missingCodeResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing MFA code status = %d, want %d", missingCodeResp.StatusCode, http.StatusUnauthorized)
	}
	var missingPayload map[string]any
	decodeJSON(t, missingCodeResp.Body, &missingPayload)
	if missingPayload["mfa_required"] != true {
		t.Fatalf("expected mfa_required=true, got %+v", missingPayload)
	}

	invalidCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "mfa-user",
		"password": "mfa-pass",
		"mfa_code": "123456",
	})
	if invalidCodeResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid MFA code status = %d, want %d", invalidCodeResp.StatusCode, http.StatusUnauthorized)
	}

	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate valid MFA code failed: %v", err)
	}
	validCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "mfa-user",
		"password": "mfa-pass",
		"mfa_code": validCode,
	})
	if validCodeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(validCodeResp.Body)
		t.Fatalf("valid MFA login status = %d, want %d, body=%s", validCodeResp.StatusCode, http.StatusOK, string(body))
	}
}

func TestUserLoginAcceptsAndConsumesRecoveryCode(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "recovery-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "recovery-user", "recovery-pass", userHome)

	secret, err := authn.NewTOTPAuthenticator("SFTPxy").GenerateSecret()
	if err != nil {
		t.Fatalf("generate recovery MFA secret failed: %v", err)
	}
	recoveryCodesJSON := `["recover-1","recover-2"]`
	if _, err := db.Exec("UPDATE users SET mfa_enabled = TRUE, mfa_secret = ?, mfa_recovery_codes = ? WHERE username = ?", secret, recoveryCodesJSON, "recovery-user"); err != nil {
		t.Fatalf("seed recovery codes failed: %v", err)
	}

	recoveryResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "recovery-user",
		"password": "recovery-pass",
		"mfa_code": "recover-1",
	})
	if recoveryResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(recoveryResp.Body)
		t.Fatalf("recovery code login status = %d, want %d, body=%s", recoveryResp.StatusCode, http.StatusOK, string(body))
	}

	var remainingCodesRaw string
	if err := db.QueryRow("SELECT COALESCE(mfa_recovery_codes, '') FROM users WHERE username = ?", "recovery-user").Scan(&remainingCodesRaw); err != nil {
		t.Fatalf("load remaining recovery codes failed: %v", err)
	}
	var remainingCodes []string
	if err := json.Unmarshal([]byte(remainingCodesRaw), &remainingCodes); err != nil {
		t.Fatalf("decode remaining recovery codes failed: %v", err)
	}
	if len(remainingCodes) != 1 || remainingCodes[0] != "recover-2" {
		t.Fatalf("remaining recovery codes = %+v, want [recover-2]", remainingCodes)
	}

	reuseResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "recovery-user",
		"password": "recovery-pass",
		"mfa_code": "recover-1",
	})
	if reuseResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code status = %d, want %d", reuseResp.StatusCode, http.StatusUnauthorized)
	}
}

func TestDisableMFAAcceptsRecoveryCodeWithoutPasswordHash(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "disable-mfa-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "federated-user", "unused-pass", userHome)

	secret, err := authn.NewTOTPAuthenticator("SFTPxy").GenerateSecret()
	if err != nil {
		t.Fatalf("generate MFA secret failed: %v", err)
	}
	if _, err := db.Exec("UPDATE users SET password_hash = NULL, mfa_enabled = TRUE, mfa_secret = ?, mfa_recovery_codes = ? WHERE username = ?", secret, `["disable-recovery"]`, "federated-user"); err != nil {
		t.Fatalf("seed federated user MFA failed: %v", err)
	}

	var userID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "federated-user").Scan(&userID); err != nil {
		t.Fatalf("load federated user id failed: %v", err)
	}
	sessionID, err := generateToken()
	if err != nil {
		t.Fatalf("generate session id failed: %v", err)
	}
	session := &authSession{
		SessionID: sessionID,
		UserID:    userID,
		Username:  "federated-user",
		Role:      "user",
		HomeDir:   userHome,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	app := newConfiguredServer(t, db, nil, nil)
	token, err := app.issueToken(session)
	if err != nil {
		t.Fatalf("issue token failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO sessions (session_id, user_id, protocol, client_ip, is_active) VALUES (?, ?, ?, ?, TRUE)", sessionID, userID, "http", "127.0.0.1"); err != nil {
		t.Fatalf("insert federated session failed: %v", err)
	}

	disableResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/user/mfa", token, map[string]string{
		"password": "disable-recovery",
	})
	if disableResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disableResp.Body)
		t.Fatalf("disable MFA status = %d, want %d, body=%s", disableResp.StatusCode, http.StatusOK, string(body))
	}

	var enabled bool
	var recoveryCodes sql.NullString
	if err := db.QueryRow("SELECT mfa_enabled, mfa_recovery_codes FROM users WHERE id = ?", userID).Scan(&enabled, &recoveryCodes); err != nil {
		t.Fatalf("load disabled MFA state failed: %v", err)
	}
	if enabled {
		t.Fatalf("expected MFA to be disabled")
	}
	if recoveryCodes.Valid && strings.TrimSpace(recoveryCodes.String) != "" {
		t.Fatalf("expected recovery codes to be cleared, got %q", recoveryCodes.String)
	}
}

func TestUserRefreshRevokesPreviousJWT(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "refresh-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "refresh-user", "refresh-pass", userHome)

	oldToken := loginUser(t, server, "refresh-user", "refresh-pass")

	refreshResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", oldToken, nil)
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("refresh status = %d, want %d, body=%s", refreshResp.StatusCode, http.StatusOK, string(body))
	}
	var refreshPayload map[string]any
	decodeJSON(t, refreshResp.Body, &refreshPayload)
	newToken, _ := refreshPayload["token"].(string)
	if newToken == "" || newToken == oldToken {
		t.Fatalf("expected a rotated token, got old=%q new=%q", oldToken, newToken)
	}

	oldProfileResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/profile", oldToken, nil)
	if oldProfileResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token profile status = %d, want %d", oldProfileResp.StatusCode, http.StatusUnauthorized)
	}

	newProfileResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/profile", newToken, nil)
	if newProfileResp.StatusCode != http.StatusOK {
		t.Fatalf("new token profile status = %d, want %d", newProfileResp.StatusCode, http.StatusOK)
	}

	var activeSessions int
	if err := db.QueryRow(
		`SELECT COUNT(*)
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		WHERE u.username = ? AND s.is_active = TRUE`,
		"refresh-user",
	).Scan(&activeSessions); err != nil {
		t.Fatalf("count active sessions failed: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("active session count = %d, want 1", activeSessions)
	}
}

func TestDisabledUserTokenIsRevokedAfterStatusChange(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "disabled-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "disabled-user", "disabled-pass", userHome)

	userToken := loginUser(t, server, "disabled-user", "disabled-pass")
	adminToken := loginAdmin(t, server)

	var userID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "disabled-user").Scan(&userID); err != nil {
		t.Fatalf("load disabled user id failed: %v", err)
	}

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/users/"+strconv.FormatInt(userID, 10), adminToken, map[string]any{
		"status": "disabled",
	})
	if updateResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("disable user status = %d, want %d, body=%s", updateResp.StatusCode, http.StatusOK, string(body))
	}

	profileResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/profile", userToken, nil)
	if profileResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled user token status = %d, want %d", profileResp.StatusCode, http.StatusUnauthorized)
	}

	var activeSessions int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE user_id = ? AND is_active = TRUE", userID).Scan(&activeSessions); err != nil {
		t.Fatalf("count disabled user sessions failed: %v", err)
	}
	if activeSessions != 0 {
		t.Fatalf("active disabled-user sessions = %d, want 0", activeSessions)
	}
}

func TestDisconnectOwnSessionRevokesJWTAccess(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	userHome := filepath.Join(t.TempDir(), "disconnect-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "disconnect-user", "disconnect-pass", userHome)

	token := loginUser(t, server, "disconnect-user", "disconnect-pass")

	sessionsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/user/sessions", token, nil)
	if sessionsResp.StatusCode != http.StatusOK {
		t.Fatalf("list own sessions status = %d, want %d", sessionsResp.StatusCode, http.StatusOK)
	}
	var sessions []map[string]any
	decodeJSON(t, sessionsResp.Body, &sessions)
	if len(sessions) != 1 {
		t.Fatalf("session count = %d, want 1", len(sessions))
	}
	sessionID, _ := sessions[0]["id"].(string)
	if sessionID == "" {
		t.Fatalf("session id should not be empty")
	}

	disconnectResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/user/sessions/"+sessionID, token, nil)
	if disconnectResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(disconnectResp.Body)
		t.Fatalf("disconnect own session status = %d, want %d, body=%s", disconnectResp.StatusCode, http.StatusOK, string(body))
	}

	profileResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/profile", token, nil)
	if profileResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token profile status = %d, want %d", profileResp.StatusCode, http.StatusUnauthorized)
	}
}

func TestPasswordExpiryRequiresForcedPasswordChangeForUnsetTimestamp(t *testing.T) {
	baseServer, db, cleanup := newTestServer(t)
	defer cleanup()
	defer baseServer.Close()

	userHome := filepath.Join(t.TempDir(), "expired-user-home")
	if err := os.MkdirAll(userHome, 0o755); err != nil {
		t.Fatalf("mkdir user home failed: %v", err)
	}
	seedUser(t, db, "expired-user", "expired-pass", userHome)

	expiryServer := newConfiguredHTTPServer(t, db, &config.Config{
		Auth: config.AuthConfig{
			PasswordExpiresDays: 1,
		},
	}, nil)

	loginResp := doJSONRequest(t, expiryServer, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "expired-user",
		"password": "expired-pass",
	})
	if loginResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(loginResp.Body)
		t.Fatalf("expired password login status = %d, want %d, body=%s", loginResp.StatusCode, http.StatusForbidden, string(body))
	}
	var loginPayload map[string]any
	decodeJSON(t, loginResp.Body, &loginPayload)
	if loginPayload["password_expired"] != true {
		t.Fatalf("expected password_expired=true, got %+v", loginPayload)
	}
	changeToken, _ := loginPayload["password_change_token"].(string)
	if changeToken == "" {
		t.Fatalf("password_change_token should not be empty")
	}

	shortResp := doJSONRequest(t, expiryServer, http.MethodPost, "/api/v1/auth/user/password/change", "", map[string]string{
		"password_change_token": changeToken,
		"new_password":          "a",
	})
	if shortResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(shortResp.Body)
		t.Fatalf("short forced password change status = %d, want %d, body=%s", shortResp.StatusCode, http.StatusBadRequest, string(body))
	}

	loginResp = doJSONRequest(t, expiryServer, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "expired-user",
		"password": "expired-pass",
	})
	if loginResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired password relogin status = %d, want %d", loginResp.StatusCode, http.StatusForbidden)
	}
	decodeJSON(t, loginResp.Body, &loginPayload)
	changeToken, _ = loginPayload["password_change_token"].(string)
	if changeToken == "" {
		t.Fatalf("second password_change_token should not be empty")
	}

	validResp := doJSONRequest(t, expiryServer, http.MethodPost, "/api/v1/auth/user/password/change", "", map[string]string{
		"password_change_token": changeToken,
		"new_password":          "expired-pass-2",
	})
	if validResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(validResp.Body)
		t.Fatalf("valid forced password change status = %d, want %d, body=%s", validResp.StatusCode, http.StatusOK, string(body))
	}

	reloginResp := doJSONRequest(t, expiryServer, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "expired-user",
		"password": "expired-pass-2",
	})
	if reloginResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(reloginResp.Body)
		t.Fatalf("post-change login status = %d, want %d, body=%s", reloginResp.StatusCode, http.StatusOK, string(body))
	}
}

func TestOpenAPIEndpointServesRealSchema(t *testing.T) {
	s := NewServerWithDependencies(config.HTTPDConfig{
		Enabled:        true,
		RESTAPIEnabled: true,
		OpenAPIEnabled: true,
	}, zap.NewNop(), ServerDependencies{})
	server := httptest.NewServer(s.Router())
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/openapi", nil)
	if err != nil {
		t.Fatalf("create openapi request failed: %v", err)
	}
	req.Header.Set("X-Forwarded-Proto", "https")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request openapi failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("openapi status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var payload map[string]interface{}
	decodeJSON(t, resp.Body, &payload)

	if payload["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v, want %q", payload["openapi"], "3.0.3")
	}

	info, ok := payload["info"].(map[string]interface{})
	if !ok {
		t.Fatalf("openapi info should be an object")
	}
	if info["version"] != "1.0.0" {
		t.Fatalf("info.version = %v, want %q", info["version"], "1.0.0")
	}

	servers, ok := payload["servers"].([]interface{})
	if !ok || len(servers) != 1 {
		t.Fatalf("servers = %#v, want one generated server entry", payload["servers"])
	}
	serverEntry, ok := servers[0].(map[string]interface{})
	if !ok {
		t.Fatalf("server entry should be an object")
	}
	expectedURL := strings.Replace(server.URL, "http://", "https://", 1)
	if serverEntry["url"] != expectedURL {
		t.Fatalf("server url = %v, want %q", serverEntry["url"], expectedURL)
	}

	paths, ok := payload["paths"].(map[string]interface{})
	if !ok {
		t.Fatalf("paths should be an object")
	}

	expectedPaths := []string{
		"/health",
		"/status",
		"/openapi",
		"/metrics",
		"/api/v1/status",
		"/api/v1/auth/admin/login",
		"/api/v1/auth/user/login",
		"/api/v1/auth/oidc/start",
		"/api/v1/auth/oidc/callback",
		"/api/v1/shares/access/{token}",
		"/api/v1/users",
		"/api/v1/users/{id}",
		"/api/v1/connections",
		"/api/v1/connections/{id}",
		"/api/v1/logs",
		"/api/v1/events/rules",
		"/api/v1/events/history",
		"/api/v1/events/emit",
		"/api/v1/profile",
		"/api/v1/profile/password",
		"/api/v1/files",
		"/api/v1/files/download",
		"/api/v1/files/upload",
		"/api/v1/files/rename",
		"/api/v1/files/folder",
		"/api/v1/shares",
		"/api/v1/shares/{shareID}/revoke",
	}
	if len(paths) != len(expectedPaths) {
		t.Fatalf("path count = %d, want %d", len(paths), len(expectedPaths))
	}
	for _, path := range expectedPaths {
		if _, ok := paths[path]; !ok {
			t.Fatalf("missing openapi path %q", path)
		}
	}

	requirePathMethods := func(path string, methods ...string) {
		t.Helper()
		operations, ok := paths[path].(map[string]interface{})
		if !ok {
			t.Fatalf("path %q should map to operations", path)
		}
		for _, method := range methods {
			if _, ok := operations[method]; !ok {
				t.Fatalf("path %q missing method %q", path, method)
			}
		}
	}
	requirePathMethods("/api/v1/users", "get", "post")
	requirePathMethods("/api/v1/users/{id}", "put", "delete")
	requirePathMethods("/api/v1/files", "get", "delete")
	requirePathMethods("/api/v1/shares", "get", "post")
	requirePathMethods("/api/v1/auth/oidc/start", "get")
	requirePathMethods("/api/v1/auth/oidc/callback", "get")

	getOperation := func(path, method string) map[string]interface{} {
		t.Helper()
		pathOperations, hasPath := paths[path].(map[string]interface{})
		if !hasPath {
			t.Fatalf("path %q should map to operations", path)
		}
		operation, hasMethod := pathOperations[method].(map[string]interface{})
		if !hasMethod {
			t.Fatalf("path %q method %q should be an object", path, method)
		}
		return operation
	}

	requireSecuritySchemes := func(path, method string, expected ...string) {
		t.Helper()
		operation := getOperation(path, method)
		rawSecurity, ok := operation["security"].([]interface{})
		if !ok {
			t.Fatalf("path %q method %q should define security", path, method)
		}
		if len(rawSecurity) != len(expected) {
			t.Fatalf("path %q method %q security count = %d, want %d", path, method, len(rawSecurity), len(expected))
		}
		for idx, schemeName := range expected {
			entry, hasEntry := rawSecurity[idx].(map[string]interface{})
			if !hasEntry {
				t.Fatalf("path %q method %q security entry %d should be an object", path, method, idx)
			}
			if _, hasScheme := entry[schemeName]; !hasScheme {
				t.Fatalf("path %q method %q missing security scheme %q at index %d", path, method, schemeName, idx)
			}
		}
	}

	requireSecuritySchemes("/api/v1/users", "get", "BearerAuth", "APIKeyAuth", "APIKeyAuthorizationAuth")
	requireSecuritySchemes("/api/v1/events/emit", "post", "BearerAuth", "APIKeyAuth", "APIKeyAuthorizationAuth")
	requireSecuritySchemes("/api/v1/profile", "get", "BearerAuth")

	components, ok := payload["components"].(map[string]interface{})
	if !ok {
		t.Fatalf("components should be an object")
	}
	securitySchemes, ok := components["securitySchemes"].(map[string]interface{})
	if !ok {
		t.Fatalf("securitySchemes should be an object")
	}
	for _, name := range []string{"BearerAuth", "APIKeyAuth", "APIKeyAuthorizationAuth", "OIDCAuth"} {
		if _, hasScheme := securitySchemes[name]; !hasScheme {
			t.Fatalf("expected %s security scheme", name)
		}
	}
	bearerAuth, ok := securitySchemes["BearerAuth"].(map[string]interface{})
	if !ok {
		t.Fatalf("BearerAuth should be an object")
	}
	if bearerAuth["bearerFormat"] != "JWT" {
		t.Fatalf("BearerAuth bearerFormat = %v, want JWT", bearerAuth["bearerFormat"])
	}

	schemas, ok := components["schemas"].(map[string]interface{})
	if !ok {
		t.Fatalf("schemas should be an object")
	}
	authResponse, ok := schemas["AuthResponse"].(map[string]interface{})
	if !ok {
		t.Fatalf("AuthResponse should be an object")
	}
	requiredFields, ok := authResponse["required"].([]interface{})
	if !ok {
		t.Fatalf("AuthResponse.required should be an array")
	}
	hasTokenType := false
	for _, field := range requiredFields {
		if field == "token_type" {
			hasTokenType = true
			break
		}
	}
	if !hasTokenType {
		t.Fatalf("AuthResponse.required should include token_type")
	}
	properties, ok := authResponse["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("AuthResponse.properties should be an object")
	}
	if _, hasTokenTypeProperty := properties["token_type"]; !hasTokenTypeProperty {
		t.Fatalf("AuthResponse.properties should include token_type")
	}
	if _, hasOIDCStartResponse := schemas["OIDCStartResponse"]; !hasOIDCStartResponse {
		t.Fatalf("expected OIDCStartResponse schema")
	}

	uploadOperations, ok := paths["/api/v1/files/upload"].(map[string]interface{})
	if !ok {
		t.Fatalf("upload path should map to operations")
	}
	uploadPost, ok := uploadOperations["post"].(map[string]interface{})
	if !ok {
		t.Fatalf("upload path should define a POST operation")
	}
	requestBody, ok := uploadPost["requestBody"].(map[string]interface{})
	if !ok {
		t.Fatalf("upload POST should define a request body")
	}
	content, ok := requestBody["content"].(map[string]interface{})
	if !ok {
		t.Fatalf("upload request body content should be an object")
	}
	if _, ok := content["multipart/form-data"]; !ok {
		t.Fatalf("upload request body should declare multipart/form-data")
	}
}

func newTestServer(t *testing.T) (*httptest.Server, *sql.DB, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "httpd-test.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)

	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA busy_timeout=10000")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")

	statements := []string{
		`CREATE TABLE admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			permissions TEXT,
			role_id INTEGER,
			mfa_secret TEXT,
			mfa_enabled BOOLEAN DEFAULT FALSE,
			filters TEXT,
			last_login_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			priority INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			permissions TEXT,
			scope TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE user_groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, group_id)
		)`,
		`CREATE TABLE user_roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			role_id INTEGER NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, role_id)
		)`,
		`CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			status TEXT NOT NULL DEFAULT 'active',
			password_hash TEXT,
			home_dir TEXT NOT NULL,
			filesystem TEXT,
			permissions TEXT,
			filters TEXT,
			quotas TEXT,
			bandwidth_limits TEXT,
			transfer_limits TEXT,
			mfa_enabled BOOLEAN DEFAULT FALSE,
			max_sessions INTEGER DEFAULT 10,
			allowed_protocols TEXT,
			denied_protocols TEXT,
			ip_filters TEXT,
			mfa_secret TEXT,
			mfa_recovery_codes TEXT,
			expiration_date DATETIME,
			description TEXT,
			password_changed_at TEXT,
			protocol_permissions TEXT,
			last_login_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			client_ip TEXT,
			connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE admin_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT UNIQUE NOT NULL,
			admin_id INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			client_ip TEXT,
			connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			actor_type TEXT NOT NULL,
			actor_name TEXT,
			target_type TEXT,
			target_id TEXT,
			protocol TEXT,
			client_ip TEXT,
			result TEXT NOT NULL,
			error_message TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE transfer_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			operation TEXT NOT NULL,
			username TEXT NOT NULL,
			protocol TEXT NOT NULL,
			connection_id TEXT,
			local_address TEXT,
			remote_address TEXT,
			file_path TEXT NOT NULL,
			file_size INTEGER,
			bytes_transferred INTEGER,
			start_time DATETIME,
			end_time DATETIME,
			duration_ms INTEGER,
			status TEXT NOT NULL,
			error TEXT,
			ftp_mode TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE http_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			username TEXT,
			client_ip TEXT,
			user_agent TEXT,
			response_time_ms INTEGER,
			request_size INTEGER,
			response_size INTEGER,
			auth_method TEXT,
			error TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE shares (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			share_type TEXT NOT NULL,
			path TEXT NOT NULL,
			password_hash TEXT,
			expires_at DATETIME,
			max_downloads INTEGER,
			max_uploads INTEGER,
			download_count INTEGER DEFAULT 0,
			upload_count INTEGER DEFAULT 0,
			ip_restrictions TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE public_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			label TEXT,
			public_key TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE event_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			trigger_type TEXT NOT NULL,
			conditions TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			schedule TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE event_actions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id INTEGER NOT NULL,
			action_type TEXT NOT NULL,
			action_config TEXT NOT NULL,
			order_index INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE event_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id INTEGER NOT NULL,
			action_id INTEGER NOT NULL,
			event_type TEXT NOT NULL,
			payload TEXT,
			result TEXT NOT NULL,
			error_message TEXT,
			executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("exec schema failed: %v", err)
		}
	}

	seedAdmin(t, db, "admin", "admin-pass")
	if _, err := db.Exec("INSERT INTO event_rules (name, trigger_type, conditions, is_active) VALUES (?, ?, ?, TRUE)", "login-command", "login", "[]"); err != nil {
		t.Fatalf("seed event rule failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO event_actions (rule_id, action_type, action_config, order_index) VALUES (?, ?, ?, ?)", 1, "command", `{"command":"/bin/echo","args":["event-ok"]}`, 0); err != nil {
		t.Fatalf("seed event action failed: %v", err)
	}

	dbWrapper := &database.DB{DB: db}
	auditRepo := repository.NewAuditRepository(dbWrapper)
	userRepo := repository.NewUserRepository(dbWrapper)
	shareRepo := repository.NewShareRepository(dbWrapper)
	eventRepo := repository.NewEventRepository(dbWrapper)
	metricsCollector := metrics.NewCollector(config.TelemetryConfig{}, zap.NewNop())
	policyEngine := policy.NewPolicyEngine(userRepo)
	shareManager := shares.NewManagerWithDependencies(shareRepo, userRepo, auditRepo, metricsCollector, zap.NewNop())
	eventManager := events.NewManagerWithOptions(zap.NewNop(), []string{"/bin/echo", "echo"}, eventRepo, metricsCollector, time.Second)
	eventManager.AddRule(&events.EventRule{
		ID:          999,
		Name:        "login-command-memory",
		TriggerType: events.EventLogin,
		Actions: []events.ActionConfig{
			{
				ID:   999,
				Type: events.ActionCommand,
				Config: map[string]interface{}{
					"command": "/bin/echo",
					"args":    []string{"event-ok"},
				},
			},
		},
		IsActive: true,
	})
	eventManager.StopCron()

	s := NewServerWithDependencies(config.HTTPDConfig{
		RESTAPIEnabled: true,
		Enabled:        true,
		SessionSecret:  "test-session-secret-1234567890",
		JWT: config.JWTConfig{
			Enabled:       true,
			Issuer:        "test-suite",
			Audience:      "test-api",
			ExpirySeconds: 3600,
		},
		APIKeys: []config.APIKeyConfig{
			{
				Key:     "integration-admin-key",
				Subject: "integration-admin",
				Role:    "admin",
				Scopes:  []string{"*"},
				Enabled: true,
			},
		},
	}, zap.NewNop(), ServerDependencies{
		DB:               db,
		UserRepo:         userRepo,
		PolicyEngine:     policyEngine,
		ShareManager:     shareManager,
		AuditRepo:        auditRepo,
		EventManager:     eventManager,
		MetricsCollector: metricsCollector,
		ProtocolEnabled: map[string]bool{
			"http": true,
		},
		TelemetryEnabled: true,
	})
	ts := httptest.NewUnstartedServer(s.Router())
	ts.EnableHTTP2 = false
	ts.Start()

	cleanup := func() {
		eventManager.Shutdown(context.Background())
		ts.CloseClientConnections()
		ts.Config.SetKeepAlivesEnabled(false)
		ts.Close()
		_ = db.Close()
	}
	return ts, db, cleanup
}

func TestAdminAPIKeyAccess(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/users", nil)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	req.Header.Set("X-API-Key", "integration-admin-key")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api key access status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestAdminLoginReturnsJWTWhenEnabled(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	resp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "admin",
		"password": "admin-pass",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]any
	decodeJSON(t, resp.Body, &payload)
	token, _ := payload["token"].(string)
	tokenType, _ := payload["token_type"].(string)
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected jwt token, got %q", token)
	}
	if tokenType != "jwt" {
		t.Fatalf("token_type = %q, want jwt", tokenType)
	}
}

func TestAdminLoginRequiresValidMFACode(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	secret, err := authn.NewTOTPAuthenticator("SFTPxy").GenerateSecret()
	if err != nil {
		t.Fatalf("generate admin MFA secret failed: %v", err)
	}
	if _, err := db.Exec("UPDATE admins SET mfa_enabled = TRUE, mfa_secret = ? WHERE username = ?", secret, "admin"); err != nil {
		t.Fatalf("enable admin MFA failed: %v", err)
	}

	missingCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "admin",
		"password": "admin-pass",
	})
	if missingCodeResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing admin MFA code status = %d, want %d", missingCodeResp.StatusCode, http.StatusUnauthorized)
	}
	var missingPayload map[string]any
	decodeJSON(t, missingCodeResp.Body, &missingPayload)
	if missingPayload["mfa_required"] != true {
		t.Fatalf("expected admin mfa_required=true, got %+v", missingPayload)
	}

	invalidCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "admin",
		"password": "admin-pass",
		"mfa_code": "123456",
	})
	if invalidCodeResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid admin MFA code status = %d, want %d", invalidCodeResp.StatusCode, http.StatusUnauthorized)
	}

	validCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate valid admin MFA code failed: %v", err)
	}
	validCodeResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "admin",
		"password": "admin-pass",
		"mfa_code": validCode,
	})
	if validCodeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(validCodeResp.Body)
		t.Fatalf("valid admin MFA login status = %d, want %d, body=%s", validCodeResp.StatusCode, http.StatusOK, string(body))
	}
}

func TestAdminRefreshRevokesPreviousJWT(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	oldToken := loginAdmin(t, server)

	refreshResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", oldToken, nil)
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("admin refresh status = %d, want %d, body=%s", refreshResp.StatusCode, http.StatusOK, string(body))
	}
	var refreshPayload map[string]any
	decodeJSON(t, refreshResp.Body, &refreshPayload)
	newToken, _ := refreshPayload["token"].(string)
	if newToken == "" || newToken == oldToken {
		t.Fatalf("expected rotated admin token, got old=%q new=%q", oldToken, newToken)
	}

	oldUsersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", oldToken, nil)
	if oldUsersResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old admin token status = %d, want %d", oldUsersResp.StatusCode, http.StatusUnauthorized)
	}

	newUsersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", newToken, nil)
	if newUsersResp.StatusCode != http.StatusOK {
		t.Fatalf("new admin token status = %d, want %d", newUsersResp.StatusCode, http.StatusOK)
	}
}

func TestAdminLoginPersistsSessionAndRefreshKeepsSingleActiveRecord(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	oldToken := loginAdmin(t, server)

	var activeSessions int
	if err := db.QueryRow("SELECT COUNT(*) FROM admin_sessions WHERE admin_id = 1 AND is_active = TRUE").Scan(&activeSessions); err != nil {
		t.Fatalf("count initial admin sessions failed: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("initial active admin sessions = %d, want 1", activeSessions)
	}

	refreshResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/refresh", oldToken, nil)
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("admin refresh status = %d, want %d, body=%s", refreshResp.StatusCode, http.StatusOK, string(body))
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM admin_sessions WHERE admin_id = 1 AND is_active = TRUE").Scan(&activeSessions); err != nil {
		t.Fatalf("count refreshed admin sessions failed: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("refreshed active admin sessions = %d, want 1", activeSessions)
	}
}

func TestDisabledAdminTokenIsRevokedAfterStatusChange(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	rootAdminToken := loginAdmin(t, server)

	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/admins", rootAdminToken, map[string]any{
		"username":    "disabled-admin",
		"password":    "disabled-admin-pass",
		"status":      "active",
		"permissions": []string{"*"},
	})
	if createResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create disabled-admin status = %d, want %d, body=%s", createResp.StatusCode, http.StatusOK, string(body))
	}
	var createdAdmin map[string]any
	decodeJSON(t, createResp.Body, &createdAdmin)
	adminID := toStringID(t, createdAdmin["id"])

	disabledAdminToken := loginAdminWithCredentials(t, server, "disabled-admin", "disabled-admin-pass")

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/admins/"+adminID, rootAdminToken, map[string]any{
		"status":      "disabled",
		"permissions": []string{"*"},
	})
	if updateResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("disable admin status = %d, want %d, body=%s", updateResp.StatusCode, http.StatusOK, string(body))
	}

	usersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", disabledAdminToken, nil)
	if usersResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled admin token status = %d, want %d", usersResp.StatusCode, http.StatusUnauthorized)
	}
}

func TestBuildOIDCSessionRejectsAdminRoleHintWithoutProviderRole(t *testing.T) {
	baseServer, db, cleanup := newTestServer(t)
	defer cleanup()
	defer baseServer.Close()

	s := newConfiguredServer(t, db, nil, func(cfg *config.HTTPDConfig) {
		cfg.OIDC = config.OIDCConfig{
			Enabled:         true,
			AllowAdmin:      true,
			AllowUser:       true,
			AutoCreateUsers: true,
		}
	})

	_, _, err := s.buildOIDCSession(context.Background(), &authn.OIDCIdentity{
		Username: "admin",
	}, oidcState{
		RoleHint: "admin",
		ReturnTo: "/admin",
	})
	if err == nil || !strings.Contains(err.Error(), "admin role not granted") {
		t.Fatalf("expected oidc admin role rejection, got %v", err)
	}
}

func TestBuildOIDCRedirectURLUsesFragment(t *testing.T) {
	redirectURL := buildOIDCRedirectURL("/client/login?redirect=%2Fclient%2Ffiles", "token-123", "jwt", "alice", "user")
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect url failed: %v", err)
	}
	if parsed.RawQuery != "redirect=%2Fclient%2Ffiles" {
		t.Fatalf("raw query = %q, want redirect preserved", parsed.RawQuery)
	}
	if strings.Contains(parsed.RawQuery, "token=") {
		t.Fatalf("token should not be present in query: %q", parsed.RawQuery)
	}
	fragmentValues, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatalf("parse fragment failed: %v", err)
	}
	if fragmentValues.Get("token") != "token-123" {
		t.Fatalf("fragment token = %q, want token-123", fragmentValues.Get("token"))
	}
	if fragmentValues.Get("role") != "user" {
		t.Fatalf("fragment role = %q, want user", fragmentValues.Get("role"))
	}
}

func TestGetConnectionsIncludesAdminSessions(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	adminToken := loginAdmin(t, server)

	resp := doJSONRequest(t, server, http.MethodGet, "/api/v1/connections", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("connections status = %d, want %d, body=%s", resp.StatusCode, http.StatusOK, string(body))
	}
	var connections []map[string]any
	decodeJSON(t, resp.Body, &connections)
	foundAdmin := false
	for _, item := range connections {
		if item["username"] == "admin" && item["principal"] == "admin" {
			foundAdmin = true
			break
		}
	}
	if !foundAdmin {
		t.Fatalf("expected admin session in connections list, got %+v", connections)
	}
}

func TestFindOrProvisionLDAPUserRejectsPathTraversalUsername(t *testing.T) {
	baseServer, db, cleanup := newTestServer(t)
	defer cleanup()
	defer baseServer.Close()

	s := newConfiguredServer(t, db, nil, func(cfg *config.HTTPDConfig) {
		cfg.LDAP = config.LDAPConfig{
			Enabled:         true,
			AutoCreateUsers: true,
			UserHomeBaseDir: filepath.Join(t.TempDir(), "ldap-users"),
		}
	})

	_, err := s.findOrProvisionLDAPUser(context.Background(), &authn.LDAPUser{
		Username: "../escape",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid path characters") {
		t.Fatalf("expected ldap provision rejection, got %v", err)
	}
}

func TestFindOrProvisionOIDCUserRejectsPathTraversalUsername(t *testing.T) {
	baseServer, db, cleanup := newTestServer(t)
	defer cleanup()
	defer baseServer.Close()

	s := newConfiguredServer(t, db, nil, func(cfg *config.HTTPDConfig) {
		cfg.OIDC = config.OIDCConfig{
			Enabled:         true,
			AutoCreateUsers: true,
			UserHomeBaseDir: filepath.Join(t.TempDir(), "oidc-users"),
		}
	})

	_, err := s.findOrProvisionOIDCUser(context.Background(), &authn.OIDCIdentity{
		Username: "..\\escape",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid path characters") {
		t.Fatalf("expected oidc provision rejection, got %v", err)
	}
}

func TestAdminRBACCrudAPIContract(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	adminToken := loginAdmin(t, server)

	createRoleResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/roles", adminToken, map[string]interface{}{
		"name":        "ops-admin",
		"description": "Operations administrator",
		"permissions": []string{"admins:read", "admins:write"},
		"scope": map[string]interface{}{
			"tenant": "default",
		},
	})
	if createRoleResp.StatusCode != http.StatusOK {
		t.Fatalf("create role status = %d, want %d", createRoleResp.StatusCode, http.StatusOK)
	}
	var createdRole map[string]interface{}
	decodeJSON(t, createRoleResp.Body, &createdRole)
	roleID := toStringID(t, createdRole["id"])

	listRolesResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/roles", adminToken, nil)
	if listRolesResp.StatusCode != http.StatusOK {
		t.Fatalf("list roles status = %d, want %d", listRolesResp.StatusCode, http.StatusOK)
	}
	var roles []map[string]interface{}
	decodeJSON(t, listRolesResp.Body, &roles)
	if len(roles) != 1 || roles[0]["name"] != "ops-admin" {
		t.Fatalf("unexpected roles payload: %+v", roles)
	}
	rolePermissions, ok := roles[0]["permissions"].([]interface{})
	if !ok || len(rolePermissions) != 2 {
		t.Fatalf("unexpected role permissions: %+v", roles[0]["permissions"])
	}

	updateRoleResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/roles/"+roleID, adminToken, map[string]interface{}{
		"name":        "ops-admin",
		"description": "Operations administrator updated",
		"permissions": []string{"admins:read", "admins:write", "groups:write"},
		"scope": map[string]interface{}{
			"tenant": "prod",
		},
	})
	if updateRoleResp.StatusCode != http.StatusOK {
		t.Fatalf("update role status = %d, want %d", updateRoleResp.StatusCode, http.StatusOK)
	}

	createGroupResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/groups", adminToken, map[string]interface{}{
		"name":        "ops-team",
		"description": "Operations team",
	})
	if createGroupResp.StatusCode != http.StatusOK {
		t.Fatalf("create group status = %d, want %d", createGroupResp.StatusCode, http.StatusOK)
	}
	var createdGroup map[string]interface{}
	decodeJSON(t, createGroupResp.Body, &createdGroup)
	groupID := toStringID(t, createdGroup["id"])

	listGroupsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/groups", adminToken, nil)
	if listGroupsResp.StatusCode != http.StatusOK {
		t.Fatalf("list groups status = %d, want %d", listGroupsResp.StatusCode, http.StatusOK)
	}
	var groups []map[string]interface{}
	decodeJSON(t, listGroupsResp.Body, &groups)
	if len(groups) != 1 || groups[0]["name"] != "ops-team" {
		t.Fatalf("unexpected groups payload: %+v", groups)
	}

	updateGroupResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/groups/"+groupID, adminToken, map[string]interface{}{
		"name":        "ops-team-updated",
		"description": "Operations team updated",
	})
	if updateGroupResp.StatusCode != http.StatusOK {
		t.Fatalf("update group status = %d, want %d", updateGroupResp.StatusCode, http.StatusOK)
	}

	roleIDInt, err := strconv.ParseInt(roleID, 10, 64)
	if err != nil {
		t.Fatalf("parse role id failed: %v", err)
	}
	createAdminResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/admins", adminToken, map[string]interface{}{
		"username": "ops-admin-user",
		"password": "ops-admin-pass",
		"status":   "active",
		"role_id":  roleIDInt,
	})
	if createAdminResp.StatusCode != http.StatusOK {
		t.Fatalf("create admin status = %d, want %d", createAdminResp.StatusCode, http.StatusOK)
	}
	var createdAdmin map[string]interface{}
	decodeJSON(t, createAdminResp.Body, &createdAdmin)
	adminID := toStringID(t, createdAdmin["id"])

	listAdminsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/admins", adminToken, nil)
	if listAdminsResp.StatusCode != http.StatusOK {
		t.Fatalf("list admins status = %d, want %d", listAdminsResp.StatusCode, http.StatusOK)
	}
	var admins []map[string]interface{}
	decodeJSON(t, listAdminsResp.Body, &admins)
	if len(admins) != 2 {
		t.Fatalf("admin count = %d, want 2", len(admins))
	}
	var foundRBACAdmin map[string]interface{}
	for _, item := range admins {
		if item["username"] == "ops-admin-user" {
			foundRBACAdmin = item
			break
		}
	}
	if foundRBACAdmin == nil {
		t.Fatalf("expected created admin in payload: %+v", admins)
	}
	if toStringID(t, foundRBACAdmin["role_id"]) != roleID {
		t.Fatalf("admin role_id = %v, want %s", foundRBACAdmin["role_id"], roleID)
	}

	updateAdminResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/admins/"+adminID, adminToken, map[string]interface{}{
		"status":  "disabled",
		"role_id": roleIDInt,
	})
	if updateAdminResp.StatusCode != http.StatusOK {
		t.Fatalf("update admin status = %d, want %d", updateAdminResp.StatusCode, http.StatusOK)
	}

	listAdminsResp = doJSONRequest(t, server, http.MethodGet, "/api/v1/admins", adminToken, nil)
	if listAdminsResp.StatusCode != http.StatusOK {
		t.Fatalf("list admins after update status = %d, want %d", listAdminsResp.StatusCode, http.StatusOK)
	}
	decodeJSON(t, listAdminsResp.Body, &admins)
	foundRBACAdmin = nil
	for _, item := range admins {
		if item["username"] == "ops-admin-user" {
			foundRBACAdmin = item
			break
		}
	}
	if foundRBACAdmin == nil || foundRBACAdmin["status"] != "disabled" {
		t.Fatalf("unexpected updated admin payload: %+v", foundRBACAdmin)
	}

	deleteAdminResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/admins/"+adminID, adminToken, nil)
	if deleteAdminResp.StatusCode != http.StatusOK {
		t.Fatalf("delete admin status = %d, want %d", deleteAdminResp.StatusCode, http.StatusOK)
	}

	deleteGroupResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/groups/"+groupID, adminToken, nil)
	if deleteGroupResp.StatusCode != http.StatusOK {
		t.Fatalf("delete group status = %d, want %d", deleteGroupResp.StatusCode, http.StatusOK)
	}

	deleteRoleResp := doJSONRequest(t, server, http.MethodDelete, "/api/v1/roles/"+roleID, adminToken, nil)
	if deleteRoleResp.StatusCode != http.StatusOK {
		t.Fatalf("delete role status = %d, want %d", deleteRoleResp.StatusCode, http.StatusOK)
	}
}

func TestRestrictedAdminPermissionsAreEnforced(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	result, err := db.Exec(
		"INSERT INTO roles (name, description, permissions, scope) VALUES (?, ?, ?, ?)",
		"group-reader",
		"Restricted group reader",
		`["groups:read"]`,
		`{}`,
	)
	if err != nil {
		t.Fatalf("seed role failed: %v", err)
	}
	roleID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read role id failed: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("limited-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash restricted admin password failed: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO admins (username, password_hash, status, permissions, role_id) VALUES (?, ?, ?, ?, ?)",
		"limited-admin",
		string(hash),
		"active",
		`[]`,
		roleID,
	); err != nil {
		t.Fatalf("seed restricted admin failed: %v", err)
	}

	loginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "limited-admin",
		"password": "limited-pass",
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("restricted admin login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	var loginPayload map[string]interface{}
	decodeJSON(t, loginResp.Body, &loginPayload)
	token, _ := loginPayload["token"].(string)
	t.Logf("DEBUG loginPayload: %+v", loginPayload)
	if token == "" {
		t.Fatalf("restricted admin token should not be empty")
	}

	groupsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/groups", token, nil)
	if groupsResp.StatusCode != http.StatusOK {
		t.Fatalf("restricted admin groups status = %d, want %d", groupsResp.StatusCode, http.StatusOK)
	}

	usersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", token, nil)
	if usersResp.StatusCode != http.StatusForbidden {
		t.Fatalf("restricted admin users status = %d, want %d", usersResp.StatusCode, http.StatusForbidden)
	}
}

func TestRestrictedAdminScopeFiltersUsersConnectionsAndLogs(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	teamHome := filepath.Join(t.TempDir(), "team-alice")
	otherHome := filepath.Join(t.TempDir(), "other-bob")
	if err := os.MkdirAll(teamHome, 0o755); err != nil {
		t.Fatalf("mkdir team home failed: %v", err)
	}
	if err := os.MkdirAll(otherHome, 0o755); err != nil {
		t.Fatalf("mkdir other home failed: %v", err)
	}
	seedUser(t, db, "team-alice", "team-pass", teamHome)
	seedUser(t, db, "other-bob", "other-pass", otherHome)

	var teamUserID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "team-alice").Scan(&teamUserID); err != nil {
		t.Fatalf("load team user id failed: %v", err)
	}
	var otherUserID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "other-bob").Scan(&otherUserID); err != nil {
		t.Fatalf("load other user id failed: %v", err)
	}

	if _, err := db.Exec("INSERT INTO sessions (session_id, user_id, protocol, client_ip, is_active) VALUES (?, ?, ?, ?, TRUE)", "scope-team-session", teamUserID, "sftp", "10.0.0.10"); err != nil {
		t.Fatalf("seed team session failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO sessions (session_id, user_id, protocol, client_ip, is_active) VALUES (?, ?, ?, ?, TRUE)", "scope-other-session", otherUserID, "sftp", "10.0.0.20"); err != nil {
		t.Fatalf("seed other session failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO audit_logs (event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "evt-team", "download", "user", "team-alice", "file", "/docs/a.txt", "sftp", "10.0.0.10", "success", ""); err != nil {
		t.Fatalf("seed team audit log failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO audit_logs (event_id, event_type, actor_type, actor_name, target_type, target_id, protocol, client_ip, result, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "evt-other", "download", "user", "other-bob", "file", "/docs/b.txt", "sftp", "10.0.0.20", "success", ""); err != nil {
		t.Fatalf("seed other audit log failed: %v", err)
	}

	roleScope := `{"users":{"username_prefixes":["team-"]},"connections":{"username_prefixes":["team-"]},"logs":{"username_prefixes":["team-"]}}`
	result, err := db.Exec(
		"INSERT INTO roles (name, description, permissions, scope) VALUES (?, ?, ?, ?)",
		"team-admin",
		"Team scoped admin",
		`["users:read","users:write","connections:read","logs:read"]`,
		roleScope,
	)
	if err != nil {
		t.Fatalf("seed scoped role failed: %v", err)
	}
	roleID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read scoped role id failed: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("scoped-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash scoped admin password failed: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO admins (username, password_hash, status, permissions, role_id) VALUES (?, ?, ?, ?, ?)",
		"scoped-admin",
		string(hash),
		"active",
		`[]`,
		roleID,
	); err != nil {
		t.Fatalf("seed scoped admin failed: %v", err)
	}

	loginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "scoped-admin",
		"password": "scoped-pass",
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("scoped admin login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	var loginPayload map[string]interface{}
	decodeJSON(t, loginResp.Body, &loginPayload)
	token, _ := loginPayload["token"].(string)
	if token == "" {
		t.Fatalf("scoped admin token should not be empty")
	}

	usersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", token, nil)
	if usersResp.StatusCode != http.StatusOK {
		t.Fatalf("scoped admin list users status = %d, want %d", usersResp.StatusCode, http.StatusOK)
	}
	var users []map[string]interface{}
	decodeJSON(t, usersResp.Body, &users)
	if len(users) != 1 || users[0]["username"] != "team-alice" {
		t.Fatalf("unexpected scoped users payload: %+v", users)
	}

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/users/"+strconv.FormatInt(otherUserID, 10), token, map[string]interface{}{
		"status": "disabled",
	})
	if updateResp.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped admin update other user status = %d, want %d", updateResp.StatusCode, http.StatusForbidden)
	}

	connectionsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/connections", token, nil)
	if connectionsResp.StatusCode != http.StatusOK {
		t.Fatalf("scoped admin list connections status = %d, want %d", connectionsResp.StatusCode, http.StatusOK)
	}
	var connections []map[string]interface{}
	decodeJSON(t, connectionsResp.Body, &connections)
	if len(connections) != 1 || connections[0]["username"] != "team-alice" {
		t.Fatalf("unexpected scoped connections payload: %+v", connections)
	}

	logsResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/logs?page=1&limit=20", token, nil)
	if logsResp.StatusCode != http.StatusOK {
		t.Fatalf("scoped admin list logs status = %d, want %d", logsResp.StatusCode, http.StatusOK)
	}
	var logsPayload struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	decodeJSON(t, logsResp.Body, &logsPayload)
	foundOther := false
	foundTeam := false
	for _, item := range logsPayload.Items {
		if item["username"] == "other-bob" {
			foundOther = true
		}
		if item["username"] == "team-alice" {
			foundTeam = true
		}
	}
	if foundOther || !foundTeam {
		t.Fatalf("unexpected scoped logs payload: %+v", logsPayload.Items)
	}
}

func TestUserCrudPersistsGroupAndRoleBindings(t *testing.T) {
	server, _, cleanup := newTestServer(t)
	defer cleanup()

	adminToken := loginAdmin(t, server)

	groupResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/groups", adminToken, map[string]any{
		"name":        "engineering",
		"description": "Engineering",
	})
	if groupResp.StatusCode != http.StatusOK {
		t.Fatalf("create group status = %d, want %d", groupResp.StatusCode, http.StatusOK)
	}
	var createdGroup map[string]any
	decodeJSON(t, groupResp.Body, &createdGroup)
	groupID := int64(createdGroup["id"].(float64))

	roleResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/roles", adminToken, map[string]any{
		"name":        "developer",
		"description": "Developer",
		"permissions": []string{"files:read"},
		"scope":       map[string]any{},
	})
	if roleResp.StatusCode != http.StatusOK {
		t.Fatalf("create role status = %d, want %d", roleResp.StatusCode, http.StatusOK)
	}
	var createdRole map[string]any
	decodeJSON(t, roleResp.Body, &createdRole)
	roleID := int64(createdRole["id"].(float64))

	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/users", adminToken, map[string]any{
		"username":       "grouped-user",
		"email":          "grouped@example.com",
		"home_directory": filepath.Join(t.TempDir(), "grouped-user"),
		"status":         "active",
		"password":       "grouped-pass",
		"group_ids":      []int64{groupID},
		"role_ids":       []int64{roleID},
	})
	if createResp.StatusCode != http.StatusOK {
		t.Fatalf("create user status = %d, want %d", createResp.StatusCode, http.StatusOK)
	}
	var createdUser map[string]any
	decodeJSON(t, createResp.Body, &createdUser)
	userID := int64(createdUser["id"].(float64))

	listResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", adminToken, nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list users status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}
	var users []map[string]any
	decodeJSON(t, listResp.Body, &users)
	var found map[string]any
	for _, item := range users {
		if item["username"] == "grouped-user" {
			found = item
			break
		}
	}
	if found == nil {
		t.Fatalf("created user not found in list: %+v", users)
	}
	if len(found["group_ids"].([]interface{})) != 1 || int64(found["group_ids"].([]interface{})[0].(float64)) != groupID {
		t.Fatalf("unexpected user group ids: %+v", found["group_ids"])
	}
	if len(found["role_ids"].([]interface{})) != 1 || int64(found["role_ids"].([]interface{})[0].(float64)) != roleID {
		t.Fatalf("unexpected user role ids: %+v", found["role_ids"])
	}

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/users/"+strconv.FormatInt(userID, 10), adminToken, map[string]any{
		"email":          "updated@example.com",
		"home_directory": filepath.Join(t.TempDir(), "grouped-user-updated"),
		"status":         "disabled",
		"group_ids":      []int64{},
		"role_ids":       []int64{},
	})
	if updateResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("update user status = %d, want %d, body: %s", updateResp.StatusCode, http.StatusOK, string(bodyBytes))
	}
	var updatedUser map[string]any
	decodeJSON(t, updateResp.Body, &updatedUser)
	if len(updatedUser["group_ids"].([]interface{})) != 0 || len(updatedUser["role_ids"].([]interface{})) != 0 {
		t.Fatalf("expected empty bindings after update: %+v", updatedUser)
	}
}

func TestRestrictedAdminScopeByGroupIDs(t *testing.T) {
	server, db, cleanup := newTestServer(t)
	defer cleanup()

	teamHome := filepath.Join(t.TempDir(), "team-user")
	otherHome := filepath.Join(t.TempDir(), "other-user")
	if err := os.MkdirAll(teamHome, 0o755); err != nil {
		t.Fatalf("mkdir team home failed: %v", err)
	}
	if err := os.MkdirAll(otherHome, 0o755); err != nil {
		t.Fatalf("mkdir other home failed: %v", err)
	}
	seedUser(t, db, "team-member", "team-pass", teamHome)
	seedUser(t, db, "other-member", "other-pass", otherHome)

	groupResult, err := db.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", "team-group", "Team group")
	if err != nil {
		t.Fatalf("seed group failed: %v", err)
	}
	groupID, err := groupResult.LastInsertId()
	if err != nil {
		t.Fatalf("read group id failed: %v", err)
	}
	otherGroupResult, err := db.Exec("INSERT INTO groups (name, description) VALUES (?, ?)", "other-group", "Other group")
	if err != nil {
		t.Fatalf("seed other group failed: %v", err)
	}
	otherGroupID, err := otherGroupResult.LastInsertId()
	if err != nil {
		t.Fatalf("read other group id failed: %v", err)
	}

	var teamUserID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "team-member").Scan(&teamUserID); err != nil {
		t.Fatalf("load team user id failed: %v", err)
	}
	var otherUserID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "other-member").Scan(&otherUserID); err != nil {
		t.Fatalf("load other user id failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", teamUserID, groupID); err != nil {
		t.Fatalf("assign team group failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", otherUserID, otherGroupID); err != nil {
		t.Fatalf("assign other group failed: %v", err)
	}

	roleScope := fmt.Sprintf(`{"users":{"group_ids":[%d]}}`, groupID)
	roleResult, err := db.Exec(
		"INSERT INTO roles (name, description, permissions, scope) VALUES (?, ?, ?, ?)",
		"team-scope-admin",
		"Team scoped admin",
		`["users:read","users:write"]`,
		roleScope,
	)
	if err != nil {
		t.Fatalf("seed scoped role failed: %v", err)
	}
	roleID, err := roleResult.LastInsertId()
	if err != nil {
		t.Fatalf("read scoped role id failed: %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("scoped-group-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash scoped admin password failed: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO admins (username, password_hash, status, permissions, role_id) VALUES (?, ?, ?, ?, ?)",
		"group-scoped-admin",
		string(hash),
		"active",
		`[]`,
		roleID,
	); err != nil {
		t.Fatalf("seed scoped admin failed: %v", err)
	}

	loginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "group-scoped-admin",
		"password": "scoped-group-pass",
	})
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("group-scoped admin login status = %d, want %d", loginResp.StatusCode, http.StatusOK)
	}
	var loginPayload map[string]any
	decodeJSON(t, loginResp.Body, &loginPayload)
	token, _ := loginPayload["token"].(string)
	if token == "" {
		t.Fatalf("group-scoped admin token should not be empty")
	}

	usersResp := doJSONRequest(t, server, http.MethodGet, "/api/v1/users", token, nil)
	if usersResp.StatusCode != http.StatusOK {
		t.Fatalf("group-scoped admin list users status = %d, want %d", usersResp.StatusCode, http.StatusOK)
	}
	var users []map[string]any
	decodeJSON(t, usersResp.Body, &users)
	if len(users) != 1 || users[0]["username"] != "team-member" {
		t.Fatalf("unexpected group-scoped users payload: %+v", users)
	}

	updateResp := doJSONRequest(t, server, http.MethodPut, "/api/v1/users/"+strconv.FormatInt(otherUserID, 10), token, map[string]any{
		"status": "disabled",
	})
	if updateResp.StatusCode != http.StatusForbidden {
		t.Fatalf("group-scoped admin update other user status = %d, want %d", updateResp.StatusCode, http.StatusForbidden)
	}

	createResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/users", token, map[string]any{
		"username":       "blocked-new-user",
		"email":          "blocked@example.com",
		"home_directory": "/home/blocked-new-user",
		"status":         "active",
		"password":       "blocked-pass",
		"group_ids":      []int64{otherGroupID},
	})
	if createResp.StatusCode != http.StatusForbidden {
		t.Fatalf("group-scoped admin create other-group user status = %d, want %d", createResp.StatusCode, http.StatusForbidden)
	}
}

func seedAdmin(t *testing.T, db *sql.DB, username, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash admin password failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO admins (username, password_hash, status, permissions) VALUES (?, ?, 'active', ?)", username, string(hash), `["*"]`); err != nil {
		t.Fatalf("seed admin failed: %v", err)
	}
}

func seedUser(t *testing.T, db *sql.DB, username, password, homeDir string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash user password failed: %v", err)
	}
	perms, _ := json.Marshal([]map[string]interface{}{
		{"path": "/", "list": true, "download": true, "upload": true, "rename": true, "create_dirs": true, "delete": true},
	})
	if _, err := db.Exec("INSERT INTO users (username, password_hash, status, home_dir, mfa_enabled, permissions) VALUES (?, ?, 'active', ?, FALSE, ?)", username, string(hash), homeDir, string(perms)); err != nil {
		t.Fatalf("seed user failed: %v", err)
	}
}

func loginAdmin(t *testing.T, server *httptest.Server) string {
	return loginAdminWithCredentials(t, server, "admin", "admin-pass")
}

func loginAdminWithCredentials(t *testing.T, server *httptest.Server, username, password string) string {
	t.Helper()
	resp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": username,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]interface{}
	decodeJSON(t, resp.Body, &payload)
	token, _ := payload["token"].(string)
	if token == "" {
		t.Fatalf("admin token should not be empty")
	}
	return token
}

func loginUser(t *testing.T, server *httptest.Server, username, password string) string {
	t.Helper()
	resp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": username,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user login status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var payload map[string]interface{}
	decodeJSON(t, resp.Body, &payload)
	token, _ := payload["token"].(string)
	if token == "" {
		t.Fatalf("user token should not be empty")
	}
	return token
}

func doJSONRequest(t *testing.T, server *httptest.Server, method, path, token string, payload interface{}) *http.Response {
	t.Helper()

	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload failed: %v", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, server.URL+path, body)
	if err != nil {
		t.Fatalf("create request failed: %v", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Close = true

	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do request failed: %v", err)
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body failed: %v", err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	return resp
}

func newConfiguredServer(t *testing.T, db *sql.DB, fullConfig *config.Config, mutate func(*config.HTTPDConfig)) *Server {
	t.Helper()
	httpConfig := config.HTTPDConfig{
		RESTAPIEnabled: true,
		Enabled:        true,
		SessionSecret:  "test-session-secret-1234567890",
		JWT: config.JWTConfig{
			Enabled:       true,
			Issuer:        "test-suite",
			Audience:      "test-api",
			ExpirySeconds: 3600,
		},
	}
	if mutate != nil {
		mutate(&httpConfig)
	}
	return NewServerWithDependencies(httpConfig, zap.NewNop(), ServerDependencies{
		DB:         db,
		FullConfig: fullConfig,
	})
}

func newConfiguredHTTPServer(t *testing.T, db *sql.DB, fullConfig *config.Config, mutate func(*config.HTTPDConfig)) *httptest.Server {
	t.Helper()
	s := newConfiguredServer(t, db, fullConfig, mutate)
	ts := httptest.NewUnstartedServer(s.Router())
	ts.EnableHTTP2 = false
	ts.Start()
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Config.SetKeepAlivesEnabled(false)
		ts.Close()
	})
	return ts
}

func uploadFileRequest(t *testing.T, server *httptest.Server, token, path, filename, content string) *http.Response {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file failed: %v", err)
	}
	if _, err := io.Copy(part, strings.NewReader(content)); err != nil {
		t.Fatalf("write multipart content failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer failed: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/files/upload?path="+path, &body)
	if err != nil {
		t.Fatalf("create upload request failed: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do upload request failed: %v", err)
	}
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})
	return resp
}

func decodeJSON(t *testing.T, r io.Reader, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(target); err != nil {
		t.Fatalf("decode json failed: %v", err)
	}
}

func toStringID(t *testing.T, value interface{}) string {
	t.Helper()
	switch v := value.(type) {
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case string:
		return v
	default:
		t.Fatalf("unsupported id type %T", value)
		return ""
	}
}
