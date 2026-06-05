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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/database"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/shares"
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
	if len(connections) != 1 {
		t.Fatalf("connection count = %d, want 1", len(connections))
	}
	connectionID, _ := connections[0]["id"].(string)
	if connectionID == "" {
		t.Fatalf("connection id should not be empty")
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

	if _, err := db.Exec("UPDATE users SET quotas = ?, mfa_enabled = TRUE WHERE username = ?", `{"max_size":1048576,"current_size":512}`, "dave"); err != nil {
		t.Fatalf("seed user quota failed: %v", err)
	}
	var userID int64
	if err := db.QueryRow("SELECT id FROM users WHERE username = ?", "dave").Scan(&userID); err != nil {
		t.Fatalf("load user id failed: %v", err)
	}
	if _, err := db.Exec("INSERT INTO public_keys (user_id, label, public_key) VALUES (?, ?, ?)", userID, "workstation", "ssh-ed25519 AAAATEST dave@workstation"); err != nil {
		t.Fatalf("seed public key failed: %v", err)
	}

	loginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "dave",
		"password": "dave-pass",
		"mfa_code": "123456",
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

	reloginResp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/user/login", "", map[string]string{
		"username": "dave",
		"password": "dave-pass-2",
		"mfa_code": "123456",
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
			password_hash TEXT NOT NULL,
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
	t.Helper()
	resp := doJSONRequest(t, server, http.MethodPost, "/api/v1/auth/admin/login", "", map[string]string{
		"username": "admin",
		"password": "admin-pass",
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
