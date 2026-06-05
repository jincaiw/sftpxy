package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/testutil"
	"github.com/pkg/sftp"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func mustMarshalPermissions(perms []policy.Permission) json.RawMessage {
	b, err := json.Marshal(perms)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSFTPPasswordAuthAndPolicy(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	permissions := mustMarshalPermissions([]policy.Permission{
		{
			Path:       "/",
			List:       true,
			Download:   true,
			Upload:     true,
			Rename:     true,
			CreateDirs: true,
		},
	})

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
		PublicKeys:      map[int64][]*repository.PublicKey{},
	}
	auditRepo := &testutil.RecordingAuditRepo{}
	sessionRepo := &testutil.RecordingSessionRepo{}

	server := newTestServer(t, config.SSHConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		PasswordAuth:  true,
		PublicKeyAuth: false,
	}, userRepo, auditRepo, sessionRepo)

	sshClient, err := dialSSH(server.listener.Addr().String(), "alice", []gossh.AuthMethod{gossh.Password("secret-pass")})
	if err != nil {
		t.Fatalf("dial ssh failed: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		t.Fatalf("new sftp client failed: %v", err)
	}

	if err := sftpClient.Mkdir("/docs"); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	writer, err := sftpClient.Create("/docs/readme.txt")
	if err != nil {
		t.Fatalf("create file failed: %v", err)
	}
	if _, err := writer.Write([]byte("hello over sftp")); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer failed: %v", err)
	}

	entries, err := sftpClient.ReadDir("/docs")
	if err != nil {
		t.Fatalf("read dir failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "readme.txt" {
		t.Fatalf("unexpected directory entries: %+v", entries)
	}

	reader, err := sftpClient.Open("/docs/readme.txt")
	if err != nil {
		t.Fatalf("open file failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read file failed: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader failed: %v", err)
	}
	if string(content) != "hello over sftp" {
		t.Fatalf("content = %q, want %q", string(content), "hello over sftp")
	}

	handler := &sftpHandlers{
		server:   server,
		user:     user,
		clientIP: net.IPv4(127, 0, 0, 1),
		basePath: user.HomeDir,
	}
	if err := handler.Filecmd(sftp.NewRequest("Remove", "/docs/readme.txt")); err == nil {
		t.Fatalf("expected delete to be denied by policy")
	}

	commandNames := make([]string, 0, len(auditRepo.CommandLogs))
	for _, entry := range auditRepo.CommandLogs {
		commandNames = append(commandNames, entry.Command)
	}
	for _, command := range []string{"Mkdir", "Open", "List", "Get", "Remove"} {
		if !slices.Contains(commandNames, command) {
			t.Fatalf("expected command log for %s, got %v", command, commandNames)
		}
	}

	eventTypes := make([]string, 0, len(auditRepo.AuditLogs))
	for _, entry := range auditRepo.AuditLogs {
		eventTypes = append(eventTypes, entry.EventType)
	}
	if !slices.Contains(eventTypes, "ssh_password_auth") {
		t.Fatalf("expected password auth audit log, got %v", eventTypes)
	}
	if !slices.Contains(eventTypes, "sftp_session") {
		t.Fatalf("expected sftp session audit log, got %v", eventTypes)
	}
	if err := sftpClient.Close(); err != nil {
		t.Fatalf("close sftp client failed: %v", err)
	}
	if err := sshClient.Close(); err != nil {
		t.Fatalf("close ssh client failed: %v", err)
	}
	waitForInactiveSessions(t, sessionRepo, "sftp")
}

func TestSFTPPublicKeyAuth(t *testing.T) {
	t.Parallel()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate client key failed: %v", err)
	}
	signer, err := gossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("new signer failed: %v", err)
	}

	user := &repository.User{
		ID:       2,
		Username: "bob",
		Status:   "active",
		HomeDir:  t.TempDir(),
		Permissions: mustMarshalPermissions([]policy.Permission{
			{Path: "/", List: true, Download: true},
		}),
	}
	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
		PublicKeys: map[int64][]*repository.PublicKey{
			user.ID: {
				{
					ID:        1,
					UserID:    user.ID,
					Label:     "primary",
					PublicKey: string(gossh.MarshalAuthorizedKey(signer.PublicKey())),
				},
			},
		},
	}
	auditRepo := &testutil.RecordingAuditRepo{}
	sessionRepo := &testutil.RecordingSessionRepo{}

	server := newTestServer(t, config.SSHConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		PasswordAuth:  false,
		PublicKeyAuth: true,
	}, userRepo, auditRepo, sessionRepo)

	sshClient, err := dialSSH(server.listener.Addr().String(), "bob", []gossh.AuthMethod{gossh.PublicKeys(signer)})
	if err != nil {
		t.Fatalf("dial ssh with public key failed: %v", err)
	}

	sftpClient, err := sftp.NewClient(sshClient)
	if err != nil {
		t.Fatalf("new sftp client failed: %v", err)
	}

	if _, err := sftpClient.ReadDir("/"); err != nil {
		t.Fatalf("read root failed: %v", err)
	}
	_ = sftpClient.Close()
	_ = sshClient.Close()

	eventTypes := make([]string, 0, len(auditRepo.AuditLogs))
	for _, entry := range auditRepo.AuditLogs {
		eventTypes = append(eventTypes, entry.EventType)
	}
	if !slices.Contains(eventTypes, "ssh_publickey_auth") {
		t.Fatalf("expected public key audit log, got %v", eventTypes)
	}
}

func TestStartRejectsUnsupportedCertificateAuth(t *testing.T) {
	t.Parallel()

	server := NewServer(
		config.SSHConfig{
			Enabled:         true,
			ListenAddress:   "127.0.0.1",
			ListenPort:      30082,
			CertificateAuth: true,
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		nil,
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := server.Start(ctx)
	if err != nil {
		t.Fatalf("certificate auth without CA keys should not fail Start, but got: %v", err)
	}
	if server.certAuth != nil {
		t.Fatalf("certAuth should be nil when no CA keys are configured")
	}
}

func newTestServer(t *testing.T, cfg config.SSHConfig, userRepo *testutil.StubUserRepo, auditRepo *testutil.RecordingAuditRepo, sessionRepo *testutil.RecordingSessionRepo) *Server {
	t.Helper()

	authService := auth.NewAuthenticationService(userRepo, &testutil.StubAdminRepo{})
	policyEngine := policy.NewPolicyEngine(userRepo)
	server := NewServer(cfg, zap.NewNop(), authService, policyEngine, userRepo, auditRepo, sessionRepo)

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start ssh server failed: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	})
	return server
}

func dialSSH(addr, username string, authMethods []gossh.AuthMethod) (*gossh.Client, error) {
	return gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
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
