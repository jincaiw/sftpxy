package ftp

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

func TestFTPLoginAndMinimalFileRoundTrip(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	user := &repository.User{
		ID:           1,
		Username:     "alice",
		Status:       "active",
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		HomeDir:      t.TempDir(),
	}
	if writeErr := os.WriteFile(filepath.Join(user.HomeDir, "hello.txt"), []byte("hello over ftp"), 0o644); writeErr != nil {
		t.Fatalf("seed ftp file failed: %v", writeErr)
	}
	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
	}
	auditRepo := &testutil.RecordingAuditRepo{}
	sessionRepo := &testutil.RecordingSessionRepo{}

	server := newTestServer(t, config.FTPConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
	}, userRepo, auditRepo, sessionRepo)

	conn, reader := dialFTP(t, server.listener.Addr().String())
	defer conn.Close()

	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("unexpected greeting: %q", line)
	}

	writeFTPCmd(t, conn, "PWD")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "530 ") {
		t.Fatalf("expected unauthenticated PWD to fail, got %q", line)
	}

	writeFTPCmd(t, conn, "USER alice")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "331 ") {
		t.Fatalf("unexpected USER response: %q", line)
	}

	writeFTPCmd(t, conn, "PASS secret-pass")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "230 ") {
		t.Fatalf("unexpected PASS response: %q", line)
	}

	writeFTPCmd(t, conn, "FEAT")
	feat := readFTPMultilineResponse(t, reader, "211")
	if !strings.Contains(feat, "UTF8") || !strings.Contains(feat, "PASV") {
		t.Fatalf("expected FEAT response to advertise UTF8/PASV, got %q", feat)
	}

	writeFTPCmd(t, conn, "PWD")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "257 ") {
		t.Fatalf("unexpected PWD response after login: %q", line)
	}

	dataConn := openPassiveDataConn(t, reader, func() net.Conn { return conn })
	writeFTPCmd(t, conn, "LIST")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "150 ") {
		t.Fatalf("unexpected LIST opening response: %q", line)
	}
	listing := readFTPData(t, dataConn)
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "226 ") {
		t.Fatalf("unexpected LIST completion response: %q", line)
	}
	if !strings.Contains(listing, "hello.txt") {
		t.Fatalf("expected LIST output to contain hello.txt, got %q", listing)
	}

	dataConn = openPassiveDataConn(t, reader, func() net.Conn { return conn })
	writeFTPCmd(t, conn, "RETR hello.txt")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "150 ") {
		t.Fatalf("unexpected RETR opening response: %q", line)
	}
	content := readFTPData(t, dataConn)
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "226 ") {
		t.Fatalf("unexpected RETR completion response: %q", line)
	}
	if content != "hello over ftp" {
		t.Fatalf("retrieved content = %q, want %q", content, "hello over ftp")
	}

	dataConn = openPassiveDataConn(t, reader, func() net.Conn { return conn })
	writeFTPCmd(t, conn, "STOR upload.txt")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "150 ") {
		t.Fatalf("unexpected STOR opening response: %q", line)
	}
	if _, writeErr := io.WriteString(dataConn, "uploaded by ftp"); writeErr != nil {
		t.Fatalf("write STOR payload failed: %v", writeErr)
	}
	if closeErr := dataConn.Close(); closeErr != nil {
		t.Fatalf("close STOR data connection failed: %v", closeErr)
	}
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "226 ") {
		t.Fatalf("unexpected STOR completion response: %q", line)
	}

	storedContent, err := os.ReadFile(filepath.Join(user.HomeDir, "upload.txt"))
	if err != nil {
		t.Fatalf("read stored ftp file failed: %v", err)
	}
	if string(storedContent) != "uploaded by ftp" {
		t.Fatalf("stored content = %q, want %q", string(storedContent), "uploaded by ftp")
	}

	writeFTPCmd(t, conn, "QUIT")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "221 ") {
		t.Fatalf("unexpected QUIT response: %q", line)
	}
	_ = conn.Close()

	if len(auditRepo.AuditLogs) == 0 || auditRepo.AuditLogs[0].EventType != "ftp_login" {
		t.Fatalf("expected ftp login audit log, got %+v", auditRepo.AuditLogs)
	}
	if len(auditRepo.CommandLogs) < 3 {
		t.Fatalf("expected ftp command logs for LIST/RETR/STOR, got %+v", auditRepo.CommandLogs)
	}
	waitForInactiveSessions(t, sessionRepo, "ftp")
}

func TestFTPPolicyDeniesProtocol(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}
	allowedProtocols, err := json.Marshal([]string{"sftp"})
	if err != nil {
		t.Fatalf("marshal allowed protocols failed: %v", err)
	}

	user := &repository.User{
		ID:               2,
		Username:         "bob",
		Status:           "active",
		PasswordHash:     sql.NullString{String: passwordHash, Valid: true},
		HomeDir:          t.TempDir(),
		AllowedProtocols: allowedProtocols,
	}
	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
	}

	server := newTestServer(t, config.FTPConfig{
		Enabled:       true,
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
	}, userRepo, &testutil.RecordingAuditRepo{}, &testutil.RecordingSessionRepo{})

	conn, reader := dialFTP(t, server.listener.Addr().String())
	defer conn.Close()
	_ = readFTPResponse(t, reader)

	writeFTPCmd(t, conn, "USER bob")
	_ = readFTPResponse(t, reader)
	writeFTPCmd(t, conn, "PASS secret-pass")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "530 ") {
		t.Fatalf("expected ftp protocol denial, got %q", line)
	}
}

func TestStartRejectsForcedTLSWithoutCertificates(t *testing.T) {
	t.Parallel()

	server := NewServer(
		config.FTPConfig{
			Enabled:         true,
			ListenAddress:   "127.0.0.1",
			ListenPort:      30086,
			ForceControlTLS: true,
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		policy.NewPolicyEngine(&testutil.StubUserRepo{}),
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("expected forced TLS without certificates to fail")
	}
}

func TestExplicitFTPSSupportsProtectedRetr(t *testing.T) {
	t.Parallel()

	passwordHash, err := auth.HashPassword("secret-pass")
	if err != nil {
		t.Fatalf("hash password failed: %v", err)
	}

	user := &repository.User{
		ID:           3,
		Username:     "carol",
		Status:       "active",
		PasswordHash: sql.NullString{String: passwordHash, Valid: true},
		HomeDir:      t.TempDir(),
	}
	if err := os.WriteFile(filepath.Join(user.HomeDir, "secure.txt"), []byte("hello over ftps"), 0o644); err != nil {
		t.Fatalf("seed ftps file failed: %v", err)
	}

	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := testutil.GenerateSelfSignedCertificate(certFile, keyFile); err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	userRepo := &testutil.StubUserRepo{
		UsersByUsername: map[string]*repository.User{user.Username: user},
		UsersByID:       map[int64]*repository.User{user.ID: user},
	}

	server := newTestServer(t, config.FTPConfig{
		Enabled:         true,
		ListenAddress:   "127.0.0.1",
		ListenPort:      0,
		ExplicitTLS:     true,
		ForceControlTLS: true,
		ForceDataTLS:    true,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
	}, userRepo, &testutil.RecordingAuditRepo{}, &testutil.RecordingSessionRepo{})

	rawConn, rawReader := dialFTP(t, server.listener.Addr().String())
	defer rawConn.Close()
	if line := readFTPResponse(t, rawReader); !strings.HasPrefix(line, "220 ") {
		t.Fatalf("unexpected FTPS greeting: %q", line)
	}

	writeFTPCmd(t, rawConn, "FEAT")
	feat := readFTPMultilineResponse(t, rawReader, "211")
	if !strings.Contains(feat, "AUTH TLS") || !strings.Contains(feat, "PROT") {
		t.Fatalf("expected FEAT to advertise AUTH TLS and PROT, got %q", feat)
	}

	writeFTPCmd(t, rawConn, "AUTH TLS")
	if line := readFTPResponse(t, rawReader); !strings.HasPrefix(line, "234 ") {
		t.Fatalf("unexpected AUTH TLS response: %q", line)
	}

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("ftps control handshake failed: %v", err)
	}
	reader := bufio.NewReader(tlsConn)

	writeFTPCmd(t, tlsConn, "PBSZ 0")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "200 ") {
		t.Fatalf("unexpected PBSZ response: %q", line)
	}
	writeFTPCmd(t, tlsConn, "PROT P")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "200 ") {
		t.Fatalf("unexpected PROT response: %q", line)
	}
	writeFTPCmd(t, tlsConn, "USER carol")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "331 ") {
		t.Fatalf("unexpected USER response: %q", line)
	}
	writeFTPCmd(t, tlsConn, "PASS secret-pass")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "230 ") {
		t.Fatalf("unexpected PASS response: %q", line)
	}

	rawDataConn := openPassiveDataConn(t, reader, func() net.Conn { return tlsConn })
	writeFTPCmd(t, tlsConn, "RETR secure.txt")
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "150 ") {
		t.Fatalf("unexpected FTPS RETR opening response: %q", line)
	}
	dataConn := tls.Client(rawDataConn, &tls.Config{InsecureSkipVerify: true})
	if err := dataConn.Handshake(); err != nil {
		t.Fatalf("ftps data handshake failed: %v", err)
	}
	content := readFTPData(t, dataConn)
	if line := readFTPResponse(t, reader); !strings.HasPrefix(line, "226 ") {
		t.Fatalf("unexpected FTPS RETR completion response: %q", line)
	}
	if content != "hello over ftps" {
		t.Fatalf("protected RETR content = %q, want %q", content, "hello over ftps")
	}
}

func TestStartRejectsInvalidPassivePortRange(t *testing.T) {
	t.Parallel()

	server := NewServer(
		config.FTPConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1",
			ListenPort:       30086,
			ExplicitTLS:      true,
			ForceControlTLS:  true,
			ForceDataTLS:     true,
			PassivePortStart: 30200,
			PassivePortEnd:   30100,
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		policy.NewPolicyEngine(&testutil.StubUserRepo{}),
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("expected invalid passive port range to fail")
	}
}

func TestStartRejectsInvalidNATExternalAddress(t *testing.T) {
	t.Parallel()

	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	if err := testutil.GenerateSelfSignedCertificate(certFile, keyFile); err != nil {
		t.Fatalf("generate cert failed: %v", err)
	}

	server := NewServer(
		config.FTPConfig{
			Enabled:            true,
			ListenAddress:      "127.0.0.1",
			ListenPort:         30086,
			ExplicitTLS:        true,
			ForceControlTLS:    true,
			ForceDataTLS:       true,
			TLSCertFile:        certFile,
			TLSKeyFile:         keyFile,
			PassivePortStart:   30100,
			PassivePortEnd:     30110,
			NATExternalAddress: "not-an-ip",
		},
		zap.NewNop(),
		auth.NewAuthenticationService(&testutil.StubUserRepo{}, &testutil.StubAdminRepo{}),
		policy.NewPolicyEngine(&testutil.StubUserRepo{}),
		&testutil.StubUserRepo{},
		&testutil.RecordingAuditRepo{},
		&testutil.RecordingSessionRepo{},
	)

	if err := server.Start(context.Background()); err == nil {
		t.Fatalf("expected invalid nat_external_address to fail")
	}
}

func newTestServer(t *testing.T, cfg config.FTPConfig, userRepo *testutil.StubUserRepo, auditRepo *testutil.RecordingAuditRepo, sessionRepo *testutil.RecordingSessionRepo) *Server {
	t.Helper()

	authService := auth.NewAuthenticationService(userRepo, &testutil.StubAdminRepo{})
	server := NewServer(cfg, zap.NewNop(), authService, policy.NewPolicyEngine(userRepo), userRepo, auditRepo, sessionRepo)

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start ftp server failed: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	})
	return server
}

func dialFTP(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial ftp failed: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func openPassiveDataConn(t *testing.T, reader *bufio.Reader, controlConn func() net.Conn) net.Conn {
	t.Helper()

	host, port := enterPassiveMode(t, controlConn(), reader)
	dataConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial passive data connection failed: %v", err)
	}
	return dataConn
}

func enterPassiveMode(t *testing.T, conn net.Conn, reader *bufio.Reader) (string, int) {
	t.Helper()

	writeFTPCmd(t, conn, "PASV")
	line := readFTPResponse(t, reader)
	if !strings.HasPrefix(line, "227 ") {
		t.Fatalf("unexpected PASV response: %q", line)
	}

	start := strings.IndexByte(line, '(')
	end := strings.LastIndexByte(line, ')')
	if start < 0 || end <= start {
		t.Fatalf("invalid PASV response format: %q", line)
	}
	parts := strings.Split(line[start+1:end], ",")
	if len(parts) != 6 {
		t.Fatalf("unexpected PASV address parts: %q", line)
	}

	values := make([]int, 0, 6)
	for _, part := range parts {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			t.Fatalf("parse PASV part %q failed: %v", part, err)
		}
		values = append(values, value)
	}
	host := fmt.Sprintf("%d.%d.%d.%d", values[0], values[1], values[2], values[3])
	port := values[4]*256 + values[5]
	return host, port
}

func writeFTPCmd(t *testing.T, conn net.Conn, command string) {
	t.Helper()

	if _, err := fmt.Fprintf(conn, "%s\r\n", command); err != nil {
		t.Fatalf("write ftp command %q failed: %v", command, err)
	}
}

func readFTPResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read ftp response failed: %v", err)
	}
	return strings.TrimSpace(line)
}

func readFTPData(t *testing.T, conn net.Conn) string {
	t.Helper()

	content, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read ftp data failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close ftp data connection failed: %v", err)
	}
	return string(content)
}

func readFTPMultilineResponse(t *testing.T, reader *bufio.Reader, code string) string {
	t.Helper()

	var lines []string
	for {
		line := readFTPResponse(t, reader)
		lines = append(lines, line)
		if strings.HasPrefix(line, code+" ") {
			break
		}
	}
	return strings.Join(lines, "\n")
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
