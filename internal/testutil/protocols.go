package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
)

type StubUserRepo struct {
	UsersByUsername map[string]*repository.User
	UsersByID       map[int64]*repository.User
	PublicKeys      map[int64][]*repository.PublicKey
}

func (r *StubUserRepo) GetByUsername(_ context.Context, username string) (*repository.User, error) {
	user, ok := r.UsersByUsername[username]
	if !ok {
		return nil, fmt.Errorf("user not found: %s", username)
	}
	return user, nil
}

func (r *StubUserRepo) GetByID(_ context.Context, id int64) (*repository.User, error) {
	user, ok := r.UsersByID[id]
	if !ok {
		return nil, fmt.Errorf("user not found: %d", id)
	}
	return user, nil
}

func (r *StubUserRepo) Create(_ context.Context, user *repository.User) (*repository.User, error) {
	if r.UsersByUsername == nil {
		r.UsersByUsername = map[string]*repository.User{}
	}
	if r.UsersByID == nil {
		r.UsersByID = map[int64]*repository.User{}
	}
	r.UsersByUsername[user.Username] = user
	r.UsersByID[user.ID] = user
	return user, nil
}

func (r *StubUserRepo) Update(_ context.Context, user *repository.User) error {
	if r.UsersByUsername != nil {
		r.UsersByUsername[user.Username] = user
	}
	if r.UsersByID != nil {
		r.UsersByID[user.ID] = user
	}
	return nil
}

func (r *StubUserRepo) Delete(_ context.Context, id int64) error {
	user, ok := r.UsersByID[id]
	if !ok {
		return nil
	}
	delete(r.UsersByID, id)
	delete(r.UsersByUsername, user.Username)
	return nil
}

func (r *StubUserRepo) List(_ context.Context, _, _ string, _, _ int) ([]*repository.User, error) {
	users := make([]*repository.User, 0, len(r.UsersByID))
	for _, user := range r.UsersByID {
		users = append(users, user)
	}
	return users, nil
}

func (r *StubUserRepo) Count(_ context.Context) (int64, error) {
	return int64(len(r.UsersByID)), nil
}

func (r *StubUserRepo) UpdateStatus(_ context.Context, id int64, status string) error {
	user, ok := r.UsersByID[id]
	if !ok {
		return fmt.Errorf("user not found: %d", id)
	}
	user.Status = status
	return nil
}

func (r *StubUserRepo) UpdateLastLogin(_ context.Context, _ int64) error {
	return nil
}

func (r *StubUserRepo) GetPublicKeys(_ context.Context, userID int64) ([]*repository.PublicKey, error) {
	return r.PublicKeys[userID], nil
}

func (r *StubUserRepo) AddPublicKey(_ context.Context, userID int64, label, publicKey string) (*repository.PublicKey, error) {
	key := &repository.PublicKey{
		ID:        int64(len(r.PublicKeys[userID]) + 1),
		UserID:    userID,
		Label:     label,
		PublicKey: publicKey,
	}
	r.PublicKeys[userID] = append(r.PublicKeys[userID], key)
	return key, nil
}

func (r *StubUserRepo) DeletePublicKey(_ context.Context, id, userID int64) error {
	keys := r.PublicKeys[userID]
	filtered := keys[:0]
	for _, key := range keys {
		if key.ID != id {
			filtered = append(filtered, key)
		}
	}
	r.PublicKeys[userID] = filtered
	return nil
}

type StubAdminRepo struct {
	AdminsByUsername map[string]*repository.Admin
}

func (r *StubAdminRepo) GetByUsername(_ context.Context, username string) (*repository.Admin, error) {
	admin, ok := r.AdminsByUsername[username]
	if !ok {
		return nil, fmt.Errorf("admin not found: %s", username)
	}
	return admin, nil
}

func (r *StubAdminRepo) GetByID(_ context.Context, id int64) (*repository.Admin, error) {
	for _, admin := range r.AdminsByUsername {
		if admin.ID == id {
			return admin, nil
		}
	}
	return nil, fmt.Errorf("admin not found: %d", id)
}

func (r *StubAdminRepo) Create(_ context.Context, admin *repository.Admin) (*repository.Admin, error) {
	if r.AdminsByUsername == nil {
		r.AdminsByUsername = map[string]*repository.Admin{}
	}
	r.AdminsByUsername[admin.Username] = admin
	return admin, nil
}

func (r *StubAdminRepo) Update(_ context.Context, admin *repository.Admin) error {
	if r.AdminsByUsername != nil {
		r.AdminsByUsername[admin.Username] = admin
	}
	return nil
}

func (r *StubAdminRepo) Delete(_ context.Context, id int64) error {
	for username, admin := range r.AdminsByUsername {
		if admin.ID == id {
			delete(r.AdminsByUsername, username)
			break
		}
	}
	return nil
}

func (r *StubAdminRepo) List(_ context.Context, _, _ int) ([]*repository.Admin, error) {
	admins := make([]*repository.Admin, 0, len(r.AdminsByUsername))
	for _, admin := range r.AdminsByUsername {
		admins = append(admins, admin)
	}
	return admins, nil
}

func (r *StubAdminRepo) UpdateLastLogin(_ context.Context, _ int64) error {
	return nil
}

type CommandLogEntry struct {
	Command  string
	Username string
	Protocol string
	Path     string
	NewPath  string
	Result   string
	Error    string
}

type HTTPLogEntry struct {
	Method         string
	Path           string
	StatusCode     int
	Username       string
	ClientIP       string
	UserAgent      string
	ResponseTimeMS int
	RequestSize    int
	ResponseSize   int
	AuthMethod     string
	Error          string
}

type RecordingAuditRepo struct {
	mu          sync.Mutex
	AuditLogs   []*repository.AuditLog
	CommandLogs []CommandLogEntry
	HTTPLogs    []HTTPLogEntry
}

func (r *RecordingAuditRepo) CreateAuditLog(_ context.Context, log *repository.AuditLog) (*repository.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copyLog := *log
	r.AuditLogs = append(r.AuditLogs, &copyLog)
	return &copyLog, nil
}

func (r *RecordingAuditRepo) ListAuditLogs(_ context.Context, _, _, _, _, _ string, _, _ int) ([]*repository.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	logs := make([]*repository.AuditLog, len(r.AuditLogs))
	copy(logs, r.AuditLogs)
	return logs, nil
}

func (r *RecordingAuditRepo) CountAuditLogs(_ context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int64(len(r.AuditLogs)), nil
}

func (r *RecordingAuditRepo) ListAuditLogsFiltered(_ context.Context, _ *repository.AuditFilter, _, _ int) ([]*repository.AuditLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	logs := make([]*repository.AuditLog, len(r.AuditLogs))
	copy(logs, r.AuditLogs)
	return logs, nil
}

func (r *RecordingAuditRepo) CreateTransferLog(_ context.Context, log *repository.TransferLog) (*repository.TransferLog, error) {
	return log, nil
}

func (r *RecordingAuditRepo) ListTransferLogs(_ context.Context, _, _, _, _ string, _, _ int) ([]*repository.TransferLog, error) {
	return nil, nil
}

func (r *RecordingAuditRepo) CreateCommandLog(_ context.Context, command, username, protocol, path, newPath, result, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.CommandLogs = append(r.CommandLogs, CommandLogEntry{
		Command:  command,
		Username: username,
		Protocol: protocol,
		Path:     path,
		NewPath:  newPath,
		Result:   result,
		Error:    errMsg,
	})
	return nil
}

func (r *RecordingAuditRepo) CreateHTTPLog(_ context.Context, method, path string, statusCode int, username, clientIP, userAgent string, responseTimeMs, requestSize, responseSize int, authMethod, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.HTTPLogs = append(r.HTTPLogs, HTTPLogEntry{
		Method:         method,
		Path:           path,
		StatusCode:     statusCode,
		Username:       username,
		ClientIP:       clientIP,
		UserAgent:      userAgent,
		ResponseTimeMS: responseTimeMs,
		RequestSize:    requestSize,
		ResponseSize:   responseSize,
		AuthMethod:     authMethod,
		Error:          errMsg,
	})
	return nil
}

func (r *RecordingAuditRepo) AddBlockedIP(_ context.Context, ip, protocol, reason string, expiresAt time.Time) (*repository.BlockedIP, error) {
	return &repository.BlockedIP{IP: ip, Protocol: protocol, Reason: reason, ExpiresAt: expiresAt, IsActive: true}, nil
}

func (r *RecordingAuditRepo) GetBlockedIP(_ context.Context, ip string) (*repository.BlockedIP, error) {
	return &repository.BlockedIP{IP: ip, IsActive: false}, nil
}

func (r *RecordingAuditRepo) UnblockIP(_ context.Context, _ string) error {
	return nil
}

func (r *RecordingAuditRepo) ListActiveBlocks(_ context.Context, _, _ int) ([]*repository.BlockedIP, error) {
	return nil, nil
}

func (r *RecordingAuditRepo) CleanExpiredBlocks(_ context.Context) error {
	return nil
}

type RecordingSessionRepo struct {
	mu       sync.Mutex
	Sessions map[string]repositorySessionRecord
}

type repositorySessionRecord struct {
	UserID   int64
	Protocol string
	ClientIP string
	Active   bool
}

func (r *RecordingSessionRepo) CreateSession(_ context.Context, sessionID string, userID int64, protocol, clientIP string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Sessions == nil {
		r.Sessions = make(map[string]repositorySessionRecord)
	}
	r.Sessions[sessionID] = repositorySessionRecord{
		UserID:   userID,
		Protocol: protocol,
		ClientIP: clientIP,
		Active:   true,
	}
	return nil
}

func (r *RecordingSessionRepo) TouchSession(_ context.Context, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.Sessions[sessionID]
	record.Active = true
	r.Sessions[sessionID] = record
	return nil
}

func (r *RecordingSessionRepo) DeactivateSession(_ context.Context, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.Sessions[sessionID]
	record.Active = false
	r.Sessions[sessionID] = record
	return nil
}

func GenerateSelfSignedCertificate(certFile, keyFile string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           nil,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certPEM, err := os.Create(certFile)
	if err != nil {
		return err
	}
	if err := pemEncode(certPEM, "CERTIFICATE", derBytes); err != nil {
		return err
	}

	keyPEM, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	if err := pemEncode(keyPEM, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey)); err != nil {
		return err
	}

	return nil
}

func pemEncode(file *os.File, pemType string, bytes []byte) error {
	block := &pem.Block{Type: pemType, Bytes: bytes}
	if err := pem.Encode(file, block); err != nil {
		return err
	}
	return file.Close()
}
