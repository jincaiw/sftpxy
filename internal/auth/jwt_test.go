package auth

import (
	"testing"
	"time"
)

func TestJWTManagerSignAndParse(t *testing.T) {
	manager, err := NewJWTManager("test-secret", "test-issuer", "test-audience")
	if err != nil {
		t.Fatalf("NewJWTManager() error = %v", err)
	}

	token, err := manager.Sign(JWTClaims{
		Subject:   "alice",
		Role:      "admin",
		UserID:    7,
		SessionID: "session-1",
		HomeDir:   "/tmp/alice",
		Scopes:    []string{"admin"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	claims, err := manager.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if claims.Subject != "alice" {
		t.Fatalf("Subject = %q, want alice", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Fatalf("Role = %q, want admin", claims.Role)
	}
	if claims.UserID != 7 {
		t.Fatalf("UserID = %d, want 7", claims.UserID)
	}
	if claims.SessionID != "session-1" {
		t.Fatalf("SessionID = %q, want session-1", claims.SessionID)
	}
}

func TestJWTManagerRejectsExpiredToken(t *testing.T) {
	manager, err := NewJWTManager("test-secret", "test-issuer", "test-audience")
	if err != nil {
		t.Fatalf("NewJWTManager() error = %v", err)
	}

	token, err := manager.Sign(JWTClaims{
		Subject:   "expired-user",
		ExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if _, err := manager.Parse(token); err == nil {
		t.Fatalf("Parse() expected expired token error")
	}
}
