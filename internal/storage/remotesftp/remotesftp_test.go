package remotesftp

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestBuildHostKeyCallbackRejectsMissingHostKey(t *testing.T) {
	t.Parallel()

	if _, err := buildHostKeyCallback(""); err == nil {
		t.Fatal("expected missing host key validation to fail")
	}
}

func TestBuildHostKeyCallbackAcceptsFingerprint(t *testing.T) {
	t.Parallel()

	_, publicKey := generateSSHTestKey(t)
	callback, err := buildHostKeyCallback(ssh.FingerprintSHA256(publicKey))
	if err != nil {
		t.Fatalf("buildHostKeyCallback failed: %v", err)
	}
	if err := callback("example.com", &net.TCPAddr{}, publicKey); err != nil {
		t.Fatalf("host key callback rejected expected fingerprint: %v", err)
	}
}

func TestBuildHostKeyCallbackAcceptsAuthorizedKey(t *testing.T) {
	t.Parallel()

	authorizedKey, publicKey := generateSSHTestKey(t)
	callback, err := buildHostKeyCallback(string(authorizedKey))
	if err != nil {
		t.Fatalf("buildHostKeyCallback failed: %v", err)
	}
	if err := callback("example.com", &net.TCPAddr{}, publicKey); err != nil {
		t.Fatalf("host key callback rejected expected authorized key: %v", err)
	}
}

func TestBuildHostKeyCallbackRejectsUnexpectedKey(t *testing.T) {
	t.Parallel()

	_, expectedPublicKey := generateSSHTestKey(t)
	_, actualPublicKey := generateSSHTestKey(t)
	callback, err := buildHostKeyCallback(ssh.FingerprintSHA256(expectedPublicKey))
	if err != nil {
		t.Fatalf("buildHostKeyCallback failed: %v", err)
	}
	if err := callback("example.com", &net.TCPAddr{}, actualPublicKey); err == nil {
		t.Fatal("expected host key mismatch to fail")
	}
}

func generateSSHTestKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()

	publicKeyRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key failed: %v", err)
	}
	publicKey, err := ssh.NewPublicKey(publicKeyRaw)
	if err != nil {
		t.Fatalf("create ssh public key failed: %v", err)
	}
	return ssh.MarshalAuthorizedKey(publicKey), publicKey
}
