package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/jincaiw/sftpxy/internal/repository"
	"golang.org/x/crypto/ssh"
)

// PublicKeyAuthenticator handles SSH public key authentication
type PublicKeyAuthenticator struct {
	userRepo repository.UserRepository
}

// NewPublicKeyAuthenticator creates a new PublicKeyAuthenticator
func NewPublicKeyAuthenticator(userRepo repository.UserRepository) *PublicKeyAuthenticator {
	return &PublicKeyAuthenticator{userRepo: userRepo}
}

// Authenticate authenticates a user with SSH public key
func (pka *PublicKeyAuthenticator) Authenticate(ctx context.Context, username string, pubKey ssh.PublicKey) (*repository.User, error) {
	user, err := pka.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check user status
	if user.Status != "active" {
		return nil, ErrUserDisabled
	}

	// Get user's public keys
	keys, err := pka.userRepo.GetPublicKeys(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	// Check if the provided key matches any of the user's keys
	pubKeyBytes := pubKey.Marshal()
	for _, key := range keys {
		parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
		if err != nil {
			continue
		}
		if subtleConstantTimeCompare(pubKeyBytes, parsedKey.Marshal()) {
			return user, nil
		}
	}

	return nil, ErrInvalidCredentials
}

// ValidatePublicKey validates and parses an SSH public key string
func ValidatePublicKey(keyString string) (ssh.PublicKey, error) {
	keyString = strings.TrimSpace(keyString)
	if keyString == "" {
		return nil, fmt.Errorf("empty public key")
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyString))
	if err != nil {
		return nil, fmt.Errorf("invalid public key format: %w", err)
	}

	return pubKey, nil
}

// GetKeyType returns the type of SSH public key
func GetKeyType(pubKey ssh.PublicKey) string {
	return pubKey.Type()
}

// GetKeyFingerprint returns the fingerprint of an SSH public key
func GetKeyFingerprint(pubKey ssh.PublicKey) string {
	hash := ssh.FingerprintSHA256(pubKey)
	return hash
}

// subtleConstantTimeCompare performs constant-time comparison of byte slices
func subtleConstantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
