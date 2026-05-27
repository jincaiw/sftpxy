package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/sftpxy/sftpxy/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserDisabled       = errors.New("user is disabled")
	ErrUserExpired        = errors.New("user has expired")
	ErrUserNotFound       = errors.New("user not found")
)

// PasswordAuthenticator handles password-based authentication
type PasswordAuthenticator struct {
	userRepo  repository.UserRepository
	adminRepo repository.AdminRepository
}

// NewPasswordAuthenticator creates a new PasswordAuthenticator
func NewPasswordAuthenticator(userRepo repository.UserRepository, adminRepo repository.AdminRepository) *PasswordAuthenticator {
	return &PasswordAuthenticator{
		userRepo:  userRepo,
		adminRepo: adminRepo,
	}
}

// AuthenticateUser authenticates a regular user with username and password
func (pa *PasswordAuthenticator) AuthenticateUser(ctx context.Context, username, password string) (*repository.User, error) {
	user, err := pa.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check user status
	if user.Status != "active" {
		return nil, ErrUserDisabled
	}

	// Check if user has password
	if !user.PasswordHash.Valid || user.PasswordHash.String == "" {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash.String), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// AuthenticateAdmin authenticates an administrator with username and password
func (pa *PasswordAuthenticator) AuthenticateAdmin(ctx context.Context, username, password string) (*repository.Admin, error) {
	admin, err := pa.adminRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check admin status
	if admin.Status != "active" {
		return nil, ErrUserDisabled
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login time
	pa.adminRepo.UpdateLastLogin(ctx, admin.ID)

	return admin, nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// VerifyPassword verifies a password against a hash using constant-time comparison
func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// APIKeyAuthenticator handles API key authentication
type APIKeyAuthenticator struct {
	validKeys map[string]bool
}

// NewAPIKeyAuthenticator creates a new APIKeyAuthenticator
func NewAPIKeyAuthenticator() *APIKeyAuthenticator {
	return &APIKeyAuthenticator{
		validKeys: make(map[string]bool),
	}
}

// AddKey adds a valid API key
func (a *APIKeyAuthenticator) AddKey(key string) {
	a.validKeys[key] = true
}

// RemoveKey removes an API key
func (a *APIKeyAuthenticator) RemoveKey(key string) {
	delete(a.validKeys, key)
}

// Authenticate checks if the provided API key is valid
func (a *APIKeyAuthenticator) Authenticate(key string) bool {
	if len(key) == 0 {
		return false
	}
	// Use constant-time comparison to prevent timing attacks
	for validKey := range a.validKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
			return true
		}
	}
	return false
}

// AuthResult contains authentication result information
type AuthResult struct {
	Success     bool
	User        *repository.User
	Admin       *repository.Admin
	MFARequired bool
	Message     string
}

// AuthenticationService provides unified authentication interface
type AuthenticationService struct {
	passwordAuth *PasswordAuthenticator
	apiKeyAuth   *APIKeyAuthenticator
}

// NewAuthenticationService creates a new AuthenticationService
func NewAuthenticationService(
	userRepo repository.UserRepository,
	adminRepo repository.AdminRepository,
) *AuthenticationService {
	return &AuthenticationService{
		passwordAuth: NewPasswordAuthenticator(userRepo, adminRepo),
		apiKeyAuth:   NewAPIKeyAuthenticator(),
	}
}

// LoginUser attempts to authenticate a user
func (s *AuthenticationService) LoginUser(ctx context.Context, username, password string) (*AuthResult, error) {
	user, err := s.passwordAuth.AuthenticateUser(ctx, username, password)
	if err != nil {
		return &AuthResult{
			Success: false,
			Message: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	result := &AuthResult{
		Success:     true,
		User:        user,
		MFARequired: user.MFAEnabled,
		Message:     "Login successful",
	}

	return result, nil
}

// LoginAdmin attempts to authenticate an admin
func (s *AuthenticationService) LoginAdmin(ctx context.Context, username, password string) (*AuthResult, error) {
	admin, err := s.passwordAuth.AuthenticateAdmin(ctx, username, password)
	if err != nil {
		return &AuthResult{
			Success: false,
			Message: fmt.Sprintf("Login failed: %v", err),
		}, nil
	}

	result := &AuthResult{
		Success:     true,
		Admin:       admin,
		MFARequired: admin.MFAEnabled,
		Message:     "Login successful",
	}

	return result, nil
}

// ValidateAPIKey validates an API key
func (s *AuthenticationService) ValidateAPIKey(key string) bool {
	return s.apiKeyAuth.Authenticate(key)
}
