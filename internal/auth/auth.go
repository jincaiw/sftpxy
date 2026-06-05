package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	"github.com/jincaiw/sftpxy/internal/defender"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUserDisabled           = errors.New("user is disabled")
	ErrUserExpired            = errors.New("user has expired")
	ErrUserNotFound           = errors.New("user not found")
	ErrPasswordExpired        = errors.New("password has expired")
	ErrPasswordChangeRequired = errors.New("password change required")
	ErrCertificateRevoked     = errors.New("certificate has been revoked")
	ErrGeoIPBlocked           = errors.New("access denied from your location")
	ErrPartialAuthRequired    = errors.New("additional authentication required")
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
	mu        sync.RWMutex
	validKeys map[string]bool
}

func NewAPIKeyAuthenticator() *APIKeyAuthenticator {
	return &APIKeyAuthenticator{
		validKeys: make(map[string]bool),
	}
}

func (a *APIKeyAuthenticator) AddKey(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.validKeys[key] = true
}

func (a *APIKeyAuthenticator) RemoveKey(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.validKeys, key)
}

func (a *APIKeyAuthenticator) Authenticate(key string) bool {
	if len(key) == 0 {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for validKey := range a.validKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(validKey)) == 1 {
			return true
		}
	}
	return false
}

// AuthResult contains authentication result information
type AuthResult struct {
	Success       bool
	User          *repository.User
	Admin         *repository.Admin
	MFARequired   bool
	Message       string
	DynamicConfig *hooks.DynamicUserConfig
}

// AuthenticationService provides unified authentication interface
type AuthenticationService struct {
	passwordAuth *PasswordAuthenticator
	apiKeyAuth   *APIKeyAuthenticator
	hookManager  *hooks.HookManager
	defender     *defender.Defender
}

func NewAuthenticationService(
	userRepo repository.UserRepository,
	adminRepo repository.AdminRepository,
) *AuthenticationService {
	return &AuthenticationService{
		passwordAuth: NewPasswordAuthenticator(userRepo, adminRepo),
		apiKeyAuth:   NewAPIKeyAuthenticator(),
	}
}

func NewAuthenticationServiceWithHooks(
	userRepo repository.UserRepository,
	adminRepo repository.AdminRepository,
	hookMgr *hooks.HookManager,
) *AuthenticationService {
	return &AuthenticationService{
		passwordAuth: NewPasswordAuthenticator(userRepo, adminRepo),
		apiKeyAuth:   NewAPIKeyAuthenticator(),
		hookManager:  hookMgr,
	}
}

// SetDefender sets the defender service for brute-force protection
func (s *AuthenticationService) SetDefender(d *defender.Defender) {
	s.defender = d
}

// LoginUser attempts to authenticate a user
func (s *AuthenticationService) LoginUser(ctx context.Context, username, password string) (*AuthResult, error) {
	if s.hookManager != nil && s.hookManager.AuthHook != nil {
		hookResult, err := s.hookManager.Authenticate(ctx, username, password)
		if err != nil {
			return &AuthResult{
				Success: false,
				Message: fmt.Sprintf("External auth failed: %v", err),
			}, nil
		}
		if !hookResult.Authenticated {
			return &AuthResult{
				Success: false,
				Message: hookResult.ErrorReason,
			}, nil
		}

		var dynConfig *hooks.DynamicUserConfig
		if s.hookManager.DynamicUserHook != nil {
			cfg, cfgErr := s.hookManager.GetDynamicConfig(ctx, username)
			if cfgErr == nil && cfg != nil {
				dynConfig = cfg
			}
			if hookResult.UserConfig != nil && dynConfig != nil {
				dynConfig = hooks.MergeDynamicConfig(hookResult.UserConfig, dynConfig)
			} else if hookResult.UserConfig != nil {
				dynConfig = hookResult.UserConfig
			}
		} else if hookResult.UserConfig != nil {
			dynConfig = hookResult.UserConfig
		}

		user, userErr := s.passwordAuth.AuthenticateUser(ctx, username, password)
		if userErr == nil {
			return &AuthResult{
				Success:       true,
				User:          user,
				MFARequired:   user.MFAEnabled,
				Message:       "Login successful",
				DynamicConfig: dynConfig,
			}, nil
		}

		return &AuthResult{
			Success:       true,
			MFARequired:   false,
			Message:       "Login successful via external auth",
			DynamicConfig: dynConfig,
		}, nil
	}

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
