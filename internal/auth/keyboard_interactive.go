package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/jincaiw/sftpxy/internal/repository"
	"golang.org/x/crypto/ssh"
)

type KeyboardInteractiveHandler struct {
	totpAuth *TOTPAuthenticator
	userRepo repository.UserRepository
	issuer   string
}

func NewKeyboardInteractiveHandler(userRepo repository.UserRepository, totpAuth *TOTPAuthenticator, issuer string) *KeyboardInteractiveHandler {
	return &KeyboardInteractiveHandler{
		userRepo: userRepo,
		totpAuth: totpAuth,
		issuer:   issuer,
	}
}

func (h *KeyboardInteractiveHandler) AuthenticateTOTP(username string, challenge ssh.KeyboardInteractiveChallenge) (*repository.User, error) {
	user, err := h.userRepo.GetByUsername(context.Background(), username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if user.Status != "active" {
		return nil, ErrUserDisabled
	}

	if !user.MFAEnabled || !user.MFASecret.Valid || user.MFASecret.String == "" {
		return nil, fmt.Errorf("MFA is not enabled for user %s", username)
	}

	answers, err := challenge(
		h.issuer,
		"Please provide your TOTP verification code.",
		[]string{"Verification code: "},
		[]bool{false},
	)
	if err != nil {
		return nil, fmt.Errorf("keyboard-interactive challenge failed: %w", err)
	}

	if len(answers) == 0 || strings.TrimSpace(answers[0]) == "" {
		return nil, ErrInvalidCredentials
	}

	valid, err := h.totpAuth.VerifyCode(user.MFASecret.String, strings.TrimSpace(answers[0]))
	if err != nil || !valid {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
