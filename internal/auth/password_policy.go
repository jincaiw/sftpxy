package auth

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/jincaiw/sftpxy/internal/config"
)

type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	DisallowUsername bool
}

func NewPasswordPolicy(cfg config.PasswordPolicyConfig) *PasswordPolicy {
	minLength := cfg.MinLength
	if minLength <= 0 {
		minLength = 8
	}
	return &PasswordPolicy{
		MinLength:        minLength,
		RequireUppercase: cfg.RequireUppercase,
		RequireLowercase: cfg.RequireLowercase,
		RequireDigit:     cfg.RequireDigit,
		RequireSpecial:   cfg.RequireSpecial,
		DisallowUsername: cfg.DisallowUsername,
	}
}

func NewDefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false,
		DisallowUsername: false,
	}
}

func (p *PasswordPolicy) ValidatePassword(password, username string) error {
	if len(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters", p.MinLength)
	}

	if p.RequireUppercase && !hasUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if p.RequireLowercase && !hasLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if p.RequireDigit && !hasDigit(password) {
		return fmt.Errorf("password must contain at least one digit")
	}

	if p.RequireSpecial && !hasSpecial(password) {
		return fmt.Errorf("password must contain at least one special character")
	}

	if p.DisallowUsername && username != "" {
		if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
			return fmt.Errorf("password must not contain the username")
		}
	}

	return nil
}

func hasUppercase(s string) bool {
	for _, r := range s {
		if unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

func hasLowercase(s string) bool {
	for _, r := range s {
		if unicode.IsLower(r) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

func hasSpecial(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return true
		}
	}
	return false
}
