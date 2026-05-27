package auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	"github.com/pquerna/otp/totp"
)

// TOTPAuthenticator handles TOTP-based MFA
type TOTPAuthenticator struct {
	issuer string
}

// NewTOTPAuthenticator creates a new TOTPAuthenticator
func NewTOTPAuthenticator(issuer string) *TOTPAuthenticator {
	return &TOTPAuthenticator{issuer: issuer}
}

// GenerateSecret generates a new TOTP secret
func (t *TOTPAuthenticator) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	return encoding.EncodeToString(secret), nil
}

// GenerateQRCodeURL generates the OTPAuth URL for QR code generation
func (t *TOTPAuthenticator) GenerateQRCodeURL(secret, accountName string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		t.issuer, accountName, secret, t.issuer)
}

// VerifyCode verifies a TOTP code
func (t *TOTPAuthenticator) VerifyCode(secret, code string) (bool, error) {
	valid := totp.Validate(code, secret)
	return valid, nil
}

// GenerateRecoveryCodes generates backup recovery codes
func GenerateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 4)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate recovery code: %w", err)
		}
		code := ""
		for _, b := range bytes {
			code += fmt.Sprintf("%02d", b%100)
		}
		codes[i] = code
	}
	return codes, nil
}
