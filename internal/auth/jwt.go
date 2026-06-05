package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidJWT = errors.New("invalid jwt")
)

// JWTClaims contains the token payload used by the HTTP/API authentication flow.
type JWTClaims struct {
	Subject   string   `json:"sub"`
	Role      string   `json:"role"`
	UserID    int64    `json:"uid,omitempty"`
	SessionID string   `json:"sid,omitempty"`
	HomeDir   string   `json:"home_dir,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  string   `json:"aud,omitempty"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

// JWTManager signs and validates HMAC-based JWTs.
type JWTManager struct {
	secret   []byte
	issuer   string
	audience string
}

// NewJWTManager creates a JWT manager with the provided secret and issuer metadata.
func NewJWTManager(secret, issuer, audience string) (*JWTManager, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("jwt secret must not be empty")
	}
	if issuer == "" {
		issuer = "sftpxy"
	}
	return &JWTManager{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
	}, nil
}

// Sign creates a compact JWT string for the given claims.
func (m *JWTManager) Sign(claims JWTClaims) (string, error) {
	if claims.Subject == "" {
		return "", fmt.Errorf("jwt subject must not be empty")
	}
	now := time.Now().Unix()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now + int64(time.Hour.Seconds())
	}
	if claims.Issuer == "" {
		claims.Issuer = m.issuer
	}
	if claims.Audience == "" {
		claims.Audience = m.audience
	}

	headerPayload := make([]string, 0, 3)
	for _, v := range []any{
		map[string]string{"alg": "HS256", "typ": "JWT"},
		claims,
	} {
		encoded, err := encodeJWTPart(v)
		if err != nil {
			return "", err
		}
		headerPayload = append(headerPayload, encoded)
	}
	signingInput := strings.Join(headerPayload, ".")
	return signingInput + "." + m.sign(signingInput), nil
}

// Parse validates a compact JWT string and returns the decoded claims.
func (m *JWTManager) Parse(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidJWT
	}
	signingInput := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(m.sign(signingInput))) {
		return nil, ErrInvalidJWT
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidJWT
	}
	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidJWT
	}
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now >= claims.ExpiresAt {
		return nil, fmt.Errorf("%w: expired", ErrInvalidJWT)
	}
	if claims.Issuer != "" && claims.Issuer != m.issuer {
		return nil, fmt.Errorf("%w: issuer mismatch", ErrInvalidJWT)
	}
	if m.audience != "" && claims.Audience != "" && claims.Audience != m.audience {
		return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidJWT)
	}
	return &claims, nil
}

func (m *JWTManager) sign(input string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func encodeJWTPart(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}
