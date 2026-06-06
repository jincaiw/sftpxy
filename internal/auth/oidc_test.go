package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jincaiw/sftpxy/internal/config"
)

func TestExchangeCodeFallsBackToIDTokenClaims(t *testing.T) {
	idToken := makeTestOIDCToken(t, map[string]any{
		"sub":   "oidc-user",
		"email": "oidc-user@example.com",
		"role":  "ops",
	})

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	}))
	defer tokenServer.Close()

	authenticator := NewOIDCAuthenticator(config.OIDCConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		AuthURL:      tokenServer.URL + "/auth",
		TokenURL:     tokenServer.URL + "/token",
		RedirectURL:  "https://example.com/callback",
		RoleMappings: map[string]string{
			"ops": "admin",
		},
	})

	identity, err := authenticator.ExchangeCode(context.Background(), "auth-code", "")
	if err != nil {
		t.Fatalf("exchange code failed: %v", err)
	}
	if identity.Username != "oidc-user" {
		t.Fatalf("username = %q, want oidc-user", identity.Username)
	}
	if identity.Email != "oidc-user@example.com" {
		t.Fatalf("email = %q, want oidc-user@example.com", identity.Email)
	}
	if identity.Role != "admin" {
		t.Fatalf("role = %q, want admin", identity.Role)
	}
}

func makeTestOIDCToken(t *testing.T, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(map[string]any{
		"alg": "none",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatalf("marshal oidc test header failed: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal oidc test claims failed: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString(headerJSON)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	return header + "." + payload + ".signature"
}
