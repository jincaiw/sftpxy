package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jincaiw/sftpxy/internal/config"
	"golang.org/x/oauth2"
)

// OIDCIdentity contains the normalized user information returned by an OIDC provider.
type OIDCIdentity struct {
	Username string
	Email    string
	Role     string
	Claims   map[string]any
}

// OIDCAuthenticator handles redirect URL generation and code exchange for OIDC.
type OIDCAuthenticator struct {
	config       config.OIDCConfig
	oauthConfig  *oauth2.Config
	httpClient   *http.Client
	providerName string
}

// NewOIDCAuthenticator creates an OIDC helper from configuration.
func NewOIDCAuthenticator(cfg config.OIDCConfig) *OIDCAuthenticator {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}
	return &OIDCAuthenticator{
		config: cfg,
		oauthConfig: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthURL,
				TokenURL: cfg.TokenURL,
			},
		},
		httpClient:   &http.Client{Transport: transport},
		providerName: cfg.ProviderName,
	}
}

// NewStatePair returns a random state and PKCE verifier for an auth request.
func (a *OIDCAuthenticator) NewStatePair() (state string, verifier string, challenge string, err error) {
	state, err = randomHex(16)
	if err != nil {
		return "", "", "", err
	}
	verifier, err = randomHex(32)
	if err != nil {
		return "", "", "", err
	}
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return state, verifier, challenge, nil
}

// AuthCodeURL returns the provider redirect URL for an authorization code flow.
func (a *OIDCAuthenticator) AuthCodeURL(state, codeChallenge string) string {
	options := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if codeChallenge != "" {
		options = append(options,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}
	return a.oauthConfig.AuthCodeURL(state, options...)
}

// ExchangeCode exchanges the authorization code and fetches userinfo.
func (a *OIDCAuthenticator) ExchangeCode(ctx context.Context, code, verifier string) (*OIDCIdentity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	options := []oauth2.AuthCodeOption{}
	if verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := a.oauthConfig.Exchange(ctx, code, options...)
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange failed: %w", err)
	}

	claims, err := claimsFromIDToken(token)
	if err != nil {
		return nil, err
	}
	if a.config.UserInfoURL != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.UserInfoURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
		resp, err := a.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("oidc userinfo request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("oidc userinfo request failed: status %d", resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
			return nil, fmt.Errorf("oidc userinfo decode failed: %w", err)
		}
		claims = mergeOIDCClaims(claimsFromTokenClaims(token), claims)
	}

	identity := &OIDCIdentity{
		Username: stringClaim(claims, a.config.UsernameField, "preferred_username", "sub"),
		Email:    stringClaim(claims, a.config.EmailField, "email"),
		Role:     normalizeOIDCRole(claims, a.config.RoleField, a.config.RoleMappings),
		Claims:   claims,
	}
	if identity.Username == "" {
		return nil, fmt.Errorf("oidc identity missing username")
	}
	return identity, nil
}

func claimsFromIDToken(token *oauth2.Token) (map[string]any, error) {
	if token == nil {
		return map[string]any{}, nil
	}
	return claimsFromTokenClaims(token), nil
}

func claimsFromTokenClaims(token *oauth2.Token) map[string]any {
	idToken, _ := token.Extra("id_token").(string)
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return map[string]any{}
	}
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return map[string]any{}
	}
	return claims
}

func mergeOIDCClaims(baseClaims, overrideClaims map[string]any) map[string]any {
	merged := map[string]any{}
	for key, value := range baseClaims {
		merged[key] = value
	}
	for key, value := range overrideClaims {
		merged[key] = value
	}
	return merged
}

func normalizeOIDCRole(claims map[string]any, roleField string, mappings map[string]string) string {
	role := stringClaim(claims, roleField, "role")
	if mapped := mappings[role]; mapped != "" {
		return mapped
	}
	return role
}

func stringClaim(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if key == "" {
			continue
		}
		if raw, ok := claims[key]; ok {
			if value, ok := raw.(string); ok {
				return value
			}
		}
	}
	return ""
}

func randomHex(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
