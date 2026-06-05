package auth

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jincaiw/sftpxy/internal/config"
)

// LDAPUser contains the user information returned by an LDAP directory lookup.
type LDAPUser struct {
	Username string
	Email    string
	Groups   []string
}

// LDAPAuthenticator authenticates users against an LDAP or Active Directory server.
type LDAPAuthenticator struct {
	config config.LDAPConfig
}

// NewLDAPAuthenticator creates a new LDAP authenticator.
func NewLDAPAuthenticator(cfg config.LDAPConfig) *LDAPAuthenticator {
	return &LDAPAuthenticator{config: cfg}
}

// Authenticate verifies the username/password pair against LDAP and returns basic attributes.
func (a *LDAPAuthenticator) Authenticate(username, password string) (*LDAPUser, error) {
	if !a.config.Enabled {
		return nil, fmt.Errorf("ldap authentication is disabled")
	}
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	conn, err := ldap.DialURL(a.config.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: a.config.InsecureSkipVerify,
	}))
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	if a.config.BindDN != "" {
		if err := conn.Bind(a.config.BindDN, a.config.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap service bind failed: %w", err)
		}
	}

	filter := fmt.Sprintf(a.config.UserFilter, ldap.EscapeFilter(username))
	request := ldap.NewSearchRequest(
		a.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{a.config.UsernameAttribute, "mail", "memberOf", "cn"},
		nil,
	)
	result, err := conn.Search(request)
	if err != nil {
		return nil, fmt.Errorf("ldap search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("ldap user not found")
	}

	entry := result.Entries[0]
	userDN := entry.DN
	if err := conn.Bind(userDN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &LDAPUser{
		Username: firstNonEmpty(
			entry.GetAttributeValue(a.config.UsernameAttribute),
			entry.GetAttributeValue("cn"),
			username,
		),
		Email: entry.GetAttributeValue("mail"),
		Groups: append(
			[]string{},
			entry.GetAttributeValues("memberOf")...,
		),
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
