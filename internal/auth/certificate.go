package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"os"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
	"golang.org/x/crypto/ssh"
)

type RevocationChecker func(serial uint64) (bool, error)

type CertificateAuthenticator struct {
	TrustedCAKeys  []ssh.PublicKey
	CheckRevoked   RevocationChecker
	CheckPrincipal bool
	userRepo       repository.UserRepository
}

func NewCertificateAuthenticator(userRepo repository.UserRepository, checkPrincipal bool) *CertificateAuthenticator {
	return &CertificateAuthenticator{
		CheckPrincipal: checkPrincipal,
		userRepo:       userRepo,
	}
}

func (ca *CertificateAuthenticator) Authenticate(username string, cert *ssh.Certificate) (*repository.User, error) {
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("certificate is not a user certificate")
	}

	if err := ca.validateCertSignature(cert); err != nil {
		return nil, fmt.Errorf("certificate signature validation failed: %w", err)
	}

	if err := ca.validateCertValidity(cert); err != nil {
		return nil, fmt.Errorf("certificate validity check failed: %w", err)
	}

	if ca.CheckPrincipal {
		if err := ca.validateCertPrincipals(username, cert); err != nil {
			return nil, fmt.Errorf("certificate principal validation failed: %w", err)
		}
	}

	if ca.CheckRevoked != nil {
		revoked, err := ca.CheckRevoked(cert.Serial)
		if err != nil {
			return nil, fmt.Errorf("certificate revocation check failed: %w", err)
		}
		if revoked {
			return nil, ErrCertificateRevoked
		}
	}

	user, err := ca.userRepo.GetByUsername(context.Background(), username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if user.Status != "active" {
		return nil, ErrUserDisabled
	}

	return user, nil
}

func (ca *CertificateAuthenticator) validateCertSignature(cert *ssh.Certificate) error {
	for _, caKey := range ca.TrustedCAKeys {
		certChecker := &ssh.CertChecker{
			IsUserAuthority: func(k ssh.PublicKey) bool {
				return subtle.ConstantTimeCompare(k.Marshal(), caKey.Marshal()) == 1
			},
		}
		if certChecker.IsUserAuthority(cert.SignatureKey) {
			if err := certChecker.CheckCert("", cert); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("certificate signed by untrusted CA")
}

func (ca *CertificateAuthenticator) validateCertValidity(cert *ssh.Certificate) error {
	now := time.Now()
	if cert.ValidAfter != 0 {
		validAfter := time.Unix(int64(cert.ValidAfter), 0)
		if now.Before(validAfter) {
			return fmt.Errorf("certificate is not yet valid")
		}
	}
	if cert.ValidBefore != 0 && cert.ValidBefore != ssh.CertTimeInfinity {
		validBefore := time.Unix(int64(cert.ValidBefore), 0)
		if now.After(validBefore) {
			return fmt.Errorf("certificate has expired")
		}
	}
	return nil
}

func (ca *CertificateAuthenticator) validateCertPrincipals(username string, cert *ssh.Certificate) error {
	for _, principal := range cert.ValidPrincipals {
		if principal == username {
			return nil
		}
	}
	return fmt.Errorf("certificate principal %q not found in valid principals", username)
}

func LoadCAKeysFromFiles(paths []string) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA key file %s: %w", path, err)
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CA key file %s: %w", path, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func IsSSHCertificate(key ssh.PublicKey) (*ssh.Certificate, bool) {
	cert, ok := key.(*ssh.Certificate)
	return cert, ok
}
