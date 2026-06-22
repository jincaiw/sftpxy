// SPDX-License-Identifier: MIT

package dataprovider

import (
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/jincaiw/sftpxy/v2/internal/plugin"
)

func CheckAdminAndPass(username, password, ip string) (Admin, error) {
	username = holder.getConfig().convertName(username)
	return holder.getProvider().validateAdminAndPass(username, password, ip)
}

// CheckCachedUserCredentials checks the credentials for a cached user
func CheckCachedUserCredentials(user *CachedUser, password, ip, loginMethod, protocol string, tlsCert *x509.Certificate) (*CachedUser, *User, error) {
	if !user.User.skipExternalAuth() && isExternalAuthConfigured(loginMethod) {
		u, _, err := CheckCompositeCredentials(user.User.Username, password, ip, loginMethod, protocol, tlsCert)
		if err != nil {
			return nil, nil, err
		}
		webDAVUsersCache.swap(&u, password)
		cu, _ := webDAVUsersCache.get(u.Username)
		return cu, &u, nil
	}
	if err := user.User.CheckLoginConditions(); err != nil {
		return user, nil, err
	}
	if loginMethod == LoginMethodPassword && user.User.Filters.IsAnonymous {
		return user, nil, nil
	}
	if loginMethod != LoginMethodPassword {
		_, err := checkUserAndTLSCertificate(&user.User, protocol, tlsCert)
		if err != nil {
			return user, nil, err
		}
		if loginMethod == LoginMethodTLSCertificate {
			if !user.User.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol) {
				return user, nil, fmt.Errorf("certificate login method is not allowed for user %q", user.User.Username)
			}
			return user, nil, nil
		}
	}
	if password == "" {
		return user, nil, ErrInvalidCredentials
	}
	if user.Password != "" {
		if password == user.Password {
			return user, nil, nil
		}
	} else {
		if ok, _ := isPasswordOK(&user.User, password); ok {
			return user, nil, nil
		}
	}
	return user, nil, ErrInvalidCredentials
}

// CheckCompositeCredentials checks multiple credentials.
// WebDAV users can send both a password and a TLS certificate within the same request
func CheckCompositeCredentials(username, password, ip, loginMethod, protocol string, tlsCert *x509.Certificate) (User, string, error) {
	username = holder.getConfig().convertName(username)
	if loginMethod == LoginMethodPassword {
		user, err := CheckUserAndPass(username, password, ip, protocol)
		return user, loginMethod, err
	}
	user, err := CheckUserBeforeTLSAuth(username, ip, protocol, tlsCert)
	if err != nil {
		return user, loginMethod, err
	}
	if !user.IsTLSVerificationEnabled() {
		// for backward compatibility with 2.0.x we only check the password and change the login method here
		// in future updates we have to return an error
		user, err := CheckUserAndPass(username, password, ip, protocol)
		return user, LoginMethodPassword, err
	}
	user, err = checkUserAndTLSCertificate(&user, protocol, tlsCert)
	if err != nil {
		return user, loginMethod, err
	}
	if loginMethod == LoginMethodTLSCertificate && !user.IsLoginMethodAllowed(LoginMethodTLSCertificate, protocol) {
		return user, loginMethod, fmt.Errorf("certificate login method is not allowed for user %q", user.Username)
	}
	if loginMethod == LoginMethodTLSCertificateAndPwd {
		if plugin.Handler.HasAuthScope(plugin.AuthScopePassword) {
			user, err = doPluginAuth(username, password, nil, ip, protocol, nil, plugin.AuthScopePassword)
		} else if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&1 != 0) {
			user, err = doExternalAuth(username, password, nil, "", ip, protocol, nil)
		} else if holder.getConfig().PreLoginHook != "" {
			user, err = executePreLoginHook(username, LoginMethodPassword, ip, protocol, nil)
		}
		if err != nil {
			return user, loginMethod, err
		}
		user, err = checkUserAndPass(&user, password, ip, protocol)
	}
	return user, loginMethod, err
}

// CheckUserBeforeTLSAuth checks if a user exits before trying mutual TLS
func CheckUserBeforeTLSAuth(username, ip, protocol string, tlsCert *x509.Certificate) (User, error) {
	username = holder.getConfig().convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate) {
		user, err := doPluginAuth(username, "", nil, ip, protocol, tlsCert, plugin.AuthScopeTLSCertificate)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&8 != 0) {
		user, err := doExternalAuth(username, "", nil, "", ip, protocol, tlsCert)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	if holder.getConfig().PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol, nil)
		if err != nil {
			return user, err
		}
		err = user.LoadAndApplyGroupSettings()
		return user, err
	}
	user, err := UserExists(username, "")
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}

// CheckUserAndTLSCert returns the SFTPxy user with the given username and check if the
// given TLS certificate allow authentication without password
func CheckUserAndTLSCert(username, ip, protocol string, tlsCert *x509.Certificate) (User, error) {
	username = holder.getConfig().convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate) {
		user, err := doPluginAuth(username, "", nil, ip, protocol, tlsCert, plugin.AuthScopeTLSCertificate)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&8 != 0) {
		user, err := doExternalAuth(username, "", nil, "", ip, protocol, tlsCert)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	if holder.getConfig().PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodTLSCertificate, ip, protocol, nil)
		if err != nil {
			return user, err
		}
		return checkUserAndTLSCertificate(&user, protocol, tlsCert)
	}
	return holder.getProvider().validateUserAndTLSCert(username, protocol, tlsCert)
}

// CheckUserAndPass retrieves the SFTPxy user with the given username and password if a match is found or an error
func CheckUserAndPass(username, password, ip, protocol string) (User, error) {
	username = holder.getConfig().convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopePassword) {
		user, err := doPluginAuth(username, password, nil, ip, protocol, nil, plugin.AuthScopePassword)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&1 != 0) {
		user, err := doExternalAuth(username, password, nil, "", ip, protocol, nil)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	if holder.getConfig().PreLoginHook != "" {
		user, err := executePreLoginHook(username, LoginMethodPassword, ip, protocol, nil)
		if err != nil {
			return user, err
		}
		return checkUserAndPass(&user, password, ip, protocol)
	}
	return holder.getProvider().validateUserAndPass(username, password, ip, protocol)
}

// CheckUserAndPubKey retrieves the SFTP user with the given username and public key if a match is found or an error
func CheckUserAndPubKey(username string, pubKey []byte, ip, protocol string, isSSHCert bool) (User, string, error) {
	username = holder.getConfig().convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopePublicKey) {
		user, err := doPluginAuth(username, "", pubKey, ip, protocol, nil, plugin.AuthScopePublicKey)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&2 != 0) {
		user, err := doExternalAuth(username, "", pubKey, "", ip, protocol, nil)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	if holder.getConfig().PreLoginHook != "" {
		user, err := executePreLoginHook(username, SSHLoginMethodPublicKey, ip, protocol, nil)
		if err != nil {
			return user, "", err
		}
		return checkUserAndPubKey(&user, pubKey, isSSHCert)
	}
	return holder.getProvider().validateUserAndPubKey(username, pubKey, isSSHCert)
}

// CheckKeyboardInteractiveAuth checks the keyboard interactive authentication and returns
// the authenticated user or an error
func CheckKeyboardInteractiveAuth(username, authHook string, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (User, error) {
	var user User
	var err error
	username = holder.getConfig().convertName(username)
	if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
		user, err = doPluginAuth(username, "", nil, ip, protocol, nil, plugin.AuthScopeKeyboardInteractive)
	} else if holder.getConfig().ExternalAuthHook != "" && (holder.getConfig().ExternalAuthScope == 0 || holder.getConfig().ExternalAuthScope&4 != 0) {
		user, err = doExternalAuth(username, "", nil, "1", ip, protocol, nil)
	} else if holder.getConfig().PreLoginHook != "" {
		user, err = executePreLoginHook(username, SSHLoginMethodKeyboardInteractive, ip, protocol, nil)
	} else {
		user, err = holder.getProvider().userExists(username, "")
	}
	if err != nil {
		return user, err
	}
	return doKeyboardInteractiveAuth(&user, authHook, client, ip, protocol, isPartialAuth)
}

// GetFTPPreAuthUser returns the SFTPxy user with the specified username
// after receiving the FTP "USER" command.
// If a pre-login hook is defined it will be executed so the SFTPxy user
// can be created if it does not exist
func GetFTPPreAuthUser(username, ip string) (User, error) {
	var user User
	var err error
	if holder.getConfig().PreLoginHook != "" {
		user, err = executePreLoginHook(username, "", ip, protocolFTP, nil)
	} else {
		user, err = UserExists(username, "")
	}
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}

// GetUserAfterIDPAuth returns the SFTPxy user with the specified username
// after a successful authentication with an external identity provider.
// If a pre-login hook is defined it will be executed so the SFTPxy user
// can be created if it does not exist
func GetUserAfterIDPAuth(username, ip, protocol string, oidcTokenFields *map[string]any) (User, error) {
	var user User
	var err error
	if holder.getConfig().PreLoginHook != "" {
		user, err = executePreLoginHook(username, LoginMethodIDP, ip, protocol, oidcTokenFields)
		user.Filters.RequirePasswordChange = false
	} else {
		user, err = UserExists(username, "")
	}
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}
