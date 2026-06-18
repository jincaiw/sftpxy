// Copyright (C) 2024 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package dataprovider

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"slices"
	"strconv"
	"strings"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"github.com/sftpgo/sdk"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/mfa"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func isPasswordOK(user *User, password string) (bool, error) {
	if holder.getConfig().PasswordCaching {
		found, match := cachedUserPasswords.Check(user.Username, password, user.Password)
		if found {
			return match, nil
		}
	}

	match := false
	updatePwd := true
	var err error

	switch {
	case strings.HasPrefix(user.Password, bcryptPwdPrefix):
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
			return match, ErrInvalidCredentials
		}
		match = true
		updatePwd = holder.getConfig().PasswordHashing.Algo != HashingAlgoBcrypt
	case strings.HasPrefix(user.Password, argonPwdPrefix):
		match, err = argon2id.ComparePasswordAndHash(password, user.Password)
		if err != nil {
			providerLog(logger.LevelError, "error comparing password with argon hash: %v", err)
			return match, err
		}
		updatePwd = holder.getConfig().PasswordHashing.Algo != HashingAlgoArgon2ID
	case util.IsStringPrefixInSlice(user.Password, unixPwdPrefixes):
		match, err = compareUnixPasswordAndHash(user, password)
		if err != nil {
			return match, err
		}
	case util.IsStringPrefixInSlice(user.Password, pbkdfPwdPrefixes):
		match, err = comparePbkdf2PasswordAndHash(password, user.Password)
		if err != nil {
			return match, err
		}
	case util.IsStringPrefixInSlice(user.Password, digestPwdPrefixes):
		match = compareDigestPasswordAndHash(user, password)
	}

	if err == nil && match {
		cachedUserPasswords.Add(user.Username, password, user.Password)
		if updatePwd {
			convertUserPassword(user.Username, password)
		}
	}
	return match, err
}

func convertUserPassword(username, plainPwd string) {
	hashedPwd, err := hashPlainPassword(plainPwd)
	if err == nil {
		err = holder.getProvider().updateUserPassword(username, hashedPwd)
	}
	if err != nil {
		providerLog(logger.LevelWarn, "unable to convert password for user %s: %v", username, err)
	} else {
		providerLog(logger.LevelDebug, "password converted for user %s", username)
	}
}

func checkUserAndTLSCertificate(user *User, protocol string, tlsCert *x509.Certificate) (User, error) {
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	switch protocol {
	case protocolFTP, protocolWebDAV:
		for _, cert := range user.Filters.TLSCerts {
			derBlock, _ := pem.Decode(util.StringToBytes(cert))
			if derBlock != nil && bytes.Equal(derBlock.Bytes, tlsCert.Raw) {
				return *user, nil
			}
		}
		if user.Filters.TLSUsername == sdk.TLSUsernameCN {
			if user.Username == tlsCert.Subject.CommonName {
				return *user, nil
			}
			return *user, fmt.Errorf("CN %q does not match username %q", tlsCert.Subject.CommonName, user.Username)
		}
		return *user, errors.New("TLS certificate is not valid")
	default:
		return *user, fmt.Errorf("certificate authentication is not supported for protocol %v", protocol)
	}
}

func checkUserAndPass(user *User, password, ip, protocol string) (User, error) {
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	if protocol != protocolHTTP && user.MustChangePassword() {
		return *user, errors.New("login not allowed, password change required")
	}
	if user.Filters.IsAnonymous {
		user.setAnonymousSettings()
		return *user, nil
	}
	password, err = checkUserPasscode(user, password, protocol)
	if err != nil {
		return *user, ErrInvalidCredentials
	}
	if user.Password == "" || strings.TrimSpace(password) == "" {
		return *user, errors.New("credentials cannot be null or empty")
	}
	if !user.Filters.Hooks.CheckPasswordDisabled {
		hookResponse, err := executeCheckPasswordHook(user.Username, password, ip, protocol)
		if err != nil {
			providerLog(logger.LevelDebug, "error executing check password hook for user %q, ip %v, protocol %v: %v",
				user.Username, ip, protocol, err)
			return *user, errors.New("unable to check credentials")
		}
		switch hookResponse.Status {
		case -1:
			// no hook configured
		case 1:
			providerLog(logger.LevelDebug, "password accepted by check password hook for user %q, ip %v, protocol %v",
				user.Username, ip, protocol)
			return *user, nil
		case 2:
			providerLog(logger.LevelDebug, "partial success from check password hook for user %q, ip %v, protocol %v",
				user.Username, ip, protocol)
			password = hookResponse.ToVerify
		default:
			providerLog(logger.LevelDebug, "password rejected by check password hook for user %q, ip %v, protocol %v, status: %v",
				user.Username, ip, protocol, hookResponse.Status)
			return *user, ErrInvalidCredentials
		}
	}

	match, err := isPasswordOK(user, password)
	if !match {
		err = ErrInvalidCredentials
	}
	return *user, err
}

func checkUserPasscode(user *User, password, protocol string) (string, error) {
	if user.Filters.TOTPConfig.Enabled {
		switch protocol {
		case protocolFTP:
			if slices.Contains(user.Filters.TOTPConfig.Protocols, protocol) {
				// the TOTP passcode has six digits
				pwdLen := len(password)
				if pwdLen < 7 {
					providerLog(logger.LevelDebug, "password len %v is too short to contain a passcode, user %q, protocol %v",
						pwdLen, user.Username, protocol)
					return "", util.NewValidationError("password too short, cannot contain the passcode")
				}
				err := user.Filters.TOTPConfig.Secret.TryDecrypt()
				if err != nil {
					providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
						user.Username, protocol, err)
					return "", err
				}
				pwd := password[0:(pwdLen - 6)]
				passcode := password[(pwdLen - 6):]
				match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, passcode,
					user.Filters.TOTPConfig.Secret.GetPayload())
				if !match || err != nil {
					providerLog(logger.LevelWarn, "invalid passcode for user %q, protocol %v, err: %v",
						user.Username, protocol, err)
					return "", util.NewValidationError("invalid passcode")
				}
				return pwd, nil
			}
		}
	}
	return password, nil
}

func checkUserAndPubKey(user *User, pubKey []byte, isSSHCert bool) (User, string, error) {
	err := user.LoadAndApplyGroupSettings()
	if err != nil {
		return *user, "", err
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, "", err
	}
	if isSSHCert {
		return *user, "", nil
	}
	if len(user.PublicKeys) == 0 {
		return *user, "", ErrInvalidCredentials
	}
	for idx, key := range user.PublicKeys {
		storedKey, comment, _, _, err := ssh.ParseAuthorizedKey(util.StringToBytes(key))
		if err != nil {
			providerLog(logger.LevelError, "error parsing stored public key %d for user %s: %v", idx, user.Username, err)
			return *user, "", err
		}
		if bytes.Equal(storedKey.Marshal(), pubKey) {
			return *user, fmt.Sprintf("%s:%s", ssh.FingerprintSHA256(storedKey), comment), nil
		}
	}
	return *user, "", ErrInvalidCredentials
}

func compareDigestPasswordAndHash(user *User, password string) bool {
	if strings.HasPrefix(user.Password, md5DigestPwdPrefix) {
		h := md5.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", md5DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	if strings.HasPrefix(user.Password, sha256DigestPwdPrefix) {
		h := sha256.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha256DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	if strings.HasPrefix(user.Password, sha512DigestPwdPrefix) {
		h := sha512.New()
		h.Write([]byte(password))
		return fmt.Sprintf("%s%x", sha512DigestPwdPrefix, h.Sum(nil)) == user.Password
	}
	return false
}

func compareUnixPasswordAndHash(user *User, password string) (bool, error) {
	if strings.HasPrefix(user.Password, yescryptPwdPrefix) {
		return compareYescryptPassword(user.Password, password)
	}
	var crypter crypt.Crypter
	if strings.HasPrefix(user.Password, sha512cryptPwdPrefix) {
		crypter = sha512_crypt.New()
	} else if strings.HasPrefix(user.Password, sha256cryptPwdPrefix) {
		crypter = sha256_crypt.New()
	} else if strings.HasPrefix(user.Password, md5cryptPwdPrefix) {
		crypter = md5_crypt.New()
	} else if strings.HasPrefix(user.Password, md5cryptApr1PwdPrefix) {
		crypter = apr1_crypt.New()
	} else {
		return false, errors.New("unix crypt: invalid or unsupported hash format")
	}
	if err := crypter.Verify(user.Password, []byte(password)); err != nil {
		return false, err
	}
	return true, nil
}

func comparePbkdf2PasswordAndHash(password, hashedPassword string) (bool, error) {
	vals := strings.Split(hashedPassword, "$")
	if len(vals) != 5 {
		return false, fmt.Errorf("pbkdf2: hash is not in the correct format")
	}
	iterations, err := strconv.Atoi(vals[2])
	if err != nil {
		return false, err
	}
	expected, err := base64.StdEncoding.DecodeString(vals[4])
	if err != nil {
		return false, err
	}
	var salt []byte
	if util.IsStringPrefixInSlice(hashedPassword, pbkdfPwdB64SaltPrefixes) {
		salt, err = base64.StdEncoding.DecodeString(vals[3])
		if err != nil {
			return false, err
		}
	} else {
		salt = []byte(vals[3])
	}
	var hashFunc func() hash.Hash
	if strings.HasPrefix(hashedPassword, pbkdf2SHA256Prefix) || strings.HasPrefix(hashedPassword, pbkdf2SHA256B64SaltPrefix) {
		hashFunc = sha256.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA512Prefix) {
		hashFunc = sha512.New
	} else if strings.HasPrefix(hashedPassword, pbkdf2SHA1Prefix) {
		hashFunc = sha1.New
	} else {
		return false, fmt.Errorf("pbkdf2: invalid or unsupported hash format %v", vals[1])
	}
	df := pbkdf2.Key([]byte(password), salt, iterations, len(expected), hashFunc)
	return subtle.ConstantTimeCompare(df, expected) == 1, nil
}
