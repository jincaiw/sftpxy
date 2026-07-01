// SPDX-License-Identifier: MIT

package dataprovider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"

	"github.com/jincaiw/sftpxy/sdk"

	"github.com/jincaiw/sftpxy/v2/internal/command"
	"github.com/jincaiw/sftpxy/v2/internal/httpclient"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/mfa"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func getSSLMode() string {
	switch holder.getConfig().Driver {
	case PGSQLDataProviderName, CockroachDataProviderName:
		switch holder.getConfig().SSLMode {
		case 0:
			return "disable"
		case 1:
			return "require"
		case 2:
			return "verify-ca"
		case 3:
			return "verify-full"
		case 4:
			return "prefer"
		case 5:
			return "allow"
		}
	case MySQLDataProviderName:
		if holder.getConfig().requireCustomTLSForMySQL() {
			return "custom"
		}
		switch holder.getConfig().SSLMode {
		case 0:
			return "false"
		case 1:
			return "true"
		case 2:
			return "skip-verify"
		case 3:
			return "preferred"
		}
	}
	return ""
}

func terminateInteractiveAuthProgram(cmd *exec.Cmd, isFinished bool) {
	if isFinished {
		return
	}
	providerLog(logger.LevelInfo, "kill interactive auth program after an unexpected error")
	err := cmd.Process.Kill()
	if err != nil {
		providerLog(logger.LevelDebug, "error killing interactive auth program: %v", err)
	}
}

func sendKeyboardAuthHTTPReq(url string, request *plugin.KeyboardAuthRequest) (*plugin.KeyboardAuthResponse, error) {
	reqAsJSON, err := json.Marshal(request)
	if err != nil {
		providerLog(logger.LevelError, "error serializing keyboard interactive auth request: %v", err)
		return nil, err
	}
	resp, err := httpclient.Post(url, "application/json", bytes.NewBuffer(reqAsJSON))
	if err != nil {
		providerLog(logger.LevelError, "error getting keyboard interactive auth hook HTTP response: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong keyboard interactive auth http status code: %v, expected 200", resp.StatusCode)
	}
	var response plugin.KeyboardAuthResponse
	err = render.DecodeJSON(resp.Body, &response)
	return &response, err
}

func doBuiltinKeyboardInteractiveAuth(user *User, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (int, error) {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		return 0, err
	}
	hasSecondFactor := user.Filters.TOTPConfig.Enabled && slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH)
	if !isPartialAuth || !hasSecondFactor {
		answers, err := client("", "", []string{"Password: "}, []bool{false})
		if err != nil {
			return 0, err
		}
		if len(answers) != 1 {
			return 0, fmt.Errorf("unexpected number of answers: %d", len(answers))
		}
		_, err = checkUserAndPass(user, answers[0], ip, protocol)
		if err != nil {
			return 0, err
		}
	}
	return checkKeyboardInteractiveSecondFactor(user, client, protocol)
}

func checkKeyboardInteractiveSecondFactor(user *User, client ssh.KeyboardInteractiveChallenge, protocol string) (int, error) {
	if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH) {
		return 1, nil
	}
	err := user.Filters.TOTPConfig.Secret.TryDecrypt()
	if err != nil {
		providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
			user.Username, protocol, err)
		return 0, err
	}
	answers, err := client("", "", []string{"Authentication code: "}, []bool{false})
	if err != nil {
		return 0, err
	}
	if len(answers) != 1 {
		return 0, fmt.Errorf("unexpected number of answers: %v", len(answers))
	}
	match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
		user.Filters.TOTPConfig.Secret.GetPayload())
	if !match || err != nil {
		providerLog(logger.LevelWarn, "invalid passcode for user %q, protocol %v, err: %v",
			user.Username, protocol, err)
		return 0, util.NewValidationError("invalid passcode")
	}
	return 1, nil
}

func executeKeyboardInteractivePlugin(user *User, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	requestID := xid.New().String()
	authStep := 1
	req := &plugin.KeyboardAuthRequest{
		Username:  user.Username,
		IP:        ip,
		Password:  user.Password,
		RequestID: requestID,
		Step:      authStep,
	}
	var response *plugin.KeyboardAuthResponse
	var err error
	for {
		response, err = plugin.Handler.ExecuteKeyboardInteractiveStep(req)
		if err != nil {
			return authResult, err
		}
		if response.AuthResult != 0 {
			return response.AuthResult, err
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive plugin: %v", err)
			return authResult, err
		}
		answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
		if err != nil {
			return authResult, err
		}
		authStep++
		req = &plugin.KeyboardAuthRequest{
			RequestID: requestID,
			Step:      authStep,
			Username:  user.Username,
			Password:  user.Password,
			Answers:   answers,
			Questions: response.Questions,
		}
	}
}

func executeKeyboardInteractiveHTTPHook(user *User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	requestID := xid.New().String()
	authStep := 1
	req := &plugin.KeyboardAuthRequest{
		Username:  user.Username,
		IP:        ip,
		Password:  user.Password,
		RequestID: requestID,
		Step:      authStep,
	}
	var response *plugin.KeyboardAuthResponse
	var err error
	for {
		response, err = sendKeyboardAuthHTTPReq(authHook, req)
		if err != nil {
			return authResult, err
		}
		if response.AuthResult != 0 {
			return response.AuthResult, err
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive http hook: %v", err)
			return authResult, err
		}
		answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
		if err != nil {
			return authResult, err
		}
		authStep++
		req = &plugin.KeyboardAuthRequest{
			RequestID: requestID,
			Step:      authStep,
			Username:  user.Username,
			Password:  user.Password,
			Answers:   answers,
			Questions: response.Questions,
		}
	}
}

func getKeyboardInteractiveAnswers(client ssh.KeyboardInteractiveChallenge, response *plugin.KeyboardAuthResponse,
	user *User, ip, protocol string,
) ([]string, error) {
	questions := response.Questions
	answers, err := client("", response.Instruction, questions, response.Echos)
	if err != nil {
		providerLog(logger.LevelInfo, "error getting interactive auth client response: %v", err)
		return answers, err
	}
	if len(answers) != len(questions) {
		err = fmt.Errorf("client answers does not match questions, expected: %v actual: %v", questions, answers)
		providerLog(logger.LevelInfo, "keyboard interactive auth error: %v", err)
		return answers, err
	}
	if len(answers) == 1 && response.CheckPwd > 0 {
		if response.CheckPwd == 2 {
			if !user.Filters.TOTPConfig.Enabled || !slices.Contains(user.Filters.TOTPConfig.Protocols, protocolSSH) {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to check TOTP passcode, TOTP is not enabled for user %q",
					user.Username)
				return answers, errors.New("TOTP not enabled for SSH protocol")
			}
			err := user.Filters.TOTPConfig.Secret.TryDecrypt()
			if err != nil {
				providerLog(logger.LevelError, "unable to decrypt TOTP secret for user %q, protocol %v, err: %v",
					user.Username, protocol, err)
				return answers, fmt.Errorf("unable to decrypt TOTP secret: %w", err)
			}
			match, err := mfa.ValidateTOTPPasscode(user.Filters.TOTPConfig.ConfigName, answers[0],
				user.Filters.TOTPConfig.Secret.GetPayload())
			if !match || err != nil {
				providerLog(logger.LevelInfo, "keyboard interactive auth error: unable to validate passcode for user %q, match? %v, err: %v",
					user.Username, match, err)
				return answers, errors.New("unable to validate TOTP passcode")
			}
		} else {
			_, err = checkUserAndPass(user, answers[0], ip, protocol)
			providerLog(logger.LevelInfo, "interactive auth hook requested password validation for user %q, validation error: %v",
				user.Username, err)
			if err != nil {
				return answers, err
			}
		}
		answers[0] = "OK"
	}
	return answers, err
}

func handleProgramInteractiveQuestions(client ssh.KeyboardInteractiveChallenge, response *plugin.KeyboardAuthResponse,
	user *User, stdin io.WriteCloser, ip, protocol string,
) error {
	answers, err := getKeyboardInteractiveAnswers(client, response, user, ip, protocol)
	if err != nil {
		return err
	}
	for _, answer := range answers {
		if runtime.GOOS == "windows" {
			answer += "\r"
		}
		answer += "\n"
		_, err = stdin.Write([]byte(answer))
		if err != nil {
			providerLog(logger.LevelError, "unable to write client answer to keyboard interactive program: %v", err)
			return err
		}
	}
	return nil
}

func executeKeyboardInteractiveProgram(user *User, authHook string, client ssh.KeyboardInteractiveChallenge, ip, protocol string) (int, error) {
	authResult := 0
	timeout, env, args := command.GetConfig(authHook, command.HookKeyboardInteractive)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, authHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPXY_AUTHD_USERNAME=%s", user.Username),
		fmt.Sprintf("SFTPXY_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPXY_AUTHD_PASSWORD=%s", user.Password))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return authResult, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return authResult, err
	}
	err = cmd.Start()
	if err != nil {
		return authResult, err
	}
	var once sync.Once
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var response plugin.KeyboardAuthResponse
		err = json.Unmarshal(scanner.Bytes(), &response)
		if err != nil {
			providerLog(logger.LevelInfo, "interactive auth error parsing response: %v", err)
			once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			break
		}
		if response.AuthResult != 0 {
			authResult = response.AuthResult
			break
		}
		if err = response.Validate(); err != nil {
			providerLog(logger.LevelInfo, "invalid response from keyboard interactive program: %v", err)
			once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			break
		}
		go func() {
			err := handleProgramInteractiveQuestions(client, &response, user, stdin, ip, protocol)
			if err != nil {
				once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
			}
		}()
	}
	if err := scanner.Err(); err != nil {
		once.Do(func() { terminateInteractiveAuthProgram(cmd, false) })
	}
	stdin.Close()
	once.Do(func() { terminateInteractiveAuthProgram(cmd, true) })
	go func() {
		_, err := cmd.Process.Wait()
		if err != nil {
			providerLog(logger.LevelWarn, "error waiting for %q process to exit: %v", authHook, err)
		}
	}()

	return authResult, err
}

func doKeyboardInteractiveAuth(user *User, authHook string, client ssh.KeyboardInteractiveChallenge,
	ip, protocol string, isPartialAuth bool,
) (User, error) {
	if err := user.LoadAndApplyGroupSettings(); err != nil {
		return *user, err
	}
	var authResult int
	var err error
	if !user.Filters.Hooks.ExternalAuthDisabled {
		if plugin.Handler.HasAuthScope(plugin.AuthScopeKeyboardInteractive) {
			authResult, err = executeKeyboardInteractivePlugin(user, client, ip, protocol)
			if authResult == 1 && err == nil {
				authResult, err = checkKeyboardInteractiveSecondFactor(user, client, protocol)
			}
		} else if authHook != "" {
			if strings.HasPrefix(authHook, "http") {
				authResult, err = executeKeyboardInteractiveHTTPHook(user, authHook, client, ip, protocol)
			} else {
				authResult, err = executeKeyboardInteractiveProgram(user, authHook, client, ip, protocol)
			}
		} else {
			authResult, err = doBuiltinKeyboardInteractiveAuth(user, client, ip, protocol, isPartialAuth)
		}
	} else {
		authResult, err = doBuiltinKeyboardInteractiveAuth(user, client, ip, protocol, isPartialAuth)
	}
	if err != nil {
		return *user, err
	}
	if authResult != 1 {
		return *user, fmt.Errorf("keyboard interactive auth failed, result: %v", authResult)
	}
	err = user.CheckLoginConditions()
	if err != nil {
		return *user, err
	}
	return *user, nil
}

func isCheckPasswordHookDefined(protocol string) bool {
	if holder.getConfig().CheckPasswordHook == "" {
		return false
	}
	if holder.getConfig().CheckPasswordScope == 0 {
		return true
	}
	switch protocol {
	case protocolSSH:
		return holder.getConfig().CheckPasswordScope&1 != 0
	case protocolFTP:
		return holder.getConfig().CheckPasswordScope&2 != 0
	case protocolWebDAV:
		return holder.getConfig().CheckPasswordScope&4 != 0
	default:
		return false
	}
}

func getPasswordHookResponse(username, password, ip, protocol string) ([]byte, error) {
	if strings.HasPrefix(holder.getConfig().CheckPasswordHook, "http") {
		var result []byte
		req := checkPasswordRequest{
			Username: username,
			Password: password,
			IP:       ip,
			Protocol: protocol,
		}
		reqAsJSON, err := json.Marshal(req)
		if err != nil {
			return result, err
		}
		resp, err := httpclient.Post(holder.getConfig().CheckPasswordHook, "application/json", bytes.NewBuffer(reqAsJSON))
		if err != nil {
			providerLog(logger.LevelError, "error getting check password hook response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong http status code from chek password hook: %v, expected 200", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	timeout, env, args := command.GetConfig(holder.getConfig().CheckPasswordHook, command.HookCheckPassword)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, holder.getConfig().CheckPasswordHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPXY_AUTHD_USERNAME=%s", username),
		fmt.Sprintf("SFTPXY_AUTHD_PASSWORD=%s", password),
		fmt.Sprintf("SFTPXY_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPXY_AUTHD_PROTOCOL=%s", protocol),
	)
	return getCmdOutput(cmd, "check_password_hook")
}

func executeCheckPasswordHook(username, password, ip, protocol string) (checkPasswordResponse, error) {
	var response checkPasswordResponse

	if !isCheckPasswordHookDefined(protocol) {
		response.Status = -1
		return response, nil
	}

	startTime := time.Now()
	out, err := getPasswordHookResponse(username, password, ip, protocol)
	providerLog(logger.LevelDebug, "check password hook executed, error: %v, elapsed: %v", err, time.Since(startTime))
	if err != nil {
		return response, err
	}
	err = json.Unmarshal(out, &response)
	return response, err
}

func getPreLoginHookResponse(loginMethod, ip, protocol string, userAsJSON []byte) ([]byte, error) {
	if strings.HasPrefix(holder.getConfig().PreLoginHook, "http") {
		var url *url.URL
		var result []byte
		url, err := url.Parse(holder.getConfig().PreLoginHook)
		if err != nil {
			providerLog(logger.LevelError, "invalid url for pre-login hook %q, error: %v", holder.getConfig().PreLoginHook, err)
			return result, err
		}
		q := url.Query()
		q.Add("login_method", loginMethod)
		q.Add("ip", ip)
		q.Add("protocol", protocol)
		url.RawQuery = q.Encode()

		resp, err := httpclient.Post(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting pre-login hook response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			return result, nil
		}
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong pre-login hook http status code: %v, expected 200", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	timeout, env, args := command.GetConfig(holder.getConfig().PreLoginHook, command.HookPreLogin)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, holder.getConfig().PreLoginHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPXY_LOGIND_USER=%s", userAsJSON),
		fmt.Sprintf("SFTPXY_LOGIND_METHOD=%s", loginMethod),
		fmt.Sprintf("SFTPXY_LOGIND_IP=%s", ip),
		fmt.Sprintf("SFTPXY_LOGIND_PROTOCOL=%s", protocol),
	)
	return getCmdOutput(cmd, "pre_login_hook")
}

func executePreLoginHook(username, loginMethod, ip, protocol string, oidcTokenFields *map[string]any) (User, error) {
	var user User

	u, mergedUser, userAsJSON, err := getUserAndJSONForHook(username, oidcTokenFields)
	if err != nil {
		return u, err
	}
	if mergedUser.Filters.Hooks.PreLoginDisabled {
		return u, nil
	}
	startTime := time.Now()
	out, err := getPreLoginHookResponse(loginMethod, ip, protocol, userAsJSON)
	if err != nil {
		return u, fmt.Errorf("pre-login hook error: %v, username %q, ip %v, protocol %v elapsed %v",
			err, username, ip, protocol, time.Since(startTime))
	}
	providerLog(logger.LevelDebug, "pre-login hook completed, elapsed: %s", time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from pre-login hook, no modification requested for user %q id: %d",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		return u, nil
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return u, fmt.Errorf("invalid pre-login hook response %q, error: %v", out, err)
	}
	if u.ID > 0 {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		user.LastPasswordChange = u.LastPasswordChange
		user.FirstDownload = u.FirstDownload
		user.FirstUpload = u.FirstUpload
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		if err := holder.getProvider().updateUser(&user); err != nil {
			return u, err
		}
	} else {
		if err := holder.getProvider().addUser(&user); err != nil {
			return u, err
		}
	}
	user, err = holder.getProvider().userExists(user.Username, "")
	if err != nil {
		return u, err
	}
	providerLog(logger.LevelDebug, "user %q added/updated from pre-login hook response, id: %d", username, u.ID)
	if u.ID > 0 {
		webDAVUsersCache.swap(&user, "")
	}
	return user, nil
}

// ExecutePostLoginHook executes the post login hook if defined
func ExecutePostLoginHook(user *User, loginMethod, ip, protocol string, err error) {
	if holder.getConfig().PostLoginHook == "" {
		return
	}
	if holder.getConfig().PostLoginScope == 1 && err == nil {
		return
	}
	if holder.getConfig().PostLoginScope == 2 && err != nil {
		return
	}

	go func() {
		actionsConcurrencyGuard <- struct{}{}
		defer func() {
			<-actionsConcurrencyGuard
		}()

		status := "0"
		if err == nil {
			status = "1"
		}

		user.PrepareForRendering()
		userAsJSON, err := json.Marshal(user)
		if err != nil {
			providerLog(logger.LevelError, "error serializing user in post login hook: %v", err)
			return
		}
		if strings.HasPrefix(holder.getConfig().PostLoginHook, "http") {
			var url *url.URL
			url, err := url.Parse(holder.getConfig().PostLoginHook)
			if err != nil {
				providerLog(logger.LevelDebug, "Invalid post-login hook %q", holder.getConfig().PostLoginHook)
				return
			}
			q := url.Query()
			q.Add("login_method", loginMethod)
			q.Add("ip", ip)
			q.Add("protocol", protocol)
			q.Add("status", status)
			url.RawQuery = q.Encode()

			startTime := time.Now()
			respCode := 0
			resp, err := httpclient.RetryablePost(url.String(), "application/json", bytes.NewBuffer(userAsJSON))
			if err == nil {
				respCode = resp.StatusCode
				resp.Body.Close()
			}
			providerLog(logger.LevelDebug, "post login hook executed for user %q, ip %v, protocol %v, response code: %v, elapsed: %v err: %v",
				user.Username, ip, protocol, respCode, time.Since(startTime), err)
			return
		}
		timeout, env, args := command.GetConfig(holder.getConfig().PostLoginHook, command.HookPostLogin)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, holder.getConfig().PostLoginHook, args...)
		cmd.Env = append(env,
			fmt.Sprintf("SFTPXY_LOGIND_USER=%s", userAsJSON),
			fmt.Sprintf("SFTPXY_LOGIND_IP=%s", ip),
			fmt.Sprintf("SFTPXY_LOGIND_METHOD=%s", loginMethod),
			fmt.Sprintf("SFTPXY_LOGIND_STATUS=%s", status),
			fmt.Sprintf("SFTPXY_LOGIND_PROTOCOL=%s", protocol))
		startTime := time.Now()
		err = cmd.Run()
		providerLog(logger.LevelDebug, "post login hook executed for user %q, ip %v, protocol %v, elapsed %v err: %v",
			user.Username, ip, protocol, time.Since(startTime), err)
	}()
}

func getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol string, cert *x509.Certificate,
	user User,
) ([]byte, error) {
	var tlsCert string
	if cert != nil {
		var err error
		tlsCert, err = util.EncodeTLSCertToPem(cert)
		if err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(holder.getConfig().ExternalAuthHook, "http") {
		var result []byte
		authRequest := make(map[string]any)
		authRequest["username"] = username
		authRequest["ip"] = ip
		authRequest["password"] = password
		authRequest["public_key"] = pkey
		authRequest["protocol"] = protocol
		authRequest["keyboard_interactive"] = keyboardInteractive
		authRequest["tls_cert"] = tlsCert
		if user.ID > 0 {
			authRequest["user"] = user
		}
		authRequestAsJSON, err := json.Marshal(authRequest)
		if err != nil {
			providerLog(logger.LevelError, "error serializing external auth request: %v", err)
			return result, err
		}
		resp, err := httpclient.Post(holder.getConfig().ExternalAuthHook, "application/json", bytes.NewBuffer(authRequestAsJSON))
		if err != nil {
			providerLog(logger.LevelWarn, "error getting external auth hook HTTP response: %v", err)
			return result, err
		}
		defer resp.Body.Close()
		providerLog(logger.LevelDebug, "external auth hook executed, response code: %v", resp.StatusCode)
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("wrong external auth http status code: %v, expected 200", resp.StatusCode)
		}

		return io.ReadAll(io.LimitReader(resp.Body, maxHookResponseSize))
	}
	var userAsJSON []byte
	var err error
	if user.ID > 0 {
		userAsJSON, err = json.Marshal(user)
		if err != nil {
			return nil, fmt.Errorf("unable to serialize user as JSON: %w", err)
		}
	}
	timeout, env, args := command.GetConfig(holder.getConfig().ExternalAuthHook, command.HookExternalAuth)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, holder.getConfig().ExternalAuthHook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPXY_AUTHD_USERNAME=%s", username),
		fmt.Sprintf("SFTPXY_AUTHD_USER=%s", userAsJSON),
		fmt.Sprintf("SFTPXY_AUTHD_IP=%s", ip),
		fmt.Sprintf("SFTPXY_AUTHD_PASSWORD=%s", password),
		fmt.Sprintf("SFTPXY_AUTHD_PUBLIC_KEY=%s", pkey),
		fmt.Sprintf("SFTPXY_AUTHD_PROTOCOL=%s", protocol),
		fmt.Sprintf("SFTPXY_AUTHD_TLS_CERT=%s", strings.ReplaceAll(tlsCert, "\n", "\\n")),
		fmt.Sprintf("SFTPXY_AUTHD_KEYBOARD_INTERACTIVE=%v", keyboardInteractive))

	return getCmdOutput(cmd, "external_auth_hook")
}

func updateUserFromExtAuthResponse(user *User, password, pkey string) {
	if password != "" {
		user.Password = password
	}
	if pkey != "" && !util.IsStringPrefixInSlice(pkey, user.PublicKeys) {
		user.PublicKeys = append(user.PublicKeys, pkey)
	}
	user.LastPasswordChange = 0
}

func checkPasswordAfterEmptyExtAuthResponse(user *User, plainPwd, protocol string) error {
	if plainPwd == "" {
		return nil
	}
	match, err := isPasswordOK(user, plainPwd)
	if match && err == nil {
		return nil
	}

	hashedPwd, err := hashPlainPassword(plainPwd)
	if err != nil {
		providerLog(logger.LevelError, "unable to hash password for user %q after empty external response: %v",
			user.Username, err)
		return err
	}
	err = holder.getProvider().updateUserPassword(user.Username, hashedPwd)
	if err != nil {
		providerLog(logger.LevelError, "unable to update password for user %q after empty external response: %v",
			user.Username, err)
	}
	user.Password = hashedPwd
	cachedUserPasswords.Add(user.Username, plainPwd, user.Password)
	if protocol != protocolWebDAV {
		webDAVUsersCache.swap(user, plainPwd)
	}
	providerLog(logger.LevelDebug, "updated password for user %q after empty external auth response", user.Username)
	return nil
}

func doExternalAuth(username, password string, pubKey []byte, keyboardInteractive, ip, protocol string,
	tlsCert *x509.Certificate,
) (User, error) {
	var user User

	u, mergedUser, err := getUserForHook(username, nil)
	if err != nil {
		return user, err
	}

	if mergedUser.skipExternalAuth() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()
	out, err := getExternalAuthResponse(username, password, pkey, keyboardInteractive, ip, protocol, tlsCert, u)
	if err != nil {
		return user, fmt.Errorf("external auth error for user %q, elapsed: %s: %w", username, time.Since(startTime), err)
	}
	providerLog(logger.LevelDebug, "external auth completed for user %q, elapsed: %s", username, time.Since(startTime))
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from external hook, no modification requested for user %q, id: %d",
			username, u.ID)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		err = checkPasswordAfterEmptyExtAuthResponse(&u, password, protocol)
		return u, err
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return user, fmt.Errorf("invalid external auth response: %v", err)
	}
	// an empty username means authentication failure
	if user.Username == "" {
		return user, ErrInvalidCredentials
	}
	updateUserFromExtAuthResponse(&user, password, pkey)
	// some users want to map multiple login usernames with a single SFTPxy account
	// for example an SFTP user logins using "user1" or "user2" and the external auth
	// returns "user" in both cases, so we use the username returned from
	// external auth and not the one used to login
	if user.Username != username {
		u, err = holder.getProvider().userExists(user.Username, "")
	}
	if u.ID > 0 && err == nil {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		user.LastPasswordChange = u.LastPasswordChange
		user.FirstDownload = u.FirstDownload
		user.FirstUpload = u.FirstUpload
		user.CreatedAt = u.CreatedAt
		user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		user, err = updateUserAfterExternalAuth(&user)
		if err == nil {
			if protocol != protocolWebDAV {
				webDAVUsersCache.swap(&user, password)
			}
			cachedUserPasswords.Add(user.Username, password, user.Password)
		}
		return user, err
	}
	err = holder.getProvider().addUser(&user)
	if err != nil {
		return user, err
	}
	return holder.getProvider().userExists(user.Username, "")
}

func doPluginAuth(username, password string, pubKey []byte, ip, protocol string,
	tlsCert *x509.Certificate, authScope int,
) (User, error) {
	var user User

	u, mergedUser, userAsJSON, err := getUserAndJSONForHook(username, nil)
	if err != nil {
		return user, err
	}

	if mergedUser.skipExternalAuth() {
		return u, nil
	}

	pkey, err := util.GetSSHPublicKeyAsString(pubKey)
	if err != nil {
		return user, err
	}

	startTime := time.Now()

	out, err := plugin.Handler.Authenticate(username, password, ip, protocol, pkey, tlsCert, authScope, userAsJSON)
	if err != nil {
		return user, fmt.Errorf("plugin auth error for user %q: %v, elapsed: %v, auth scope: %d",
			username, err, time.Since(startTime), authScope)
	}
	providerLog(logger.LevelDebug, "plugin auth completed for user %q, elapsed: %v, auth scope: %d",
		username, time.Since(startTime), authScope)
	if util.IsByteArrayEmpty(out) {
		providerLog(logger.LevelDebug, "empty response from plugin auth, no modification requested for user %q id: %d, auth scope: %d",
			username, u.ID, authScope)
		if u.ID == 0 {
			return u, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		err = checkPasswordAfterEmptyExtAuthResponse(&u, password, protocol)
		return u, err
	}
	err = json.Unmarshal(out, &user)
	if err != nil {
		return user, fmt.Errorf("invalid plugin auth response: %v", err)
	}
	updateUserFromExtAuthResponse(&user, password, pkey)
	if u.ID > 0 {
		user.ID = u.ID
		user.UsedQuotaSize = u.UsedQuotaSize
		user.UsedQuotaFiles = u.UsedQuotaFiles
		user.UsedUploadDataTransfer = u.UsedUploadDataTransfer
		user.UsedDownloadDataTransfer = u.UsedDownloadDataTransfer
		user.LastQuotaUpdate = u.LastQuotaUpdate
		user.LastLogin = u.LastLogin
		user.LastPasswordChange = u.LastPasswordChange
		user.FirstDownload = u.FirstDownload
		user.FirstUpload = u.FirstUpload
		// preserve TOTP config and recovery codes
		user.Filters.TOTPConfig = u.Filters.TOTPConfig
		user.Filters.RecoveryCodes = u.Filters.RecoveryCodes
		user, err = updateUserAfterExternalAuth(&user)
		if err == nil {
			if protocol != protocolWebDAV {
				webDAVUsersCache.swap(&user, password)
			}
			cachedUserPasswords.Add(user.Username, password, user.Password)
		}
		return user, err
	}
	err = holder.getProvider().addUser(&user)
	if err != nil {
		return user, err
	}
	return holder.getProvider().userExists(user.Username, "")
}

func updateUserAfterExternalAuth(user *User) (User, error) {
	if err := holder.getProvider().updateUser(user); err != nil {
		return *user, err
	}
	return holder.getProvider().userExists(user.Username, "")
}

func getUserForHook(username string, oidcTokenFields *map[string]any) (User, User, error) {
	u, err := holder.getProvider().userExists(username, "")
	if err != nil {
		if !errors.Is(err, util.ErrNotFound) {
			return u, u, err
		}
		u = User{
			BaseUser: sdk.BaseUser{
				ID:       0,
				Username: username,
			},
		}
	}
	mergedUser := u.getACopy()
	err = mergedUser.LoadAndApplyGroupSettings()
	if err != nil {
		return u, mergedUser, err
	}

	u.OIDCCustomFields = oidcTokenFields
	return u, mergedUser, err
}

func getUserAndJSONForHook(username string, oidcTokenFields *map[string]any) (User, User, []byte, error) {
	u, mergedUser, err := getUserForHook(username, oidcTokenFields)
	if err != nil {
		return u, mergedUser, nil, err
	}
	userAsJSON, err := json.Marshal(u)
	if err != nil {
		return u, mergedUser, userAsJSON, err
	}
	return u, mergedUser, userAsJSON, err
}

func isLastActivityRecent(lastActivity int64, minDelay time.Duration) bool {
	lastActivityTime := util.GetTimeFromMsecSinceEpoch(lastActivity)
	diff := -time.Until(lastActivityTime)
	if diff < -10*time.Second {
		return false
	}
	return diff < minDelay
}
