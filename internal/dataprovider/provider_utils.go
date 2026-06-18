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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/plugin"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func isExternalAuthConfigured(loginMethod string) bool {
	if holder.getConfig().ExternalAuthHook != "" {
		if holder.getConfig().ExternalAuthScope == 0 {
			return true
		}
		switch loginMethod {
		case LoginMethodPassword:
			return holder.getConfig().ExternalAuthScope&1 != 0
		case LoginMethodTLSCertificate:
			return holder.getConfig().ExternalAuthScope&8 != 0
		case LoginMethodTLSCertificateAndPwd:
			return holder.getConfig().ExternalAuthScope&1 != 0 || holder.getConfig().ExternalAuthScope&8 != 0
		}
	}
	switch loginMethod {
	case LoginMethodPassword:
		return plugin.Handler.HasAuthScope(plugin.AuthScopePassword)
	case LoginMethodTLSCertificate:
		return plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate)
	case LoginMethodTLSCertificateAndPwd:
		return plugin.Handler.HasAuthScope(plugin.AuthScopePassword) ||
			plugin.Handler.HasAuthScope(plugin.AuthScopeTLSCertificate)
	default:
		return false
	}
}

func replaceTemplateVars(input string) string {
	var result strings.Builder
	i := 0
	for i < len(input) {
		if i+2 <= len(input) && input[i:i+2] == "{{" {
			if i+2 < len(input) {
				nextChar := input[i+2]
				if nextChar == ' ' || nextChar == '.' || nextChar == '-' {
					// Don't replace if followed by space, dot or minus.
					result.WriteString("{{")
					i += 2
					continue
				}
			}

			// Find the closing "}}"
			closing := strings.Index(input[i:], "}}")
			if closing != -1 {
				// Replace with {{. only if it's a proper template variable.
				result.WriteString("{{.")
				result.WriteString(input[i+2 : i+closing])
				result.WriteString("}}")
				i += closing + 2
				continue
			}
		}
		result.WriteByte(input[i])
		i++
	}
	return result.String()
}

func updateEventActionPlaceholders(actions []BaseEventAction) ([]BaseEventAction, error) {
	var result []BaseEventAction

	for _, action := range actions {
		options, err := json.Marshal(action.Options)
		if err != nil {
			return nil, err
		}
		convertedOptions := replaceTemplateVars(string(options))
		var opts BaseEventActionOptions
		err = json.Unmarshal([]byte(convertedOptions), &opts)
		if err != nil {
			return nil, err
		}
		action.Options = opts
		result = append(result, action)
	}

	return result, nil
}

func getConfigPath(name, configDir string) string {
	if !util.IsFileInputValid(name) {
		return ""
	}
	if name != "" && !filepath.IsAbs(name) {
		return filepath.Join(configDir, name)
	}
	return name
}

func checkReservedUsernames(username string) error {
	if slices.Contains(reservedUsers, username) {
		return util.NewValidationError("this username is reserved")
	}
	return nil
}

func errSchemaVersionTooOld(version int) error {
	return fmt.Errorf("database schema version %d is too old, please see the upgrading docs: https://docs.sftpgo.com/latest/data-provider/#upgrading", version)
}

func getCmdOutput(cmd *exec.Cmd, sender string) ([]byte, error) {
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(stderr)

	go func() {
		for scanner.Scan() {
			if out := scanner.Text(); out != "" {
				logger.Log(logger.LevelWarn, sender, "", "%s", out)
			}
		}
		if err := scanner.Err(); err != nil {
			logger.Log(logger.LevelError, sender, "", "error reading stderr: %v", err)
		}
	}()

	err = cmd.Wait()
	return stdout.Bytes(), err
}

func providerLog(level logger.LogLevel, format string, v ...any) {
	logger.Log(level, logSender, "", format, v...)
}
