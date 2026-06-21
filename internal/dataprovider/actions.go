// SPDX-License-Identifier: MIT

package dataprovider

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jincaiw/sftpxy/sdk/plugin/notifier"

	"github.com/jincaiw/sftpxy/v2/internal/command"
	"github.com/jincaiw/sftpxy/v2/internal/httpclient"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

const (
	// ActionExecutorSelf is used as username for self action, for example a user/admin that updates itself
	ActionExecutorSelf = "__self__"
	// ActionExecutorSystem is used as username for actions with no explicit executor associated, for example
	// adding/updating a user/admin by loading initial data
	ActionExecutorSystem = "__system__"
)

const (
	actionObjectUser        = "user"
	actionObjectFolder      = "folder"
	actionObjectGroup       = "group"
	actionObjectAdmin       = "admin"
	actionObjectAPIKey      = "api_key"
	actionObjectShare       = "share"
	actionObjectEventAction = "event_action"
	actionObjectEventRule   = "event_rule"
	actionObjectRole        = "role"
	actionObjectIPListEntry = "ip_list_entry"
	actionObjectConfigs     = "configs"
)

var (
	actionsConcurrencyGuard = make(chan struct{}, 100)
	reservedUsers           = []string{ActionExecutorSelf, ActionExecutorSystem}
)

func executeAction(operation, executor, ip, objectType, objectName, role string, object plugin.Renderer) {
	if plugin.Handler.HasNotifiers() {
		plugin.Handler.NotifyProviderEvent(&notifier.ProviderEvent{
			Action:     operation,
			Username:   executor,
			ObjectType: objectType,
			ObjectName: objectName,
			IP:         ip,
			Role:       role,
			Timestamp:  time.Now().UnixNano(),
		}, object)
	}
	if fnHandleRuleForProviderEvent != nil {
		fnHandleRuleForProviderEvent(operation, executor, ip, objectType, objectName, role, object)
	}
	if holder.getConfig().Actions.Hook == "" {
		return
	}
	if !slices.Contains(holder.getConfig().Actions.ExecuteOn, operation) ||
		!slices.Contains(holder.getConfig().Actions.ExecuteFor, objectType) {
		return
	}

	go func() {
		actionsConcurrencyGuard <- struct{}{}
		defer func() {
			<-actionsConcurrencyGuard
		}()

		dataAsJSON, err := object.RenderAsJSON(operation != operationDelete)
		if err != nil {
			providerLog(logger.LevelError, "unable to serialize user as JSON for operation %q: %v", operation, err)
			return
		}
		if strings.HasPrefix(holder.getConfig().Actions.Hook, "http") {
			var url *url.URL
			url, err := url.Parse(holder.getConfig().Actions.Hook)
			if err != nil {
				providerLog(logger.LevelError, "Invalid http_notification_url %q for operation %q: %v",
					holder.getConfig().Actions.Hook, operation, err)
				return
			}
			q := url.Query()
			q.Add("action", operation)
			q.Add("username", executor)
			q.Add("ip", ip)
			q.Add("object_type", objectType)
			q.Add("object_name", objectName)
			if role != "" {
				q.Add("role", role)
			}
			q.Add("timestamp", fmt.Sprintf("%d", time.Now().UnixNano()))
			url.RawQuery = q.Encode()
			startTime := time.Now()
			resp, err := httpclient.RetryablePost(url.String(), "application/json", bytes.NewBuffer(dataAsJSON))
			respCode := 0
			if err == nil {
				respCode = resp.StatusCode
				resp.Body.Close()
			}
			providerLog(logger.LevelDebug, "notified operation %q to URL: %s status code: %d, elapsed: %s err: %v",
				operation, url.Redacted(), respCode, time.Since(startTime), err)
			return
		}
		executeNotificationCommand(operation, executor, ip, objectType, objectName, role, dataAsJSON) //nolint:errcheck // the error is used in test cases only
	}()
}

func executeNotificationCommand(operation, executor, ip, objectType, objectName, role string, objectAsJSON []byte) error {
	if !filepath.IsAbs(holder.getConfig().Actions.Hook) {
		err := fmt.Errorf("invalid notification command %q", holder.getConfig().Actions.Hook)
		logger.Warn(logSender, "", "unable to execute notification command: %v", err)
		return err
	}

	timeout, env, args := command.GetConfig(holder.getConfig().Actions.Hook, command.HookProviderActions)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, holder.getConfig().Actions.Hook, args...)
	cmd.Env = append(env,
		fmt.Sprintf("SFTPXY_PROVIDER_ACTION=%s", operation),
		fmt.Sprintf("SFTPXY_PROVIDER_OBJECT_TYPE=%s", objectType),
		fmt.Sprintf("SFTPXY_PROVIDER_OBJECT_NAME=%s", objectName),
		fmt.Sprintf("SFTPXY_PROVIDER_USERNAME=%s", executor),
		fmt.Sprintf("SFTPXY_PROVIDER_IP=%s", ip),
		fmt.Sprintf("SFTPXY_PROVIDER_ROLE=%s", role),
		fmt.Sprintf("SFTPXY_PROVIDER_TIMESTAMP=%d", util.GetTimeAsMsSinceEpoch(time.Now())),
		fmt.Sprintf("SFTPXY_PROVIDER_OBJECT=%s", objectAsJSON))

	startTime := time.Now()
	err := cmd.Run()
	providerLog(logger.LevelDebug, "executed command %q, elapsed: %s, error: %v", holder.getConfig().Actions.Hook,
		time.Since(startTime), err)
	return err
}
