// SPDX-License-Identifier: MIT

package common

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jincaiw/sftpxy/sdk"
	"github.com/jincaiw/sftpxy/sdk/plugin/notifier"

	"github.com/jincaiw/sftpxy/v2/internal/command"
	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/httpclient"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
)

var (
	errUnexpectedHTTResponse = errors.New("unexpected HTTP hook response code")
	hooksConcurrencyGuard    = make(chan struct{}, 150)
	activeHooks              atomic.Int32
)

func startNewHook() {
	activeHooks.Add(1)
	hooksConcurrencyGuard <- struct{}{}
}

func hookEnded() {
	activeHooks.Add(-1)
	<-hooksConcurrencyGuard
}

// ProtocolActions defines the action to execute on file operations and SSH commands
type ProtocolActions struct {
	// Valid values are download, upload, pre-delete, delete, rename, ssh_cmd. Empty slice to disable
	ExecuteOn []string `json:"execute_on" mapstructure:"execute_on"`
	// Actions to be performed synchronously.
	// The pre-delete action is always executed synchronously while the other ones are asynchronous.
	// Executing an action synchronously means that SFTPxy will not return a result code to the client
	// (which is waiting for it) until your hook have completed its execution.
	ExecuteSync []string `json:"execute_sync" mapstructure:"execute_sync"`
	// Absolute path to an external program or an HTTP URL
	Hook string `json:"hook" mapstructure:"hook"`
}

// actionHandler holds the active ActionHandler. It is stored atomically:
// tests replace it while goroutines from previously executed actions may
// still read it.
var actionHandler atomic.Pointer[ActionHandler]

func init() {
	h := ActionHandler(&defaultActionHandler{})
	actionHandler.Store(&h)
}

// getActionHandler returns the active ActionHandler.
func getActionHandler() ActionHandler {
	if h := actionHandler.Load(); h != nil {
		return *h
	}
	return &defaultActionHandler{}
}

// InitializeActionHandler lets the user choose an action handler implementation.
//
// Do NOT call this function after application initialization.
func InitializeActionHandler(handler ActionHandler) {
	actionHandler.Store(&handler)
}

// ExecutePreAction executes a pre-* action and returns the result.
// The returned status has the following meaning:
// - 0 not executed
// - 1 executed using an external hook
// - 2 executed using the event manager
func ExecutePreAction(conn *BaseConnection, operation, filePath, virtualPath string, fileSize int64, openFlags int) (int, error) {
	var event *notifier.FsEvent
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	configMutex.RLock()
	executeOn := Config.Actions.ExecuteOn
	configMutex.RUnlock()
	hasHook := slices.Contains(executeOn, operation)
	hasRules := eventManager.hasFsRules()
	if !hasHook && !hasNotifiersPlugin && !hasRules {
		return 0, nil
	}
	dateTime := time.Now()
	event = newActionNotification(&conn.User, operation, filePath, virtualPath, "", "", "",
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, openFlags, conn.getNotificationStatus(nil), 0, dateTime, nil)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(event)
	}
	if hasRules {
		params := EventParams{
			Name:              event.Username,
			Groups:            conn.User.Groups,
			Event:             event.Action,
			Status:            event.Status,
			VirtualPath:       event.VirtualPath,
			FsPath:            event.Path,
			VirtualTargetPath: event.VirtualTargetPath,
			FsTargetPath:      event.TargetPath,
			ObjectName:        path.Base(event.VirtualPath),
			Extension:         path.Ext(event.VirtualPath),
			FileSize:          event.FileSize,
			Protocol:          event.Protocol,
			IP:                event.IP,
			Role:              event.Role,
			Timestamp:         dateTime,
			Email:             conn.User.Email,
			Object:            nil,
		}
		executedSync, err := eventManager.handleFsEvent(params)
		if executedSync {
			return 2, err
		}
	}
	if !hasHook {
		return 0, nil
	}
	return getActionHandler().Handle(event)
}

// ExecuteActionNotification executes the defined hook, if any, for the specified action
func ExecuteActionNotification(conn *BaseConnection, operation, filePath, virtualPath, target, virtualTarget, sshCmd string,
	fileSize int64, err error, elapsed int64, metadata map[string]string,
) error {
	hasNotifiersPlugin := plugin.Handler.HasNotifiers()
	configMutex.RLock()
	executeOn := Config.Actions.ExecuteOn
	executeSync := Config.Actions.ExecuteSync
	configMutex.RUnlock()
	hasHook := slices.Contains(executeOn, operation)
	hasRules := eventManager.hasFsRules()
	if !hasHook && !hasNotifiersPlugin && !hasRules {
		return nil
	}
	dateTime := time.Now()
	notification := newActionNotification(&conn.User, operation, filePath, virtualPath, target, virtualTarget, sshCmd,
		conn.protocol, conn.GetRemoteIP(), conn.ID, fileSize, 0, conn.getNotificationStatus(err), elapsed, dateTime, metadata)
	if hasNotifiersPlugin {
		plugin.Handler.NotifyFsEvent(notification)
	}
	if hasRules {
		params := EventParams{
			Name:              notification.Username,
			Groups:            conn.User.Groups,
			Event:             notification.Action,
			Status:            notification.Status,
			VirtualPath:       notification.VirtualPath,
			FsPath:            notification.Path,
			VirtualTargetPath: notification.VirtualTargetPath,
			FsTargetPath:      notification.TargetPath,
			ObjectName:        path.Base(notification.VirtualPath),
			Extension:         path.Ext(notification.VirtualPath),
			FileSize:          notification.FileSize,
			Elapsed:           notification.Elapsed,
			Protocol:          notification.Protocol,
			IP:                notification.IP,
			Role:              notification.Role,
			Timestamp:         dateTime,
			Email:             conn.User.Email,
			Object:            nil,
			Metadata:          metadata,
		}
		if err != nil {
			params.AddError(fmt.Errorf("%q failed: %w", params.Event, err))
		}
		executedSync, err := eventManager.handleFsEvent(params)
		if executedSync {
			return err
		}
	}
	if hasHook {
		if slices.Contains(executeSync, operation) {
			_, err := getActionHandler().Handle(notification)
			return err
		}
		go func() {
			startNewHook()
			defer hookEnded()

			getActionHandler().Handle(notification) //nolint:errcheck
		}()
	}
	return nil
}

// ActionHandler handles a notification for a Protocol Action.
type ActionHandler interface {
	Handle(notification *notifier.FsEvent) (int, error)
}

func newActionNotification(
	user *dataprovider.User,
	operation, filePath, virtualPath, target, virtualTarget, sshCmd, protocol, ip, sessionID string,
	fileSize int64,
	openFlags, status int, elapsed int64,
	datetime time.Time,
	metadata map[string]string,
) *notifier.FsEvent {
	var bucket, endpoint string

	fsConfig := user.GetFsConfigForPath(virtualPath)

	switch fsConfig.Provider {
	case sdk.S3FilesystemProvider:
		bucket = fsConfig.S3Config.Bucket
		endpoint = fsConfig.S3Config.Endpoint
	case sdk.GCSFilesystemProvider:
		bucket = fsConfig.GCSConfig.Bucket
	case sdk.AzureBlobFilesystemProvider:
		bucket = fsConfig.AzBlobConfig.Container
		if fsConfig.AzBlobConfig.Endpoint != "" {
			endpoint = fsConfig.AzBlobConfig.Endpoint
		}
	case sdk.SFTPFilesystemProvider:
		endpoint = fsConfig.SFTPConfig.Endpoint
	case sdk.HTTPFilesystemProvider:
		endpoint = fsConfig.HTTPConfig.Endpoint
	}

	return &notifier.FsEvent{
		Action:            operation,
		Username:          user.Username,
		Path:              filePath,
		TargetPath:        target,
		VirtualPath:       virtualPath,
		VirtualTargetPath: virtualTarget,
		SSHCmd:            sshCmd,
		FileSize:          fileSize,
		FsProvider:        int(fsConfig.Provider),
		Bucket:            bucket,
		Endpoint:          endpoint,
		Status:            status,
		Protocol:          protocol,
		IP:                ip,
		SessionID:         sessionID,
		OpenFlags:         openFlags,
		Role:              user.Role,
		Timestamp:         datetime.UnixNano(),
		Elapsed:           elapsed,
		Metadata:          metadata,
	}
}

type defaultActionHandler struct{}

func (h *defaultActionHandler) Handle(event *notifier.FsEvent) (int, error) {
	configMutex.RLock()
	executeOn := Config.Actions.ExecuteOn
	hook := Config.Actions.Hook
	configMutex.RUnlock()

	if !slices.Contains(executeOn, event.Action) {
		return 0, nil
	}

	if hook == "" {
		logger.Warn(event.Protocol, "", "Unable to send notification, no hook is defined")

		return 0, nil
	}

	if strings.HasPrefix(hook, "http") {
		err := h.handleHTTP(event, hook)
		return 1, err
	}

	err := h.handleCommand(event, hook)
	return 1, err
}

func (h *defaultActionHandler) handleHTTP(event *notifier.FsEvent, hook string) error {
	u, err := url.Parse(hook)
	if err != nil {
		logger.Error(event.Protocol, "", "Invalid hook %q for operation %q: %v",
			hook, event.Action, err)
		return err
	}

	startTime := time.Now()
	respCode := 0

	var b bytes.Buffer
	_ = json.NewEncoder(&b).Encode(event)

	resp, err := httpclient.RetryablePost(hook, "application/json", &b)
	if err == nil {
		respCode = resp.StatusCode
		resp.Body.Close()

		if respCode != http.StatusOK {
			err = errUnexpectedHTTResponse
		}
	}

	logger.Debug(event.Protocol, "", "notified operation %q to URL: %s status code: %d, elapsed: %s err: %v",
		event.Action, u.Redacted(), respCode, time.Since(startTime), err)

	return err
}

func (h *defaultActionHandler) handleCommand(event *notifier.FsEvent, hook string) error {
	if !filepath.IsAbs(hook) {
		err := fmt.Errorf("invalid notification command %q", hook)
		logger.Warn(event.Protocol, "", "unable to execute notification command: %v", err)

		return err
	}

	timeout, env, args := command.GetConfig(hook, command.HookFsActions)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, hook, args...)
	cmd.Env = append(env, notificationAsEnvVars(event)...)

	startTime := time.Now()
	err := cmd.Run()

	logger.Debug(event.Protocol, "", "executed command %q, elapsed: %s, error: %v",
		hook, time.Since(startTime), err)

	return err
}

func notificationAsEnvVars(event *notifier.FsEvent) []string {
	result := []string{
		fmt.Sprintf("SFTPXY_ACTION=%s", event.Action),
		fmt.Sprintf("SFTPXY_ACTION_USERNAME=%s", event.Username),
		fmt.Sprintf("SFTPXY_ACTION_PATH=%s", event.Path),
		fmt.Sprintf("SFTPXY_ACTION_TARGET=%s", event.TargetPath),
		fmt.Sprintf("SFTPXY_ACTION_VIRTUAL_PATH=%s", event.VirtualPath),
		fmt.Sprintf("SFTPXY_ACTION_VIRTUAL_TARGET=%s", event.VirtualTargetPath),
		fmt.Sprintf("SFTPXY_ACTION_SSH_CMD=%s", event.SSHCmd),
		fmt.Sprintf("SFTPXY_ACTION_FILE_SIZE=%d", event.FileSize),
		fmt.Sprintf("SFTPXY_ACTION_ELAPSED=%d", event.Elapsed),
		fmt.Sprintf("SFTPXY_ACTION_FS_PROVIDER=%d", event.FsProvider),
		fmt.Sprintf("SFTPXY_ACTION_BUCKET=%s", event.Bucket),
		fmt.Sprintf("SFTPXY_ACTION_ENDPOINT=%s", event.Endpoint),
		fmt.Sprintf("SFTPXY_ACTION_STATUS=%d", event.Status),
		fmt.Sprintf("SFTPXY_ACTION_PROTOCOL=%s", event.Protocol),
		fmt.Sprintf("SFTPXY_ACTION_IP=%s", event.IP),
		fmt.Sprintf("SFTPXY_ACTION_SESSION_ID=%s", event.SessionID),
		fmt.Sprintf("SFTPXY_ACTION_OPEN_FLAGS=%d", event.OpenFlags),
		fmt.Sprintf("SFTPXY_ACTION_TIMESTAMP=%d", event.Timestamp),
		fmt.Sprintf("SFTPXY_ACTION_ROLE=%s", event.Role),
	}
	if len(event.Metadata) > 0 {
		data, err := json.Marshal(event.Metadata)
		if err == nil {
			result = append(result, fmt.Sprintf("SFTPXY_ACTION_METADATA=%s", data))
		}
	}
	return result
}
