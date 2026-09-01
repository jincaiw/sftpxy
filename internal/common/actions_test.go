// SPDX-License-Identifier: MIT

package common

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lithammer/shortuuid/v4"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"

	"github.com/jincaiw/sftpxy/sdk"
	"github.com/jincaiw/sftpxy/sdk/plugin/notifier"

	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
	"github.com/jincaiw/sftpxy/v2/internal/vfs"
)

func TestNewActionNotification(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	user.FsConfig.Provider = sdk.LocalFilesystemProvider
	user.FsConfig.S3Config = vfs.S3FsConfig{
		BaseS3FsConfig: sdk.BaseS3FsConfig{
			Bucket:   "s3bucket",
			Endpoint: "endpoint",
		},
	}
	user.FsConfig.GCSConfig = vfs.GCSFsConfig{
		BaseGCSFsConfig: sdk.BaseGCSFsConfig{
			Bucket: "gcsbucket",
		},
	}
	user.FsConfig.AzBlobConfig = vfs.AzBlobFsConfig{
		BaseAzBlobFsConfig: sdk.BaseAzBlobFsConfig{
			Container: "azcontainer",
			Endpoint:  "azendpoint",
		},
	}
	user.FsConfig.SFTPConfig = vfs.SFTPFsConfig{
		BaseSFTPFsConfig: sdk.BaseSFTPFsConfig{
			Endpoint: "sftpendpoint",
		},
	}
	user.FsConfig.HTTPConfig = vfs.HTTPFsConfig{
		BaseHTTPFsConfig: sdk.BaseHTTPFsConfig{
			Endpoint: "httpendpoint",
		},
	}
	c := NewBaseConnection("id", ProtocolSSH, "", "", user)
	sessionID := xid.New().String()
	a := newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, c.getNotificationStatus(errors.New("fake error")), 0, time.Now(), nil)
	assert.Equal(t, user.Username, a.Username)
	assert.Equal(t, 0, len(a.Bucket))
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 2, a.Status)

	user.FsConfig.Provider = sdk.S3FilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSSH, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, time.Now(), nil)
	assert.Equal(t, "s3bucket", a.Bucket)
	assert.Equal(t, "endpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = sdk.GCSFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(ErrQuotaExceeded), 0, time.Now(), nil)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 3, a.Status)
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(fmt.Errorf("wrapper quota error: %w", ErrQuotaExceeded)), 0, time.Now(), nil)
	assert.Equal(t, "gcsbucket", a.Bucket)
	assert.Equal(t, 0, len(a.Endpoint))
	assert.Equal(t, 3, a.Status)

	user.FsConfig.Provider = sdk.HTTPFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSSH, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, time.Now(), nil)
	assert.Equal(t, "httpendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	user.FsConfig.Provider = sdk.AzureBlobFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, time.Now(), nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)

	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSCP, "", sessionID,
		123, os.O_APPEND, c.getNotificationStatus(nil), 0, time.Now(), nil)
	assert.Equal(t, "azcontainer", a.Bucket)
	assert.Equal(t, "azendpoint", a.Endpoint)
	assert.Equal(t, 1, a.Status)
	assert.Equal(t, os.O_APPEND, a.OpenFlags)

	user.FsConfig.Provider = sdk.SFTPFilesystemProvider
	a = newActionNotification(&user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, c.getNotificationStatus(nil), 0, time.Now(), nil)
	assert.Equal(t, "sftpendpoint", a.Endpoint)
}

func TestActionHTTP(t *testing.T) {
	ConfigRLock()
	actionsCopy := Config.Actions
	ConfigRUnlock()

	ConfigLock()
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      fmt.Sprintf("http://%v", httpAddr),
	}
	ConfigUnlock()
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	a := newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "",
		xid.New().String(), 123, 0, 1, 0, time.Now(), nil)
	status, err := getActionHandler().Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 1, status)

	ConfigLock()
	Config.Actions.Hook = "http://invalid:1234"
	ConfigUnlock()
	status, err = getActionHandler().Handle(a)
	assert.Error(t, err)
	assert.Equal(t, 1, status)

	ConfigLock()
	Config.Actions.Hook = fmt.Sprintf("http://%v/404", httpAddr)
	ConfigUnlock()
	status, err = getActionHandler().Handle(a)
	if assert.Error(t, err) {
		assert.EqualError(t, err, errUnexpectedHTTResponse.Error())
	}
	assert.Equal(t, 1, status)

	ConfigLock()
	Config.Actions = actionsCopy
	ConfigUnlock()
}

func TestActionCMD(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	ConfigRLock()
	actionsCopy := Config.Actions
	ConfigRUnlock()

	hookCmd, err := exec.LookPath("true")
	assert.NoError(t, err)

	ConfigLock()
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      hookCmd,
	}
	ConfigUnlock()
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}
	sessionID := shortuuid.New()
	a := newActionNotification(user, operationDownload, "path", "vpath", "target", "", "", ProtocolSFTP, "", sessionID,
		123, 0, 1, 0, time.Now(), map[string]string{"key": "value"})
	status, err := getActionHandler().Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 1, status)

	c := NewBaseConnection("id", ProtocolSFTP, "", "", *user)
	err = ExecuteActionNotification(c, OperationSSHCmd, "path", "vpath", "target", "vtarget", "sha1sum", 0, nil, 0, nil)
	assert.NoError(t, err)

	err = ExecuteActionNotification(c, operationDownload, "path", "vpath", "", "", "", 0, nil, 0, nil)
	assert.NoError(t, err)

	ConfigLock()
	Config.Actions = actionsCopy
	ConfigUnlock()
}

func TestWrongActions(t *testing.T) {
	ConfigRLock()
	actionsCopy := Config.Actions
	ConfigRUnlock()

	badCommand := "/bad/command"
	if runtime.GOOS == osWindows {
		badCommand = "C:\\bad\\command"
	}
	ConfigLock()
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationUpload},
		Hook:      badCommand,
	}
	ConfigUnlock()
	user := &dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
		},
	}

	a := newActionNotification(user, operationUpload, "", "", "", "", "", ProtocolSFTP, "", xid.New().String(),
		123, 0, 1, 0, time.Now(), nil)
	status, err := getActionHandler().Handle(a)
	assert.Error(t, err, "action with bad command must fail")
	assert.Equal(t, 1, status)

	a.Action = operationDelete
	status, err = getActionHandler().Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	ConfigLock()
	Config.Actions.Hook = "http://foo\x7f.com/"
	ConfigUnlock()
	a.Action = operationUpload
	status, err = getActionHandler().Handle(a)
	assert.Error(t, err, "action with bad url must fail")
	assert.Equal(t, 1, status)

	ConfigLock()
	Config.Actions.Hook = ""
	ConfigUnlock()
	status, err = getActionHandler().Handle(a)
	assert.NoError(t, err)
	assert.Equal(t, 0, status)

	ConfigLock()
	Config.Actions.Hook = "relative path"
	ConfigUnlock()
	status, err = getActionHandler().Handle(a)
	if assert.Error(t, err) {
		ConfigRLock()
		hook := Config.Actions.Hook
		ConfigRUnlock()
		assert.EqualError(t, err, fmt.Sprintf("invalid notification command %q", hook))
	}
	assert.Equal(t, 1, status)

	ConfigLock()
	Config.Actions = actionsCopy
	ConfigUnlock()
}

func TestPreDeleteAction(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("this test is not available on Windows")
	}
	ConfigRLock()
	actionsCopy := Config.Actions
	ConfigRUnlock()

	hookCmd, err := exec.LookPath("true")
	assert.NoError(t, err)
	ConfigLock()
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationPreDelete},
		Hook:      "missing hook",
	}
	ConfigUnlock()
	homeDir := filepath.Join(os.TempDir(), "test_user")
	err = os.MkdirAll(homeDir, os.ModePerm)
	assert.NoError(t, err)
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "username",
			HomeDir:  homeDir,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	fs := vfs.NewOsFs("id", homeDir, "", nil)
	c := NewBaseConnection("id", ProtocolSFTP, "", "", user)

	testfile := filepath.Join(user.HomeDir, "testfile")
	err = os.WriteFile(testfile, []byte("test"), os.ModePerm)
	assert.NoError(t, err)
	info, err := os.Stat(testfile)
	assert.NoError(t, err)
	err = c.RemoveFile(fs, testfile, "testfile", info)
	assert.ErrorIs(t, err, c.GetPermissionDeniedError())
	assert.FileExists(t, testfile)
	ConfigLock()
	Config.Actions.Hook = hookCmd
	ConfigUnlock()
	err = c.RemoveFile(fs, testfile, "testfile", info)
	assert.NoError(t, err)
	assert.NoFileExists(t, testfile)

	os.RemoveAll(homeDir)

	ConfigLock()
	Config.Actions = actionsCopy
	ConfigUnlock()
}

func TestUnconfiguredHook(t *testing.T) {
	ConfigRLock()
	actionsCopy := Config.Actions
	ConfigRUnlock()

	ConfigLock()
	Config.Actions = ProtocolActions{
		ExecuteOn: []string{operationDownload},
		Hook:      "",
	}
	ConfigUnlock()
	pluginsConfig := []plugin.Config{
		{
			Type: "notifier",
		},
	}
	err := plugin.Initialize(pluginsConfig, "debug")
	assert.Error(t, err)
	assert.True(t, plugin.Handler.HasNotifiers())

	c := NewBaseConnection("id", ProtocolSFTP, "", "", dataprovider.User{})
	status, err := ExecutePreAction(c, OperationPreDownload, "", "", 0, 0)
	assert.NoError(t, err)
	assert.Equal(t, status, 0)
	status, err = ExecutePreAction(c, operationPreDelete, "", "", 0, 0)
	assert.NoError(t, err)
	assert.Equal(t, status, 0)

	err = ExecuteActionNotification(c, operationDownload, "", "", "", "", "", 0, nil, 0, nil)
	assert.NoError(t, err)

	err = plugin.Initialize(nil, "debug")
	assert.NoError(t, err)
	assert.False(t, plugin.Handler.HasNotifiers())

	ConfigLock()
	Config.Actions = actionsCopy
	ConfigUnlock()
}

type actionHandlerStub struct {
	// called is atomic: a previous test may leave an async action hook
	// goroutine running that calls Handle concurrently with this test
	called atomic.Bool
}

func (h *actionHandlerStub) Handle(_ *notifier.FsEvent) (int, error) {
	h.called.Store(true)

	return 1, nil
}

func TestInitializeActionHandler(t *testing.T) {
	handler := &actionHandlerStub{}

	InitializeActionHandler(handler)
	t.Cleanup(func() {
		InitializeActionHandler(&defaultActionHandler{})
	})

	status, err := getActionHandler().Handle(&notifier.FsEvent{})
	assert.NoError(t, err)
	assert.True(t, handler.called.Load())
	assert.Equal(t, 1, status)
}
