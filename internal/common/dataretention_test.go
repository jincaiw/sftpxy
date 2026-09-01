// SPDX-License-Identifier: MIT

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jincaiw/sftpxy/sdk"

	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/util"
	"github.com/jincaiw/sftpxy/v2/internal/vfs"
)

func TestRetentionPermissionsAndGetFolder(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "user1",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermListItems, dataprovider.PermDelete}
	user.Permissions["/dir1"] = []string{dataprovider.PermListItems}
	user.Permissions["/dir2/sub1"] = []string{dataprovider.PermCreateDirs}
	user.Permissions["/dir2/sub2"] = []string{dataprovider.PermDelete}

	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/dir2",
				Retention: 24 * 7,
			},
			{
				Path:      "/dir3",
				Retention: 24 * 7,
			},
			{
				Path:      "/dir2/sub1/sub",
				Retention: 24,
			},
		},
	}

	conn := NewBaseConnection("", "", "", "", user)
	conn.SetProtocol(ProtocolDataRetention)
	conn.ID = fmt.Sprintf("data_retention_%v", user.Username)
	check.conn = conn
	check.updateUserPermissions()
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir1"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2/sub1"])
	assert.Equal(t, []string{dataprovider.PermAny}, conn.User.Permissions["/dir2/sub2"])

	_, err := check.getFolderRetention("/")
	assert.Error(t, err)
	folder, err := check.getFolderRetention("/dir3")
	assert.NoError(t, err)
	assert.Equal(t, "/dir3", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub3")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub2")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub1")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2", folder.Path)
	folder, err = check.getFolderRetention("/dir2/sub1/sub/sub")
	assert.NoError(t, err)
	assert.Equal(t, "/dir2/sub1/sub", folder.Path)
}

func TestRetentionCheckAddRemove(t *testing.T) {
	username := "username"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/",
				Retention: 48,
			},
		},
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get("")
	require.Len(t, checks, 1)
	assert.Equal(t, username, checks[0].Username)
	assert.Greater(t, checks[0].StartTime, int64(0))
	require.Len(t, checks[0].Folders, 1)
	assert.Equal(t, check.Folders[0].Path, checks[0].Folders[0].Path)
	assert.Equal(t, check.Folders[0].Retention, checks[0].Folders[0].Retention)

	assert.Nil(t, RetentionChecks.Add(check, &user))
	assert.True(t, RetentionChecks.remove(username))
	require.Len(t, RetentionChecks.Get(""), 0)
	assert.False(t, RetentionChecks.remove(username))
}

func TestRetentionCheckRole(t *testing.T) {
	username := "retuser"
	role1 := "retrole1"
	role2 := "retrole2"
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			Role:     role1,
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/",
				Retention: 48,
			},
		},
	}
	assert.NotNil(t, RetentionChecks.Add(check, &user))
	checks := RetentionChecks.Get("")
	require.Len(t, checks, 1)
	assert.Empty(t, checks[0].Role)
	checks = RetentionChecks.Get(role1)
	require.Len(t, checks, 1)
	checks = RetentionChecks.Get(role2)
	require.Len(t, checks, 0)
	user.Role = ""
	assert.Nil(t, RetentionChecks.Add(check, &user))
	assert.True(t, RetentionChecks.remove(username))
	require.Len(t, RetentionChecks.Get(""), 0)
}

func TestCleanupErrors(t *testing.T) {
	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: "u",
		},
	}
	user.Permissions = make(map[string][]string)
	user.Permissions["/"] = []string{dataprovider.PermAny}
	check := &RetentionCheck{
		Folders: []dataprovider.FolderRetention{
			{
				Path:      "/path",
				Retention: 48,
			},
		},
	}
	check = RetentionChecks.Add(*check, &user)
	require.NotNil(t, check)

	err := check.removeFile("missing file", nil)
	assert.Error(t, err)

	err = check.cleanupFolder("/", 0)
	assert.Error(t, err)

	err = check.cleanupFolder("/", 1000)
	assert.ErrorIs(t, err, util.ErrRecursionTooDeep)

	assert.True(t, RetentionChecks.remove(user.Username))
}

// TestScheduledCleanupFilesOlderThan3Days verifies the full scheduled data
// retention chain: a daily scheduled rule triggers a data retention check
// action which deletes files older than 72 hours (3 days) based on their
// modification time.
func TestScheduledCleanupFilesOlderThan3Days(t *testing.T) {
	username := "retention3days"
	homeDir := filepath.Join(os.TempDir(), username)
	err := os.MkdirAll(homeDir, os.ModePerm)
	require.NoError(t, err)

	user := dataprovider.User{
		BaseUser: sdk.BaseUser{
			Username: username,
			HomeDir:  homeDir,
			Status:   1,
			Permissions: map[string][]string{
				"/": {dataprovider.PermAny},
			},
		},
		FsConfig: vfs.Filesystem{
			Provider: sdk.LocalFilesystemProvider,
		},
	}
	err = dataprovider.AddUser(&user, "", "", "")
	require.NoError(t, err)

	subDir := filepath.Join(homeDir, "subdir")
	err = os.MkdirAll(subDir, os.ModePerm)
	require.NoError(t, err)

	now := time.Now()
	files := []struct {
		name    string
		path    string
		modTime time.Time
		deleted bool
	}{
		{name: "old_4days.txt", path: homeDir, modTime: now.Add(-96 * time.Hour), deleted: true},
		{name: "old_73h.txt", path: homeDir, modTime: now.Add(-73 * time.Hour), deleted: true},
		{name: "recent_71h.txt", path: homeDir, modTime: now.Add(-71 * time.Hour), deleted: false},
		{name: "recent_now.txt", path: homeDir, modTime: now, deleted: false},
		{name: "old_in_subdir.txt", path: subDir, modTime: now.Add(-100 * time.Hour), deleted: true},
		{name: "recent_in_subdir.txt", path: subDir, modTime: now.Add(-time.Hour), deleted: false},
	}
	for _, f := range files {
		p := filepath.Join(f.path, f.name)
		err = os.WriteFile(p, []byte("test content"), 0o644)
		require.NoError(t, err)
		err = os.Chtimes(p, f.modTime, f.modTime)
		require.NoError(t, err)
	}

	// Action: data retention check, delete files older than 72 hours (3 days)
	action := &dataprovider.BaseEventAction{
		Name: "cleanup_files_older_than_3_days",
		Type: dataprovider.ActionTypeDataRetentionCheck,
		Options: dataprovider.BaseEventActionOptions{
			RetentionConfig: dataprovider.EventActionDataRetentionConfig{
				Folders: []dataprovider.FolderRetention{
					{
						Path:      "/",
						Retention: 72, // 3 days
					},
				},
			},
		},
	}
	err = dataprovider.AddEventAction(action, "", "", "")
	require.NoError(t, err)

	// Rule: daily schedule at 03:00
	startEventScheduler()
	defer stopEventScheduler()
	rule := &dataprovider.EventRule{
		Name:    "daily_cleanup_3_days",
		Status:  1,
		Trigger: dataprovider.EventTriggerSchedule,
		Conditions: dataprovider.EventConditions{
			Schedules: []dataprovider.Schedule{
				{
					Hours:      "3",
					DayOfWeek:  "*",
					DayOfMonth: "*",
					Month:      "*",
				},
			},
			Options: dataprovider.ConditionOptions{
				Names: []dataprovider.ConditionPattern{
					{
						Pattern: username,
					},
				},
			},
		},
		Actions: []dataprovider.EventAction{
			{
				BaseEventAction: dataprovider.BaseEventAction{
					Name: action.Name,
				},
				Order: 1,
			},
		},
	}
	err = dataprovider.AddEventRule(rule, "", "", "")
	require.NoError(t, err)

	// verify the cron spec generated by the daily schedule
	assert.Equal(t, "0 3 * * *", rule.Conditions.Schedules[0].GetCronSpec())

	// execute the scheduled rule exactly as the real cron scheduler does
	job := eventCronJob{
		ruleName: rule.Name,
	}
	job.Run()

	for _, f := range files {
		p := filepath.Join(f.path, f.name)
		if f.deleted {
			assert.NoFileExists(t, p, "file %q should have been deleted (mtime %v)", f.name, f.modTime)
		} else {
			assert.FileExists(t, p, "file %q should have been kept (mtime %v)", f.name, f.modTime)
		}
	}

	err = dataprovider.DeleteEventRule(rule.Name, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteEventAction(action.Name, "", "", "")
	assert.NoError(t, err)
	err = dataprovider.DeleteUser(username, "", "", "")
	assert.NoError(t, err)
	err = os.RemoveAll(homeDir)
	assert.NoError(t, err)
}
