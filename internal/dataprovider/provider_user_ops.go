// SPDX-License-Identifier: MIT

package dataprovider

import (
	"errors"
	"time"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/util"
	"github.com/jincaiw/sftpxy/v2/internal/vfs"
)

func HasAdmin() bool {
	return isAdminCreated.Load()
}

// AddAdmin adds a new SFTPxy admin
func AddAdmin(admin *Admin, executor, ipAddress, role string) error {
	admin.Filters.RecoveryCodes = nil
	admin.Filters.TOTPConfig = AdminTOTPConfig{
		Enabled: false,
	}
	admin.Username = holder.getConfig().convertName(admin.Username)
	err := holder.getProvider().addAdmin(admin)
	if err == nil {
		isAdminCreated.Store(true)
		executeAction(operationAdd, executor, ipAddress, actionObjectAdmin, admin.Username, role, admin)
	}
	return err
}

// UpdateAdmin updates an existing SFTPxy admin
func UpdateAdmin(admin *Admin, executor, ipAddress, role string) error {
	err := holder.getProvider().updateAdmin(admin)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAdmin, admin.Username, role, admin)
	}
	return err
}

// DeleteAdmin deletes an existing SFTPxy admin
func DeleteAdmin(username, executor, ipAddress, role string) error {
	username = holder.getConfig().convertName(username)
	admin, err := holder.getProvider().adminExists(username)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteAdmin(admin)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAdmin, admin.Username, role, &admin)
		cachedAdminPasswords.Remove(username)
	}
	return err
}

// AdminExists returns the admin with the given username if it exists
func AdminExists(username string) (Admin, error) {
	username = holder.getConfig().convertName(username)
	return holder.getProvider().adminExists(username)
}

// UserExists checks if the given SFTPxy username exists, returns an error if no match is found
func UserExists(username, role string) (User, error) {
	username = holder.getConfig().convertName(username)
	return holder.getProvider().userExists(username, role)
}

// GetAdminSignature returns the signature for the admin with the specified
// username.
func GetAdminSignature(username string) (string, error) {
	username = holder.getConfig().convertName(username)
	return holder.getProvider().getAdminSignature(username)
}

// GetUserSignature returns the signature for the user with the specified
// username.
func GetUserSignature(username string) (string, error) {
	username = holder.getConfig().convertName(username)
	return holder.getProvider().getUserSignature(username)
}

// GetUserWithGroupSettings tries to return the user with the specified username
// loading also the group settings
func GetUserWithGroupSettings(username, role string) (User, error) {
	username = holder.getConfig().convertName(username)
	user, err := holder.getProvider().userExists(username, role)
	if err != nil {
		return user, err
	}
	err = user.LoadAndApplyGroupSettings()
	return user, err
}

// GetUserVariants tries to return the user with the specified username with and without
// group settings applied
func GetUserVariants(username, role string) (User, User, error) {
	username = holder.getConfig().convertName(username)
	user, err := holder.getProvider().userExists(username, role)
	if err != nil {
		return user, User{}, err
	}
	userWithGroupSettings := user.getACopy()
	err = userWithGroupSettings.LoadAndApplyGroupSettings()
	return user, userWithGroupSettings, err
}

// AddUser adds a new SFTPxy user.
func AddUser(user *User, executor, ipAddress, role string) error {
	user.Username = holder.getConfig().convertName(user.Username)
	err := holder.getProvider().addUser(user)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectUser, user.Username, role, user)
	}
	return err
}

// UpdateUserPassword updates the user password
func UpdateUserPassword(username, plainPwd, executor, ipAddress, role string) error {
	user, err := holder.getProvider().userExists(username, role)
	if err != nil {
		return err
	}
	userCopy := user.getACopy()
	userCopy.Password = plainPwd
	if err := createUserPasswordHash(&userCopy); err != nil {
		return err
	}
	user.LastPasswordChange = userCopy.LastPasswordChange
	user.Password = userCopy.Password
	user.Filters.RequirePasswordChange = false
	// the last password change is set when validating the user
	if err := holder.getProvider().updateUser(&user); err != nil {
		return err
	}
	webDAVUsersCache.swap(&user, plainPwd)
	executeAction(operationUpdate, executor, ipAddress, actionObjectUser, username, role, &user)
	return nil
}

// UpdateUser updates an existing SFTPxy user.
func UpdateUser(user *User, executor, ipAddress, role string) error {
	if user.groupSettingsApplied {
		return errors.New("cannot save a user with group settings applied")
	}
	err := holder.getProvider().updateUser(user)
	if err == nil {
		webDAVUsersCache.swap(user, "")
		executeAction(operationUpdate, executor, ipAddress, actionObjectUser, user.Username, role, user)
	}
	return err
}

// DeleteUser deletes an existing SFTPxy user.
func DeleteUser(username, executor, ipAddress, role string) error {
	username = holder.getConfig().convertName(username)
	user, err := holder.getProvider().userExists(username, role)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteUser(user, holder.getConfig().IsShared == 1)
	if err == nil {
		RemoveCachedWebDAVUser(user.Username)
		delayedQuotaUpdater.resetUserQuota(user.Username)
		cachedUserPasswords.Remove(username)
		executeAction(operationDelete, executor, ipAddress, actionObjectUser, user.Username, role, &user)
	}
	return err
}

// AddActiveTransfer stores the specified transfer
func AddActiveTransfer(transfer ActiveTransfer) {
	if err := holder.getProvider().addActiveTransfer(transfer); err != nil {
		providerLog(logger.LevelError, "unable to add transfer id %v, connection id %v: %v",
			transfer.ID, transfer.ConnID, err)
	}
}

// UpdateActiveTransferSizes updates the current upload and download sizes for the specified transfer
func UpdateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) {
	if err := holder.getProvider().updateActiveTransferSizes(ulSize, dlSize, transferID, connectionID); err != nil {
		providerLog(logger.LevelError, "unable to update sizes for transfer id %v, connection id %v: %v",
			transferID, connectionID, err)
	}
}

// RemoveActiveTransfer removes the specified transfer
func RemoveActiveTransfer(transferID int64, connectionID string) {
	if err := holder.getProvider().removeActiveTransfer(transferID, connectionID); err != nil {
		providerLog(logger.LevelError, "unable to delete transfer id %v, connection id %v: %v",
			transferID, connectionID, err)
	}
}

// CleanupActiveTransfers removes the transfer before the specified time
func CleanupActiveTransfers(before time.Time) error {
	err := holder.getProvider().cleanupActiveTransfers(before)
	if err == nil {
		providerLog(logger.LevelDebug, "deleted active transfers updated before: %v", before)
	} else {
		providerLog(logger.LevelError, "error deleting active transfers updated before %v: %v", before, err)
	}
	return err
}

// GetActiveTransfers retrieves the active transfers with an update time after the specified value
func GetActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return holder.getProvider().getActiveTransfers(from)
}

// AddSharedSession stores a new session within the data provider
func AddSharedSession(session Session) error {
	err := holder.getProvider().addSharedSession(session)
	if err != nil {
		providerLog(logger.LevelError, "unable to add shared session, key %q, type: %v, err: %v",
			session.Key, session.Type, err)
	}
	return err
}

// DeleteSharedSession deletes the session with the specified key
func DeleteSharedSession(key string, sessionType SessionType) error {
	err := holder.getProvider().deleteSharedSession(key, sessionType)
	if err != nil {
		providerLog(logger.LevelError, "unable to add shared session, key %q, err: %v", key, err)
	}
	return err
}

// GetSharedSession retrieves the session with the specified key
func GetSharedSession(key string, sessionType SessionType) (Session, error) {
	return holder.getProvider().getSharedSession(key, sessionType)
}

// CleanupSharedSessions removes the shared session with the specified type and
// before the specified time
func CleanupSharedSessions(sessionType SessionType, before time.Time) error {
	err := holder.getProvider().cleanupSharedSessions(sessionType, util.GetTimeAsMsSinceEpoch(before))
	if err == nil {
		providerLog(logger.LevelDebug, "deleted shared sessions before: %v, type: %v", before, sessionType)
	} else {
		providerLog(logger.LevelError, "error deleting shared session before %v, type %v: %v", before, sessionType, err)
	}
	return err
}

// ReloadConfig reloads provider configuration.
// Currently only implemented for memory provider, allows to reload the users
// from the configured file, if defined
func ReloadConfig() error {
	return holder.getProvider().reloadConfig()
}

// GetShares returns an array of shares respecting limit and offset
func GetShares(limit, offset int, order, username string) ([]Share, error) {
	return holder.getProvider().getShares(limit, offset, order, username)
}

// GetAPIKeys returns an array of API keys respecting limit and offset
func GetAPIKeys(limit, offset int, order string) ([]APIKey, error) {
	return holder.getProvider().getAPIKeys(limit, offset, order)
}

// GetAdmins returns an array of admins respecting limit and offset
func GetAdmins(limit, offset int, order string) ([]Admin, error) {
	return holder.getProvider().getAdmins(limit, offset, order)
}

// GetRoles returns an array of roles respecting limit and offset
func GetRoles(limit, offset int, order string, minimal bool) ([]Role, error) {
	return holder.getProvider().getRoles(limit, offset, order, minimal)
}

// GetGroups returns an array of groups respecting limit and offset
func GetGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return holder.getProvider().getGroups(limit, offset, order, minimal)
}

// GetUsers returns an array of users respecting limit and offset
func GetUsers(limit, offset int, order, role string) ([]User, error) {
	return holder.getProvider().getUsers(limit, offset, order, role)
}

// GetUsersForQuotaCheck returns the users with the fields required for a quota check
func GetUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return holder.getProvider().getUsersForQuotaCheck(toFetch)
}

// AddFolder adds a new virtual folder.
func AddFolder(folder *vfs.BaseVirtualFolder, executor, ipAddress, role string) error {
	folder.Name = holder.getConfig().convertName(folder.Name)
	err := holder.getProvider().addFolder(folder)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: *folder})
	}
	return err
}

// UpdateFolder updates the specified virtual folder
func UpdateFolder(folder *vfs.BaseVirtualFolder, users []string, groups []string, executor, ipAddress, role string) error {
	err := holder.getProvider().updateFolder(folder)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: *folder})
		usersInGroups, errGrp := holder.getProvider().getUsersInGroups(groups)
		if errGrp == nil {
			users = append(users, usersInGroups...)
			users = util.RemoveDuplicates(users, false)
		} else {
			providerLog(logger.LevelWarn, "unable to get users in groups %+v: %v", groups, errGrp)
		}
		for _, user := range users {
			holder.getProvider().setUpdatedAt(user)
			u, err := holder.getProvider().userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			} else {
				RemoveCachedWebDAVUser(user)
			}
		}
	}
	return err
}

// DeleteFolder deletes an existing folder.
func DeleteFolder(folderName, executor, ipAddress, role string) error {
	folderName = holder.getConfig().convertName(folderName)
	folder, err := holder.getProvider().getFolderByName(folderName)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteFolder(folder)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectFolder, folder.Name, role, &wrappedFolder{Folder: folder})
		users := folder.Users
		usersInGroups, errGrp := holder.getProvider().getUsersInGroups(folder.Groups)
		if errGrp == nil {
			users = append(users, usersInGroups...)
			users = util.RemoveDuplicates(users, false)
		} else {
			providerLog(logger.LevelWarn, "unable to get users in groups %+v: %v", folder.Groups, errGrp)
		}
		for _, user := range users {
			holder.getProvider().setUpdatedAt(user)
			u, err := holder.getProvider().userExists(user, "")
			if err == nil {
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			}
			RemoveCachedWebDAVUser(user)
		}
		delayedQuotaUpdater.resetFolderQuota(folderName)
	}
	return err
}

// GetFolderByName returns the folder with the specified name if any
func GetFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	name = holder.getConfig().convertName(name)
	return holder.getProvider().getFolderByName(name)
}

// GetFolders returns an array of folders respecting limit and offset
func GetFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return holder.getProvider().getFolders(limit, offset, order, minimal)
}
