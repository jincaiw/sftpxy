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
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

func UpdateUserQuota(user *User, filesAdd int, sizeAdd int64, reset bool) error {
	if holder.getConfig().TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	} else if holder.getConfig().TrackQuota == 2 && !reset && !user.HasQuotaRestrictions() {
		return nil
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	if holder.getConfig().DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetUserQuota(user.Username)
		}
		return holder.getProvider().updateQuota(user.Username, filesAdd, sizeAdd, reset)
	}
	delayedQuotaUpdater.updateUserQuota(user.Username, filesAdd, sizeAdd)
	return nil
}

// UpdateUserFolderQuota updates the quota for the given user and virtual folder.
func UpdateUserFolderQuota(folder *vfs.VirtualFolder, user *User, filesAdd int, sizeAdd int64, reset bool) {
	if folder.IsIncludedInUserQuota() {
		UpdateUserQuota(user, filesAdd, sizeAdd, reset) //nolint:errcheck
		return
	}
	UpdateVirtualFolderQuota(&folder.BaseVirtualFolder, filesAdd, sizeAdd, reset) //nolint:errcheck
}

// UpdateVirtualFolderQuota updates the quota for the given virtual folder adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
func UpdateVirtualFolderQuota(vfolder *vfs.BaseVirtualFolder, filesAdd int, sizeAdd int64, reset bool) error {
	if holder.getConfig().TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	if filesAdd == 0 && sizeAdd == 0 && !reset {
		return nil
	}
	if holder.getConfig().DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetFolderQuota(vfolder.Name)
		}
		return holder.getProvider().updateFolderQuota(vfolder.Name, filesAdd, sizeAdd, reset)
	}
	delayedQuotaUpdater.updateFolderQuota(vfolder.Name, filesAdd, sizeAdd)
	return nil
}

// UpdateUserTransferQuota updates the transfer quota for the given SFTPGo user.
// If reset is true uploadSize and downloadSize indicates the actual sizes instead of the difference.
func UpdateUserTransferQuota(user *User, uploadSize, downloadSize int64, reset bool) error {
	if holder.getConfig().TrackQuota == 0 {
		return util.NewMethodDisabledError(trackQuotaDisabledError)
	} else if holder.getConfig().TrackQuota == 2 && !reset && !user.HasTransferQuotaRestrictions() {
		return nil
	}
	if downloadSize == 0 && uploadSize == 0 && !reset {
		return nil
	}
	if holder.getConfig().DelayedQuotaUpdate == 0 || reset {
		if reset {
			delayedQuotaUpdater.resetUserTransferQuota(user.Username)
		}
		return holder.getProvider().updateTransferQuota(user.Username, uploadSize, downloadSize, reset)
	}
	delayedQuotaUpdater.updateUserTransferQuota(user.Username, uploadSize, downloadSize)
	return nil
}

// UpdateUserTransferTimestamps updates the first download/upload fields if unset
func UpdateUserTransferTimestamps(username string, isUpload bool) error {
	if isUpload {
		err := holder.getProvider().setFirstUploadTimestamp(username)
		if err != nil {
			providerLog(logger.LevelWarn, "unable to set first upload: %v", err)
		}
		return err
	}
	err := holder.getProvider().setFirstDownloadTimestamp(username)
	if err != nil {
		providerLog(logger.LevelWarn, "unable to set first download: %v", err)
	}
	return err
}

// GetUsedQuota returns the used quota for the given SFTPGo user.
func GetUsedQuota(username string) (int, int64, int64, int64, error) {
	if holder.getConfig().TrackQuota == 0 {
		return 0, 0, 0, 0, util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	files, size, ulTransferSize, dlTransferSize, err := holder.getProvider().getUsedQuota(username)
	if err != nil {
		return files, size, ulTransferSize, dlTransferSize, err
	}
	delayedFiles, delayedSize := delayedQuotaUpdater.getUserPendingQuota(username)
	delayedUlTransferSize, delayedDLTransferSize := delayedQuotaUpdater.getUserPendingTransferQuota(username)

	return files + delayedFiles, size + delayedSize, ulTransferSize + delayedUlTransferSize,
		dlTransferSize + delayedDLTransferSize, err
}

// GetUsedVirtualFolderQuota returns the used quota for the given virtual folder.
func GetUsedVirtualFolderQuota(name string) (int, int64, error) {
	if holder.getConfig().TrackQuota == 0 {
		return 0, 0, util.NewMethodDisabledError(trackQuotaDisabledError)
	}
	files, size, err := holder.getProvider().getUsedFolderQuota(name)
	if err != nil {
		return files, size, err
	}
	delayedFiles, delayedSize := delayedQuotaUpdater.getFolderPendingQuota(name)
	return files + delayedFiles, size + delayedSize, err
}

// GetConfigs returns the configurations
func GetConfigs() (Configs, error) {
	return holder.getProvider().getConfigs()
}

// UpdateConfigs updates configurations
func UpdateConfigs(configs *Configs, executor, ipAddress, role string) error {
	if configs == nil {
		configs = &Configs{}
	} else {
		configs.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	err := holder.getProvider().setConfigs(configs)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectConfigs, "configs", role, configs)
	}
	return err
}

// AddShare adds a new share
