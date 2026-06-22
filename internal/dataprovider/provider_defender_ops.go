// SPDX-License-Identifier: MIT

package dataprovider

import (
	"time"

	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func GetDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return holder.getProvider().getDefenderHosts(from, limit)
}

// GetDefenderHostByIP returns a defender host by ip, if any
func GetDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return holder.getProvider().getDefenderHostByIP(ip, from)
}

// IsDefenderHostBanned returns a defender entry and no error if the specified host is banned
func IsDefenderHostBanned(ip string) (DefenderEntry, error) {
	return holder.getProvider().isDefenderHostBanned(ip)
}

// UpdateDefenderBanTime increments ban time for the specified ip
func UpdateDefenderBanTime(ip string, minutes int) error {
	return holder.getProvider().updateDefenderBanTime(ip, minutes)
}

// DeleteDefenderHost removes the specified IP from the defender lists
func DeleteDefenderHost(ip string) error {
	return holder.getProvider().deleteDefenderHost(ip)
}

// AddDefenderEvent adds an event for the given IP with the given score
// and returns the host with the updated score
func AddDefenderEvent(ip string, score int, from int64) (DefenderEntry, error) {
	if err := holder.getProvider().addDefenderEvent(ip, score); err != nil {
		return DefenderEntry{}, err
	}
	return holder.getProvider().getDefenderHostByIP(ip, from)
}

// SetDefenderBanTime sets the ban time for the specified IP
func SetDefenderBanTime(ip string, banTime int64) error {
	return holder.getProvider().setDefenderBanTime(ip, banTime)
}

// CleanupDefender removes events and hosts older than "from" from the data provider
func CleanupDefender(from int64) error {
	return holder.getProvider().cleanupDefender(from)
}

// UpdateShareLastUse updates the LastUseAt and UsedTokens for the given share.
// When numTokens is positive the usage is reserved atomically: if max_tokens is
// set and the reservation would exceed it the share is left unchanged and
// ErrShareUsageExceeded is returned. A non-positive numTokens refunds previously
// reserved tokens and is always applied.
func UpdateShareLastUse(share *Share, numTokens int) error {
	return holder.getProvider().updateShareLastUse(share.ShareID, numTokens)
}

// UpdateAPIKeyLastUse updates the LastUseAt field for the given API key
func UpdateAPIKeyLastUse(apiKey *APIKey) error {
	lastUse := util.GetTimeFromMsecSinceEpoch(apiKey.LastUseAt)
	diff := -time.Until(lastUse)
	if diff < 0 || diff > lastLoginMinDelay {
		return holder.getProvider().updateAPIKeyLastUse(apiKey.KeyID)
	}
	return nil
}

// UpdateLastLogin updates the last login field for the given SFTPxy user
func UpdateLastLogin(user *User) {
	delay := lastLoginMinDelay
	if user.Filters.ExternalAuthCacheTime > 0 {
		delay = time.Duration(user.Filters.ExternalAuthCacheTime) * time.Second
	}
	if user.LastLogin <= user.UpdatedAt || !isLastActivityRecent(user.LastLogin, delay) {
		err := holder.getProvider().updateLastLogin(user.Username)
		if err == nil {
			webDAVUsersCache.updateLastLogin(user.Username)
		}
	}
}

// UpdateAdminLastLogin updates the last login field for the given SFTPxy admin
func UpdateAdminLastLogin(admin *Admin) {
	if !isLastActivityRecent(admin.LastLogin, lastLoginMinDelay) {
		holder.getProvider().updateAdminLastLogin(admin.Username) //nolint:errcheck
	}
}

// UpdateUserQuota updates the quota for the given SFTPxy user adding filesAdd and sizeAdd.
// If reset is true filesAdd and sizeAdd indicates the total files and the total size instead of the difference.
