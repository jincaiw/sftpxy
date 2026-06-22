// SPDX-License-Identifier: MIT

package dataprovider

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

func dumpUsers(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeUsers) {
		users, err := holder.getProvider().dumpUsers()
		if err != nil {
			return err
		}
		data.Users = users
	}
	return nil
}

func dumpFolders(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeFolders) {
		folders, err := holder.getProvider().dumpFolders()
		if err != nil {
			return err
		}
		data.Folders = folders
	}
	return nil
}

func dumpGroups(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeGroups) {
		groups, err := holder.getProvider().dumpGroups()
		if err != nil {
			return err
		}
		data.Groups = groups
	}
	return nil
}

func dumpAdmins(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeAdmins) {
		admins, err := holder.getProvider().dumpAdmins()
		if err != nil {
			return err
		}
		data.Admins = admins
	}
	return nil
}

func dumpAPIKeys(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeAPIKeys) {
		apiKeys, err := holder.getProvider().dumpAPIKeys()
		if err != nil {
			return err
		}
		data.APIKeys = apiKeys
	}
	return nil
}

func dumpShares(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeShares) {
		shares, err := holder.getProvider().dumpShares()
		if err != nil {
			return err
		}
		data.Shares = shares
	}
	return nil
}

func dumpActions(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeActions) {
		actions, err := holder.getProvider().dumpEventActions()
		if err != nil {
			return err
		}
		data.EventActions = actions
	}
	return nil
}

func dumpRules(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeRules) {
		rules, err := holder.getProvider().dumpEventRules()
		if err != nil {
			return err
		}
		data.EventRules = rules
	}
	return nil
}

func dumpRoles(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeRoles) {
		roles, err := holder.getProvider().dumpRoles()
		if err != nil {
			return err
		}
		data.Roles = roles
	}
	return nil
}

func dumpIPLists(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeIPLists) {
		ipLists, err := holder.getProvider().dumpIPListEntries()
		if err != nil {
			return err
		}
		data.IPLists = ipLists
	}
	return nil
}

func dumpConfigs(data *BackupData, scopes []string) error {
	if len(scopes) == 0 || slices.Contains(scopes, DumpScopeConfigs) {
		configs, err := holder.getProvider().getConfigs()
		if err != nil {
			return err
		}
		data.Configs = &configs
	}
	return nil
}

// DumpData returns a dump containing the requested scopes.
// Empty scopes means all
func DumpData(scopes []string) (BackupData, error) {
	data := BackupData{
		Version: DumpVersion,
	}
	if err := dumpGroups(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpUsers(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpFolders(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpAdmins(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpAPIKeys(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpShares(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpActions(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpRules(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpRoles(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpIPLists(&data, scopes); err != nil {
		return data, err
	}
	if err := dumpConfigs(&data, scopes); err != nil {
		return data, err
	}

	return data, nil
}

// ParseDumpData tries to parse data as BackupData
func ParseDumpData(data []byte) (BackupData, error) {
	var dump BackupData
	err := json.Unmarshal(data, &dump)
	if err != nil {
		return dump, err
	}
	if dump.Version < 17 {
		providerLog(logger.LevelInfo, "updating placeholders for actions restored from dump version %d", dump.Version)
		eventActions, err := updateEventActionPlaceholders(dump.EventActions)
		if err != nil {
			return dump, fmt.Errorf("unable to update event action placeholders for dump version %d: %w", dump.Version, err)
		}
		dump.EventActions = eventActions
	}
	return dump, err
}

// GetProviderConfig returns the current provider configuration
func GetProviderConfig() Config {
	return *holder.getConfig()
}

// GetProviderStatus returns an error if the provider is not available
func GetProviderStatus() ProviderStatus {
	err := holder.getProvider().checkAvailability()
	status := ProviderStatus{
		Driver: holder.getConfig().Driver,
	}
	if err == nil {
		status.IsActive = true
	} else {
		status.IsActive = false
		status.Error = err.Error()
	}
	return status
}

// Close releases all provider resources.
// This method is used in test cases.
// Closing an uninitialized provider is not supported
func Close() error {
	stopScheduler()
	return holder.getProvider().close()
}
