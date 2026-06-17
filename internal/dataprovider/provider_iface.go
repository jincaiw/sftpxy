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
	"crypto/x509"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

// This file decomposes the historical monolithic Provider interface into
// domain-focused sub-interfaces and re-composes them via Go interface
// embedding. Every backend (MySQL, PostgreSQL, SQLite, Bolt, Memory) still
// implements the full set of methods, so it satisfies the composed Provider
// without any code change. The decomposition is purely structural and brings:
//   - readability: each capability is a named, scannable contract;
//   - testability: tests can depend on a narrow sub-interface (e.g. UserStore)
//     and mock only the methods they exercise;
//   - evolvability: adding a capability means defining a new sub-interface and
//     embedding it, instead of appending to a 120+-method God interface.
//
// The composed Provider is the single contract enforced at runtime; the
// sub-interfaces are the recommended seams for new code and unit tests.

// AuthStore groups the credential-validation methods.
type AuthStore interface {
	validateUserAndPass(username, password, ip, protocol string) (User, error)
	validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error)
	validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error)
	validateAdminAndPass(username, password, ip string) (Admin, error)
	// updateUserPassword is used internally when converting passwords from other hash formats.
	updateUserPassword(username, password string) error
}

// UserStore groups user CRUD, listing and signature methods.
type UserStore interface {
	userExists(username, role string) (User, error)
	addUser(user *User) error
	updateUser(user *User) error
	deleteUser(user User, softDelete bool) error
	getUsers(limit int, offset int, order, role string) ([]User, error)
	dumpUsers() ([]User, error)
	getRecentlyUpdatedUsers(after int64) ([]User, error)
	getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error)
	updateLastLogin(username string) error
	getAdminSignature(username string) (string, error)
	getUserSignature(username string) (string, error)
	setUpdatedAt(username string)
	setFirstDownloadTimestamp(username string) error
	setFirstUploadTimestamp(username string) error
}

// QuotaStore groups the storage/transfer quota accounting methods.
type QuotaStore interface {
	updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error
	updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error
	getUsedQuota(username string) (int, int64, int64, int64, error)
	updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error
	getUsedFolderQuota(name string) (int, int64, error)
}

// FolderStore groups the virtual folder CRUD methods.
type FolderStore interface {
	getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error)
	getFolderByName(name string) (vfs.BaseVirtualFolder, error)
	addFolder(folder *vfs.BaseVirtualFolder) error
	updateFolder(folder *vfs.BaseVirtualFolder) error
	deleteFolder(folder vfs.BaseVirtualFolder) error
	dumpFolders() ([]vfs.BaseVirtualFolder, error)
}

// GroupStore groups the group CRUD and lookup methods.
type GroupStore interface {
	getGroups(limit, offset int, order string, minimal bool) ([]Group, error)
	getGroupsWithNames(names []string) ([]Group, error)
	getUsersInGroups(names []string) ([]string, error)
	groupExists(name string) (Group, error)
	addGroup(group *Group) error
	updateGroup(group *Group) error
	deleteGroup(group Group) error
	dumpGroups() ([]Group, error)
}

// AdminStore groups the admin CRUD methods.
type AdminStore interface {
	adminExists(username string) (Admin, error)
	addAdmin(admin *Admin) error
	updateAdmin(admin *Admin) error
	deleteAdmin(admin Admin) error
	getAdmins(limit int, offset int, order string) ([]Admin, error)
	dumpAdmins() ([]Admin, error)
	updateAdminLastLogin(username string) error
}

// APIKeyStore groups the API key CRUD methods.
type APIKeyStore interface {
	apiKeyExists(keyID string) (APIKey, error)
	addAPIKey(apiKey *APIKey) error
	updateAPIKey(apiKey *APIKey) error
	deleteAPIKey(apiKey APIKey) error
	getAPIKeys(limit int, offset int, order string) ([]APIKey, error)
	dumpAPIKeys() ([]APIKey, error)
	updateAPIKeyLastUse(keyID string) error
}

// ShareStore groups the share CRUD methods.
type ShareStore interface {
	shareExists(shareID, username string) (Share, error)
	addShare(share *Share) error
	updateShare(share *Share) error
	deleteShare(share Share) error
	getShares(limit int, offset int, order, username string) ([]Share, error)
	dumpShares() ([]Share, error)
	updateShareLastUse(shareID string, numTokens int) error
}

// DefenderStore groups the brute-force defender host methods.
type DefenderStore interface {
	getDefenderHosts(from int64, limit int) ([]DefenderEntry, error)
	getDefenderHostByIP(ip string, from int64) (DefenderEntry, error)
	isDefenderHostBanned(ip string) (DefenderEntry, error)
	updateDefenderBanTime(ip string, minutes int) error
	deleteDefenderHost(ip string) error
	addDefenderEvent(ip string, score int) error
	setDefenderBanTime(ip string, banTime int64) error
	cleanupDefender(from int64) error
}

// TransferStore groups the active-transfer and shared-session bookkeeping
// used for cluster-wide transfer visibility.
type TransferStore interface {
	addActiveTransfer(transfer ActiveTransfer) error
	updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error
	removeActiveTransfer(transferID int64, connectionID string) error
	cleanupActiveTransfers(before time.Time) error
	getActiveTransfers(from time.Time) ([]ActiveTransfer, error)
	addSharedSession(session Session) error
	deleteSharedSession(key string, sessionType SessionType) error
	getSharedSession(key string, sessionType SessionType) (Session, error)
	cleanupSharedSessions(sessionType SessionType, before int64) error
}

// EventStore groups event actions, event rules and scheduler task methods.
type EventStore interface {
	getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error)
	dumpEventActions() ([]BaseEventAction, error)
	eventActionExists(name string) (BaseEventAction, error)
	addEventAction(action *BaseEventAction) error
	updateEventAction(action *BaseEventAction) error
	deleteEventAction(action BaseEventAction) error
	getEventRules(limit, offset int, order string) ([]EventRule, error)
	dumpEventRules() ([]EventRule, error)
	getRecentlyUpdatedRules(after int64) ([]EventRule, error)
	eventRuleExists(name string) (EventRule, error)
	addEventRule(rule *EventRule) error
	updateEventRule(rule *EventRule) error
	deleteEventRule(rule EventRule, softDelete bool) error
	getTaskByName(name string) (Task, error)
	addTask(name string) error
	updateTask(name string, version int64) error
	updateTaskTimestamp(name string) error
}

// NodeStore groups cluster node, role and IP-list methods. These are grouped
// together because they all deal with cluster-scoped administrative entities.
type NodeStore interface {
	addNode() error
	getNodeByName(name string) (Node, error)
	getNodes() ([]Node, error)
	updateNodeTimestamp() error
	cleanupNodes() error
	roleExists(name string) (Role, error)
	addRole(role *Role) error
	updateRole(role *Role) error
	deleteRole(role Role) error
	getRoles(limit, offset int, order string, minimal bool) ([]Role, error)
	dumpRoles() ([]Role, error)
	ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error)
	addIPListEntry(entry *IPListEntry) error
	updateIPListEntry(entry *IPListEntry) error
	deleteIPListEntry(entry IPListEntry, softDelete bool) error
	getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error)
	getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error)
	dumpIPListEntries() ([]IPListEntry, error)
	countIPListEntries(listType IPListType) (int64, error)
	getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error)
}

// ConfigStore groups the runtime configuration persistence and backend
// lifecycle methods.
type ConfigStore interface {
	getConfigs() (Configs, error)
	setConfigs(configs *Configs) error
	checkAvailability() error
	close() error
	reloadConfig() error
	initializeDatabase() error
	migrateDatabase() error
	revertDatabase(targetVersion int) error
	resetDatabase() error
}

// Provider defines the interface that data providers must implement.
// It is composed of domain-focused sub-interfaces (AuthStore, UserStore, ...)
// so that each capability is independently referenceable — for example, unit
// tests can depend on a narrow seam such as UserStore instead of the whole
// contract. Backend structs satisfy Provider by implementing every method, as
// before; no behavioral change is intended by this decomposition.
type Provider interface {
	AuthStore
	UserStore
	QuotaStore
	FolderStore
	GroupStore
	AdminStore
	APIKeyStore
	ShareStore
	DefenderStore
	TransferStore
	EventStore
	NodeStore
	ConfigStore
}
