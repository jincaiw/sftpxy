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
	"fmt"
	"slices"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
)

func AddShare(share *Share, executor, ipAddress, role string) error {
	err := holder.getProvider().addShare(share)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectShare, share.ShareID, role, share)
	}
	return err
}

// UpdateShare updates an existing share
func UpdateShare(share *Share, executor, ipAddress, role string) error {
	err := holder.getProvider().updateShare(share)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectShare, share.ShareID, role, share)
	}
	return err
}

// DeleteShare deletes an existing share
func DeleteShare(shareID string, executor, ipAddress, role string) error {
	share, err := holder.getProvider().shareExists(shareID, executor)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteShare(share)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectShare, shareID, role, &share)
	}
	return err
}

// ShareExists returns the share with the given ID if it exists
func ShareExists(shareID, username string) (Share, error) {
	if shareID == "" {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %q does not exist", shareID))
	}
	return holder.getProvider().shareExists(shareID, username)
}

// AddIPListEntry adds a new IP list entry
func AddIPListEntry(entry *IPListEntry, executor, ipAddress, executorRole string) error {
	err := holder.getProvider().addIPListEntry(entry)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, entry)
		for _, l := range inMemoryLists {
			l.addEntry(entry)
		}
	}
	return err
}

// UpdateIPListEntry updates an existing IP list entry
func UpdateIPListEntry(entry *IPListEntry, executor, ipAddress, executorRole string) error {
	err := holder.getProvider().updateIPListEntry(entry)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, entry)
		for _, l := range inMemoryLists {
			l.updateEntry(entry)
		}
	}
	return err
}

// DeleteIPListEntry deletes an existing IP list entry
func DeleteIPListEntry(ipOrNet string, listType IPListType, executor, ipAddress, executorRole string) error {
	entry, err := holder.getProvider().ipListEntryExists(ipOrNet, listType)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteIPListEntry(entry, holder.getConfig().IsShared == 1)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectIPListEntry, entry.getName(), executorRole, &entry)
		for _, l := range inMemoryLists {
			l.removeEntry(&entry)
		}
	}
	return err
}

// IPListEntryExists returns the IP list entry with the given IP/net and type if it exists
func IPListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	return holder.getProvider().ipListEntryExists(ipOrNet, listType)
}

// GetIPListEntries returns the IP list entries applying the specified criteria and search limit
func GetIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	if !slices.Contains(supportedIPListType, listType) {
		return nil, util.NewValidationError(fmt.Sprintf("invalid list type %d", listType))
	}
	return holder.getProvider().getIPListEntries(listType, filter, from, order, limit)
}

// AddRole adds a new role
func AddRole(role *Role, executor, ipAddress, executorRole string) error {
	role.Name = holder.getConfig().convertName(role.Name)
	err := holder.getProvider().addRole(role)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectRole, role.Name, executorRole, role)
	}
	return err
}

// UpdateRole updates an existing Role
func UpdateRole(role *Role, executor, ipAddress, executorRole string) error {
	err := holder.getProvider().updateRole(role)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectRole, role.Name, executorRole, role)
	}
	return err
}

// DeleteRole deletes an existing Role
func DeleteRole(name string, executor, ipAddress, executorRole string) error {
	name = holder.getConfig().convertName(name)
	role, err := holder.getProvider().roleExists(name)
	if err != nil {
		return err
	}
	if len(role.Admins) > 0 {
		errorString := fmt.Sprintf("the role %q is referenced, it cannot be removed", role.Name)
		return util.NewValidationError(errorString)
	}
	err = holder.getProvider().deleteRole(role)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectRole, role.Name, executorRole, &role)
		for _, user := range role.Users {
			holder.getProvider().setUpdatedAt(user)
			u, err := holder.getProvider().userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			}
		}
	}
	return err
}

// RoleExists returns the Role with the given name if it exists
func RoleExists(name string) (Role, error) {
	name = holder.getConfig().convertName(name)
	return holder.getProvider().roleExists(name)
}

// AddGroup adds a new group
func AddGroup(group *Group, executor, ipAddress, role string) error {
	group.Name = holder.getConfig().convertName(group.Name)
	err := holder.getProvider().addGroup(group)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectGroup, group.Name, role, group)
	}
	return err
}

// UpdateGroup updates an existing Group
func UpdateGroup(group *Group, users []string, executor, ipAddress, role string) error {
	err := holder.getProvider().updateGroup(group)
	if err == nil {
		for _, user := range users {
			holder.getProvider().setUpdatedAt(user)
			u, err := holder.getProvider().userExists(user, "")
			if err == nil {
				webDAVUsersCache.swap(&u, "")
			} else {
				RemoveCachedWebDAVUser(user)
			}
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectGroup, group.Name, role, group)
	}
	return err
}

// DeleteGroup deletes an existing Group
func DeleteGroup(name string, executor, ipAddress, role string) error {
	name = holder.getConfig().convertName(name)
	group, err := holder.getProvider().groupExists(name)
	if err != nil {
		return err
	}
	if len(group.Users) > 0 {
		errorString := fmt.Sprintf("the group %q is referenced, it cannot be removed", group.Name)
		return util.NewValidationError(errorString)
	}
	err = holder.getProvider().deleteGroup(group)
	if err == nil {
		for _, user := range group.Users {
			holder.getProvider().setUpdatedAt(user)
			u, err := holder.getProvider().userExists(user, "")
			if err == nil {
				executeAction(operationUpdate, executor, ipAddress, actionObjectUser, u.Username, u.Role, &u)
			}
			RemoveCachedWebDAVUser(user)
		}
		executeAction(operationDelete, executor, ipAddress, actionObjectGroup, group.Name, role, &group)
	}
	return err
}

// GroupExists returns the Group with the given name if it exists
func GroupExists(name string) (Group, error) {
	name = holder.getConfig().convertName(name)
	return holder.getProvider().groupExists(name)
}

// AddAPIKey adds a new API key
func AddAPIKey(apiKey *APIKey, executor, ipAddress, role string) error {
	err := holder.getProvider().addAPIKey(apiKey)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, apiKey)
	}
	return err
}

// UpdateAPIKey updates an existing API key
func UpdateAPIKey(apiKey *APIKey, executor, ipAddress, role string) error {
	err := holder.getProvider().updateAPIKey(apiKey)
	if err == nil {
		executeAction(operationUpdate, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, apiKey)
	}
	return err
}

// DeleteAPIKey deletes an existing API key
func DeleteAPIKey(keyID string, executor, ipAddress, role string) error {
	apiKey, err := holder.getProvider().apiKeyExists(keyID)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteAPIKey(apiKey)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectAPIKey, apiKey.KeyID, role, &apiKey)
		cachedAPIKeys.Remove(keyID)
	}
	return err
}

// APIKeyExists returns the API key with the given ID if it exists
func APIKeyExists(keyID string) (APIKey, error) {
	if keyID == "" {
		return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %q does not exist", keyID))
	}
	return holder.getProvider().apiKeyExists(keyID)
}

// GetEventActions returns an array of event actions respecting limit and offset
func GetEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return holder.getProvider().getEventActions(limit, offset, order, minimal)
}

// EventActionExists returns the event action with the given name if it exists
func EventActionExists(name string) (BaseEventAction, error) {
	name = holder.getConfig().convertName(name)
	return holder.getProvider().eventActionExists(name)
}

// AddEventAction adds a new event action
func AddEventAction(action *BaseEventAction, executor, ipAddress, role string) error {
	action.Name = holder.getConfig().convertName(action.Name)
	err := holder.getProvider().addEventAction(action)
	if err == nil {
		executeAction(operationAdd, executor, ipAddress, actionObjectEventAction, action.Name, role, action)
	}
	return err
}

// UpdateEventAction updates an existing event action
func UpdateEventAction(action *BaseEventAction, executor, ipAddress, role string) error {
	err := holder.getProvider().updateEventAction(action)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectEventAction, action.Name, role, action)
	}
	return err
}

// DeleteEventAction deletes an existing event action
func DeleteEventAction(name string, executor, ipAddress, role string) error {
	name = holder.getConfig().convertName(name)
	action, err := holder.getProvider().eventActionExists(name)
	if err != nil {
		return err
	}
	if len(action.Rules) > 0 {
		errorString := fmt.Sprintf("the event action %#q is referenced, it cannot be removed", action.Name)
		return util.NewValidationError(errorString)
	}
	err = holder.getProvider().deleteEventAction(action)
	if err == nil {
		executeAction(operationDelete, executor, ipAddress, actionObjectEventAction, action.Name, role, &action)
	}
	return err
}

// GetEventRules returns an array of event rules respecting limit and offset
func GetEventRules(limit, offset int, order string) ([]EventRule, error) {
	return holder.getProvider().getEventRules(limit, offset, order)
}

// GetRecentlyUpdatedRules returns the event rules updated after the specified time
func GetRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return holder.getProvider().getRecentlyUpdatedRules(after)
}

// EventRuleExists returns the event rule with the given name if it exists
func EventRuleExists(name string) (EventRule, error) {
	name = holder.getConfig().convertName(name)
	return holder.getProvider().eventRuleExists(name)
}

// AddEventRule adds a new event rule
func AddEventRule(rule *EventRule, executor, ipAddress, role string) error {
	rule.Name = holder.getConfig().convertName(rule.Name)
	err := holder.getProvider().addEventRule(rule)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationAdd, executor, ipAddress, actionObjectEventRule, rule.Name, role, rule)
	}
	return err
}

// UpdateEventRule updates an existing event rule
func UpdateEventRule(rule *EventRule, executor, ipAddress, role string) error {
	err := holder.getProvider().updateEventRule(rule)
	if err == nil {
		if fnReloadRules != nil {
			fnReloadRules()
		}
		executeAction(operationUpdate, executor, ipAddress, actionObjectEventRule, rule.Name, role, rule)
	}
	return err
}

// DeleteEventRule deletes an existing event rule
func DeleteEventRule(name string, executor, ipAddress, role string) error {
	name = holder.getConfig().convertName(name)
	rule, err := holder.getProvider().eventRuleExists(name)
	if err != nil {
		return err
	}
	err = holder.getProvider().deleteEventRule(rule, holder.getConfig().IsShared == 1)
	if err == nil {
		if fnRemoveRule != nil {
			fnRemoveRule(rule.Name)
		}
		executeAction(operationDelete, executor, ipAddress, actionObjectEventRule, rule.Name, role, &rule)
	}
	return err
}

// RemoveEventRule delets an existing event rule without marking it as deleted
func RemoveEventRule(rule EventRule) error {
	return holder.getProvider().deleteEventRule(rule, false)
}

// GetTaskByName returns the task with the specified name
func GetTaskByName(name string) (Task, error) {
	return holder.getProvider().getTaskByName(name)
}

// AddTask add a task with the specified name
func AddTask(name string) error {
	return holder.getProvider().addTask(name)
}

// UpdateTask updates the task with the specified name and version
func UpdateTask(name string, version int64) error {
	return holder.getProvider().updateTask(name, version)
}

// UpdateTaskTimestamp updates the timestamp for the task with the specified name
func UpdateTaskTimestamp(name string) error {
	return holder.getProvider().updateTaskTimestamp(name)
}

// GetNodes returns the other cluster nodes
func GetNodes() ([]Node, error) {
	if currentNode == nil {
		return nil, nil
	}
	nodes, err := holder.getProvider().getNodes()
	if err != nil {
		providerLog(logger.LevelError, "unable to get other cluster nodes %v", err)
	}
	return nodes, err
}

// GetNodeByName returns a node, different from the current one, by name
func GetNodeByName(name string) (Node, error) {
	if currentNode == nil {
		return Node{}, util.NewRecordNotFoundError(errNoClusterNodes.Error())
	}
	if name == currentNode.Name {
		return Node{}, util.NewValidationError(fmt.Sprintf("%s is the current node, it must refer to other nodes", name))
	}
	return holder.getProvider().getNodeByName(name)
}

// HasAdmin returns true if the first admin has been created
// and so SFTPGo is ready to be used
