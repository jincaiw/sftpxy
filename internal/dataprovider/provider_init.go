// SPDX-License-Identifier: MIT

package dataprovider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/jincaiw/sftpxy/sdk"
	"golang.org/x/crypto/bcrypt"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func checkSharedMode() {
	if !slices.Contains(sharedProviders, holder.getConfig().Driver) {
		holder.getConfig().IsShared = 0
	}
}

// Initialize the data provider.
// An error is returned if the configured driver is invalid or if the data provider cannot be initialized
func Initialize(cnf Config, basePath string, checkAdmins bool) error {
	holder.setConfig(cnf)
	checkSharedMode()
	holder.getConfig().Actions.ExecuteOn = util.RemoveDuplicates(holder.getConfig().Actions.ExecuteOn, true)
	holder.getConfig().Actions.ExecuteFor = util.RemoveDuplicates(holder.getConfig().Actions.ExecuteFor, true)

	cnf.BackupsPath = getConfigPath(cnf.BackupsPath, basePath)
	if cnf.BackupsPath == "" {
		return fmt.Errorf("required directory is invalid, backup path %q", cnf.BackupsPath)
	}
	absoluteBackupPath, err := util.GetAbsolutePath(cnf.BackupsPath)
	if err != nil {
		return fmt.Errorf("unable to get absolute backup path: %w", err)
	}
	holder.getConfig().BackupsPath = absoluteBackupPath

	if err := initializeHashingAlgo(&cnf); err != nil {
		return err
	}
	if err := validateHooks(); err != nil {
		return err
	}
	password, err := util.ResolveConfigValue(cnf.Password, cnf.PasswordFile, basePath)
	if err != nil {
		return fmt.Errorf("unable to read password from file %q: %w", cnf.PasswordFile, err)
	}
	holder.getConfig().Password = password
	if err := createProvider(basePath); err != nil {
		return err
	}
	if err := checkDatabase(checkAdmins); err != nil {
		return err
	}
	admins, err := holder.getProvider().getAdmins(1, 0, OrderASC)
	if err != nil {
		return err
	}
	isAdminCreated.Store(len(admins) > 0)
	if err := holder.getConfig().Node.validate(); err != nil {
		return err
	}
	delayedQuotaUpdater.start()
	if currentNode != nil {
		holder.getConfig().BackupsPath = filepath.Join(holder.getConfig().BackupsPath, currentNode.Name)
	}
	providerLog(logger.LevelDebug, "absolute backup path %q", holder.getConfig().BackupsPath)
	return startScheduler()
}

func checkDatabase(checkAdmins bool) error {
	if holder.getConfig().UpdateMode == 0 {
		err := holder.getProvider().initializeDatabase()
		if err != nil && err != ErrNoInitRequired {
			logger.WarnToConsole("unable to initialize data provider: %v", err)
			providerLog(logger.LevelError, "unable to initialize data provider: %v", err)
			return err
		}
		if err == nil {
			logger.DebugToConsole("data provider successfully initialized")
			providerLog(logger.LevelInfo, "data provider successfully initialized")
		}
		err = holder.getProvider().migrateDatabase()
		if err != nil && err != ErrNoInitRequired {
			providerLog(logger.LevelError, "database migration error: %v", err)
			return err
		}
		if checkAdmins && holder.getConfig().CreateDefaultAdmin {
			err = checkDefaultAdmin()
			if err != nil {
				providerLog(logger.LevelError, "erro checking the default admin: %v", err)
				return err
			}
		}
	} else {
		providerLog(logger.LevelInfo, "database initialization/migration skipped, manual mode is configured")
	}
	return nil
}

func validateHooks() error {
	var hooks []string
	if holder.getConfig().PreLoginHook != "" && !strings.HasPrefix(holder.getConfig().PreLoginHook, "http") {
		hooks = append(hooks, holder.getConfig().PreLoginHook)
	}
	if holder.getConfig().ExternalAuthHook != "" && !strings.HasPrefix(holder.getConfig().ExternalAuthHook, "http") {
		hooks = append(hooks, holder.getConfig().ExternalAuthHook)
	}
	if holder.getConfig().PostLoginHook != "" && !strings.HasPrefix(holder.getConfig().PostLoginHook, "http") {
		hooks = append(hooks, holder.getConfig().PostLoginHook)
	}
	if holder.getConfig().CheckPasswordHook != "" && !strings.HasPrefix(holder.getConfig().CheckPasswordHook, "http") {
		hooks = append(hooks, holder.getConfig().CheckPasswordHook)
	}

	for _, hook := range hooks {
		if !filepath.IsAbs(hook) {
			return fmt.Errorf("invalid hook: %q must be an absolute path", hook)
		}
		_, err := os.Stat(hook)
		if err != nil {
			providerLog(logger.LevelError, "invalid hook: %v", err)
			return err
		}
	}

	return nil
}

// GetBackupsPath returns the normalized backups path
func GetBackupsPath() string {
	return holder.getConfig().BackupsPath
}

// GetProviderFromValue returns the FilesystemProvider matching the specified value.
// If no match is found LocalFilesystemProvider is returned.
func GetProviderFromValue(value string) sdk.FilesystemProvider {
	val, err := strconv.Atoi(value)
	if err != nil {
		return sdk.LocalFilesystemProvider
	}
	result := sdk.FilesystemProvider(val)
	if sdk.IsProviderSupported(result) {
		return result
	}
	return sdk.LocalFilesystemProvider
}

func initializeHashingAlgo(cnf *Config) error {
	parallelism := cnf.PasswordHashing.Argon2Options.Parallelism
	if parallelism == 0 {
		parallelism = uint8(runtime.NumCPU())
	}
	holder.setArgon2Params(&argon2id.Params{
		Memory:      cnf.PasswordHashing.Argon2Options.Memory,
		Iterations:  cnf.PasswordHashing.Argon2Options.Iterations,
		Parallelism: parallelism,
		SaltLength:  16,
		KeyLength:   32,
	})

	if holder.getConfig().PasswordHashing.Algo == HashingAlgoBcrypt {
		if holder.getConfig().PasswordHashing.BcryptOptions.Cost > bcrypt.MaxCost {
			err := fmt.Errorf("invalid bcrypt cost %v, max allowed %v", holder.getConfig().PasswordHashing.BcryptOptions.Cost, bcrypt.MaxCost)
			logger.WarnToConsole("Unable to initialize data provider: %v", err)
			providerLog(logger.LevelError, "Unable to initialize data provider: %v", err)
			return err
		}
	}
	return nil
}

func validateSQLTablesPrefix() error {
	initSQLTables()
	if holder.getConfig().SQLTablesPrefix != "" {
		for _, char := range holder.getConfig().SQLTablesPrefix {
			if !strings.Contains(sqlPrefixValidChars, strings.ToLower(string(char))) {
				return errors.New("invalid sql_tables_prefix only chars in range 'a..z', 'A..Z', '0-9' and '_' are allowed")
			}
		}
		sqlTableUsers = holder.getConfig().SQLTablesPrefix + sqlTableUsers
		sqlTableFolders = holder.getConfig().SQLTablesPrefix + sqlTableFolders
		sqlTableUsersFoldersMapping = holder.getConfig().SQLTablesPrefix + sqlTableUsersFoldersMapping
		sqlTableAdmins = holder.getConfig().SQLTablesPrefix + sqlTableAdmins
		sqlTableAPIKeys = holder.getConfig().SQLTablesPrefix + sqlTableAPIKeys
		sqlTableShares = holder.getConfig().SQLTablesPrefix + sqlTableShares
		sqlTableSharesGroupsMapping = holder.getConfig().SQLTablesPrefix + sqlTableSharesGroupsMapping
		sqlTableDefenderEvents = holder.getConfig().SQLTablesPrefix + sqlTableDefenderEvents
		sqlTableDefenderHosts = holder.getConfig().SQLTablesPrefix + sqlTableDefenderHosts
		sqlTableActiveTransfers = holder.getConfig().SQLTablesPrefix + sqlTableActiveTransfers
		sqlTableGroups = holder.getConfig().SQLTablesPrefix + sqlTableGroups
		sqlTableUsersGroupsMapping = holder.getConfig().SQLTablesPrefix + sqlTableUsersGroupsMapping
		sqlTableAdminsGroupsMapping = holder.getConfig().SQLTablesPrefix + sqlTableAdminsGroupsMapping
		sqlTableGroupsFoldersMapping = holder.getConfig().SQLTablesPrefix + sqlTableGroupsFoldersMapping
		sqlTableSharedSessions = holder.getConfig().SQLTablesPrefix + sqlTableSharedSessions
		sqlTableEventsActions = holder.getConfig().SQLTablesPrefix + sqlTableEventsActions
		sqlTableEventsRules = holder.getConfig().SQLTablesPrefix + sqlTableEventsRules
		sqlTableRulesActionsMapping = holder.getConfig().SQLTablesPrefix + sqlTableRulesActionsMapping
		sqlTableTasks = holder.getConfig().SQLTablesPrefix + sqlTableTasks
		sqlTableNodes = holder.getConfig().SQLTablesPrefix + sqlTableNodes
		sqlTableRoles = holder.getConfig().SQLTablesPrefix + sqlTableRoles
		sqlTableIPLists = holder.getConfig().SQLTablesPrefix + sqlTableIPLists
		sqlTableConfigs = holder.getConfig().SQLTablesPrefix + sqlTableConfigs
		sqlTableSchemaVersion = holder.getConfig().SQLTablesPrefix + sqlTableSchemaVersion
		providerLog(logger.LevelDebug, "sql table for users %q, folders %q users folders mapping %q admins %q "+
			"api keys %q shares %q defender hosts %q defender events %q transfers %q  groups %q "+
			"users groups mapping %q admins groups mapping %q groups folders mapping %q shared sessions %q "+
			"schema version %q events actions %q events rules %q rules actions mapping %q tasks %q nodes %q roles %q"+
			"ip lists %q share groups mapping %q configs %q",
			sqlTableUsers, sqlTableFolders, sqlTableUsersFoldersMapping, sqlTableAdmins, sqlTableAPIKeys,
			sqlTableShares, sqlTableDefenderHosts, sqlTableDefenderEvents, sqlTableActiveTransfers, sqlTableGroups,
			sqlTableUsersGroupsMapping, sqlTableAdminsGroupsMapping, sqlTableGroupsFoldersMapping, sqlTableSharedSessions,
			sqlTableSchemaVersion, sqlTableEventsActions, sqlTableEventsRules, sqlTableRulesActionsMapping,
			sqlTableTasks, sqlTableNodes, sqlTableRoles, sqlTableIPLists, sqlTableSharesGroupsMapping, sqlTableConfigs)
	}
	return nil
}

func checkDefaultAdmin() error {
	admins, err := holder.getProvider().getAdmins(1, 0, OrderASC)
	if err != nil {
		return err
	}
	if len(admins) > 0 {
		return nil
	}
	logger.Debug(logSender, "", "no admins found, try to create the default one")
	// we need to create the default admin
	admin := &Admin{}
	if err := admin.setFromEnv(); err != nil {
		return err
	}
	return holder.getProvider().addAdmin(admin)
}

// InitializeDatabase creates the initial database structure
func InitializeDatabase(cnf Config, basePath string) error {
	holder.setConfig(cnf)

	if err := initializeHashingAlgo(&cnf); err != nil {
		return err
	}

	err := createProvider(basePath)
	if err != nil {
		return err
	}
	err = holder.getProvider().initializeDatabase()
	if err != nil && err != ErrNoInitRequired {
		return err
	}
	return holder.getProvider().migrateDatabase()
}

// RevertDatabase restores schema and/or data to a previous version
func RevertDatabase(cnf Config, basePath string, targetVersion int) error {
	holder.setConfig(cnf)

	err := createProvider(basePath)
	if err != nil {
		return err
	}
	err = holder.getProvider().initializeDatabase()
	if err != nil && err != ErrNoInitRequired {
		return err
	}
	return holder.getProvider().revertDatabase(targetVersion)
}

// ResetDatabase restores schema and/or data to a previous version
func ResetDatabase(cnf Config, basePath string) error {
	holder.setConfig(cnf)

	if err := createProvider(basePath); err != nil {
		return err
	}
	return holder.getProvider().resetDatabase()
}

// CheckAdminAndPass validates the given admin and password connecting from ip
