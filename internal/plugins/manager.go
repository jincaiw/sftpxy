package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"

	"github.com/jincaiw/sftpxy/internal/config"
	"go.uber.org/zap"
)

type Plugin interface {
	Name() string
	Version() string
	Init(config map[string]interface{}) error
	HealthCheck() error
	Close() error
}

type AuthPlugin interface {
	Plugin
	Authenticate(ctx context.Context, username, password string) (bool, map[string]interface{}, error)
}

type StoragePlugin interface {
	Plugin
	ConfigureBackend(ctx context.Context, name string, config map[string]interface{}) error
}

type AuditPlugin interface {
	Plugin
	OnAuditEvent(ctx context.Context, eventType string, payload map[string]interface{}) error
}

type FilterPlugin interface {
	Plugin
	AllowUpload(ctx context.Context, path string, size int64) (bool, error)
	AllowDownload(ctx context.Context, path string) (bool, error)
	AllowCommand(ctx context.Context, command string) (bool, error)
}

type IdentityPlugin interface {
	Plugin
	LookupUser(ctx context.Context, username string) (map[string]interface{}, error)
	LookupGroups(ctx context.Context, username string) ([]string, error)
}

type PluginStatus string

const (
	StatusEnabled  PluginStatus = "enabled"
	StatusDisabled PluginStatus = "disabled"
	StatusError    PluginStatus = "error"
)

type PluginInfo struct {
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Status  PluginStatus `json:"status"`
	Type    string       `json:"type"`
	Error   string       `json:"error,omitempty"`
}

type pluginEntry struct {
	plugin Plugin
	status PluginStatus
	err    error
}

type PluginManager struct {
	plugins map[string]*pluginEntry
	config  config.PluginsConfig
	logger  *zap.Logger
	mu      sync.RWMutex
}

func NewPluginManager(cfg config.PluginsConfig, log *zap.Logger) *PluginManager {
	return &PluginManager{
		plugins: make(map[string]*pluginEntry),
		config:  cfg,
		logger:  log.Named("plugins"),
	}
}

func (pm *PluginManager) LoadPlugins(pluginDir string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pluginDir == "" {
		pluginDir = pm.config.Directory
	}
	if pluginDir == "" {
		pm.logger.Info("No plugin directory configured, skipping plugin loading")
		return nil
	}

	info, err := os.Stat(pluginDir)
	if err != nil {
		if os.IsNotExist(err) {
			pm.logger.Info("Plugin directory does not exist", zap.String("dir", pluginDir))
			return nil
		}
		return fmt.Errorf("failed to stat plugin directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("plugin path is not a directory: %s", pluginDir)
	}

	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".so") {
			continue
		}

		pluginPath := filepath.Join(pluginDir, name)
		if err := pm.loadPluginFromSO(pluginPath); err != nil {
			pm.logger.Warn("Failed to load plugin",
				zap.String("path", pluginPath),
				zap.Error(err),
			)
		}
	}

	return nil
}

func (pm *PluginManager) loadPluginFromSO(path string) error {
	so, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", path, err)
	}

	sym, err := so.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("plugin %s does not export NewPlugin: %w", path, err)
	}

	newPluginFunc, ok := sym.(func() Plugin)
	if !ok {
		return fmt.Errorf("plugin %s NewPlugin has wrong signature", path)
	}

	p := newPluginFunc()
	if p == nil {
		return fmt.Errorf("plugin %s NewPlugin returned nil", path)
	}

	pluginName := p.Name()
	if pm.isDisabled(pluginName) {
		pm.plugins[pluginName] = &pluginEntry{
			plugin: p,
			status: StatusDisabled,
		}
		pm.logger.Info("Plugin loaded but disabled", zap.String("name", pluginName))
		return nil
	}

	pluginConfig := pm.getPluginConfig(pluginName)
	if err := p.Init(pluginConfig); err != nil {
		pm.plugins[pluginName] = &pluginEntry{
			plugin: p,
			status: StatusError,
			err:    err,
		}
		pm.logger.Error("Plugin init failed",
			zap.String("name", pluginName),
			zap.Error(err),
		)
		return nil
	}

	pm.plugins[pluginName] = &pluginEntry{
		plugin: p,
		status: StatusEnabled,
	}
	pm.logger.Info("Plugin loaded and enabled",
		zap.String("name", pluginName),
		zap.String("version", p.Version()),
	)
	return nil
}

func (pm *PluginManager) GetPlugin(name string) (Plugin, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	entry, ok := pm.plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	if entry.status != StatusEnabled {
		return nil, fmt.Errorf("plugin %q is %s", name, entry.status)
	}
	return entry.plugin, nil
}

func (pm *PluginManager) RegisterPlugin(name string, p Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}

	if pm.isDisabled(name) {
		pm.plugins[name] = &pluginEntry{
			plugin: p,
			status: StatusDisabled,
		}
		pm.logger.Info("Plugin registered but disabled", zap.String("name", name))
		return nil
	}

	pluginConfig := pm.getPluginConfig(name)
	if err := p.Init(pluginConfig); err != nil {
		pm.plugins[name] = &pluginEntry{
			plugin: p,
			status: StatusError,
			err:    err,
		}
		return fmt.Errorf("plugin %q init failed: %w", name, err)
	}

	pm.plugins[name] = &pluginEntry{
		plugin: p,
		status: StatusEnabled,
	}
	pm.logger.Info("Plugin registered and enabled",
		zap.String("name", name),
		zap.String("version", p.Version()),
	)
	return nil
}

func (pm *PluginManager) EnablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry, ok := pm.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	if entry.status == StatusEnabled {
		return nil
	}

	pluginConfig := pm.getPluginConfig(name)
	if err := entry.plugin.Init(pluginConfig); err != nil {
		entry.status = StatusError
		entry.err = err
		return fmt.Errorf("plugin %q init failed: %w", name, err)
	}

	entry.status = StatusEnabled
	entry.err = nil
	pm.logger.Info("Plugin enabled", zap.String("name", name))
	return nil
}

func (pm *PluginManager) DisablePlugin(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry, ok := pm.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}
	if entry.status == StatusDisabled {
		return nil
	}

	if err := entry.plugin.Close(); err != nil {
		pm.logger.Warn("Plugin close error on disable",
			zap.String("name", name),
			zap.Error(err),
		)
	}

	entry.status = StatusDisabled
	pm.logger.Info("Plugin disabled", zap.String("name", name))
	return nil
}

func (pm *PluginManager) ListPlugins() []PluginInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make([]PluginInfo, 0, len(pm.plugins))
	for name, entry := range pm.plugins {
		info := PluginInfo{
			Name:    name,
			Version: entry.plugin.Version(),
			Status:  entry.status,
		}
		if _, ok := entry.plugin.(AuthPlugin); ok {
			info.Type = "auth"
		} else if _, ok := entry.plugin.(StoragePlugin); ok {
			info.Type = "storage"
		} else if _, ok := entry.plugin.(AuditPlugin); ok {
			info.Type = "audit"
		} else if _, ok := entry.plugin.(FilterPlugin); ok {
			info.Type = "filter"
		} else if _, ok := entry.plugin.(IdentityPlugin); ok {
			info.Type = "identity"
		} else {
			info.Type = "generic"
		}
		if entry.err != nil {
			info.Error = entry.err.Error()
		}
		result = append(result, info)
	}
	return result
}

func (pm *PluginManager) HealthCheckAll() map[string]error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[string]error)
	for name, entry := range pm.plugins {
		if entry.status != StatusEnabled {
			continue
		}
		if err := entry.plugin.HealthCheck(); err != nil {
			results[name] = err
			pm.logger.Warn("Plugin health check failed",
				zap.String("name", name),
				zap.Error(err),
			)
		}
	}
	return results
}

func (pm *PluginManager) CloseAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, entry := range pm.plugins {
		if entry.status == StatusEnabled {
			if err := entry.plugin.Close(); err != nil {
				pm.logger.Warn("Plugin close error",
					zap.String("name", name),
					zap.Error(err),
				)
			}
			entry.status = StatusDisabled
		}
	}
	pm.logger.Info("All plugins closed")
}

func (pm *PluginManager) isDisabled(name string) bool {
	for _, d := range pm.config.Disabled {
		if d == name {
			return true
		}
	}
	if len(pm.config.Enabled) == 0 {
		return false
	}
	for _, e := range pm.config.Enabled {
		if e == name {
			return false
		}
	}
	return true
}

func (pm *PluginManager) getPluginConfig(name string) map[string]interface{} {
	if pm.config.Configs == nil {
		return nil
	}
	cfg, ok := pm.config.Configs[name]
	if !ok {
		return nil
	}
	if m, ok := cfg.(map[string]interface{}); ok {
		return m
	}
	return nil
}
