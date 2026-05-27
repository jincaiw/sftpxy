package events

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// EventType represents the type of event
type EventType string

const (
	EventPreUpload    EventType = "pre-upload"
	EventUpload       EventType = "upload"
	EventPreDownload  EventType = "pre-download"
	EventDownload     EventType = "download"
	EventPreDelete    EventType = "pre-delete"
	EventDelete       EventType = "delete"
	EventRename       EventType = "rename"
	EventMkdir        EventType = "mkdir"
	EventRmdir        EventType = "rmdir"
	EventSSHCommand   EventType = "ssh.command"
	EventUserCreated  EventType = "user.created"
	EventUserUpdated  EventType = "user.updated"
	EventUserDeleted  EventType = "user.deleted"
	EventConnect      EventType = "connect"
	EventLogin        EventType = "login"
	EventDisconnect   EventType = "disconnect"
)

// EventPayload contains event data
type EventPayload struct {
	EventID    string                 `json:"event_id"`
	EventType  EventType              `json:"event_type"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     int64                  `json:"user_id,omitempty"`
	Username   string                 `json:"username,omitempty"`
	Protocol   string                 `json:"protocol,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	ConnectionID string               `json:"connection_id,omitempty"`
	FilePath   string                 `json:"file_path,omitempty"`
	FileName   string                 `json:"file_name,omitempty"`
	FileSize   int64                  `json:"file_size,omitempty"`
	FileExt    string                 `json:"file_ext,omitempty"`
	Result     string                 `json:"result,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
}

// ActionType represents the type of action to execute
type ActionType string

const (
	ActionHTTP    ActionType = "http"
	ActionCommand ActionType = "command"
	ActionEmail   ActionType = "email"
	ActionFileOp  ActionType = "file_operation"
)

// ActionConfig contains action configuration
type ActionConfig struct {
	Type   ActionType              `json:"type"`
	Config map[string]interface{}  `json:"config"`
}

// Condition represents a rule condition
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// EventRule represents an event rule
type EventRule struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	TriggerType EventType   `json:"trigger_type"`
	Conditions  []Condition `json:"conditions"`
	Actions     []ActionConfig `json:"actions"`
	IsActive    bool        `json:"is_active"`
	Schedule    string      `json:"schedule,omitempty"` // cron expression
}

// ExecutionResult holds the result of an action execution
type ExecutionResult struct {
	ActionType  ActionType
	Success     bool
	Error       error
	Duration    time.Duration
	ResponseData string
}

// EventHandler defines the interface for handling events
type EventHandler interface {
	HandleEvent(ctx context.Context, payload *EventPayload) error
}

// HTTPActionHandler handles HTTP notification actions
type HTTPActionHandler struct {
	logger *zap.Logger
}

// NewHTTPActionHandler creates a new HTTP action handler
func NewHTTPActionHandler(log *zap.Logger) *HTTPActionHandler {
	return &HTTPActionHandler{logger: log}
}

// Execute executes an HTTP action
func (h *HTTPActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	url, _ := config["url"].(string)
	if url == "" {
		return &ExecutionResult{ActionType: ActionHTTP, Success: false, Error: fmt.Errorf("url is required"), Duration: time.Since(start)}, nil
	}

	h.logger.Info("Executing HTTP action", zap.String("url", url), zap.String("event", string(payload.EventType)))

	// Placeholder: In production, send HTTP POST request
	return &ExecutionResult{
		ActionType:  ActionHTTP,
		Success:     true,
		Duration:    time.Since(start),
		ResponseData: "sent",
	}, nil
}

// CommandActionHandler handles command execution actions
type CommandActionHandler struct {
	logger    *zap.Logger
	whitelist []string
}

// NewCommandActionHandler creates a new command action handler
func NewCommandActionHandler(log *zap.Logger, whitelist []string) *CommandActionHandler {
	return &CommandActionHandler{logger: log, whitelist: whitelist}
}

// Execute executes a command action
func (c *CommandActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	cmd, _ := config["command"].(string)
	if cmd == "" {
		return &ExecutionResult{ActionType: ActionCommand, Success: false, Error: fmt.Errorf("command is required"), Duration: time.Since(start)}, nil
	}

	// Check whitelist
	allowed := false
	for _, w := range c.whitelist {
		if w == cmd {
			allowed = true
			break
		}
	}
	if !allowed {
		return &ExecutionResult{ActionType: ActionCommand, Success: false, Error: fmt.Errorf("command not in whitelist"), Duration: time.Since(start)}, nil
	}

	c.logger.Info("Executing command action", zap.String("command", cmd))

	return &ExecutionResult{
		ActionType: ActionCommand,
		Success:    true,
		Duration:   time.Since(start),
	}, nil
}

// EmailActionHandler handles email notification actions
type EmailActionHandler struct {
	logger *zap.Logger
}

// NewEmailActionHandler creates a new email action handler
func NewEmailActionHandler(log *zap.Logger) *EmailActionHandler {
	return &EmailActionHandler{logger: log}
}

// Execute executes an email action
func (e *EmailActionHandler) Execute(ctx context.Context, config map[string]interface{}, payload *EventPayload) (*ExecutionResult, error) {
	start := time.Now()
	to, _ := config["to"].(string)
	subject, _ := config["subject"].(string)

	e.logger.Info("Sending email notification", zap.String("to", to), zap.String("subject", subject))

	return &ExecutionResult{
		ActionType: ActionEmail,
		Success:    true,
		Duration:   time.Since(start),
	}, nil
}

// Manager manages event rules and execution
type Manager struct {
	rules       map[int64]*EventRule
	mu          sync.RWMutex
	cron        *cron.Cron
	httpHandler *HTTPActionHandler
	cmdHandler  *CommandActionHandler
	emailHandler *EmailActionHandler
	logger      *zap.Logger
}

// NewManager creates a new event manager
func NewManager(log *zap.Logger, commandWhitelist []string) *Manager {
	m := &Manager{
		rules:        make(map[int64]*EventRule),
		cron:         cron.New(cron.WithSeconds()),
		httpHandler:  NewHTTPActionHandler(log),
		cmdHandler:   NewCommandActionHandler(log, commandWhitelist),
		emailHandler: NewEmailActionHandler(log),
		logger:       log.Named("event_manager"),
	}
	m.cron.Start()
	return m
}

// AddRule adds an event rule
func (m *Manager) AddRule(rule *EventRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[rule.ID] = rule

	// If it's a scheduled rule, add to cron
	if rule.Schedule != "" && rule.IsActive {
		ruleID := rule.ID
		m.cron.AddFunc(rule.Schedule, func() {
			m.executeScheduledRule(ruleID)
		})
	}

	m.logger.Info("Event rule added", zap.Int64("id", rule.ID), zap.String("name", rule.Name))
}

// RemoveRule removes an event rule
func (m *Manager) RemoveRule(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, id)
	m.logger.Info("Event rule removed", zap.Int64("id", id))
}

// GetRule gets a rule by ID
func (m *Manager) GetRule(id int64) *EventRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rules[id]
}

// ListRules lists all rules
func (m *Manager) ListRules() []*EventRule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var rules []*EventRule
	for _, r := range m.rules {
		rules = append(rules, r)
	}
	return rules
}

// EmitEvent emits an event and triggers matching rules
func (m *Manager) EmitEvent(ctx context.Context, payload *EventPayload) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.logger.Debug("Event emitted", zap.String("type", string(payload.EventType)), zap.String("user", payload.Username))

	for _, rule := range m.rules {
		if !rule.IsActive {
			continue
		}
		if rule.TriggerType != payload.EventType {
			continue
		}
		if !m.evaluateConditions(rule.Conditions, payload) {
			continue
		}
		go m.executeActions(ctx, rule, payload)
	}
}

// Shutdown shuts down the event manager
func (m *Manager) Shutdown(ctx context.Context) {
	m.logger.Info("Shutting down event manager")
	m.cron.Stop()
}

// Internal methods

func (m *Manager) evaluateConditions(conditions []Condition, payload *EventPayload) bool {
	for _, cond := range conditions {
		if !m.evaluateCondition(cond, payload) {
			return false
		}
	}
	return true
}

func (m *Manager) evaluateCondition(cond Condition, payload *EventPayload) bool {
	var actualValue interface{}

	switch cond.Field {
	case "username":
		actualValue = payload.Username
	case "protocol":
		actualValue = payload.Protocol
	case "client_ip":
		actualValue = payload.ClientIP
	case "file_path":
		actualValue = payload.FilePath
	case "file_name":
		actualValue = payload.FileName
	case "file_size":
		actualValue = payload.FileSize
	case "file_ext":
		actualValue = payload.FileExt
	case "result":
		actualValue = payload.Result
	default:
		return true
	}

	switch cond.Operator {
	case "eq":
		return actualValue == cond.Value
	case "ne":
		return actualValue != cond.Value
	case "contains":
		if str, ok := actualValue.(string); ok {
			if val, ok := cond.Value.(string); ok {
				return contains(str, val)
			}
		}
	case "gt":
		if num, ok := actualValue.(int64); ok {
			if val, ok := cond.Value.(float64); ok {
				return num > int64(val)
			}
		}
	case "lt":
		if num, ok := actualValue.(int64); ok {
			if val, ok := cond.Value.(float64); ok {
				return num < int64(val)
			}
		}
	}

	return true
}

func (m *Manager) executeActions(ctx context.Context, rule *EventRule, payload *EventPayload) {
	for _, action := range rule.Actions {
		result, err := m.executeAction(ctx, action, payload)
		if err != nil {
			m.logger.Error("Action execution failed",
				zap.Int64("rule_id", rule.ID),
				zap.String("action_type", string(action.Type)),
				zap.Error(err),
			)
		} else {
			m.logger.Debug("Action executed",
				zap.Int64("rule_id", rule.ID),
				zap.String("action_type", string(result.ActionType)),
				zap.Bool("success", result.Success),
				zap.Duration("duration", result.Duration),
			)
		}
	}
}

func (m *Manager) executeAction(ctx context.Context, action ActionConfig, payload *EventPayload) (*ExecutionResult, error) {
	switch action.Type {
	case ActionHTTP:
		return m.httpHandler.Execute(ctx, action.Config, payload)
	case ActionCommand:
		return m.cmdHandler.Execute(ctx, action.Config, payload)
	case ActionEmail:
		return m.emailHandler.Execute(ctx, action.Config, payload)
	default:
		return &ExecutionResult{Success: false, Error: fmt.Errorf("unknown action type: %s", action.Type)}, nil
	}
}

func (m *Manager) executeScheduledRule(ruleID int64) {
	m.mu.RLock()
	rule, ok := m.rules[ruleID]
	m.mu.RUnlock()

	if !ok || !rule.IsActive {
		return
	}

	payload := &EventPayload{
		EventID:   fmt.Sprintf("sched_%d_%d", ruleID, time.Now().Unix()),
		EventType: EventUpload, // placeholder
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	m.executeActions(ctx, rule, payload)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
