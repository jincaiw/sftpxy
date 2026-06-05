package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
)

type EventType string

const (
	LoginSuccess          EventType = "login_success"
	LoginFailed           EventType = "login_failed"
	MFASuccess            EventType = "mfa_success"
	MFAFailed             EventType = "mfa_failed"
	FileUpload            EventType = "file_upload"
	FileDownload          EventType = "file_download"
	FileDelete            EventType = "file_delete"
	FileRename            EventType = "file_rename"
	DirCreate             EventType = "dir_create"
	DirDelete             EventType = "dir_delete"
	ShareCreate           EventType = "share_create"
	ShareModify           EventType = "share_modify"
	ShareRevoke           EventType = "share_revoke"
	ShareAccess           EventType = "share_access"
	AdminCreateUser       EventType = "admin_create_user"
	AdminUpdateUser       EventType = "admin_update_user"
	AdminDeleteUser       EventType = "admin_delete_user"
	AdminUpdatePermission EventType = "admin_update_permission"
	APICall               EventType = "api_call"
	EventActionExecute    EventType = "event_action_execute"
	HookInvoke            EventType = "hook_invoke"
	DefenderBlock         EventType = "defender_block"
	DefenderUnblock       EventType = "defender_unblock"
	ConfigChange          EventType = "config_change"
	DataBackup            EventType = "data_backup"
	DataRestore           EventType = "data_restore"
)

type ActorType string

const (
	ActorUser   ActorType = "user"
	ActorAdmin  ActorType = "admin"
	ActorSystem ActorType = "system"
)

type TargetType string

const (
	TargetUser       TargetType = "user"
	TargetAdmin      TargetType = "admin"
	TargetFile       TargetType = "file"
	TargetDirectory  TargetType = "directory"
	TargetShare      TargetType = "share"
	TargetPermission TargetType = "permission"
	TargetConfig     TargetType = "config"
	TargetIP         TargetType = "ip"
	TargetRule       TargetType = "rule"
	TargetResource   TargetType = "resource"
)

type AuditEvent struct {
	EventID      string     `json:"event_id"`
	EventType    EventType  `json:"event_type"`
	ActorType    ActorType  `json:"actor_type"`
	ActorName    string     `json:"actor_name"`
	TargetType   TargetType `json:"target_type"`
	TargetID     string     `json:"target_id"`
	Protocol     string     `json:"protocol"`
	ClientIP     string     `json:"client_ip"`
	Result       string     `json:"result"`
	ErrorMessage string     `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type AuditFilter struct {
	FromTime       time.Time
	ToTime         time.Time
	Username       string
	Admin          string
	ClientIP       string
	Protocol       string
	EventType      string
	FilePath       string
	Status         string
	ErrorCode      string
	ConnectionID   string
	EventRuleID    string
	StorageBackend string
}

type AuditRecorder interface {
	Record(ctx context.Context, event *AuditEvent) error
	Query(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditEvent, error)
}

type auditRecorder struct {
	repo   repository.AuditRepository
	logger *zap.Logger
}

func NewAuditRecorder(repo repository.AuditRepository, logger *zap.Logger) AuditRecorder {
	return &auditRecorder{
		repo:   repo,
		logger: logger.Named("audit_recorder"),
	}
}

func (r *auditRecorder) Record(ctx context.Context, event *AuditEvent) error {
	if event.EventID == "" {
		event.EventID = generateEventID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	_, err := r.repo.CreateAuditLog(ctx, &repository.AuditLog{
		EventID:      event.EventID,
		EventType:    string(event.EventType),
		ActorType:    string(event.ActorType),
		ActorName:    event.ActorName,
		TargetType:   string(event.TargetType),
		TargetID:     event.TargetID,
		Protocol:     event.Protocol,
		ClientIP:     event.ClientIP,
		Result:       event.Result,
		ErrorMessage: event.ErrorMessage,
	})
	if err != nil {
		r.logger.Warn("failed to record audit event",
			zap.String("event_type", string(event.EventType)),
			zap.String("actor", event.ActorName),
			zap.Error(err),
		)
		return err
	}
	return nil
}

func (r *auditRecorder) Query(ctx context.Context, filter *AuditFilter, limit, offset int) ([]*AuditEvent, error) {
	logs, err := r.repo.ListAuditLogsFiltered(ctx, &repository.AuditFilter{
		FromTime:       filter.FromTime,
		ToTime:         filter.ToTime,
		Username:       filter.Username,
		Admin:          filter.Admin,
		ClientIP:       filter.ClientIP,
		Protocol:       filter.Protocol,
		EventType:      filter.EventType,
		FilePath:       filter.FilePath,
		Status:         filter.Status,
		ErrorCode:      filter.ErrorCode,
		ConnectionID:   filter.ConnectionID,
		EventRuleID:    filter.EventRuleID,
		StorageBackend: filter.StorageBackend,
	}, limit, offset)
	if err != nil {
		return nil, err
	}

	events := make([]*AuditEvent, 0, len(logs))
	for _, log := range logs {
		events = append(events, &AuditEvent{
			EventID:      log.EventID,
			EventType:    EventType(log.EventType),
			ActorType:    ActorType(log.ActorType),
			ActorName:    log.ActorName,
			TargetType:   TargetType(log.TargetType),
			TargetID:     log.TargetID,
			Protocol:     log.Protocol,
			ClientIP:     log.ClientIP,
			Result:       log.Result,
			ErrorMessage: log.ErrorMessage,
			CreatedAt:    log.CreatedAt,
		})
	}
	return events, nil
}

func generateEventID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.999999")))
	}
	return hex.EncodeToString(bytes)
}
