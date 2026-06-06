package httpd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	pathpkg "path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/metrics"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/jincaiw/sftpxy/internal/shares"
	"go.uber.org/zap"
)

// ServerDependencies captures optional collaborators used by the HTTP API.
type ServerDependencies struct {
	DB               *sql.DB
	UserRepo         repository.UserRepository
	PolicyEngine     *policy.PolicyEngine
	ShareManager     *shares.Manager
	AuditRepo        repository.AuditRepository
	EventManager     *events.Manager
	MetricsCollector *metrics.Collector
	ProtocolEnabled  map[string]bool
	TelemetryEnabled bool
	FullConfig       *config.Config
	ConfigPath       string
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func queryInt(r *http.Request, key string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func (s *Server) httpAuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)

		duration := time.Since(start)
		session, _ := s.sessionFromRequest(r)
		username := ""
		if session != nil {
			username = session.Username
		}

		if s.metricsCollector != nil {
			s.metricsCollector.RecordHTTPRequest(r.Method, r.URL.Path, strconv.Itoa(recorder.status), duration.Seconds())
		}

		if s.auditRepo == nil {
			return
		}

		errMsg := ""
		if recorder.status >= http.StatusBadRequest {
			errMsg = http.StatusText(recorder.status)
		}

		capturedMethod := r.Method
		capturedPath := r.URL.Path
		capturedStatus := recorder.status
		capturedUsername := username
		capturedIP := clientIPFromRequest(r)
		capturedUA := r.UserAgent()
		capturedDurationMs := int(duration.Milliseconds())
		capturedReqSize := int(maxInt64(0, r.ContentLength))
		capturedRespSize := recorder.bytes
		s.enqueueAudit(func() {
			if err := s.auditRepo.CreateHTTPLog(
				context.Background(),
				capturedMethod,
				capturedPath,
				capturedStatus,
				capturedUsername,
				capturedIP,
				capturedUA,
				capturedDurationMs,
				capturedReqSize,
				capturedRespSize,
				"bearer",
				errMsg,
			); err != nil {
				s.logger.Debug("failed to persist http log", zap.Error(err))
			}
		})
	})
}

func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil || s.shareManager == nil {
		s.writeError(w, http.StatusUnauthorized, "share service is not available")
		return
	}

	var req struct {
		Path           string   `json:"path"`
		ShareType      string   `json:"share_type"`
		Password       string   `json:"password"`
		ExpiresAt      string   `json:"expires_at"`
		MaxDownloads   int      `json:"max_downloads"`
		MaxUploads     int      `json:"max_uploads"`
		IPRestrictions []string `json:"ip_restrictions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Path == "" {
		s.writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	if req.ShareType == "" {
		req.ShareType = string(shares.ShareTypeDownload)
	}

	user, err := s.loadUser(r.Context(), session)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}
	virtualPath, _, err := s.resolveVirtualPath(req.Path)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch shares.ShareType(req.ShareType) {
	case shares.ShareTypeDownload:
		if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpDownload, virtualPath, 0); err != nil {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
	case shares.ShareTypeUpload:
		if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpUpload, virtualPath, 0); err != nil {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
	case "both":
		if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpDownload, virtualPath, 0); err != nil {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if err := s.authorizeFileOperation(r.Context(), session, user, r, policy.OpUpload, virtualPath, 0); err != nil {
			s.writeError(w, http.StatusForbidden, err.Error())
			return
		}
	default:
		s.writeError(w, http.StatusBadRequest, "invalid share_type")
		return
	}
	req.Path = virtualPath

	var expiresAt time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid expires_at")
			return
		}
		expiresAt = parsed
	}

	share, err := s.shareManager.CreateShare(r.Context(), shares.ShareRequest{
		UserID:         session.UserID,
		Path:           req.Path,
		ShareType:      shares.ShareType(req.ShareType),
		Password:       req.Password,
		ExpiresAt:      expiresAt,
		MaxDownloads:   req.MaxDownloads,
		MaxUploads:     req.MaxUploads,
		IPRestrictions: req.IPRestrictions,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusCreated, share)
}

func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil || s.shareManager == nil {
		s.writeError(w, http.StatusUnauthorized, "share service is not available")
		return
	}

	items, err := s.shareManager.ListUserShares(r.Context(), session.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) revokeShare(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil || s.shareManager == nil {
		s.writeError(w, http.StatusUnauthorized, "share service is not available")
		return
	}

	shareID, err := strconv.ParseInt(chi.URLParam(r, "shareID"), 10, 64)
	if err != nil || shareID <= 0 {
		s.writeError(w, http.StatusBadRequest, "invalid share id")
		return
	}

	if err := s.shareManager.RevokeShare(r.Context(), shareID, session.UserID); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"message": "share revoked"})
}

func (s *Server) accessShare(w http.ResponseWriter, r *http.Request) {
	if s.shareManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "share service is not available")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	share, err := s.shareManager.AccessShare(r.Context(), chi.URLParam(r, "token"), req.Password, clientIPFromRequest(r))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, share)
}

func (s *Server) downloadSharedFile(w http.ResponseWriter, r *http.Request) {
	if s.shareManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "share service is not available")
		return
	}

	token := chi.URLParam(r, "token")
	password := r.URL.Query().Get("password")

	share, err := s.shareManager.AccessShare(r.Context(), token, password, clientIPFromRequest(r))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if share.ShareType != shares.ShareTypeDownload && share.ShareType != "both" {
		s.writeError(w, http.StatusBadRequest, "share does not allow downloads")
		return
	}

	if share.MaxDownloads > 0 && share.DownloadCount >= share.MaxDownloads {
		s.writeError(w, http.StatusBadRequest, "download limit reached")
		return
	}

	var user *repository.User
	if s.userRepo != nil {
		user, err = s.userRepo.GetByID(r.Context(), share.UserID)
	} else if s.db != nil {
		session := &authSession{UserID: share.UserID, Username: share.Username}
		user, err = s.loadUser(r.Context(), session)
	}
	if err != nil || user == nil {
		s.writeError(w, http.StatusInternalServerError, "failed to load share owner")
		return
	}

	fs, cleanup, err := buildUserFileSystem(user)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to access files")
		return
	}
	defer cleanup()

	virtualPath := share.Path
	storagePath := virtualPath
	if resolved, storage, resolveErr := s.resolveVirtualPath(virtualPath); resolveErr == nil {
		storagePath = storage
		virtualPath = resolved
	}
	shareSession := &authSession{
		UserID:   share.UserID,
		Username: share.Username,
		Role:     "user",
	}
	if err := s.authorizeFileOperation(r.Context(), shareSession, user, r, policy.OpDownload, virtualPath, 0); err != nil {
		s.writeError(w, http.StatusForbidden, err.Error())
		return
	}

	info, err := fs.Stat(r.Context(), storagePath)
	if err != nil || info.IsDir {
		s.writeError(w, http.StatusNotFound, "File not found")
		return
	}

	reader, err := fs.Open(r.Context(), storagePath)
	if err != nil {
		s.logger.Error("open shared file failed", zap.Error(err), zap.String("path", virtualPath))
		s.writeError(w, http.StatusInternalServerError, "Failed to download file")
		return
	}
	defer reader.Close()

	if incrementErr := s.shareManager.IncrementDownloadCount(r.Context(), share.ID); incrementErr != nil {
		s.logger.Warn("increment share download count failed", zap.Error(incrementErr))
	}

	s.recordAudit(share.Username, "user", "download", "http", virtualPath, "success", "share:"+token)

	if s.hookManager != nil {
		go s.hookManager.OnFileEvent(context.Background(), hooks.FileEventDownload, &hooks.FileEventPayload{
			Event:     hooks.FileEventDownload,
			FilePath:  virtualPath,
			FileName:  pathpkg.Base(virtualPath),
			FileSize:  info.Size,
			Username:  share.Username,
			UserID:    share.UserID,
			Protocol:  "http",
			ClientIP:  r.RemoteAddr,
			Timestamp: time.Now(),
		})
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", pathpkg.Base(virtualPath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if info.Size > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	}
	if _, err := io.Copy(w, reader); err != nil {
		s.logger.Warn("stream shared file download failed", zap.Error(err), zap.String("path", virtualPath))
	}
}

func (s *Server) listLogs(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusServiceUnavailable, "database is not available")
		return
	}
	session := s.currentSession(r)

	page := queryInt(r, "page", 1)
	limit := queryInt(r, "limit", 20)
	offset := (page - 1) * limit

	protocol := strings.TrimSpace(r.URL.Query().Get("protocol"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	username := strings.TrimSpace(r.URL.Query().Get("username"))

	baseQuery := `
SELECT id, timestamp, username, action, protocol, remote_addr, details, status
FROM (
	SELECT
		id,
		created_at AS timestamp,
		COALESCE(actor_name, '') AS username,
		event_type AS action,
		COALESCE(protocol, '') AS protocol,
		COALESCE(client_ip, '') AS remote_addr,
		CASE
			WHEN COALESCE(error_message, '') <> '' THEN error_message
			WHEN COALESCE(target_type, '') <> '' OR COALESCE(target_id, '') <> '' THEN COALESCE(target_type, '') || ':' || COALESCE(target_id, '')
			ELSE ''
		END AS details,
		result AS status
	FROM audit_logs
	UNION ALL
	SELECT
		id,
		created_at AS timestamp,
		username,
		operation AS action,
		protocol,
		COALESCE(remote_address, '') AS remote_addr,
		file_path AS details,
		status
	FROM transfer_logs
	UNION ALL
	SELECT
		id,
		created_at AS timestamp,
		COALESCE(username, '') AS username,
		method AS action,
		'http' AS protocol,
		COALESCE(client_ip, '') AS remote_addr,
		path AS details,
		CASE WHEN status_code BETWEEN 200 AND 399 THEN 'success' ELSE 'failed' END AS status
	FROM http_logs
) logs
WHERE 1=1`

	args := []interface{}{}
	if protocol != "" {
		baseQuery += " AND protocol = ?"
		args = append(args, protocol)
	}
	if action != "" {
		baseQuery += " AND action = ?"
		args = append(args, action)
	}
	if username != "" {
		baseQuery += " AND username LIKE ?"
		args = append(args, "%"+username+"%")
	}
	if session != nil && session.Role == "admin" {
		exact, prefixes, restricted := usernameScopeConfig(session.Filters, "logs")
		if restricted {
			parts := make([]string, 0, len(exact)+len(prefixes))
			for _, item := range exact {
				parts = append(parts, "username = ?")
				args = append(args, item)
			}
			for _, prefix := range prefixes {
				parts = append(parts, "username LIKE ?")
				args = append(args, prefix+"%")
			}
			if len(parts) == 0 {
				baseQuery += " AND 1=0"
			} else {
				baseQuery += " AND (" + strings.Join(parts, " OR ") + ")"
			}
		}
	}

	countQuery := "SELECT COUNT(*) FROM (" + baseQuery + ")"
	var total int64
	if err := s.db.QueryRowContext(r.Context(), countQuery, args...).Scan(&total); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	query := baseQuery + " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type logItem struct {
		ID        int64     `json:"id"`
		Timestamp time.Time `json:"timestamp"`
		Username  string    `json:"username"`
		Action    string    `json:"action"`
		Protocol  string    `json:"protocol"`
		RemoteIP  string    `json:"remote_addr"`
		Details   string    `json:"details"`
		Status    string    `json:"status"`
	}

	items := make([]logItem, 0)
	for rows.Next() {
		var item logItem
		if err := rows.Scan(&item.ID, &item.Timestamp, &item.Username, &item.Action, &item.Protocol, &item.RemoteIP, &item.Details, &item.Status); err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		items = append(items, item)
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (s *Server) listEventRules(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}
	rules := s.eventManager.ListRules()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"items": rules, "total": len(rules)})
}

func (s *Server) emitEvent(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeError(w, http.StatusServiceUnavailable, "event manager is not available")
		return
	}

	var payload events.EventPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if payload.EventType == "" {
		s.writeError(w, http.StatusBadRequest, "event_type is required")
		return
	}
	if payload.EventID == "" {
		payload.EventID = fmt.Sprintf("evt_%d", time.Now().UnixNano())
	}
	if payload.Timestamp.IsZero() {
		payload.Timestamp = time.Now().UTC()
	}

	results, err := s.eventManager.ProcessEvent(r.Context(), &payload)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"event": payload, "results": results})
}

func (s *Server) listEventHistory(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}, "total": 0})
		return
	}

	page := queryInt(r, "page", 1)
	limit := queryInt(r, "limit", 20)
	offset := (page - 1) * limit
	eventType := strings.TrimSpace(r.URL.Query().Get("event_type"))
	result := strings.TrimSpace(r.URL.Query().Get("result"))

	items, total, err := s.eventManager.ListHistory(r.Context(), eventType, result, limit, offset)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	dbStatus := "disabled"
	if s.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.db.PingContext(ctx); err != nil {
			status = "degraded"
			dbStatus = "down"
		} else {
			dbStatus = "up"
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(s.startTime).String(),
		"version":   s.version,
		"database": map[string]interface{}{
			"status": dbStatus,
		},
		"telemetry": map[string]interface{}{
			"enabled": s.telemetryEnabled,
		},
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var goroutines map[string]int64
	connectionCounts := s.protocolConnectionCounts(r.Context())
	activeShares := int64(0)
	if s.db != nil {
		_ = s.db.QueryRowContext(
			r.Context(),
			"SELECT COUNT(*) FROM shares WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
		).Scan(&activeShares)
	}

	goroutines = map[string]int64{}
	for protocol, count := range connectionCounts {
		goroutines[protocol] = count
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"service": "SFTPxy",
		"version": s.version,
		"uptime":  time.Since(s.startTime).String(),
		"runtime": runtimeSnapshot(),
		"memory":  runtimeSnapshot()["memory"],
		"protocols": map[string]interface{}{
			"ssh_enabled":       s.protocolEnabled("ssh"),
			"ftp_enabled":       s.protocolEnabled("ftp"),
			"webdav_enabled":    s.protocolEnabled("webdav"),
			"webadmin_enabled":  s.config.Enabled && s.config.WebAdminEnabled,
			"webclient_enabled": s.config.Enabled && s.config.WebClientEnabled,
		},
		"connections": map[string]interface{}{
			"active_total": byProtocolTotal(connectionCounts),
			"by_protocol":  goroutines,
		},
		"shares": map[string]interface{}{
			"active": activeShares,
		},
		"telemetry": map[string]interface{}{
			"enabled": s.telemetryEnabled,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func runtimeSnapshot() map[string]interface{} {
	var memoryStats runtimeMemStats
	memoryStats.read()
	return map[string]interface{}{
		"go_version":    memoryStats.goVersion,
		"os":            memoryStats.goos,
		"arch":          memoryStats.goarch,
		"num_goroutine": memoryStats.goroutines,
		"num_cpu":       memoryStats.cpus,
		"memory": map[string]interface{}{
			"alloc_mb":       memoryStats.allocMB,
			"total_alloc_mb": memoryStats.totalAllocMB,
			"sys_mb":         memoryStats.sysMB,
			"num_gc":         memoryStats.numGC,
			"heap_objects":   memoryStats.heapObjects,
		},
	}
}

type runtimeMemStats struct {
	goVersion    string
	goos         string
	goarch       string
	goroutines   int
	cpus         int
	allocMB      float64
	totalAllocMB float64
	sysMB        float64
	numGC        uint32
	heapObjects  uint64
}

func (m *runtimeMemStats) read() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	m.goVersion = runtime.Version()
	m.goos = runtime.GOOS
	m.goarch = runtime.GOARCH
	m.goroutines = runtime.NumGoroutine()
	m.cpus = runtime.NumCPU()
	m.allocMB = float64(stats.Alloc) / 1024 / 1024
	m.totalAllocMB = float64(stats.TotalAlloc) / 1024 / 1024
	m.sysMB = float64(stats.Sys) / 1024 / 1024
	m.numGC = stats.NumGC
	m.heapObjects = stats.HeapObjects
}

func byProtocolTotal(values map[string]int64) int64 {
	var total int64
	for _, value := range values {
		total += value
	}
	return total
}

func (s *Server) protocolConnectionCounts(ctx context.Context) map[string]int64 {
	counts := map[string]int64{
		"ssh":    0,
		"ftp":    0,
		"webdav": 0,
		"http":   0,
	}
	if s.db == nil {
		return counts
	}

	rows, err := s.db.QueryContext(ctx, "SELECT protocol, COUNT(*) FROM sessions WHERE is_active = TRUE GROUP BY protocol")
	if err != nil {
		return counts
	}
	defer rows.Close()

	for rows.Next() {
		var protocol string
		var count int64
		if err := rows.Scan(&protocol, &count); err == nil {
			counts[protocol] = count
		}
	}
	return counts
}
