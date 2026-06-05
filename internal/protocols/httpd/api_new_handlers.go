package httpd

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	authn "github.com/jincaiw/sftpxy/internal/auth"
	"github.com/jincaiw/sftpxy/internal/config"
	"github.com/jincaiw/sftpxy/internal/events"
	"github.com/jincaiw/sftpxy/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// ============================================================================
// Virtual Folders API (PRD Section 9)
// ============================================================================

func (s *Server) listVirtualFolders(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	rows, err := s.db.Query(
		"SELECT id, name, mapped_path, filesystem_type, COALESCE(filesystem_config, ''), COALESCE(owner_user_id, 0), is_shared, created_at, updated_at FROM virtual_folders ORDER BY id ASC",
	)
	if err != nil {
		s.logger.Error("list virtual folders failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load virtual folders")
		return
	}
	defer rows.Close()

	folders := make([]map[string]any, 0)
	for rows.Next() {
		var (
			id          int64
			name        string
			mappedPath  string
			fsType      string
			fsConfig    string
			ownerUserID int64
			isShared    bool
			createdAt   string
			updatedAt   string
		)
		if err := rows.Scan(&id, &name, &mappedPath, &fsType, &fsConfig, &ownerUserID, &isShared, &createdAt, &updatedAt); err != nil {
			s.logger.Error("scan virtual folder failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to load virtual folders")
			return
		}
		folder := map[string]any{
			"id":              id,
			"name":            name,
			"mapped_path":     mappedPath,
			"filesystem_type": fsType,
			"is_shared":       isShared,
			"created_at":      createdAt,
			"updated_at":      updatedAt,
		}
		if ownerUserID > 0 {
			folder["owner_user_id"] = ownerUserID
		} else {
			folder["owner_user_id"] = nil
		}
		if strings.TrimSpace(fsConfig) != "" {
			folder["filesystem_config"] = decodeJSONRaw(fsConfig, map[string]any{})
		} else {
			folder["filesystem_config"] = nil
		}
		folders = append(folders, folder)
	}
	s.writeJSON(w, http.StatusOK, folders)
}

func (s *Server) createVirtualFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	var req struct {
		Name             string `json:"name"`
		MappedPath       string `json:"mapped_path"`
		FilesystemType   string `json:"filesystem_type"`
		FilesystemConfig any    `json:"filesystem_config"`
		OwnerUserID      *int64 `json:"owner_user_id"`
		IsShared         bool   `json:"is_shared"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.MappedPath = strings.TrimSpace(req.MappedPath)
	req.FilesystemType = strings.TrimSpace(req.FilesystemType)
	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Folder name is required")
		return
	}
	if req.MappedPath == "" {
		s.writeError(w, http.StatusBadRequest, "Mapped path is required")
		return
	}
	if req.FilesystemType == "" {
		req.FilesystemType = "local"
	}

	fsConfigJSON, _ := json.Marshal(req.FilesystemConfig)
	var ownerUserID any
	if req.OwnerUserID != nil && *req.OwnerUserID > 0 {
		ownerUserID = *req.OwnerUserID
	} else {
		ownerUserID = nil
	}

	result, err := s.db.Exec(
		"INSERT INTO virtual_folders (name, mapped_path, filesystem_type, filesystem_config, owner_user_id, is_shared) VALUES (?, ?, ?, ?, ?, ?)",
		strings.TrimSpace(req.Name), strings.TrimSpace(req.MappedPath), strings.TrimSpace(req.FilesystemType), string(fsConfigJSON), ownerUserID, req.IsShared,
	)
	if err != nil {
		s.logger.Error("create virtual folder failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create virtual folder")
		return
	}
	id, _ := result.LastInsertId()

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "create_virtual_folder", "http", req.Name, "success", "")
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id":                id,
		"name":              strings.TrimSpace(req.Name),
		"mapped_path":       strings.TrimSpace(req.MappedPath),
		"filesystem_type":   strings.TrimSpace(req.FilesystemType),
		"filesystem_config": req.FilesystemConfig,
		"owner_user_id":     req.OwnerUserID,
		"is_shared":         req.IsShared,
	})
}

func (s *Server) getVirtualFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}

	var (
		id          int64
		name        string
		mappedPath  string
		fsType      string
		fsConfig    sql.NullString
		ownerUserID sql.NullInt64
		isShared    bool
		createdAt   string
		updatedAt   string
	)
	if err := s.db.QueryRow(
		"SELECT id, name, mapped_path, filesystem_type, filesystem_config, owner_user_id, is_shared, created_at, updated_at FROM virtual_folders WHERE id = ?",
		folderID,
	).Scan(&id, &name, &mappedPath, &fsType, &fsConfig, &ownerUserID, &isShared, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Virtual folder not found")
			return
		}
		s.logger.Error("get virtual folder failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load virtual folder")
		return
	}

	// Load associated users
	userRows, err := s.db.Query(
		"SELECT user_id, virtual_path, COALESCE(permissions, ''), COALESCE(quota, '') FROM user_virtual_folders WHERE folder_id = ?", folderID,
	)
	if err != nil {
		s.logger.Error("load folder users failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load virtual folder")
		return
	}
	defer userRows.Close()
	users := make([]map[string]any, 0)
	for userRows.Next() {
		var userID int64
		var virtualPath, perms, quota string
		if err := userRows.Scan(&userID, &virtualPath, &perms, &quota); err != nil {
			continue
		}
		entry := map[string]any{
			"user_id":      userID,
			"virtual_path": virtualPath,
		}
		if strings.TrimSpace(perms) != "" {
			entry["permissions"] = decodeJSONRaw(perms, []any{})
		}
		if strings.TrimSpace(quota) != "" {
			entry["quota"] = decodeJSONRaw(quota, map[string]any{})
		}
		users = append(users, entry)
	}

	// Load associated groups
	groupRows, err := s.db.Query(
		"SELECT group_id, virtual_path, COALESCE(permissions, '') FROM group_virtual_folders WHERE folder_id = ?", folderID,
	)
	if err != nil {
		s.logger.Error("load folder groups failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load virtual folder")
		return
	}
	defer groupRows.Close()
	groups := make([]map[string]any, 0)
	for groupRows.Next() {
		var groupID int64
		var virtualPath, perms string
		if err := groupRows.Scan(&groupID, &virtualPath, &perms); err != nil {
			continue
		}
		entry := map[string]any{
			"group_id":     groupID,
			"virtual_path": virtualPath,
		}
		if strings.TrimSpace(perms) != "" {
			entry["permissions"] = decodeJSONRaw(perms, []any{})
		}
		groups = append(groups, entry)
	}

	folder := map[string]any{
		"id":              id,
		"name":            name,
		"mapped_path":     mappedPath,
		"filesystem_type": fsType,
		"is_shared":       isShared,
		"created_at":      createdAt,
		"updated_at":      updatedAt,
		"users":           users,
		"groups":          groups,
	}
	if ownerUserID.Valid && ownerUserID.Int64 > 0 {
		folder["owner_user_id"] = ownerUserID.Int64
	} else {
		folder["owner_user_id"] = nil
	}
	if fsConfig.Valid && strings.TrimSpace(fsConfig.String) != "" {
		folder["filesystem_config"] = decodeJSONRaw(fsConfig.String, map[string]any{})
	} else {
		folder["filesystem_config"] = nil
	}
	s.writeJSON(w, http.StatusOK, folder)
}

func (s *Server) updateVirtualFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	var req struct {
		Name             string `json:"name"`
		MappedPath       string `json:"mapped_path"`
		FilesystemType   string `json:"filesystem_type"`
		FilesystemConfig any    `json:"filesystem_config"`
		OwnerUserID      *int64 `json:"owner_user_id"`
		IsShared         *bool  `json:"is_shared"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.MappedPath = strings.TrimSpace(req.MappedPath)
	req.FilesystemType = strings.TrimSpace(req.FilesystemType)
	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Folder name is required")
		return
	}
	if req.MappedPath == "" {
		s.writeError(w, http.StatusBadRequest, "Mapped path is required")
		return
	}

	var exists int
	if err := s.db.QueryRow("SELECT 1 FROM virtual_folders WHERE id = ?", folderID).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Virtual folder not found")
			return
		}
		s.logger.Error("check virtual folder failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to update virtual folder")
		return
	}

	fsConfigJSON, _ := json.Marshal(req.FilesystemConfig)
	var ownerUserID any
	if req.OwnerUserID != nil && *req.OwnerUserID > 0 {
		ownerUserID = *req.OwnerUserID
	} else {
		ownerUserID = nil
	}

	isShared := false
	if req.IsShared != nil {
		isShared = *req.IsShared
	}

	if _, err := s.db.Exec(
		"UPDATE virtual_folders SET name = ?, mapped_path = ?, filesystem_type = ?, filesystem_config = ?, owner_user_id = ?, is_shared = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		strings.TrimSpace(req.Name), strings.TrimSpace(req.MappedPath), strings.TrimSpace(req.FilesystemType), string(fsConfigJSON), ownerUserID, isShared, folderID,
	); err != nil {
		s.logger.Error("update virtual folder failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to update virtual folder")
		return
	}

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "update_virtual_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "virtual folder updated"})
}

func (s *Server) deleteVirtualFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM user_virtual_folders WHERE folder_id = ?", folderID); err != nil {
		s.logger.Error("delete user folder associations failed", zap.Error(err))
	}
	if _, err := s.db.Exec("DELETE FROM group_virtual_folders WHERE folder_id = ?", folderID); err != nil {
		s.logger.Error("delete group folder associations failed", zap.Error(err))
	}
	if _, err := s.db.Exec("DELETE FROM virtual_folders WHERE id = ?", folderID); err != nil {
		s.logger.Error("delete virtual folder failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete virtual folder")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "delete_virtual_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "virtual folder deleted"})
}

func (s *Server) addUserToFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	var req struct {
		UserID      int64  `json:"user_id"`
		VirtualPath string `json:"virtual_path"`
		Permissions any    `json:"permissions"`
		Quota       any    `json:"quota"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.UserID <= 0 {
		s.writeError(w, http.StatusBadRequest, "User id is required")
		return
	}
	if strings.TrimSpace(req.VirtualPath) == "" {
		s.writeError(w, http.StatusBadRequest, "Virtual path is required")
		return
	}
	permsJSON, _ := json.Marshal(req.Permissions)
	quotaJSON, _ := json.Marshal(req.Quota)

	if _, err := s.db.Exec(
		"INSERT INTO user_virtual_folders (user_id, folder_id, virtual_path, permissions, quota) VALUES (?, ?, ?, ?, ?)",
		req.UserID, folderID, strings.TrimSpace(req.VirtualPath), string(permsJSON), string(quotaJSON),
	); err != nil {
		s.logger.Error("add user to folder failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to add user to folder")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "add_user_to_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "user added to folder"})
}

func (s *Server) removeUserFromFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil || userID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM user_virtual_folders WHERE user_id = ? AND folder_id = ?", userID, folderID); err != nil {
		s.logger.Error("remove user from folder failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to remove user from folder")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "remove_user_from_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "user removed from folder"})
}

func (s *Server) addGroupToFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	var req struct {
		GroupID     int64  `json:"group_id"`
		VirtualPath string `json:"virtual_path"`
		Permissions any    `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.GroupID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Group id is required")
		return
	}
	if strings.TrimSpace(req.VirtualPath) == "" {
		s.writeError(w, http.StatusBadRequest, "Virtual path is required")
		return
	}
	permsJSON, _ := json.Marshal(req.Permissions)

	if _, err := s.db.Exec(
		"INSERT INTO group_virtual_folders (group_id, folder_id, virtual_path, permissions) VALUES (?, ?, ?, ?)",
		req.GroupID, folderID, strings.TrimSpace(req.VirtualPath), string(permsJSON),
	); err != nil {
		s.logger.Error("add group to folder failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to add group to folder")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "add_group_to_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "group added to folder"})
}

func (s *Server) removeGroupFromFolder(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	groupID, err := strconv.ParseInt(chi.URLParam(r, "groupID"), 10, 64)
	if err != nil || groupID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid group id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM group_virtual_folders WHERE group_id = ? AND folder_id = ?", groupID, folderID); err != nil {
		s.logger.Error("remove group from folder failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to remove group from folder")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "remove_group_from_folder", "http", strconv.FormatInt(folderID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "group removed from folder"})
}

// ============================================================================
// Quota Management API (PRD Section 10.4)
// ============================================================================

func (s *Server) getUserQuota(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil || userID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}
	var (
		username string
		quotas   sql.NullString
		homeDir  string
	)
	if err := s.db.QueryRow(
		"SELECT username, quotas, home_dir FROM users WHERE id = ?", userID,
	).Scan(&username, &quotas, &homeDir); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.logger.Error("get user quota failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to get user quota")
		return
	}

	quotaConfig := map[string]any{"configured": false}
	if quotas.Valid && strings.TrimSpace(quotas.String) != "" {
		quotaConfig["configured"] = true
		var parsed any
		if err := json.Unmarshal([]byte(quotas.String), &parsed); err == nil {
			quotaConfig["raw"] = parsed
		} else {
			quotaConfig["raw"] = quotas.String
		}
	}

	// Calculate current usage from home directory
	var totalSize int64
	_ = s.db.QueryRow(
		"SELECT COALESCE(SUM(file_size), 0) FROM transfer_logs WHERE username = ? AND operation = 'upload' AND status = 'success'",
		username,
	).Scan(&totalSize)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"user_id":       userID,
		"username":      username,
		"home_dir":      homeDir,
		"quota":         quotaConfig,
		"current_usage": totalSize,
	})
}

func (s *Server) scanUserQuota(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil || userID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}
	var username string
	if err := s.db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to scan quota")
		return
	}

	var totalSize int64
	_ = s.db.QueryRow(
		"SELECT COALESCE(SUM(file_size), 0) FROM transfer_logs WHERE username = ? AND operation = 'upload' AND status = 'success'",
		username,
	).Scan(&totalSize)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"user_id":       userID,
		"username":      username,
		"scanned_bytes": totalSize,
		"scanned_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) recalculateUserQuota(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	userID, err := strconv.ParseInt(chi.URLParam(r, "userID"), 10, 64)
	if err != nil || userID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid user id")
		return
	}
	var username string
	if err := s.db.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "User not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to recalculate quota")
		return
	}

	var totalSize int64
	_ = s.db.QueryRow(
		"SELECT COALESCE(SUM(file_size), 0) FROM transfer_logs WHERE username = ? AND operation = 'upload' AND status = 'success'",
		username,
	).Scan(&totalSize)

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "recalculate_quota", "http", username, "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"user_id":         userID,
		"username":        username,
		"total_bytes":     totalSize,
		"recalculated_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) getFolderQuota(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	folderID, err := strconv.ParseInt(chi.URLParam(r, "folderID"), 10, 64)
	if err != nil || folderID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid folder id")
		return
	}
	var (
		name       string
		mappedPath string
	)
	if err := s.db.QueryRow(
		"SELECT name, mapped_path FROM virtual_folders WHERE id = ?", folderID,
	).Scan(&name, &mappedPath); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Virtual folder not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to get folder quota")
		return
	}

	// Get per-user quotas for this folder
	rows, err := s.db.Query(
		"SELECT user_id, COALESCE(quota, '') FROM user_virtual_folders WHERE folder_id = ?", folderID,
	)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to get folder quota")
		return
	}
	defer rows.Close()

	userQuotas := make([]map[string]any, 0)
	for rows.Next() {
		var userID int64
		var quota string
		if err := rows.Scan(&userID, &quota); err != nil {
			continue
		}
		entry := map[string]any{"user_id": userID}
		if strings.TrimSpace(quota) != "" {
			var parsed any
			if err := json.Unmarshal([]byte(quota), &parsed); err == nil {
				entry["quota"] = parsed
			} else {
				entry["quota"] = quota
			}
		}
		userQuotas = append(userQuotas, entry)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"folder_id":   folderID,
		"name":        name,
		"mapped_path": mappedPath,
		"user_quotas": userQuotas,
	})
}

// ============================================================================
// Backup/Restore API (PRD Section 19.6)
// ============================================================================

func (s *Server) exportBackup(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	backup := map[string]any{}

	// Export users
	userRows, err := s.db.Query("SELECT id, username, COALESCE(email, ''), status, home_dir, COALESCE(filesystem, ''), COALESCE(permissions, ''), COALESCE(filters, ''), COALESCE(quotas, ''), COALESCE(bandwidth_limits, ''), COALESCE(transfer_limits, ''), max_sessions, COALESCE(allowed_protocols, ''), COALESCE(denied_protocols, ''), COALESCE(ip_filters, ''), mfa_enabled, COALESCE(expiration_date, ''), COALESCE(description, ''), created_at, updated_at FROM users ORDER BY id ASC")
	if err == nil {
		defer userRows.Close()
		users := make([]map[string]any, 0)
		for userRows.Next() {
			var id int64
			var username, email, status, homeDir string
			var filesystem, permissions, filters, quotas, bwLimits, txLimits string
			var maxSessions int
			var allowedProto, deniedProto, ipFilters, expDate, desc, createdAt, updatedAt string
			var mfaEnabled bool
			if err := userRows.Scan(&id, &username, &email, &status, &homeDir, &filesystem, &permissions, &filters, &quotas, &bwLimits, &txLimits, &maxSessions, &allowedProto, &deniedProto, &ipFilters, &mfaEnabled, &expDate, &desc, &createdAt, &updatedAt); err != nil {
				continue
			}
			users = append(users, map[string]any{
				"id": id, "username": username, "email": email, "status": status, "home_dir": homeDir,
				"filesystem": decodeJSONRaw(filesystem, nil), "permissions": decodeJSONRaw(permissions, nil),
				"filters": decodeJSONRaw(filters, nil), "quotas": decodeJSONRaw(quotas, nil),
				"bandwidth_limits": decodeJSONRaw(bwLimits, nil), "transfer_limits": decodeJSONRaw(txLimits, nil),
				"max_sessions": maxSessions, "allowed_protocols": decodeJSONRaw(allowedProto, nil),
				"denied_protocols": decodeJSONRaw(deniedProto, nil), "ip_filters": decodeJSONRaw(ipFilters, nil),
				"mfa_enabled": mfaEnabled, "expiration_date": expDate, "description": desc,
				"created_at": createdAt, "updated_at": updatedAt,
			})
		}
		backup["users"] = users
	}

	// Export admins
	adminRows, err := s.db.Query("SELECT id, username, status, COALESCE(permissions, '[]'), COALESCE(filters, '{}'), COALESCE(role_id, 0), mfa_enabled, created_at, updated_at FROM admins ORDER BY id ASC")
	if err == nil {
		defer adminRows.Close()
		admins := make([]map[string]any, 0)
		for adminRows.Next() {
			var id int64
			var username, status, perms, filtersStr string
			var roleID int64
			var mfaEnabled bool
			var createdAt, updatedAt string
			if err := adminRows.Scan(&id, &username, &status, &perms, &filtersStr, &roleID, &mfaEnabled, &createdAt, &updatedAt); err != nil {
				continue
			}
			admins = append(admins, map[string]any{
				"id": id, "username": username, "status": status,
				"permissions": decodeJSONRaw(perms, []any{}),
				"filters":     decodeJSONRaw(filtersStr, map[string]any{}),
				"role_id":     roleID, "mfa_enabled": mfaEnabled,
				"created_at": createdAt, "updated_at": updatedAt,
			})
		}
		backup["admins"] = admins
	}

	// Export groups
	groupRows, err := s.db.Query("SELECT id, name, COALESCE(description, ''), COALESCE(settings, '{}'), COALESCE(user_settings, '{}'), created_at, updated_at FROM groups ORDER BY id ASC")
	if err == nil {
		defer groupRows.Close()
		groups := make([]map[string]any, 0)
		for groupRows.Next() {
			var id int64
			var name, desc, settings, userSettings, createdAt, updatedAt string
			if err := groupRows.Scan(&id, &name, &desc, &settings, &userSettings, &createdAt, &updatedAt); err != nil {
				continue
			}
			groups = append(groups, map[string]any{
				"id": id, "name": name, "description": desc,
				"settings":      decodeJSONRaw(settings, map[string]any{}),
				"user_settings": decodeJSONRaw(userSettings, map[string]any{}),
				"created_at":    createdAt, "updated_at": updatedAt,
			})
		}
		backup["groups"] = groups
	}

	// Export roles
	roleRows, err := s.db.Query("SELECT id, name, COALESCE(description, ''), COALESCE(permissions, '[]'), COALESCE(scope, '{}'), created_at FROM roles ORDER BY id ASC")
	if err == nil {
		defer roleRows.Close()
		roles := make([]map[string]any, 0)
		for roleRows.Next() {
			var id int64
			var name, desc, perms, scope, createdAt string
			if err := roleRows.Scan(&id, &name, &desc, &perms, &scope, &createdAt); err != nil {
				continue
			}
			roles = append(roles, map[string]any{
				"id": id, "name": name, "description": desc,
				"permissions": decodeJSONRaw(perms, []any{}),
				"scope":       decodeJSONRaw(scope, map[string]any{}),
				"created_at":  createdAt,
			})
		}
		backup["roles"] = roles
	}

	// Export folders
	folderRows, err := s.db.Query("SELECT id, name, mapped_path, filesystem_type, COALESCE(filesystem_config, ''), COALESCE(owner_user_id, 0), is_shared, created_at, updated_at FROM virtual_folders ORDER BY id ASC")
	if err == nil {
		defer folderRows.Close()
		folders := make([]map[string]any, 0)
		for folderRows.Next() {
			var id int64
			var name, mappedPath, fsType, fsConfig string
			var ownerUserID int64
			var isShared bool
			var createdAt, updatedAt string
			if err := folderRows.Scan(&id, &name, &mappedPath, &fsType, &fsConfig, &ownerUserID, &isShared, &createdAt, &updatedAt); err != nil {
				continue
			}
			folders = append(folders, map[string]any{
				"id": id, "name": name, "mapped_path": mappedPath,
				"filesystem_type":   fsType,
				"filesystem_config": decodeJSONRaw(fsConfig, nil),
				"owner_user_id":     ownerUserID, "is_shared": isShared,
				"created_at": createdAt, "updated_at": updatedAt,
			})
		}
		backup["folders"] = folders
	}

	// Export event_rules
	ruleRows, err := s.db.Query("SELECT id, name, COALESCE(description, ''), trigger_type, COALESCE(trigger_config, '{}'), COALESCE(conditions, '{}'), is_active, COALESCE(schedule, ''), created_at, updated_at FROM event_rules ORDER BY id ASC")
	if err == nil {
		defer ruleRows.Close()
		rules := make([]map[string]any, 0)
		for ruleRows.Next() {
			var id int64
			var name, desc, triggerType, triggerConfig, conditions string
			var isActive bool
			var schedule, createdAt, updatedAt string
			if err := ruleRows.Scan(&id, &name, &desc, &triggerType, &triggerConfig, &conditions, &isActive, &schedule, &createdAt, &updatedAt); err != nil {
				continue
			}
			rules = append(rules, map[string]any{
				"id": id, "name": name, "description": desc,
				"trigger_type":   triggerType,
				"trigger_config": decodeJSONRaw(triggerConfig, map[string]any{}),
				"conditions":     decodeJSONRaw(conditions, map[string]any{}),
				"is_active":      isActive, "schedule": schedule,
				"created_at": createdAt, "updated_at": updatedAt,
			})
		}
		backup["event_rules"] = rules
	}

	// Export shares
	shareRows, err := s.db.Query("SELECT id, token, user_id, share_type, path, COALESCE(expires_at, ''), COALESCE(max_downloads, 0), COALESCE(max_uploads, 0), download_count, upload_count, COALESCE(ip_restrictions, '[]'), is_active, created_at, updated_at FROM shares ORDER BY id ASC")
	if err == nil {
		defer shareRows.Close()
		shares := make([]map[string]any, 0)
		for shareRows.Next() {
			var id int64
			var token string
			var userID int64
			var shareType, path, expiresAt string
			var maxDownloads, maxUploads, downloadCount, uploadCount int64
			var ipRestrictions string
			var isActive bool
			var createdAt, updatedAt string
			if err := shareRows.Scan(&id, &token, &userID, &shareType, &path, &expiresAt, &maxDownloads, &maxUploads, &downloadCount, &uploadCount, &ipRestrictions, &isActive, &createdAt, &updatedAt); err != nil {
				continue
			}
			shares = append(shares, map[string]any{
				"id": id, "token": token, "user_id": userID,
				"share_type": shareType, "path": path,
				"expires_at":    expiresAt,
				"max_downloads": maxDownloads, "max_uploads": maxUploads,
				"download_count": downloadCount, "upload_count": uploadCount,
				"ip_restrictions": decodeJSONRaw(ipRestrictions, []any{}),
				"is_active":       isActive, "created_at": createdAt, "updated_at": updatedAt,
			})
		}
		backup["shares"] = shares
	}

	backup["exported_at"] = time.Now().UTC().Format(time.RFC3339)
	backup["version"] = s.version

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "export_backup", "http", "", "success", "")
	}
	s.writeJSON(w, http.StatusOK, backup)
}

func (s *Server) importRestore(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	var req struct {
		Data             json.RawMessage `json:"data"`
		ConflictStrategy string          `json:"conflict_strategy"` // "skip" or "overwrite"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Data) == 0 {
		s.writeError(w, http.StatusBadRequest, "Data is required")
		return
	}
	conflictStrategy := strings.TrimSpace(req.ConflictStrategy)
	if conflictStrategy == "" {
		conflictStrategy = "skip"
	}
	if conflictStrategy != "skip" && conflictStrategy != "overwrite" {
		s.writeError(w, http.StatusBadRequest, "conflict_strategy must be 'skip' or 'overwrite'")
		return
	}

	var backup map[string]json.RawMessage
	if err := json.Unmarshal(req.Data, &backup); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid backup data format")
		return
	}

	stats := map[string]any{
		"conflict_strategy": conflictStrategy,
		"imported":          map[string]int{},
		"skipped":           map[string]int{},
		"errors":            map[string]int{},
	}
	imported := stats["imported"].(map[string]int)
	skipped := stats["skipped"].(map[string]int)
	errors := stats["errors"].(map[string]int)

	// Helper to check if record exists
	recordExists := func(table, column string, value any) bool {
		var count int
		err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", table, column), value).Scan(&count)
		return err == nil && count > 0
	}

	// Import roles
	if rolesRaw, ok := backup["roles"]; ok {
		var roles []map[string]any
		if err := json.Unmarshal(rolesRaw, &roles); err == nil {
			for _, role := range roles {
				name, _ := role["name"].(string)
				if name == "" {
					errors["roles"]++
					continue
				}
				if recordExists("roles", "name", name) {
					if conflictStrategy == "skip" {
						skipped["roles"]++
						continue
					}
					// overwrite: delete and re-insert
					s.db.Exec("DELETE FROM roles WHERE name = ?", name)
				}
				permsJSON, _ := json.Marshal(role["permissions"])
				scopeJSON, _ := json.Marshal(role["scope"])
				desc, _ := role["description"].(string)
				if _, err := s.db.Exec("INSERT INTO roles (name, description, permissions, scope) VALUES (?, ?, ?, ?)", name, desc, string(permsJSON), string(scopeJSON)); err != nil {
					errors["roles"]++
					continue
				}
				imported["roles"]++
			}
		}
	}

	// Import groups
	if groupsRaw, ok := backup["groups"]; ok {
		var groups []map[string]any
		if err := json.Unmarshal(groupsRaw, &groups); err == nil {
			for _, group := range groups {
				name, _ := group["name"].(string)
				if name == "" {
					errors["groups"]++
					continue
				}
				if recordExists("groups", "name", name) {
					if conflictStrategy == "skip" {
						skipped["groups"]++
						continue
					}
					s.db.Exec("DELETE FROM groups WHERE name = ?", name)
				}
				desc, _ := group["description"].(string)
				settingsJSON, _ := json.Marshal(group["settings"])
				userSettingsJSON, _ := json.Marshal(group["user_settings"])
				if _, err := s.db.Exec("INSERT INTO groups (name, description, settings, user_settings) VALUES (?, ?, ?, ?)", name, desc, string(settingsJSON), string(userSettingsJSON)); err != nil {
					errors["groups"]++
					continue
				}
				imported["groups"]++
			}
		}
	}

	// Import admins
	if adminsRaw, ok := backup["admins"]; ok {
		var admins []map[string]any
		if err := json.Unmarshal(adminsRaw, &admins); err == nil {
			for _, admin := range admins {
				username, _ := admin["username"].(string)
				if username == "" {
					errors["admins"]++
					continue
				}
				if recordExists("admins", "username", username) {
					if conflictStrategy == "skip" {
						skipped["admins"]++
						continue
					}
					s.db.Exec("DELETE FROM admins WHERE username = ?", username)
				}
				status, _ := admin["status"].(string)
				if status == "" {
					status = "active"
				}
				permsJSON, _ := json.Marshal(admin["permissions"])
				filtersJSON, _ := json.Marshal(admin["filters"])
				defaultPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
				if _, err := s.db.Exec("INSERT INTO admins (username, password_hash, status, permissions, filters) VALUES (?, ?, ?, ?, ?)", username, string(defaultPasswordHash), status, string(permsJSON), string(filtersJSON)); err != nil {
					errors["admins"]++
					continue
				}
				imported["admins"]++
			}
		}
	}

	// Import users
	if usersRaw, ok := backup["users"]; ok {
		var users []map[string]any
		if err := json.Unmarshal(usersRaw, &users); err == nil {
			for _, user := range users {
				username, _ := user["username"].(string)
				if username == "" {
					errors["users"]++
					continue
				}
				if recordExists("users", "username", username) {
					if conflictStrategy == "skip" {
						skipped["users"]++
						continue
					}
					s.db.Exec("DELETE FROM users WHERE username = ?", username)
				}
				email, _ := user["email"].(string)
				status, _ := user["status"].(string)
				if status == "" {
					status = "active"
				}
				homeDir, _ := user["home_dir"].(string)
				if homeDir == "" {
					homeDir = "data/users/" + username
				}
				fsJSON, _ := json.Marshal(user["filesystem"])
				permsJSON, _ := json.Marshal(user["permissions"])
				filtersJSON, _ := json.Marshal(user["filters"])
				quotasJSON, _ := json.Marshal(user["quotas"])
				bwJSON, _ := json.Marshal(user["bandwidth_limits"])
				txJSON, _ := json.Marshal(user["transfer_limits"])
				maxSessions := 10
				if ms, ok := user["max_sessions"].(float64); ok {
					maxSessions = int(ms)
				}
				allowedProtoJSON, _ := json.Marshal(user["allowed_protocols"])
				deniedProtoJSON, _ := json.Marshal(user["denied_protocols"])
				ipFiltersJSON, _ := json.Marshal(user["ip_filters"])
				defaultPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
				if _, err := s.db.Exec(
					"INSERT INTO users (username, email, status, password_hash, home_dir, filesystem, permissions, filters, quotas, bandwidth_limits, transfer_limits, max_sessions, allowed_protocols, denied_protocols, ip_filters) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
					username, email, status, string(defaultPasswordHash), homeDir, string(fsJSON), string(permsJSON), string(filtersJSON), string(quotasJSON), string(bwJSON), string(txJSON), maxSessions, string(allowedProtoJSON), string(deniedProtoJSON), string(ipFiltersJSON),
				); err != nil {
					errors["users"]++
					continue
				}
				imported["users"]++
			}
		}
	}

	// Import folders
	if foldersRaw, ok := backup["folders"]; ok {
		var folders []map[string]any
		if err := json.Unmarshal(foldersRaw, &folders); err == nil {
			for _, folder := range folders {
				name, _ := folder["name"].(string)
				mappedPath, _ := folder["mapped_path"].(string)
				fsType, _ := folder["filesystem_type"].(string)
				if name == "" || mappedPath == "" {
					errors["folders"]++
					continue
				}
				// Check by name+mapped_path combination
				var count int
				_ = s.db.QueryRow("SELECT COUNT(*) FROM virtual_folders WHERE name = ? AND mapped_path = ?", name, mappedPath).Scan(&count)
				if count > 0 {
					if conflictStrategy == "skip" {
						skipped["folders"]++
						continue
					}
					s.db.Exec("DELETE FROM virtual_folders WHERE name = ? AND mapped_path = ?", name, mappedPath)
				}
				fsConfigJSON, _ := json.Marshal(folder["filesystem_config"])
				isShared := false
				if is, ok := folder["is_shared"].(bool); ok {
					isShared = is
				}
				var ownerUserID any
				if oid, ok := folder["owner_user_id"].(float64); ok && oid > 0 {
					ownerUserID = int64(oid)
				}
				if _, err := s.db.Exec("INSERT INTO virtual_folders (name, mapped_path, filesystem_type, filesystem_config, owner_user_id, is_shared) VALUES (?, ?, ?, ?, ?, ?)", name, mappedPath, fsType, string(fsConfigJSON), ownerUserID, isShared); err != nil {
					errors["folders"]++
					continue
				}
				imported["folders"]++
			}
		}
	}

	// Import event_rules
	if rulesRaw, ok := backup["event_rules"]; ok {
		var rules []map[string]any
		if err := json.Unmarshal(rulesRaw, &rules); err == nil {
			for _, rule := range rules {
				name, _ := rule["name"].(string)
				triggerType, _ := rule["trigger_type"].(string)
				if name == "" || triggerType == "" {
					errors["event_rules"]++
					continue
				}
				if recordExists("event_rules", "name", name) {
					if conflictStrategy == "skip" {
						skipped["event_rules"]++
						continue
					}
					s.db.Exec("DELETE FROM event_rules WHERE name = ?", name)
				}
				desc, _ := rule["description"].(string)
				triggerConfigJSON, _ := json.Marshal(rule["trigger_config"])
				conditionsJSON, _ := json.Marshal(rule["conditions"])
				isActive := true
				if ia, ok := rule["is_active"].(bool); ok {
					isActive = ia
				}
				schedule, _ := rule["schedule"].(string)
				if _, err := s.db.Exec("INSERT INTO event_rules (name, description, trigger_type, trigger_config, conditions, is_active, schedule) VALUES (?, ?, ?, ?, ?, ?, ?)", name, desc, triggerType, string(triggerConfigJSON), string(conditionsJSON), isActive, schedule); err != nil {
					errors["event_rules"]++
					continue
				}
				imported["event_rules"]++
			}
		}
	}

	// Import shares
	if sharesRaw, ok := backup["shares"]; ok {
		var shares []map[string]any
		if err := json.Unmarshal(sharesRaw, &shares); err == nil {
			for _, share := range shares {
				token, _ := share["token"].(string)
				if token == "" {
					errors["shares"]++
					continue
				}
				if recordExists("shares", "token", token) {
					if conflictStrategy == "skip" {
						skipped["shares"]++
						continue
					}
					s.db.Exec("DELETE FROM shares WHERE token = ?", token)
				}
				userID := int64(0)
				if uid, ok := share["user_id"].(float64); ok {
					userID = int64(uid)
				}
				shareType, _ := share["share_type"].(string)
				path, _ := share["path"].(string)
				ipRestrictionsJSON, _ := json.Marshal(share["ip_restrictions"])
				if _, err := s.db.Exec("INSERT INTO shares (token, user_id, share_type, path, ip_restrictions, is_active) VALUES (?, ?, ?, ?, ?, TRUE)", token, userID, shareType, path, string(ipRestrictionsJSON)); err != nil {
					errors["shares"]++
					continue
				}
				imported["shares"]++
			}
		}
	}

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "import_restore", "http", "", "success", "")
	}
	s.writeJSON(w, http.StatusOK, stats)
}

// ============================================================================
// Defender API (PRD Section 11.12)
// ============================================================================

func (s *Server) listBlockedIPs(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	page := queryInt(r, "page", 1)
	limit := queryInt(r, "limit", 20)
	offset := (page - 1) * limit

	rows, err := s.db.Query(
		"SELECT id, ip, COALESCE(protocol, ''), COALESCE(reason, ''), blocked_at, COALESCE(expires_at, ''), is_active FROM defender_blocklist WHERE is_active = TRUE ORDER BY blocked_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		s.logger.Error("list blocked IPs failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to list blocked IPs")
		return
	}
	defer rows.Close()

	blocks := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var ip, protocol, reason, blockedAt, expiresAt string
		var isActive bool
		if err := rows.Scan(&id, &ip, &protocol, &reason, &blockedAt, &expiresAt, &isActive); err != nil {
			continue
		}
		block := map[string]any{
			"id":         id,
			"ip":         ip,
			"protocol":   protocol,
			"reason":     reason,
			"blocked_at": blockedAt,
			"is_active":  isActive,
		}
		if expiresAt != "" {
			block["expires_at"] = expiresAt
		}
		blocks = append(blocks, block)
	}

	var total int64
	_ = s.db.QueryRow("SELECT COUNT(*) FROM defender_blocklist WHERE is_active = TRUE").Scan(&total)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"items": blocks,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (s *Server) getBlockedIP(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		s.writeError(w, http.StatusBadRequest, "IP address is required")
		return
	}

	var id int64
	var protocol, reason, blockedAt string
	var expiresAt sql.NullString
	var isActive bool
	err := s.db.QueryRow(
		"SELECT id, COALESCE(protocol, ''), COALESCE(reason, ''), blocked_at, expires_at, is_active FROM defender_blocklist WHERE ip = ? AND is_active = TRUE LIMIT 1",
		ip,
	).Scan(&id, &protocol, &reason, &blockedAt, &expiresAt, &isActive)
	if err != nil {
		if err == sql.ErrNoRows {
			s.writeJSON(w, http.StatusOK, map[string]any{
				"ip":        ip,
				"blocked":   false,
				"is_active": false,
			})
			return
		}
		s.logger.Error("get blocked IP failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to get block status")
		return
	}

	block := map[string]any{
		"id":         id,
		"ip":         ip,
		"protocol":   protocol,
		"reason":     reason,
		"blocked_at": blockedAt,
		"is_active":  isActive,
		"blocked":    true,
	}
	if expiresAt.Valid {
		block["expires_at"] = expiresAt.String
	}
	s.writeJSON(w, http.StatusOK, block)
}

func (s *Server) unblockIP(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		s.writeError(w, http.StatusBadRequest, "IP address is required")
		return
	}
	result, err := s.db.Exec("UPDATE defender_blocklist SET is_active = FALSE WHERE ip = ? AND is_active = TRUE", ip)
	if err != nil {
		s.logger.Error("unblock IP failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to unblock IP")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		s.writeError(w, http.StatusNotFound, "IP is not blocked")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "unblock_ip", "http", ip, "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "IP unblocked", "ip": ip})
}

// ============================================================================
// Config API (PRD Section 5)
// ============================================================================

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	if s.fullConfig == nil {
		s.writeError(w, http.StatusInternalServerError, "Configuration is not available")
		return
	}
	masked := s.fullConfig.MaskSensitive()
	s.writeJSON(w, http.StatusOK, masked)
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	if s.fullConfig == nil {
		s.writeError(w, http.StatusInternalServerError, "Configuration is not available")
		return
	}
	var req struct {
		Common   *config.CommonConfig   `json:"common"`
		SSH      *config.SSHConfig      `json:"ssh"`
		FTP      *config.FTPConfig      `json:"ftp"`
		WebDAV   *config.WebDAVConfig   `json:"webdav"`
		HTTPD    *config.HTTPDConfig    `json:"httpd"`
		MFA      *config.MFAConfig      `json:"mfa"`
		SMTP     *config.SMTPConfig     `json:"smtp"`
		Auth     *config.AuthConfig     `json:"auth"`
		Defender *config.DefenderConfig `json:"defender"`
		Hooks    *struct {
			Auth             config.HooksAuthConfig         `json:"auth"`
			DynamicUser      config.HooksDynamicUserConfig  `json:"dynamic_user"`
			FileEvents       []config.HooksFileEventConfig  `json:"file_events"`
			ConnectionEvents []config.HooksConnectionConfig `json:"connection_events"`
		} `json:"hooks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Common != nil {
		if strings.TrimSpace(req.Common.LogLevel) != "" {
			s.fullConfig.Common.LogLevel = req.Common.LogLevel
		}
		if req.Common.GlobalTimeout > 0 {
			s.fullConfig.Common.GlobalTimeout = req.Common.GlobalTimeout
		}
	}
	if req.SSH != nil {
		s.fullConfig.SSH.Enabled = req.SSH.Enabled
		if req.SSH.ListenPort > 0 {
			s.fullConfig.SSH.ListenPort = req.SSH.ListenPort
		}
	}
	if req.FTP != nil {
		s.fullConfig.FTP.Enabled = req.FTP.Enabled
		if req.FTP.ListenPort > 0 {
			s.fullConfig.FTP.ListenPort = req.FTP.ListenPort
		}
	}
	if req.WebDAV != nil {
		s.fullConfig.WebDAV.Enabled = req.WebDAV.Enabled
		if req.WebDAV.ListenPort > 0 {
			s.fullConfig.WebDAV.ListenPort = req.WebDAV.ListenPort
		}
	}
	if req.HTTPD != nil {
		s.fullConfig.HTTPD.Enabled = req.HTTPD.Enabled
		if req.HTTPD.ListenPort > 0 {
			s.fullConfig.HTTPD.ListenPort = req.HTTPD.ListenPort
		}
		if req.HTTPD.ClientListenPort > 0 {
			s.fullConfig.HTTPD.ClientListenPort = req.HTTPD.ClientListenPort
		}
		s.fullConfig.HTTPD.WebClientEnabled = req.HTTPD.WebClientEnabled
		s.fullConfig.HTTPD.WebAdminEnabled = req.HTTPD.WebAdminEnabled
		s.fullConfig.HTTPD.RESTAPIEnabled = req.HTTPD.RESTAPIEnabled
		s.fullConfig.HTTPD.OpenAPIEnabled = req.HTTPD.OpenAPIEnabled
		if len(req.HTTPD.CORSOrigins) > 0 {
			s.fullConfig.HTTPD.CORSOrigins = req.HTTPD.CORSOrigins
		}
	}
	if req.MFA != nil {
		s.fullConfig.MFA.Enabled = req.MFA.Enabled
		if strings.TrimSpace(req.MFA.Issuer) != "" {
			s.fullConfig.MFA.Issuer = req.MFA.Issuer
		}
		s.fullConfig.MFA.ForceForAdmins = req.MFA.ForceForAdmins
		s.fullConfig.MFA.ForceForUsers = req.MFA.ForceForUsers
	}
	if req.SMTP != nil {
		if strings.TrimSpace(req.SMTP.Host) != "" {
			s.fullConfig.SMTP.Host = req.SMTP.Host
		}
		if req.SMTP.Port > 0 {
			s.fullConfig.SMTP.Port = req.SMTP.Port
		}
		if strings.TrimSpace(req.SMTP.Username) != "" {
			s.fullConfig.SMTP.Username = req.SMTP.Username
		}
		if strings.TrimSpace(req.SMTP.Password) != "" {
			s.fullConfig.SMTP.Password = req.SMTP.Password
		}
		if strings.TrimSpace(req.SMTP.From) != "" {
			s.fullConfig.SMTP.From = req.SMTP.From
		}
		s.fullConfig.SMTP.UseTLS = req.SMTP.UseTLS
	}
	if req.Auth != nil {
		s.fullConfig.Auth.PasswordPolicy = req.Auth.PasswordPolicy
		s.fullConfig.Auth.IPFilter = req.Auth.IPFilter
		s.fullConfig.Auth.GeoIP = req.Auth.GeoIP
	}
	if req.Defender != nil {
		s.fullConfig.Defender = *req.Defender
	}
	if req.Hooks != nil {
		s.fullConfig.Hooks.Auth = req.Hooks.Auth
		s.fullConfig.Hooks.DynamicUser = req.Hooks.DynamicUser
		s.fullConfig.Hooks.FileEvents = req.Hooks.FileEvents
		s.fullConfig.Hooks.Connection = req.Hooks.ConnectionEvents
	}

	if s.configPath != "" {
		if err := config.Save(s.configPath, s.fullConfig); err != nil {
			s.logger.Error("failed to persist config", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to save configuration")
			return
		}
	}

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "update_config", "http", "", "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "configuration updated"})
}

// ============================================================================
// Token Refresh (PRD Section 14.1)
// ============================================================================

func (s *Server) refreshToken(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	// Issue a new token with the same claims but refreshed expiry
	newSession := &authSession{
		SessionID: session.SessionID,
		UserID:    session.UserID,
		Username:  session.Username,
		Role:      session.Role,
		Scopes:    session.Scopes,
		Filters:   session.Filters,
		HomeDir:   session.HomeDir,
		ExpiresAt: time.Now().Add(s.tokenTTL()),
	}
	token, err := s.issueToken(newSession)
	if err != nil {
		s.logger.Error("refresh token failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to refresh token")
		return
	}

	// Invalidate old session token and store new one
	s.deleteSession(session.Token)
	newSession.Token = token
	s.storeSession(newSession)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"token_type": s.tokenType(),
		"expires_at": newSession.ExpiresAt.Format(time.RFC3339),
	})
}

// ============================================================================
// User-side APIs (PRD Section 14.3)
// ============================================================================

func (s *Server) getOwnQuota(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var quotas sql.NullString
	if err := s.db.QueryRow("SELECT quotas FROM users WHERE id = ?", session.UserID).Scan(&quotas); err != nil {
		s.logger.Error("get own quota failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to get quota")
		return
	}

	var quotaSize int64
	var quotaFiles int64
	if quotas.Valid && strings.TrimSpace(quotas.String) != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(quotas.String), &parsed); err == nil {
			if v, ok := parsed["size"]; ok {
				switch val := v.(type) {
				case float64:
					quotaSize = int64(val)
				case int64:
					quotaSize = val
				}
			}
			if v, ok := parsed["files"]; ok {
				switch val := v.(type) {
				case float64:
					quotaFiles = int64(val)
				case int64:
					quotaFiles = val
				}
			}
		}
	}

	var totalSize int64
	_ = s.db.QueryRow(
		"SELECT COALESCE(SUM(file_size), 0) FROM transfer_logs WHERE username = ? AND operation = 'upload' AND status = 'success'",
		session.Username,
	).Scan(&totalSize)

	var fileCount int64
	_ = s.db.QueryRow(
		"SELECT COUNT(*) FROM transfer_logs WHERE username = ? AND operation = 'upload' AND status = 'success'",
		session.Username,
	).Scan(&fileCount)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"bytes_used":  totalSize,
		"bytes_total": quotaSize,
		"files_used":  fileCount,
		"files_total": quotaFiles,
	})
}

func (s *Server) getOwnSessions(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	rows, err := s.db.Query(
		"SELECT session_id, protocol, COALESCE(client_ip, ''), connected_at, last_activity_at FROM sessions WHERE user_id = ? AND is_active = TRUE ORDER BY connected_at DESC",
		session.UserID,
	)
	if err != nil {
		s.logger.Error("get own sessions failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to get sessions")
		return
	}
	defer rows.Close()

	sessions := make([]map[string]any, 0)
	for rows.Next() {
		var sessionID, protocol, clientIP, connectedAt, lastActivity string
		if err := rows.Scan(&sessionID, &protocol, &clientIP, &connectedAt, &lastActivity); err != nil {
			continue
		}
		sessions = append(sessions, map[string]any{
			"id":            sessionID,
			"protocol":      protocol,
			"client_ip":     clientIP,
			"started_at":    connectedAt,
			"last_activity": lastActivity,
		})
	}
	s.writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) disconnectOwnSession(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	sessionID := chi.URLParam(r, "sessionID")
	if sessionID == "" {
		s.writeError(w, http.StatusBadRequest, "Invalid session id")
		return
	}

	var userID int64
	if err := s.db.QueryRow(
		"SELECT user_id FROM sessions WHERE session_id = ? AND is_active = TRUE LIMIT 1",
		sessionID,
	).Scan(&userID); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Session not found")
			return
		}
		s.logger.Error("lookup own session failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to disconnect session")
		return
	}

	if userID != session.UserID {
		s.writeError(w, http.StatusForbidden, "Forbidden")
		return
	}

	result, err := s.db.Exec("UPDATE sessions SET is_active = FALSE WHERE session_id = ?", sessionID)
	if err != nil {
		s.logger.Error("disconnect own session failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to disconnect session")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		s.writeError(w, http.StatusNotFound, "Session not found")
		return
	}

	s.invalidateSessionByID(sessionID)
	s.recordAudit(session.Username, "user", "disconnect_own_session", "http", sessionID, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) addOwnPublicKey(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var req struct {
		Label     string `json:"label"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		s.writeError(w, http.StatusBadRequest, "Public key is required")
		return
	}

	result, err := s.db.Exec(
		"INSERT INTO public_keys (user_id, label, public_key) VALUES (?, ?, ?)",
		session.UserID, strings.TrimSpace(req.Label), strings.TrimSpace(req.PublicKey),
	)
	if err != nil {
		s.logger.Error("add public key failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to add public key")
		return
	}
	id, _ := result.LastInsertId()

	var fingerprint string
	if parsedKey, err := ssh.ParsePublicKey([]byte(strings.TrimSpace(req.PublicKey))); err == nil {
		fingerprint = ssh.FingerprintSHA256(parsedKey)
	}

	s.recordAudit(session.Username, "user", "add_public_key", "http", strconv.FormatInt(id, 10), "success", "")
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id":          id,
		"label":       strings.TrimSpace(req.Label),
		"public_key":  strings.TrimSpace(req.PublicKey),
		"fingerprint": fingerprint,
	})
}

func (s *Server) removeOwnPublicKey(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	keyID, err := strconv.ParseInt(chi.URLParam(r, "keyID"), 10, 64)
	if err != nil || keyID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid key id")
		return
	}

	result, err := s.db.Exec("DELETE FROM public_keys WHERE id = ? AND user_id = ?", keyID, session.UserID)
	if err != nil {
		s.logger.Error("remove public key failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to remove public key")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		s.writeError(w, http.StatusNotFound, "Public key not found")
		return
	}

	s.recordAudit(session.Username, "user", "remove_public_key", "http", strconv.FormatInt(keyID, 10), "success", "")
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "public key removed"})
}

func (s *Server) setupMFA(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	// Check if MFA is already enabled
	var mfaEnabled bool
	_ = s.db.QueryRow("SELECT mfa_enabled FROM users WHERE id = ?", session.UserID).Scan(&mfaEnabled)
	if mfaEnabled {
		s.writeError(w, http.StatusBadRequest, "MFA is already enabled")
		return
	}

	issuer := "SFTPxy"
	if s.fullConfig != nil && strings.TrimSpace(s.fullConfig.MFA.Issuer) != "" {
		issuer = s.fullConfig.MFA.Issuer
	}

	totpAuth := authn.NewTOTPAuthenticator(issuer)
	secret, err := totpAuth.GenerateSecret()
	if err != nil {
		s.logger.Error("generate TOTP secret failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to setup MFA")
		return
	}

	// Store the secret temporarily (MFA not yet enabled)
	if _, err := s.db.Exec("UPDATE users SET mfa_secret = ? WHERE id = ?", secret, session.UserID); err != nil {
		s.logger.Error("store TOTP secret failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to setup MFA")
		return
	}

	qrURL := totpAuth.GenerateQRCodeURL(secret, session.Username)

	recoveryCodes := make([]string, 6)
	for i := range recoveryCodes {
		codeBytes := make([]byte, 6)
		if _, err := rand.Read(codeBytes); err != nil {
			s.logger.Error("generate recovery code failed", zap.Error(err))
			s.writeError(w, http.StatusInternalServerError, "Failed to setup MFA")
			return
		}
		recoveryCodes[i] = hex.EncodeToString(codeBytes)
	}

	recoveryCodesJSON, _ := json.Marshal(recoveryCodes)
	if _, err := s.db.Exec("UPDATE users SET mfa_recovery_codes = ? WHERE id = ?", string(recoveryCodesJSON), session.UserID); err != nil {
		s.logger.Error("store recovery codes failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to setup MFA")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"secret":         secret,
		"qr_code_url":    qrURL,
		"issuer":         issuer,
		"recovery_codes": recoveryCodes,
		"message":        "Verify with a TOTP code to enable MFA",
	})
}

func (s *Server) verifyMFA(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		s.writeError(w, http.StatusBadRequest, "MFA code is required")
		return
	}

	var mfaSecret sql.NullString
	var mfaEnabled bool
	if err := s.db.QueryRow("SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?", session.UserID).Scan(&mfaSecret, &mfaEnabled); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to verify MFA")
		return
	}
	if mfaEnabled {
		s.writeError(w, http.StatusBadRequest, "MFA is already enabled")
		return
	}
	if !mfaSecret.Valid || strings.TrimSpace(mfaSecret.String) == "" {
		s.writeError(w, http.StatusBadRequest, "MFA setup not initiated. Call /mfa/setup first")
		return
	}

	issuer := "SFTPxy"
	if s.fullConfig != nil && strings.TrimSpace(s.fullConfig.MFA.Issuer) != "" {
		issuer = s.fullConfig.MFA.Issuer
	}

	totpAuth := authn.NewTOTPAuthenticator(issuer)
	valid, err := totpAuth.VerifyCode(mfaSecret.String, strings.TrimSpace(req.Code))
	if err != nil || !valid {
		s.writeError(w, http.StatusBadRequest, "Invalid MFA code")
		return
	}

	// Enable MFA
	if _, err := s.db.Exec("UPDATE users SET mfa_enabled = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = ?", session.UserID); err != nil {
		s.logger.Error("enable MFA failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to enable MFA")
		return
	}

	s.recordAudit(session.Username, "user", "enable_mfa", "http", session.Username, "success", "")

	var recoveryCodes []string
	var recoveryCodesRaw sql.NullString
	if err := s.db.QueryRow("SELECT mfa_recovery_codes FROM users WHERE id = ?", session.UserID).Scan(&recoveryCodesRaw); err == nil && recoveryCodesRaw.Valid {
		json.Unmarshal([]byte(recoveryCodesRaw.String), &recoveryCodes)
	}

	s.writeJSON(w, http.StatusOK, map[string]any{"message": "MFA enabled successfully", "recovery_codes": recoveryCodes})
}

func (s *Server) disableMFA(w http.ResponseWriter, r *http.Request) {
	session := s.currentSession(r)
	if session == nil {
		s.writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Password) == "" {
		s.writeError(w, http.StatusBadRequest, "Password is required")
		return
	}

	var passwordHash string
	var mfaEnabled bool
	if err := s.db.QueryRow("SELECT password_hash, mfa_enabled FROM users WHERE id = ?", session.UserID).Scan(&passwordHash, &mfaEnabled); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to disable MFA")
		return
	}
	if !mfaEnabled {
		s.writeError(w, http.StatusBadRequest, "MFA is not enabled")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		s.writeError(w, http.StatusUnauthorized, "Invalid password")
		return
	}

	if _, err := s.db.Exec("UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_recovery_codes = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?", session.UserID); err != nil {
		s.logger.Error("disable MFA failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to disable MFA")
		return
	}

	s.recordAudit(session.Username, "user", "disable_mfa", "http", session.Username, "success", "")
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "MFA disabled successfully"})
}

// ============================================================================
// Data Retention API (PRD Section 14.2)
// ============================================================================

func (s *Server) listDataRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	rows, err := s.db.Query(
		"SELECT id, name, COALESCE(description, ''), scope, COALESCE(scope_id, 0), retention_days, action, COALESCE(action_config, ''), is_active, created_at, updated_at FROM data_retention_policies ORDER BY id ASC",
	)
	if err != nil {
		s.logger.Error("list data retention policies failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to load data retention policies")
		return
	}
	defer rows.Close()

	policies := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var name, desc, scope string
		var scopeID int64
		var retentionDays int
		var action, actionConfig string
		var isActive bool
		var createdAt, updatedAt string
		if err := rows.Scan(&id, &name, &desc, &scope, &scopeID, &retentionDays, &action, &actionConfig, &isActive, &createdAt, &updatedAt); err != nil {
			continue
		}
		policy := map[string]any{
			"id":             id,
			"name":           name,
			"description":    desc,
			"scope":          scope,
			"retention_days": retentionDays,
			"action":         action,
			"is_active":      isActive,
			"created_at":     createdAt,
			"updated_at":     updatedAt,
		}
		if scopeID > 0 {
			policy["scope_id"] = scopeID
		} else {
			policy["scope_id"] = nil
		}
		if strings.TrimSpace(actionConfig) != "" {
			policy["action_config"] = decodeJSONRaw(actionConfig, map[string]any{})
		} else {
			policy["action_config"] = nil
		}
		policies = append(policies, policy)
	}
	s.writeJSON(w, http.StatusOK, policies)
}

func (s *Server) createDataRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	var req struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Scope         string `json:"scope"`
		ScopeID       *int64 `json:"scope_id"`
		RetentionDays int    `json:"retention_days"`
		Action        string `json:"action"`
		ActionConfig  any    `json:"action_config"`
		IsActive      *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "Policy name is required")
		return
	}
	if req.RetentionDays <= 0 {
		s.writeError(w, http.StatusBadRequest, "Retention days must be positive")
		return
	}
	if strings.TrimSpace(req.Scope) == "" {
		req.Scope = "global"
	}
	if strings.TrimSpace(req.Action) == "" {
		req.Action = "delete"
	}

	actionConfigJSON, _ := json.Marshal(req.ActionConfig)
	var scopeID any
	if req.ScopeID != nil && *req.ScopeID > 0 {
		scopeID = *req.ScopeID
	} else {
		scopeID = nil
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	result, err := s.db.Exec(
		"INSERT INTO data_retention_policies (name, description, scope, scope_id, retention_days, action, action_config, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), strings.TrimSpace(req.Scope), scopeID, req.RetentionDays, strings.TrimSpace(req.Action), string(actionConfigJSON), isActive,
	)
	if err != nil {
		s.logger.Error("create data retention policy failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create data retention policy")
		return
	}
	id, _ := result.LastInsertId()

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "create_retention_policy", "http", req.Name, "success", "")
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"id":             id,
		"name":           strings.TrimSpace(req.Name),
		"description":    strings.TrimSpace(req.Description),
		"scope":          strings.TrimSpace(req.Scope),
		"scope_id":       req.ScopeID,
		"retention_days": req.RetentionDays,
		"action":         strings.TrimSpace(req.Action),
		"action_config":  req.ActionConfig,
		"is_active":      isActive,
	})
}

func (s *Server) updateDataRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	policyID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || policyID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid policy id")
		return
	}
	var req struct {
		Name          string `json:"name"`
		Description   string `json:"description"`
		Scope         string `json:"scope"`
		ScopeID       *int64 `json:"scope_id"`
		RetentionDays int    `json:"retention_days"`
		Action        string `json:"action"`
		ActionConfig  any    `json:"action_config"`
		IsActive      *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Verify policy exists
	var exists int
	if err := s.db.QueryRow("SELECT 1 FROM data_retention_policies WHERE id = ?", policyID).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			s.writeError(w, http.StatusNotFound, "Data retention policy not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update data retention policy")
		return
	}

	actionConfigJSON, _ := json.Marshal(req.ActionConfig)
	var scopeID any
	if req.ScopeID != nil && *req.ScopeID > 0 {
		scopeID = *req.ScopeID
	} else {
		scopeID = nil
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	if _, err := s.db.Exec(
		"UPDATE data_retention_policies SET name = ?, description = ?, scope = ?, scope_id = ?, retention_days = ?, action = ?, action_config = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		strings.TrimSpace(req.Name), strings.TrimSpace(req.Description), strings.TrimSpace(req.Scope), scopeID, req.RetentionDays, strings.TrimSpace(req.Action), string(actionConfigJSON), isActive, policyID,
	); err != nil {
		s.logger.Error("update data retention policy failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to update data retention policy")
		return
	}

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "update_retention_policy", "http", strconv.FormatInt(policyID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "data retention policy updated"})
}

func (s *Server) deleteDataRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		s.writeError(w, http.StatusInternalServerError, "Database not available")
		return
	}
	policyID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || policyID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid policy id")
		return
	}
	if _, err := s.db.Exec("DELETE FROM data_retention_policies WHERE id = ?", policyID); err != nil {
		s.logger.Error("delete data retention policy failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to delete data retention policy")
		return
	}
	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "delete_retention_policy", "http", strconv.FormatInt(policyID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "data retention policy deleted"})
}

func (s *Server) adminListShares(w http.ResponseWriter, r *http.Request) {
	if s.shareManager == nil {
		s.writeError(w, http.StatusInternalServerError, "Share manager not available")
		return
	}

	items, err := s.shareManager.ListAllShares(r.Context())
	if err != nil {
		s.logger.Error("admin list shares failed", zap.Error(err))
		s.writeError(w, http.StatusInternalServerError, "Failed to list shares")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": len(items),
	})
}

func (s *Server) adminDeleteShare(w http.ResponseWriter, r *http.Request) {
	shareID, err := strconv.ParseInt(chi.URLParam(r, "shareID"), 10, 64)
	if err != nil || shareID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid share id")
		return
	}

	if s.shareManager == nil {
		s.writeError(w, http.StatusInternalServerError, "Share manager not available")
		return
	}

	if err := s.shareManager.DeleteShare(r.Context(), shareID); err != nil {
		s.logger.Error("admin delete share failed", zap.Error(err))
		s.writeError(w, http.StatusNotFound, "Share not found")
		return
	}

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "delete_share", "http", strconv.FormatInt(shareID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "share deleted"})
}

func (s *Server) createEventRule(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeError(w, http.StatusInternalServerError, "Event manager not available")
		return
	}

	var rule events.EventRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if strings.TrimSpace(rule.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "Rule name is required")
		return
	}
	if strings.TrimSpace(string(rule.TriggerType)) == "" {
		s.writeError(w, http.StatusBadRequest, "Trigger type is required")
		return
	}
	if rule.TriggerType == events.EventSchedule && strings.TrimSpace(rule.Schedule) == "" {
		s.writeError(w, http.StatusBadRequest, "Schedule cron expression is required for schedule trigger type")
		return
	}

	repo := s.eventManager.Repo()
	if repo == nil {
		s.writeError(w, http.StatusInternalServerError, "Event repository not available")
		return
	}

	conditionsJSON, _ := json.Marshal(rule.Conditions)
	record, err := repo.CreateRule(r.Context(), &repository.EventRuleRecord{
		Name:        rule.Name,
		Description: sql.NullString{String: rule.Description, Valid: rule.Description != ""},
		TriggerType: string(rule.TriggerType),
		Conditions:  conditionsJSON,
		IsActive:    rule.IsActive,
		Schedule:    sql.NullString{String: rule.Schedule, Valid: rule.Schedule != ""},
	})
	if err != nil {
		s.logger.Error("create event rule failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to create event rule")
		return
	}

	for i, action := range rule.Actions {
		configJSON, _ := json.Marshal(action.Config)
		_, err := repo.CreateAction(r.Context(), &repository.EventActionRecord{
			RuleID:     record.ID,
			ActionType: string(action.Type),
			Config:     configJSON,
			OrderIndex: i,
		})
		if err != nil {
			s.logger.Error("create event action failed", zap.Error(err), zap.Int64("rule_id", record.ID), zap.Int("action_index", i))
		}
	}

	rule.ID = record.ID
	s.eventManager.AddRule(&rule)

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "create_event_rule", "http", rule.Name, "success", "")
	}
	s.writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) updateEventRule(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeError(w, http.StatusInternalServerError, "Event manager not available")
		return
	}

	ruleID, err := strconv.ParseInt(chi.URLParam(r, "ruleID"), 10, 64)
	if err != nil || ruleID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid rule id")
		return
	}

	var rule events.EventRule
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := json.Unmarshal(bodyBytes, &rule); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var rawPayload map[string]interface{}
	json.Unmarshal(bodyBytes, &rawPayload)
	_, isActiveProvided := rawPayload["is_active"]

	repo := s.eventManager.Repo()
	if repo == nil {
		s.writeError(w, http.StatusInternalServerError, "Event repository not available")
		return
	}

	isPartialUpdate := strings.TrimSpace(rule.Name) == ""
	if isPartialUpdate {
		existing, err := repo.GetRuleByID(r.Context(), ruleID)
		if err != nil {
			s.writeError(w, http.StatusNotFound, "Rule not found")
			return
		}
		rule.Name = existing.Name
		rule.Description = existing.Description.String
		rule.TriggerType = events.EventType(existing.TriggerType)
		if existing.Conditions != nil {
			json.Unmarshal(existing.Conditions, &rule.Conditions)
		}
		if !isActiveProvided {
			rule.IsActive = existing.IsActive
		}
		if existing.Schedule.Valid {
			rule.Schedule = existing.Schedule.String
		}
		if len(rule.Actions) == 0 {
			actions, _ := repo.GetActionsByRuleID(r.Context(), ruleID)
			for _, a := range actions {
				var config map[string]interface{}
				if a.Config != nil {
					json.Unmarshal(a.Config, &config)
				}
				rule.Actions = append(rule.Actions, events.ActionConfig{
					ID:         a.ID,
					Type:       events.ActionType(a.ActionType),
					Config:     config,
					OrderIndex: a.OrderIndex,
				})
			}
		}
	}

	if strings.TrimSpace(rule.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "Rule name is required")
		return
	}
	if rule.TriggerType == events.EventSchedule && strings.TrimSpace(rule.Schedule) == "" {
		s.writeError(w, http.StatusBadRequest, "Schedule cron expression is required for schedule trigger type")
		return
	}

	conditionsJSON, _ := json.Marshal(rule.Conditions)
	_, err = repo.UpdateRule(r.Context(), &repository.EventRuleRecord{
		ID:          ruleID,
		Name:        rule.Name,
		Description: sql.NullString{String: rule.Description, Valid: rule.Description != ""},
		TriggerType: string(rule.TriggerType),
		Conditions:  conditionsJSON,
		IsActive:    rule.IsActive,
		Schedule:    sql.NullString{String: rule.Schedule, Valid: rule.Schedule != ""},
	})
	if err != nil {
		s.logger.Error("update event rule failed", zap.Error(err))
		s.writeError(w, http.StatusBadRequest, "Failed to update event rule")
		return
	}

	var actionRecords []*repository.EventActionRecord
	for i, action := range rule.Actions {
		configJSON, _ := json.Marshal(action.Config)
		actionRecords = append(actionRecords, &repository.EventActionRecord{
			RuleID:     ruleID,
			ActionType: string(action.Type),
			Config:     configJSON,
			OrderIndex: i,
		})
	}
	if err := repo.UpdateRuleActions(r.Context(), ruleID, actionRecords); err != nil {
		s.logger.Error("update rule actions failed", zap.Error(err), zap.Int64("rule_id", ruleID))
		s.writeError(w, http.StatusInternalServerError, "Failed to update rule actions")
		return
	}

	rule.ID = ruleID
	s.eventManager.UpdateRule(&rule)

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "update_event_rule", "http", strconv.FormatInt(ruleID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, rule)
}

func (s *Server) deleteEventRule(w http.ResponseWriter, r *http.Request) {
	if s.eventManager == nil {
		s.writeError(w, http.StatusInternalServerError, "Event manager not available")
		return
	}

	ruleID, err := strconv.ParseInt(chi.URLParam(r, "ruleID"), 10, 64)
	if err != nil || ruleID <= 0 {
		s.writeError(w, http.StatusBadRequest, "Invalid rule id")
		return
	}

	repo := s.eventManager.Repo()
	if repo != nil {
		if err := repo.DeleteActionsByRuleID(r.Context(), ruleID); err != nil {
			s.logger.Error("delete event actions failed", zap.Error(err), zap.Int64("rule_id", ruleID))
		}
		if err := repo.DeleteRule(r.Context(), ruleID); err != nil {
			s.logger.Error("delete event rule failed", zap.Error(err))
			s.writeError(w, http.StatusNotFound, "Event rule not found")
			return
		}
	}

	s.eventManager.RemoveRule(ruleID)

	session := s.currentSession(r)
	if session != nil {
		s.recordAudit(session.Username, "admin", "delete_event_rule", "http", strconv.FormatInt(ruleID, 10), "success", "")
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"message": "event rule deleted"})
}
