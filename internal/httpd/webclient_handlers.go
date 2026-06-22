// SPDX-License-Identifier: MIT

package httpd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/render"
	"github.com/rs/xid"
	"github.com/jincaiw/sftpxy/sdk"

	"github.com/jincaiw/sftpxy/v2/internal/common"
	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/jwt"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/smtp"
	"github.com/jincaiw/sftpxy/v2/internal/util"
	"github.com/jincaiw/sftpxy/v2/internal/vfs"
)

func (s *httpdServer) handleWebClientDownloadZip(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartMem)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	baseConn := common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r), r.RemoteAddr, user)
	connection := newConnection(baseConn, w, r)
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	files := r.Form.Get("files")
	var filesList []string
	err = json.Unmarshal(util.StringToBytes(files), &filesList)
	if err != nil {
		s.renderClientBadRequestPage(w, r, err)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(connection.GetUsername(), filesList)))
	renderCompressedFiles(w, connection, name, filesList, nil)
}

func (s *httpdServer) handleClientSharePartialDownload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxMultipartMem)
	if err := r.ParseForm(); err != nil {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	transferQuota := connection.GetTransferQuota()
	if !transferQuota.HasDownloadSpace() {
		err = util.NewI18nError(connection.GetReadQuotaExceededError(), util.I18nErrorQuotaRead)
		connection.Log(logger.LevelInfo, "denying share read due to quota limits")
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getMappedStatusCode(err), err, "")
		return
	}
	files := r.Form.Get("files")
	var filesList []string
	err = json.Unmarshal(util.StringToBytes(files), &filesList)
	if err != nil {
		s.renderClientBadRequestPage(w, r, err)
		return
	}

	if err := dataprovider.UpdateShareLastUse(&share, 1); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
		getCompressedFileName(fmt.Sprintf("share-%s", share.Name), filesList)))
	renderCompressedFiles(w, connection, name, filesList, &share)
}

func (s *httpdServer) handleShareGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError500Message), getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError500Message), getRespStatus(err))
		return
	}
	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nError429Message), http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	lister, err := connection.ReadDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nErrorDirListGeneric), getMappedStatusCode(err))
		return
	}
	defer lister.Close()

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		contents, err := lister.Next(limit)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			return nil, 0, err
		}
		results := make([]map[string]any, 0, len(contents))
		for idx, info := range contents {
			if !info.Mode().IsDir() && !info.Mode().IsRegular() {
				continue
			}
			res := make(map[string]any)
			res["id"] = offset + idx + 1
			if info.IsDir() {
				res["type"] = "1"
				res["size"] = ""
			} else {
				res["type"] = "2"
				res["size"] = info.Size()
			}
			res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
			res["name"] = info.Name()
			res["url"] = getFileObjectURL(share.GetRelativePath(name), info.Name(),
				path.Join(webClientPubSharesPath, share.ShareID, "browse"))
			res["last_modified"] = getFileObjectModTime(info.ModTime())
			results = append(results, res)
		}
		data, err := json.Marshal(results)
		count := limit
		if len(results) == 0 {
			count = 0
		}
		return data, count, err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleClientUploadToShare(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeWrite, dataprovider.ShareScopeReadWrite}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if share.Scope == dataprovider.ShareScopeReadWrite {
		http.Redirect(w, r, path.Join(webClientPubSharesPath, share.ShareID, "browse"), http.StatusFound)
		return
	}
	s.renderUploadToSharePage(w, r, &share)
}

func (s *httpdServer) handleShareGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
			util.NewI18nError(err, util.I18nError429Message), share)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Unix(0, 0), false)
	} else {
		info, err = connection.Stat(name, 1)
	}
	if err != nil {
		s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
			util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), share)
		return
	}
	if info.IsDir() {
		s.renderSharedFilesPage(w, r, share.GetRelativePath(name), nil, share)
		return
	}
	if err := dataprovider.UpdateShareLastUse(&share, 1); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	if status, err := downloadFile(w, r, connection, name, info, false, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
		if status > 0 {
			s.renderSharedFilesPage(w, r, path.Dir(share.GetRelativePath(name)),
				util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), share)
		}
	}
}

func (s *httpdServer) handleShareViewPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	name := util.CleanPath(r.URL.Query().Get("path"))
	data := viewPDFPage{
		commonBasePage: getCommonBasePage(r),
		Title:          path.Base(name),
		URL: fmt.Sprintf("%s?path=%s&_=%d", path.Join(webClientPubSharesPath, share.ShareID, "getpdf"),
			url.QueryEscape(name), time.Now().UTC().Unix()),
		Branding:  s.binding.webClientBranding(),
		Languages: s.binding.languages(),
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}

func (s *httpdServer) handleShareGetPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead, dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 1)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, status,
			util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(fmt.Errorf("%q is not a file", name), util.I18nErrorPDFMessage))
		return
	}
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	if err := s.ensurePDF(w, r, name, connection); err != nil {
		return
	}
	if err := dataprovider.UpdateShareLastUse(&share, 1); err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, getRespStatus(err), err, "")
		return
	}
	if _, err := downloadFile(w, r, connection, name, info, true, &share); err != nil {
		dataprovider.UpdateShareLastUse(&share, -1) //nolint:errcheck
	}
}

func (s *httpdServer) handleClientGetDirContents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorDirList403, http.StatusForbidden)
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		sendAPIResponse(w, r, nil, util.I18nErrorDirListUser, getRespStatus(err))
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%s_%s", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		sendAPIResponse(w, r, err, getI18NErrorString(err, util.I18nErrorDirList403), http.StatusForbidden)
		return
	}
	baseConn := common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r), r.RemoteAddr, user)
	connection := newConnection(baseConn, w, r)
	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, util.I18nErrorDirList429, http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	lister, err := connection.ReadDir(name)
	if err != nil {
		statusCode := getMappedStatusCode(err)
		sendAPIResponse(w, r, err, i18nListDirMsg(statusCode), statusCode)
		return
	}
	defer lister.Close()

	dirTree := r.URL.Query().Get("dirtree") == "1"
	dataGetter := func(limit, offset int) ([]byte, int, error) {
		contents, err := lister.Next(limit)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			return nil, 0, err
		}
		results := make([]map[string]any, 0, len(contents))
		for idx, info := range contents {
			res := make(map[string]any)
			res["id"] = offset + idx + 1
			res["url"] = getFileObjectURL(name, info.Name(), webClientFilesPath)
			if info.IsDir() {
				res["type"] = "1"
				res["size"] = ""
				res["dir_path"] = url.QueryEscape(path.Join(name, info.Name()))
			} else {
				if dirTree {
					continue
				}
				res["type"] = "2"
				if info.Mode()&os.ModeSymlink != 0 {
					res["size"] = ""
				} else {
					res["size"] = info.Size()
					if info.Size() < httpdMaxEditFileSize {
						res["edit_url"] = strings.Replace(res["url"].(string), webClientFilesPath, webClientEditFilePath, 1)
					}
				}
			}
			res["meta"] = fmt.Sprintf("%v_%v", res["type"], info.Name())
			res["name"] = info.Name()
			res["last_modified"] = getFileObjectModTime(info.ModTime())
			results = append(results, res)
		}
		data, err := json.Marshal(results)
		count := limit
		if len(results) == 0 {
			count = 0
		}
		return data, count, err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleClientGetFiles(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	baseConn := common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r), r.RemoteAddr, user)
	connection := newConnection(baseConn, w, r)
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	var info os.FileInfo
	if name == "/" {
		info = vfs.NewFileInfo(name, true, 0, time.Unix(0, 0), false)
	} else {
		info, err = connection.Stat(name, 0)
	}
	if err != nil {
		s.renderFilesPage(w, r, path.Dir(name), util.NewI18nError(err, i18nFsMsg(getRespStatus(err))), &user)
		return
	}
	if info.IsDir() {
		s.renderFilesPage(w, r, name, nil, &user)
		return
	}
	if status, err := downloadFile(w, r, connection, name, info, false, nil); err != nil && status != 0 {
		if status > 0 {
			if status == http.StatusRequestedRangeNotSatisfiable {
				s.renderClientMessagePage(w, r, util.I18nError416Title, status,
					util.NewI18nError(err, util.I18nError416Message), "")
				return
			}
			s.renderFilesPage(w, r, path.Dir(name), util.NewI18nError(err, i18nFsMsg(status)), &user)
		}
	}
}

func (s *httpdServer) handleClientEditFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}

	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	baseConn := common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r), r.RemoteAddr, user)
	connection := newConnection(baseConn, w, r)
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	info, err := connection.Stat(name, 0)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, status, util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, http.StatusBadRequest,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("The path %q does not point to a file", name)),
				util.I18nErrorEditDir,
			), "")
		return
	}
	if info.Size() > httpdMaxEditFileSize {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, http.StatusBadRequest,
			util.NewI18nError(
				util.NewValidationError(fmt.Sprintf("The file size %v for %q exceeds the maximum allowed size",
					util.ByteCountIEC(info.Size()), name)),
				util.I18nErrorEditSize,
			), "")
		return
	}

	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nError500Message), "")
		return
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.Copy(&b, reader)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorEditorTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nError500Message), "")
		return
	}

	s.renderEditFilePage(w, r, name, b.String(), !user.CanAddFilesFromWeb(path.Dir(name)))
}

func (s *httpdServer) handleClientAddShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}
	share := &dataprovider.Share{Scope: dataprovider.ShareScopeRead}
	if user.Filters.DefaultSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.DefaultSharesExpiration)))
	} else if user.Filters.MaxSharesExpiration > 0 {
		share.ExpiresAt = util.GetTimeAsMsSinceEpoch(time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration)))
	}
	dirName := "/"
	if _, ok := r.URL.Query()["path"]; ok {
		dirName = util.CleanPath(r.URL.Query().Get("path"))
	}

	if _, ok := r.URL.Query()["files"]; ok {
		files := r.URL.Query().Get("files")
		var filesList []string
		err := json.Unmarshal(util.StringToBytes(files), &filesList)
		if err != nil {
			s.renderClientBadRequestPage(w, r, err)
			return
		}
		for _, f := range filesList {
			if f != "" {
				share.Paths = append(share.Paths, path.Join(dirName, f))
			}
		}
	}

	s.renderAddUpdateSharePage(w, r, share, nil, true)
}

func (s *httpdServer) handleClientUpdateShareGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if err == nil {
		s.renderAddUpdateSharePage(w, r, &share, nil, false)
	} else if errors.Is(err, util.ErrNotFound) {
		s.renderClientNotFoundPage(w, r, err)
	} else {
		s.renderClientInternalServerErrorPage(w, r, err)
	}
}

func (s *httpdServer) handleClientAddSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	share, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nError500Message), true)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	share.ID = 0
	share.ShareID = util.GenerateUniqueID()
	share.LastUseAt = 0
	share.Username = claims.Username
	if share.Password == "" {
		if slices.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderAddUpdateSharePage(w, r, share,
				util.NewI18nError(util.NewValidationError("You are not allowed to share files/folders without password"), util.I18nErrorShareNoPwd),
				true)
			return
		}
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nErrorGetUser), true)
		return
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(share.ExpiresAt)); err != nil {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(
			err,
			util.I18nErrorShareExpirationOutOfRange,
			util.I18nErrorArgs(
				map[string]any{
					"val": time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration+1)).UnixMilli(),
					"formatParams": map[string]string{
						"year":  "numeric",
						"month": "numeric",
						"day":   "numeric",
					},
				},
			),
		), true)
		return
	}
	err = dataprovider.AddShare(share, claims.Username, ipAddr, claims.Role)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, share, util.NewI18nError(err, util.I18nErrorShareGeneric), true)
	}
}

func (s *httpdServer) handleClientUpdateSharePost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, claims.Username)
	if errors.Is(err, util.ErrNotFound) {
		s.renderClientNotFoundPage(w, r, err)
		return
	} else if err != nil {
		s.renderClientInternalServerErrorPage(w, r, err)
		return
	}
	updatedShare, err := getShareFromPostFields(r)
	if err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nError500Message), false)
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	updatedShare.ShareID = shareID
	updatedShare.Username = claims.Username
	if updatedShare.Password == redactedSecret {
		updatedShare.Password = share.Password
	}
	if updatedShare.Password == "" {
		if slices.Contains(claims.Permissions, sdk.WebClientShareNoPasswordDisabled) {
			s.renderAddUpdateSharePage(w, r, updatedShare,
				util.NewI18nError(util.NewValidationError("You are not allowed to share files/folders without password"), util.I18nErrorShareNoPwd),
				false)
			return
		}
	}
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nErrorGetUser), false)
		return
	}
	if err := user.CheckMaxShareExpiration(util.GetTimeFromMsecSinceEpoch(updatedShare.ExpiresAt)); err != nil {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(
			err,
			util.I18nErrorShareExpirationOutOfRange,
			util.I18nErrorArgs(
				map[string]any{
					"val": time.Now().Add(24 * time.Hour * time.Duration(user.Filters.MaxSharesExpiration+1)).UnixMilli(),
					"formatParams": map[string]string{
						"year":  "numeric",
						"month": "numeric",
						"day":   "numeric",
					},
				},
			),
		), false)
		return
	}
	err = dataprovider.UpdateShare(updatedShare, claims.Username, ipAddr, claims.Role)
	if err == nil {
		http.Redirect(w, r, webClientSharesPath, http.StatusSeeOther)
	} else {
		s.renderAddUpdateSharePage(w, r, updatedShare, util.NewI18nError(err, util.I18nErrorShareGeneric), false)
	}
}

func getAllShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, nil, util.I18nErrorInvalidToken, http.StatusForbidden)
		return
	}

	dataGetter := func(limit, offset int) ([]byte, int, error) {
		shares, err := dataprovider.GetShares(limit, offset, dataprovider.OrderASC, claims.Username)
		if err != nil {
			return nil, 0, err
		}
		data, err := json.Marshal(shares)
		return data, len(shares), err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func (s *httpdServer) handleClientGetShares(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	data := clientSharesPage{
		baseClientPage:      s.getBaseClientPageData(util.I18nSharesTitle, webClientSharesPath, w, r),
		BasePublicSharesURL: webClientPubSharesPath,
		BaseURL:             s.binding.BaseURL,
	}
	renderClientTemplate(w, templateClientShares, data)
}

func (s *httpdServer) handleClientGetProfile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientProfilePage(w, r, nil)
}

func (s *httpdServer) handleWebClientChangePwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientChangePasswordPage(w, r, nil)
}

func (s *httpdServer) handleWebClientProfilePost(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	err := r.ParseForm()
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := verifyCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	user, userMerged, err := dataprovider.GetUserVariants(claims.Username, "")
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nErrorGetUser))
		return
	}
	if !userMerged.CanUpdateProfile() {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(
			errors.New("you are not allowed to change anything"),
			util.I18nErrorNoPermissions,
		))
		return
	}
	if userMerged.CanManagePublicKeys() {
		for k := range r.Form {
			if hasPrefixAndSuffix(k, "public_keys[", "][public_key]") {
				r.Form.Add("public_keys", r.Form.Get(k))
			}
		}
		user.PublicKeys = r.Form["public_keys"]
	}
	if userMerged.CanManageTLSCerts() {
		for k := range r.Form {
			if hasPrefixAndSuffix(k, "tls_certs[", "][tls_cert]") {
				r.Form.Add("tls_certs", r.Form.Get(k))
			}
		}
		user.Filters.TLSCerts = r.Form["tls_certs"]
	}
	if userMerged.CanChangeAPIKeyAuth() {
		user.Filters.AllowAPIKeyAuth = r.Form.Get("allow_api_key_auth") != ""
	}
	if userMerged.CanChangeInfo() {
		user.Email = strings.TrimSpace(r.Form.Get("email"))
		user.Description = r.Form.Get("description")
		for k := range r.Form {
			if hasPrefixAndSuffix(k, "additional_emails[", "][additional_email]") {
				email := strings.TrimSpace(r.Form.Get(k))
				if email != "" {
					r.Form.Add("additional_emails", email)
				}
			}
		}
		user.Filters.AdditionalEmails = r.Form["additional_emails"]
	}
	err = dataprovider.UpdateUser(&user, dataprovider.ActionExecutorSelf, ipAddr, user.Role)
	if err != nil {
		s.renderClientProfilePage(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	s.renderClientMessagePage(w, r, util.I18nProfileTitle, http.StatusOK, nil, util.I18nProfileUpdated)
}

func (s *httpdServer) handleWebClientMFA(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientMFAPage(w, r)
}

func (s *httpdServer) handleWebClientTwoFactor(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorPage(w, r, nil)
}

func (s *httpdServer) handleWebClientTwoFactorRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	s.renderClientTwoFactorRecoveryPage(w, r, nil)
}

func getShareFromPostFields(r *http.Request) (*dataprovider.Share, error) {
	share := &dataprovider.Share{}
	if err := r.ParseForm(); err != nil {
		return share, util.NewI18nError(err, util.I18nErrorInvalidForm)
	}
	for k := range r.Form {
		if hasPrefixAndSuffix(k, "paths[", "][path]") {
			r.Form.Add("paths", r.Form.Get(k))
		}
	}

	share.Name = strings.TrimSpace(r.Form.Get("name"))
	share.Description = r.Form.Get("description")
	for _, p := range r.Form["paths"] {
		if strings.TrimSpace(p) != "" {
			share.Paths = append(share.Paths, p)
		}
	}
	share.Password = strings.TrimSpace(r.Form.Get("password"))
	share.AllowFrom = getSliceFromDelimitedValues(r.Form.Get("allowed_ip"), ",")
	scope, err := strconv.Atoi(r.Form.Get("scope"))
	if err != nil {
		return share, util.NewI18nError(err, util.I18nErrorShareScope)
	}
	share.Scope = dataprovider.ShareScope(scope)
	maxTokens, err := strconv.Atoi(r.Form.Get("max_tokens"))
	if err != nil {
		return share, util.NewI18nError(err, util.I18nErrorShareMaxTokens)
	}
	share.MaxTokens = maxTokens
	expirationDateMillis := int64(0)
	expirationDateString := strings.TrimSpace(r.Form.Get("expiration_date"))
	if expirationDateString != "" {
		expirationDate, err := time.Parse(webDateTimeFormat, expirationDateString)
		if err != nil {
			return share, util.NewI18nError(err, util.I18nErrorShareExpiration)
		}
		expirationDateMillis = util.GetTimeAsMsSinceEpoch(expirationDate)
	}
	share.ExpiresAt = expirationDateMillis
	return share, nil
}

func (s *httpdServer) handleWebClientForgotPwd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	if !smtp.IsEnabled() {
		s.renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderClientForgotPwdPage(w, r, nil)
}

func (s *httpdServer) handleWebClientForgotPwdPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	err := r.ParseForm()
	if err != nil {
		s.renderClientForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	username := strings.TrimSpace(r.Form.Get("username"))
	err = handleForgotPassword(r, username, false)
	if err != nil {
		s.renderClientForgotPwdPage(w, r, util.NewI18nError(err, util.I18nErrorPwdResetGeneric))
		return
	}
	http.Redirect(w, r, webClientResetPwdPath, http.StatusFound)
}

func (s *httpdServer) handleWebClientPasswordReset(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	if !smtp.IsEnabled() {
		s.renderClientNotFoundPage(w, r, errors.New("this page does not exist"))
		return
	}
	s.renderClientResetPwdPage(w, r, nil)
}

func (s *httpdServer) handleClientViewPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	name := r.URL.Query().Get("path")
	if name == "" {
		s.renderClientBadRequestPage(w, r, errors.New("no file specified"))
		return
	}
	name = util.CleanPath(name)
	data := viewPDFPage{
		commonBasePage: getCommonBasePage(r),
		Title:          path.Base(name),
		URL:            fmt.Sprintf("%s?path=%s&_=%d", webClientGetPDFPath, url.QueryEscape(name), time.Now().UTC().Unix()),
		Branding:       s.binding.webClientBranding(),
		Languages:      s.binding.languages(),
	}
	renderClientTemplate(w, templateClientViewPDF, data)
}

func (s *httpdServer) handleClientGetPDF(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		s.renderClientForbiddenPage(w, r, util.NewI18nError(errInvalidTokenClaims, util.I18nErrorInvalidToken))
		return
	}
	name := r.URL.Query().Get("path")
	if name == "" {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(errors.New("no file specified"), util.I18nError400Message))
		return
	}
	name = util.CleanPath(name)
	user, err := dataprovider.GetUserWithGroupSettings(claims.Username, "")
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nError500Title, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorGetUser), "")
		return
	}

	connID := xid.New().String()
	protocol := getProtocolFromRequest(r)
	connectionID := fmt.Sprintf("%v_%v", protocol, connID)
	if err := checkHTTPClientUser(&user, r, connectionID, false, false); err != nil {
		s.renderClientForbiddenPage(w, r, err)
		return
	}
	baseConn := common.NewBaseConnection(connID, protocol, util.GetHTTPLocalAddress(r), r.RemoteAddr, user)
	connection := newConnection(baseConn, w, r)
	if err = common.Connections.Add(connection); err != nil {
		s.renderClientMessagePage(w, r, util.I18nError429Title, http.StatusTooManyRequests,
			util.NewI18nError(err, util.I18nError429Message), "")
		return
	}
	defer common.Connections.Remove(connection.GetID())

	info, err := connection.Stat(name, 0)
	if err != nil {
		status := getRespStatus(err)
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle, status, util.NewI18nError(err, i18nFsMsg(status)), "")
		return
	}
	if info.IsDir() {
		s.renderClientBadRequestPage(w, r, util.NewI18nError(fmt.Errorf("%q is not a file", name), util.I18nErrorPDFMessage))
		return
	}
	connection.User.CheckFsRoot(connection.ID) //nolint:errcheck
	if err := s.ensurePDF(w, r, name, connection); err != nil {
		return
	}
	downloadFile(w, r, connection, name, info, true, nil) //nolint:errcheck
}

func (s *httpdServer) ensurePDF(w http.ResponseWriter, r *http.Request, name string, connection *Connection) error {
	reader, err := connection.getFileReader(name, 0, r.Method)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle,
			getRespStatus(err), util.NewI18nError(err, util.I18nError500Message), "")
		return err
	}
	defer reader.Close()

	var b bytes.Buffer
	_, err = io.CopyN(&b, reader, 128)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nErrorPDFTitle, getRespStatus(err),
			util.NewI18nError(err, util.I18nErrorPDFMessage), "")
		return err
	}
	if ctype := http.DetectContentType(b.Bytes()); ctype != "application/pdf" {
		connection.Log(logger.LevelDebug, "detected %q content type, expected PDF, file %q", ctype, name)
		err := fmt.Errorf("the file %q does not look like a PDF", name)
		s.renderClientBadRequestPage(w, r, util.NewI18nError(err, util.I18nErrorPDFMessage))
		return err
	}
	return nil
}

func (s *httpdServer) handleClientShareLoginGet(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	s.renderShareLoginPage(w, r, nil)
}

func (s *httpdServer) handleClientShareLoginPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	ipAddr := util.GetIPFromRemoteAddress(r.RemoteAddr)
	if err := r.ParseForm(); err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidForm))
		return
	}
	if err := verifyLoginCookieAndCSRFToken(r, s.csrfTokenAuth); err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCSRF))
		return
	}
	invalidateToken(r)
	shareID := getURLParam(r, "id")
	share, err := dataprovider.ShareExists(shareID, "")
	if err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nErrorInvalidCredentials))
		return
	}
	match, err := share.CheckCredentials(strings.TrimSpace(r.Form.Get("share_password")))
	if !match || err != nil {
		handleDefenderEventLoginFailed(ipAddr, dataprovider.ErrInvalidCredentials) //nolint:errcheck
		s.renderShareLoginPage(w, r, util.NewI18nError(dataprovider.ErrInvalidCredentials, util.I18nErrorInvalidCredentials))
		return
	}
	next := path.Clean(r.URL.Query().Get("next"))
	baseShareURL := path.Join(webClientPubSharesPath, share.ShareID)
	isRedirect, redirectTo := checkShareRedirectURL(next, baseShareURL)
	c := &jwt.Claims{
		Username: shareID,
	}
	if isRedirect {
		c.Ref = next
	}
	err = createAndSetCookie(w, r, c, s.tokenAuth, tokenAudienceWebShare, ipAddr)
	if err != nil {
		s.renderShareLoginPage(w, r, util.NewI18nError(err, util.I18nError500Message))
		return
	}
	if isRedirect {
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}
	s.renderClientMessagePage(w, r, util.I18nSharedFilesTitle, http.StatusOK, nil, util.I18nShareLoginOK)
}

func (s *httpdServer) handleClientShareLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)

	shareID := getURLParam(r, "id")
	ctx, claims, err := s.getShareClaims(r, shareID)
	if err != nil {
		s.renderClientMessagePage(w, r, util.I18nShareAccessErrorTitle, http.StatusForbidden,
			util.NewI18nError(err, util.I18nErrorInvalidToken), "")
		return
	}
	removeCookie(w, r.WithContext(ctx), webBaseClientPath)

	redirectURL := path.Join(webClientPubSharesPath, shareID, fmt.Sprintf("login?next=%s", url.QueryEscape(claims.Ref)))
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *httpdServer) handleClientSharedFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeRead}
	share, _, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	query := ""
	if r.URL.RawQuery != "" {
		query = "?" + r.URL.RawQuery
	}
	s.renderShareDownloadPage(w, r, &share, path.Join(webClientPubSharesPath, share.ShareID)+query)
}

func (s *httpdServer) handleClientCheckExist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	defer common.Connections.Remove(connection.GetID())

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))

	doCheckExist(w, r, connection, name)
}

func (s *httpdServer) handleClientShareCheckExist(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	validScopes := []dataprovider.ShareScope{dataprovider.ShareScopeReadWrite}
	share, connection, err := s.checkPublicShare(w, r, validScopes)
	if err != nil {
		return
	}
	if err := validateBrowsableShare(share, connection); err != nil {
		sendAPIResponse(w, r, err, "", getRespStatus(err))
		return
	}
	name, err := getBrowsableSharedPath(share.Paths[0], r)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}

	if err = common.Connections.Add(connection); err != nil {
		sendAPIResponse(w, r, err, "Unable to add connection", http.StatusTooManyRequests)
		return
	}
	defer common.Connections.Remove(connection.GetID())

	doCheckExist(w, r, connection, name)
}

func doCheckExist(w http.ResponseWriter, r *http.Request, connection *Connection, name string) {
	var filesList filesToCheck
	err := render.DecodeJSON(r.Body, &filesList)
	if err != nil {
		sendAPIResponse(w, r, err, "", http.StatusBadRequest)
		return
	}
	if len(filesList.Files) == 0 {
		sendAPIResponse(w, r, errors.New("files to be checked are mandatory"), "", http.StatusBadRequest)
		return
	}

	lister, err := connection.ListDir(name)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get directory contents", getMappedStatusCode(err))
		return
	}
	defer lister.Close()

	dataGetter := func(limit, _ int) ([]byte, int, error) {
		contents, err := lister.Next(limit)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if err != nil {
			return nil, 0, err
		}
		existing := make([]map[string]any, 0)
		for _, info := range contents {
			if slices.Contains(filesList.Files, info.Name()) {
				res := make(map[string]any)
				res["name"] = info.Name()
				if info.IsDir() {
					res["type"] = "1"
					res["size"] = ""
				} else {
					res["type"] = "2"
					res["size"] = info.Size()
				}
				existing = append(existing, res)
			}
		}
		data, err := json.Marshal(existing)
		count := limit
		if len(existing) == 0 {
			count = 0
		}
		return data, count, err
	}

	streamJSONArray(w, defaultQueryLimit, dataGetter)
}

func getWebTask(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	claims, err := jwt.FromContext(r.Context())
	if err != nil || claims.Username == "" {
		sendAPIResponse(w, r, err, "Invalid token claims", http.StatusBadRequest)
		return
	}
	taskID := getURLParam(r, "id")

	task, err := webTaskMgr.Get(taskID)
	if err != nil {
		sendAPIResponse(w, r, err, "Unable to get task", getMappedStatusCode(err))
		return
	}
	if task.User != claims.Username {
		sendAPIResponse(w, r, nil, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	render.JSON(w, r, task)
}

func taskDeleteDir(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}

	name := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      name,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeDeleteTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func taskRenameFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	oldName := connection.User.GetCleanedPath(r.URL.Query().Get("path"))
	newName := connection.User.GetCleanedPath(r.URL.Query().Get("target"))
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      oldName,
		Target:    newName,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeRenameTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func taskCopyFsEntry(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	connection, err := getUserConnection(w, r)
	if err != nil {
		return
	}
	source := r.URL.Query().Get("path")
	target := r.URL.Query().Get("target")
	copyFromSource := strings.HasSuffix(source, "/")
	copyInTarget := strings.HasSuffix(target, "/")
	source = connection.User.GetCleanedPath(source)
	target = connection.User.GetCleanedPath(target)
	if copyFromSource {
		source += "/"
	}
	if copyInTarget {
		target += "/"
	}
	task := webTaskData{
		ID:        connection.GetID(),
		User:      connection.GetUsername(),
		Path:      source,
		Target:    target,
		Timestamp: util.GetTimeAsMsSinceEpoch(time.Now()),
		Status:    0,
	}
	if err := webTaskMgr.Add(task); err != nil {
		common.Connections.Remove(connection.GetID())
		sendAPIResponse(w, r, nil, "Unable to create task", http.StatusInternalServerError)
		return
	}
	go executeCopyTask(connection, task)
	sendAPIResponse(w, r, nil, task.ID, http.StatusAccepted)
}

func executeDeleteTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK
	if err := conn.RemoveAll(task.Path); err != nil {
		status = getMappedStatusCode(err)
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "delete task finished, status: %d, update task err: %v", status, err)
}

func executeRenameTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK

	if !conn.IsSameResource(task.Path, task.Target) {
		if err := conn.Copy(task.Path, task.Target); err != nil {
			status = getMappedStatusCode(err)
			task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
			task.Status = status
			err = webTaskMgr.Add(task)
			conn.Log(logger.LevelDebug, "copy step for rename task finished, status: %d, update task err: %v", status, err)
			return
		}
		if err := conn.RemoveAll(task.Path); err != nil {
			status = getMappedStatusCode(err)
		}
	} else {
		if err := conn.Rename(task.Path, task.Target); err != nil {
			status = getMappedStatusCode(err)
		}
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "rename task finished, status: %d, update task err: %v", status, err)
}

func executeCopyTask(conn *Connection, task webTaskData) {
	done := make(chan bool)

	defer func() {
		close(done)
		common.Connections.Remove(conn.GetID())
	}()

	go keepAliveTask(task, done, 2*time.Minute)

	status := http.StatusOK
	if err := conn.Copy(task.Path, task.Target); err != nil {
		status = getMappedStatusCode(err)
	}

	task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
	task.Status = status
	err := webTaskMgr.Add(task)
	conn.Log(logger.LevelDebug, "copy task finished, status: %d, update task err: %v", status, err)
}

func keepAliveTask(task webTaskData, done chan bool, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			task.Timestamp = util.GetTimeAsMsSinceEpoch(time.Now())
			err := webTaskMgr.Add(task)
			logger.Debug(logSender, task.ID, "task timestamp updated, err: %v", err)
		}
	}
}
