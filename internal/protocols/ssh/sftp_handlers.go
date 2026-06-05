package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jincaiw/sftpxy/internal/hooks"
	"github.com/jincaiw/sftpxy/internal/policy"
	"github.com/jincaiw/sftpxy/internal/repository"
	"github.com/pkg/sftp"
)

type sftpHandlers struct {
	server      *Server
	user        *repository.User
	clientIP    net.IP
	basePath    string
	hookManager *hooks.HookManager
}

func newSFTPHandlers(server *Server, user *repository.User, clientIP net.IP) sftp.Handlers {
	handler := &sftpHandlers{
		server:      server,
		user:        user,
		clientIP:    clientIP,
		basePath:    user.HomeDir,
		hookManager: server.hookManager,
	}

	return sftp.Handlers{
		FileGet:  handler,
		FilePut:  handler,
		FileCmd:  handler,
		FileList: handler,
	}
}

func (h *sftpHandlers) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	fullPath, virtualPath, err := h.resolve(req.Filepath)
	if err != nil {
		return nil, err
	}
	if err := h.checkAllowed(policy.OpDownload, virtualPath, 0); err != nil {
		return nil, err
	}

	if hookErr := h.fireFileEvent(hooks.FileEventPreDownload, virtualPath, 0, false); hookErr != nil {
		return nil, hookErr
	}

	file, err := os.Open(fullPath)
	h.logCommand("Get", virtualPath, "", err)

	if err == nil {
		h.fireFileEventAsync(hooks.FileEventDownload, virtualPath, 0, false)
	}

	return file, err
}

func (h *sftpHandlers) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	file, err := h.openFile(req)
	if err != nil {
		return nil, err
	}

	if req.Pflags().Write || req.Pflags().Creat || req.Pflags().Trunc {
		h.fireFileEventAsync(hooks.FileEventUpload, req.Filepath, 0, false)
	}

	return file, nil
}

func (h *sftpHandlers) OpenFile(req *sftp.Request) (sftp.WriterAtReaderAt, error) {
	return h.openFile(req)
}

func (h *sftpHandlers) openFile(req *sftp.Request) (*os.File, error) {
	flags := req.Pflags()
	if flags.Append {
		return nil, fmt.Errorf("append is not supported in minimal SFTP mode")
	}

	fullPath, virtualPath, err := h.resolve(req.Filepath)
	if err != nil {
		return nil, err
	}

	op := policy.OpDownload
	if flags.Write || flags.Creat || flags.Trunc {
		op = policy.OpUpload
	}
	if err := h.checkAllowed(op, virtualPath, 0); err != nil {
		return nil, err
	}

	if op == policy.OpUpload {
		if hookErr := h.fireFileEvent(hooks.FileEventPreUpload, virtualPath, 0, false); hookErr != nil {
			return nil, hookErr
		}
	}

	if flags.Creat {
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return nil, err
		}
	}

	file, err := os.OpenFile(fullPath, osOpenFlags(flags), 0644)
	h.logCommand("Open", virtualPath, "", err)
	return file, err
}

func (h *sftpHandlers) Filecmd(req *sftp.Request) error {
	fullPath, virtualPath, err := h.resolve(req.Filepath)
	if err != nil {
		return err
	}

	var commandErr error
	switch req.Method {
	case "Setstat":
		commandErr = h.handleSetstat(fullPath, virtualPath, req)
	case "Rename":
		_, _, commandErr = h.resolve(req.Target)
		if commandErr == nil {
			commandErr = h.checkAllowed(policy.OpRename, virtualPath, 0)
		}
		if commandErr == nil {
			if hookErr := h.fireFileEvent(hooks.FileEventRename, virtualPath, 0, false); hookErr != nil {
				commandErr = hookErr
			}
		}
		if commandErr == nil {
			targetFullPath, _, resolveErr := h.resolve(req.Target)
			if resolveErr != nil {
				commandErr = resolveErr
			} else {
				commandErr = os.Rename(fullPath, targetFullPath)
			}
		}
	case "Rmdir":
		commandErr = h.checkAllowed(policy.OpRmdir, virtualPath, 0)
		if commandErr == nil {
			if hookErr := h.fireFileEvent(hooks.FileEventPreDelete, virtualPath, 0, true); hookErr != nil {
				commandErr = hookErr
			}
		}
		if commandErr == nil {
			commandErr = os.Remove(fullPath)
			if commandErr == nil {
				h.fireFileEventAsync(hooks.FileEventRmdir, virtualPath, 0, true)
			}
		}
	case "Remove":
		commandErr = h.checkAllowed(policy.OpDelete, virtualPath, 0)
		if commandErr == nil {
			if hookErr := h.fireFileEvent(hooks.FileEventPreDelete, virtualPath, 0, false); hookErr != nil {
				commandErr = hookErr
			}
		}
		if commandErr == nil {
			commandErr = os.Remove(fullPath)
			if commandErr == nil {
				h.fireFileEventAsync(hooks.FileEventDelete, virtualPath, 0, false)
			}
		}
	case "Mkdir":
		commandErr = h.checkAllowed(policy.OpMkdir, virtualPath, 0)
		if commandErr == nil {
			commandErr = os.MkdirAll(fullPath, 0755)
			if commandErr == nil {
				h.fireFileEventAsync(hooks.FileEventMkdir, virtualPath, 0, true)
			}
		}
	default:
		commandErr = fmt.Errorf("unsupported SFTP command %s", req.Method)
	}

	h.logCommand(req.Method, virtualPath, req.Target, commandErr)
	return commandErr
}

func (h *sftpHandlers) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	fullPath, virtualPath, err := h.resolve(req.Filepath)
	if err != nil {
		return nil, err
	}

	if err := h.checkAllowed(policy.OpList, virtualPath, 0); err != nil {
		return nil, err
	}

	switch req.Method {
	case "List":
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			h.logCommand("List", virtualPath, "", err)
			return nil, err
		}

		infos := make([]os.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			infos = append(infos, info)
		}
		h.logCommand("List", virtualPath, "", nil)
		return &osFileInfoLister{entries: infos}, nil

	case "Stat", "Lstat":
		info, err := os.Stat(fullPath)
		if err != nil {
			h.logCommand(req.Method, virtualPath, "", err)
			return nil, err
		}
		h.logCommand(req.Method, virtualPath, "", nil)
		return &osFileInfoLister{entries: []os.FileInfo{info}}, nil
	default:
		return nil, fmt.Errorf("unsupported SFTP listing operation %s", req.Method)
	}
}

func (h *sftpHandlers) RealPath(requestPath string) (string, error) {
	_, virtualPath, err := h.resolve(requestPath)
	if err != nil {
		return "", err
	}
	return virtualPath, nil
}

func (h *sftpHandlers) handleSetstat(fullPath, virtualPath string, req *sftp.Request) error {
	attrFlags := req.AttrFlags()
	attrs := req.Attributes()

	if attrFlags.Size {
		if err := h.checkAllowed(policy.OpTruncate, virtualPath, int64(attrs.Size)); err != nil {
			return err
		}
		if err := os.Truncate(fullPath, int64(attrs.Size)); err != nil {
			return err
		}
	}

	if attrFlags.Permissions {
		if err := h.checkAllowed(policy.OpChmod, virtualPath, 0); err != nil {
			return err
		}
		if err := os.Chmod(fullPath, attrs.FileMode()); err != nil {
			return err
		}
	}

	if attrFlags.Acmodtime {
		if err := h.checkAllowed(policy.OpChtimes, virtualPath, 0); err != nil {
			return err
		}
		if err := os.Chtimes(fullPath, attrs.AccessTime(), attrs.ModTime()); err != nil {
			return err
		}
	}

	return nil
}

func (h *sftpHandlers) resolve(requestPath string) (string, string, error) {
	virtualPath := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	fullPath := filepath.Join(h.basePath, filepath.FromSlash(strings.TrimPrefix(virtualPath, "/")))

	absBase, err := filepath.Abs(h.basePath)
	if err != nil {
		return "", "", err
	}
	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", "", err
	}
	rel, err := filepath.Rel(absBase, absFullPath)
	if err != nil {
		return "", "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", syscall.EPERM
	}

	return absFullPath, virtualPath, nil
}

func (h *sftpHandlers) checkAllowed(op policy.OperationType, filePath string, size int64) error {
	if h.server.policyEngine == nil {
		return nil
	}

	allowed, err := h.server.policyEngine.CanPerformOperation(context.Background(), policy.OperationRequest{
		UserID:    h.user.ID,
		Username:  h.user.Username,
		Protocol:  "sftp",
		ClientIP:  h.clientIP,
		Operation: op,
		FilePath:  filePath,
		FileSize:  size,
	})
	if err != nil || !allowed {
		if err != nil {
			return err
		}
		return syscall.EPERM
	}

	return nil
}

func (h *sftpHandlers) logCommand(command, filePath, newPath string, err error) {
	if h.server.auditRepo == nil {
		return
	}

	result := "success"
	errMsg := ""
	if err != nil {
		result = "failure"
		errMsg = err.Error()
	}

	_ = h.server.auditRepo.CreateCommandLog(context.Background(), command, h.user.Username, "sftp", filePath, newPath, result, errMsg)
}

func osOpenFlags(flags sftp.FileOpenFlags) int {
	openFlags := 0
	switch {
	case flags.Read && flags.Write:
		openFlags |= os.O_RDWR
	case flags.Write:
		openFlags |= os.O_WRONLY
	default:
		openFlags |= os.O_RDONLY
	}

	if flags.Creat {
		openFlags |= os.O_CREATE
	}
	if flags.Trunc {
		openFlags |= os.O_TRUNC
	}
	if flags.Excl {
		openFlags |= os.O_EXCL
	}

	return openFlags
}

type osFileInfoLister struct {
	entries []os.FileInfo
}

func (l *osFileInfoLister) ListAt(dest []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.entries)) {
		return 0, io.EOF
	}

	n := copy(dest, l.entries[offset:])
	if int(offset)+n >= len(l.entries) {
		return n, io.EOF
	}
	return n, nil
}

func (h *sftpHandlers) fireFileEvent(event hooks.FileEvent, filePath string, fileSize int64, isDir bool) error {
	if h.hookManager == nil {
		return nil
	}
	return h.hookManager.OnFileEvent(context.Background(), event, &hooks.FileEventPayload{
		Event:     event,
		FilePath:  filePath,
		FileName:  filepath.Base(filePath),
		FileSize:  fileSize,
		Username:  h.user.Username,
		UserID:    h.user.ID,
		Protocol:  "sftp",
		ClientIP:  h.clientIP.String(),
		IsDir:     isDir,
		Timestamp: time.Now(),
	})
}

func (h *sftpHandlers) fireFileEventAsync(event hooks.FileEvent, filePath string, fileSize int64, isDir bool) {
	if h.hookManager == nil {
		return
	}
	go func() {
		_ = h.hookManager.OnFileEvent(context.Background(), event, &hooks.FileEventPayload{
			Event:     event,
			FilePath:  filePath,
			FileName:  filepath.Base(filePath),
			FileSize:  fileSize,
			Username:  h.user.Username,
			UserID:    h.user.ID,
			Protocol:  "sftp",
			ClientIP:  h.clientIP.String(),
			IsDir:     isDir,
			Timestamp: time.Now(),
		})
	}()
}
