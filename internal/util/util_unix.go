// SPDX-License-Identifier: MIT

//go:build unix

package util

import (
	"strconv"
	"syscall"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

// SetUmask sets the specified umask
func SetUmask(val string) {
	if val == "" {
		return
	}
	umask, err := strconv.ParseUint(val, 8, 31)
	if err != nil {
		logger.Error(logSender, "", "invalid umask %q: %v", val, err)
		return
	}
	logger.Debug(logSender, "", "set umask to: %d, configured value: %q", umask, val)
	syscall.Umask(int(umask))
}
