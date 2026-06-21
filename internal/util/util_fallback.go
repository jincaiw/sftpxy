// SPDX-License-Identifier: MIT

//go:build !unix

package util

import (
	"runtime"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

// SetUmask sets the specified umask
func SetUmask(val string) {
	if val == "" {
		return
	}
	logger.Debug(logSender, "", "umask not supported on OS %q", runtime.GOOS)
}
