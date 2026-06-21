// SPDX-License-Identifier: MIT

//go:build !windows

package vfs

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isCrossDeviceError(err error) bool {
	return errors.Is(err, unix.EXDEV)
}

func isInvalidNameError(_ error) bool {
	return false
}
