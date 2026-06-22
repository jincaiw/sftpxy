// SPDX-License-Identifier: MIT

//go:build !unixcrypt || !cgo

package dataprovider

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-unixcrypt")
}

func compareYescryptPassword(_, _ string) (bool, error) {
	return false, errors.New("yescrypt hash format is not supported or disabled")
}
