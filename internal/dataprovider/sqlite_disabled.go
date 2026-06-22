// SPDX-License-Identifier: MIT

//go:build nosqlite || !cgo

package dataprovider

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-sqlite")
}

func initializeSQLiteProvider(_ string) error {
	return errors.New("SQLite disabled at build time")
}
