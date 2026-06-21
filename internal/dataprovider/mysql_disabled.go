// SPDX-License-Identifier: MIT

//go:build nomysql

package dataprovider

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-mysql")
}

func initializeMySQLProvider() error {
	return errors.New("MySQL disabled at build time")
}
