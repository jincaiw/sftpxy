// SPDX-License-Identifier: MIT

//go:build nopgsql

package dataprovider

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-pgsql")
}

func initializePGSQLProvider() error {
	return errors.New("PostgreSQL disabled at build time")
}
