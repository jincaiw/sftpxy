// SPDX-License-Identifier: MIT

//go:build nobolt

package dataprovider

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-bolt")
}

func initializeBoltProvider(_ string) error {
	return errors.New("bolt disabled at build time")
}
