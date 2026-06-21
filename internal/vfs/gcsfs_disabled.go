// SPDX-License-Identifier: MIT

//go:build nogcs

package vfs

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-gcs")
}

// NewGCSFs returns an error, GCS is disabled
func NewGCSFs(_, _, _ string, _ GCSFsConfig) (Fs, error) {
	return nil, errors.New("Google Cloud Storage disabled at build time")
}
