// SPDX-License-Identifier: MIT

//go:build nos3

package vfs

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-s3")
}

// NewS3Fs returns an error, S3 is disabled
func NewS3Fs(_, _, _ string, _ S3FsConfig) (Fs, error) {
	return nil, errors.New("S3 disabled at build time")
}
