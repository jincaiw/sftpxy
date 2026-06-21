// SPDX-License-Identifier: MIT

//go:build noazblob

package vfs

import (
	"errors"

	"github.com/jincaiw/sftpxy/v2/internal/version"
)

func init() {
	version.AddFeature("-azblob")
}

// NewAzBlobFs returns an error, Azure Blob storage is disabled
func NewAzBlobFs(_, _, _ string, _ AzBlobFsConfig) (Fs, error) {
	return nil, errors.New("Azure Blob Storage disabled at build time")
}
