// SPDX-License-Identifier: MIT

//go:build noportable

package cmd

import "github.com/jincaiw/sftpxy/v2/internal/version"

func init() {
	version.AddFeature("-portable")
}
