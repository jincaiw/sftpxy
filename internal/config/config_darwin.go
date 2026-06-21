// SPDX-License-Identifier: MIT

//go:build darwin

package config

import "github.com/spf13/viper"

// macOS specific config search path
func setViperAdditionalConfigPaths() {
	viper.AddConfigPath("/usr/local/etc/SFTPxy")
}
