// SPDX-License-Identifier: MIT

//go:build linux

package config

import "github.com/spf13/viper"

// linux specific config search path
func setViperAdditionalConfigPaths() {
	viper.AddConfigPath("$HOME/.config/SFTPxy")
	viper.AddConfigPath("/etc/SFTPxy")
	viper.AddConfigPath("/usr/local/etc/SFTPxy")
}
