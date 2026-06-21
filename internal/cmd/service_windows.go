// SPDX-License-Identifier: MIT

package cmd

import (
	"github.com/spf13/cobra"
)

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "Manage the SFTPxy Windows Service",
	}
)

func init() {
	rootCmd.AddCommand(serviceCmd)
}
