// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/service"
)

var (
	reloadCmd = &cobra.Command{
		Use:   "reload",
		Short: "Reload the SFTPxy Windows Service sending a \"paramchange\" request",
		Run: func(_ *cobra.Command, _ []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Reload()
			if err != nil {
				fmt.Printf("Error sending reload signal: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Reload signal sent!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(reloadCmd)
}
