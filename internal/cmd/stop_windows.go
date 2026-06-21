// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/service"
)

var (
	stopCmd = &cobra.Command{
		Use:   "stop",
		Short: "Stop the SFTPxy Windows Service",
		Run: func(_ *cobra.Command, _ []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.Stop()
			if err != nil {
				fmt.Printf("Error stopping service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service stopped!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(stopCmd)
}
