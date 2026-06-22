// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/service"
)

var (
	statusCmd = &cobra.Command{
		Use:   "status",
		Short: "Retrieve the status for the SFTPxy Windows Service",
		Run: func(_ *cobra.Command, _ []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			status, err := s.Status()
			if err != nil {
				fmt.Printf("Error querying service status: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service status: %q\r\n", status.String())
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(statusCmd)
}
