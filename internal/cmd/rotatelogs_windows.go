// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/service"
)

var (
	rotateLogCmd = &cobra.Command{
		Use:   "rotatelogs",
		Short: "Signal to the running service to rotate the logs",
		Run: func(_ *cobra.Command, _ []string) {
			s := service.WindowsService{
				Service: service.Service{
					Shutdown: make(chan bool),
				},
			}
			err := s.RotateLogFile()
			if err != nil {
				fmt.Printf("Error sending rotate log file signal to the service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Rotate log file signal sent!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(rotateLogCmd)
}
