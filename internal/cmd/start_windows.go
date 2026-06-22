// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/service"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

var (
	startCmd = &cobra.Command{
		Use:   "start",
		Short: "Start the SFTPxy Windows Service",
		Run: func(_ *cobra.Command, _ []string) {
			configDir = util.CleanDirInput(configDir)
			checkServeParamsFromEnvFiles(configDir)
			service.SetGraceTime(graceTime)
			s := service.Service{
				ConfigDir:         configDir,
				ConfigFile:        configFile,
				LogFilePath:       logFilePath,
				LogMaxSize:        logMaxSize,
				LogMaxBackups:     logMaxBackups,
				LogMaxAge:         logMaxAge,
				LogCompress:       logCompress,
				LogLevel:          logLevel,
				LogUTCTime:        logUTCTime,
				LoadDataFrom:      loadDataFrom,
				LoadDataMode:      loadDataMode,
				LoadDataQuotaScan: loadDataQuotaScan,
				LoadDataClean:     loadDataClean,
				Shutdown:          make(chan bool),
			}
			winService := service.WindowsService{
				Service: s,
			}
			err := winService.RunService()
			if err != nil {
				fmt.Printf("Error starting service: %v\r\n", err)
				os.Exit(1)
			} else {
				fmt.Printf("Service started!\r\n")
			}
		},
	}
)

func init() {
	serviceCmd.AddCommand(startCmd)
	addServeFlags(startCmd)
}
