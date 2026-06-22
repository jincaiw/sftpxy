// SPDX-License-Identifier: MIT

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/version"
)

var (
	manDir    string
	genManCmd = &cobra.Command{
		Use:   "man",
		Short: "Generate man pages for SFTPxy",
		Long: `This command automatically generates up-to-date man pages of SFTPxy's
command-line interface.
By default, it creates the man page files in the "man" directory under the
current directory.
`,
		Run: func(cmd *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			if _, err := os.Stat(manDir); errors.Is(err, fs.ErrNotExist) {
				err = os.MkdirAll(manDir, os.ModePerm)
				if err != nil {
					logger.WarnToConsole("Unable to generate man page files: %v", err)
					os.Exit(1)
				}
			}
			header := &doc.GenManHeader{
				Section: "1",
				Manual:  "SFTPxy Manual",
				Source:  fmt.Sprintf("SFTPxy %v", version.Get().Version),
			}
			cmd.Root().DisableAutoGenTag = true
			err := doc.GenManTree(cmd.Root(), header, manDir)
			if err != nil {
				logger.WarnToConsole("Unable to generate man page files: %v", err)
				os.Exit(1)
			}
		},
	}
)

func init() {
	genManCmd.Flags().StringVarP(&manDir, "dir", "d", "man", "The directory to write the man pages")
	genCmd.AddCommand(genManCmd)
}
