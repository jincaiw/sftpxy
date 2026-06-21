// SPDX-License-Identifier: MIT

package cmd

import (
	"os"
	"os/signal"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
)

func registerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	go func() {
		for range c {
			logger.DebugToConsole("Received interrupt request")
			plugin.Handler.Cleanup()
			os.Exit(0)
		}
	}()
}
