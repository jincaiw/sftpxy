// SPDX-License-Identifier: MIT

package service

import (
	"os"
	"os/signal"

	"github.com/jincaiw/sftpxy/v2/internal/common"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
)

func registerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			logger.Debug(logSender, "", "Received interrupt request")
			plugin.Handler.Cleanup()
			common.WaitForTransfers(graceTime)
			os.Exit(0)
		}
	}()
}
