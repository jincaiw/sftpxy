// SPDX-License-Identifier: MIT

//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/plugin"
)

func registerSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range c {
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				logger.DebugToConsole("Received interrupt request")
				plugin.Handler.Cleanup()
				os.Exit(0)
			}
		}
	}()
}
