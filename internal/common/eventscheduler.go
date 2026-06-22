// SPDX-License-Identifier: MIT

package common

import (
	"time"

	"github.com/robfig/cron/v3"

	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

var (
	eventScheduler *cron.Cron
)

func stopEventScheduler() {
	if eventScheduler != nil {
		eventScheduler.Stop()
		eventScheduler = nil
	}
}

func startEventScheduler() {
	stopEventScheduler()

	options := []cron.Option{
		cron.WithLogger(cron.DiscardLogger),
	}
	if !dataprovider.UseLocalTime() {
		eventManagerLog(logger.LevelDebug, "use UTC time for the scheduler")
		options = append(options, cron.WithLocation(time.UTC))
	}

	eventScheduler = cron.New(options...)
	eventManager.loadRules()
	_, err := eventScheduler.AddFunc("@every 10m", eventManager.loadRules)
	util.PanicOnError(err)
	eventScheduler.Start()
}
