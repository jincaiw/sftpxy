// SPDX-License-Identifier: MIT

package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/config"
	"github.com/jincaiw/sftpxy/v2/internal/httpclient"
	"github.com/jincaiw/sftpxy/v2/internal/httpd"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

func getHealthzURLFromBindings(bindings []httpd.Binding) string {
	for _, b := range bindings {
		if b.Port > 0 && b.IsValid() {
			var url string
			if b.EnableHTTPS {
				url = "https://"
			} else {
				url = "http://"
			}
			if b.Address == "" {
				url += "127.0.0.1"
			} else {
				url += b.Address
			}
			url += fmt.Sprintf(":%d", b.Port)
			url += "/healthz"
			return url
		}
	}
	return ""
}

var (
	pingCmd = &cobra.Command{
		Use:   "ping",
		Short: "Issues an health check to SFTPxy",
		Long: `This command is only useful in environments where system commands like
"curl", "wget" and similar are not available.
Checks over UNIX domain sockets are not supported`,
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.WarnToConsole("Unable to load configuration: %v", err)
				os.Exit(1)
			}
			httpConfig := config.GetHTTPConfig()
			err = httpConfig.Initialize(configDir)
			if err != nil {
				logger.ErrorToConsole("error initializing http client: %v", err)
				os.Exit(1)
			}
			telemetryConfig := config.GetTelemetryConfig()
			var url string
			if telemetryConfig.BindPort > 0 {
				if telemetryConfig.CertificateFile != "" && telemetryConfig.CertificateKeyFile != "" {
					url += "https://"
				} else {
					url += "http://"
				}
				if telemetryConfig.BindAddress == "" {
					url += "127.0.0.1"
				} else {
					url += telemetryConfig.BindAddress
				}
				url += fmt.Sprintf(":%d", telemetryConfig.BindPort)
				url += "/healthz"
			}
			if url == "" {
				httpdConfig := config.GetHTTPDConfig()
				url = getHealthzURLFromBindings(httpdConfig.Bindings)
			}
			if url == "" {
				logger.ErrorToConsole("no suitable configuration found, please enable the telemetry server or REST API over HTTP/S")
				os.Exit(1)
			}

			logger.DebugToConsole("Health Check URL %q", url)
			resp, err := httpclient.RetryableGet(url)
			if err != nil {
				logger.ErrorToConsole("Unable to connect to SFTPxy: %v", err)
				os.Exit(1)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				logger.ErrorToConsole("Unexpected status code %d", resp.StatusCode)
				os.Exit(1)
			}
			logger.InfoToConsole("OK")
		},
	}
)

func init() {
	addConfigFlags(pingCmd)
	rootCmd.AddCommand(pingCmd)
}
