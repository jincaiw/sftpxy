// SPDX-License-Identifier: MIT

package cmd

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/jincaiw/sftpxy/v2/internal/config"
	"github.com/jincaiw/sftpxy/v2/internal/dataprovider"
	"github.com/jincaiw/sftpxy/v2/internal/logger"
	"github.com/jincaiw/sftpxy/v2/internal/smtp"
	"github.com/jincaiw/sftpxy/v2/internal/util"
)

var (
	smtpTestRecipient string
	smtpTestCmd       = &cobra.Command{
		Use:   "smtptest",
		Short: "Test the SMTP configuration",
		Long: `SFTPxy will try to send a test email to the specified recipient.
If the SMTP configuration is correct you should receive this email.`,
		Run: func(_ *cobra.Command, _ []string) {
			logger.DisableLogger()
			logger.EnableConsoleLogger(zerolog.DebugLevel)
			configDir = util.CleanDirInput(configDir)
			err := config.LoadConfig(configDir, configFile)
			if err != nil {
				logger.ErrorToConsole("Unable to load configuration: %v", err)
				os.Exit(1)
			}
			providerConf := config.GetProviderConf()
			err = dataprovider.Initialize(providerConf, configDir, false)
			if err != nil {
				logger.ErrorToConsole("error initializing data provider: %v", err)
				os.Exit(1)
			}
			smtpConfig := config.GetSMTPConfig()
			smtpConfig.Debug = 1
			err = smtpConfig.Initialize(configDir, false)
			if err != nil {
				logger.ErrorToConsole("unable to initialize SMTP configuration: %v", err)
				os.Exit(1)
			}
			err = smtp.SendEmail([]string{smtpTestRecipient}, nil, "SFTPxy - Testing Email Settings", "It appears your SFTPxy email is setup correctly!",
				smtp.EmailContentTypeTextPlain)
			if err != nil {
				logger.WarnToConsole("Error sending email: %v", err)
				os.Exit(1)
			}
			logger.InfoToConsole("No errors were reported while sending the test email. Please check your inbox to make sure.")
		},
	}
)

func init() {
	addConfigFlags(smtpTestCmd)
	smtpTestCmd.Flags().StringVar(&smtpTestRecipient, "recipient", "", `email address to send the test e-mail to`)
	smtpTestCmd.MarkFlagRequired("recipient") //nolint:errcheck

	rootCmd.AddCommand(smtpTestCmd)
}
