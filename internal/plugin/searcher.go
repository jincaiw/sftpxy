// SPDX-License-Identifier: MIT

package plugin

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/jincaiw/sftpxy/sdk/plugin/eventsearcher"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

type searcherPlugin struct {
	config    Config
	searchear eventsearcher.Searcher
	client    *plugin.Client
}

func newSearcherPlugin(config Config) (*searcherPlugin, error) {
	p := &searcherPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create events searcher plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *searcherPlugin) exited() bool {
	return p.client.Exited()
}

func (p *searcherPlugin) cleanup() {
	p.client.Kill()
}

func (p *searcherPlugin) initialize() error {
	killProcess(p.config.Cmd)
	logger.Debug(logSender, "", "create new searcher plugin %q", p.config.Cmd)
	secureConfig, err := p.config.getSecureConfig()
	if err != nil {
		return err
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: eventsearcher.Handshake,
		Plugins:         eventsearcher.PluginMap,
		Cmd:             p.config.getCommand(),
		SkipHostEnv:     true,
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolGRPC,
		},
		AutoMTLS:     p.config.AutoMTLS,
		SecureConfig: secureConfig,
		Managed:      false,
		Logger: &logger.HCLogAdapter{
			Logger: hclog.New(&hclog.LoggerOptions{
				Name:        fmt.Sprintf("%v.%v", logSender, eventsearcher.PluginName),
				Level:       pluginsLogLevel,
				DisableTime: true,
			}),
		},
	})
	rpcClient, err := client.Client()
	if err != nil {
		logger.Debug(logSender, "", "unable to get rpc client for plugin %q: %v", p.config.Cmd, err)
		return err
	}
	raw, err := rpcClient.Dispense(eventsearcher.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %q: %v",
			eventsearcher.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.searchear = raw.(eventsearcher.Searcher)

	return nil
}
