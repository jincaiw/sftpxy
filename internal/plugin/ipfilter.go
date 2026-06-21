// SPDX-License-Identifier: MIT

package plugin

import (
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/jincaiw/sftpxy/sdk/plugin/ipfilter"

	"github.com/jincaiw/sftpxy/v2/internal/logger"
)

type ipFilterPlugin struct {
	config Config
	filter ipfilter.Filter
	client *plugin.Client
}

func newIPFilterPlugin(config Config) (*ipFilterPlugin, error) {
	p := &ipFilterPlugin{
		config: config,
	}
	if err := p.initialize(); err != nil {
		logger.Warn(logSender, "", "unable to create IP filter plugin: %v, config %+v", err, config)
		return nil, err
	}
	return p, nil
}

func (p *ipFilterPlugin) exited() bool {
	return p.client.Exited()
}

func (p *ipFilterPlugin) cleanup() {
	p.client.Kill()
}

func (p *ipFilterPlugin) initialize() error {
	logger.Debug(logSender, "", "create new IP filter plugin %q", p.config.Cmd)
	killProcess(p.config.Cmd)
	secureConfig, err := p.config.getSecureConfig()
	if err != nil {
		return err
	}
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: ipfilter.Handshake,
		Plugins:         ipfilter.PluginMap,
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
				Name:        fmt.Sprintf("%v.%v", logSender, ipfilter.PluginName),
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
	raw, err := rpcClient.Dispense(ipfilter.PluginName)
	if err != nil {
		logger.Debug(logSender, "", "unable to get plugin %v from rpc client for command %q: %v",
			ipfilter.PluginName, p.config.Cmd, err)
		return err
	}

	p.client = client
	p.filter = raw.(ipfilter.Filter)

	return nil
}
