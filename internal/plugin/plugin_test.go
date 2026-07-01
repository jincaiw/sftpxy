package plugin

import (
	"os"
	"os/exec"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	hashicorpplugin "github.com/hashicorp/go-plugin"
	"github.com/stretchr/testify/require"

	"github.com/jincaiw/sftpxy/sdk/plugin/auth"
)

type testAuthImpl struct{}

func (testAuthImpl) CheckUserAndPass(_, _, _, _ string, _ []byte) ([]byte, error) {
	return []byte("pass"), nil
}

func (testAuthImpl) CheckUserAndTLSCert(_, _, _, _ string, _ []byte) ([]byte, error) {
	return []byte("tls"), nil
}

func (testAuthImpl) CheckUserAndPublicKey(_, _, _, _ string, _ []byte) ([]byte, error) {
	return []byte("pubkey"), nil
}

func (testAuthImpl) CheckUserAndKeyboardInteractive(_, _, _ string, _ []byte) ([]byte, error) {
	return []byte("kbd"), nil
}

func (testAuthImpl) SendKeyboardAuthRequest(_, _, _, _ string, _ []string, _ []string, _ int32) (string, []string, []bool, int, int, error) {
	return "instruction", []string{"question"}, []bool{true}, 1, 0, nil
}

func TestPluginHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	mode := os.Getenv("PLUGIN_TEST_MODE")
	handshake := auth.Handshake
	if mode == "legacy" {
		handshake = auth.LegacyHandshake
	}

	hashicorpplugin.Serve(&hashicorpplugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]hashicorpplugin.Plugin{
			auth.PluginName: &auth.Plugin{Impl: testAuthImpl{}},
		},
		GRPCServer: hashicorpplugin.DefaultGRPCServer,
	})
}

func TestNewPluginClientSupportsNewAndLegacyHandshake(t *testing.T) {
	for _, mode := range []string{"new", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestPluginHelperProcess")
			cmd.Env = append(os.Environ(),
				"GO_WANT_HELPER_PROCESS=1",
				"PLUGIN_TEST_MODE="+mode,
			)

			client, err := newPluginClient(&hashicorpplugin.ClientConfig{
				HandshakeConfig: auth.Handshake,
				Plugins:         auth.PluginMap,
				Cmd:             cmd,
				SkipHostEnv:     true,
				AllowedProtocols: []hashicorpplugin.Protocol{
					hashicorpplugin.ProtocolGRPC,
				},
				Managed: false,
				Logger:  hclog.NewNullLogger(),
			}, &auth.LegacyHandshake)
			require.NoError(t, err)
			defer client.Kill()

			rpcClient, err := client.Client()
			require.NoError(t, err)
			raw, err := rpcClient.Dispense(auth.PluginName)
			require.NoError(t, err)

			service := raw.(auth.Authenticator)
			got, err := service.CheckUserAndPass("user", "pass", "127.0.0.1", "sftp", nil)
			require.NoError(t, err)
			require.Equal(t, []byte("pass"), got)
		})
	}
}
