package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdInstallScriptStagesRuntimeResources(t *testing.T) {
	t.Parallel()

	content := readFile(t, filepath.Join("systemd", "install.sh"))
	required := []string{
		`SHARE_DIR="/usr/local/share/sftpxy"`,
		`CERT_DIR="$CONFIG_DIR/certs"`,
		`HOST_KEY_PATH="$DATA_DIR/keys/ssh_host_ed25519_key"`,
		`cp -R "$REPO_ROOT/migrations" "$SHARE_DIR/migrations"`,
		`"$BINARY_PATH" generate-hostkey --output "$HOST_KEY_PATH"`,
		`"$BINARY_PATH" validate-config --config "$CONFIG_DIR/config.yaml" --strict-production`,
		`cat > "$CONFIG_DIR/config.yaml" <<EOF`,
		`log_path: "/var/log/sftpxy/sftpxy.log"`,
		`connection_string: "/var/lib/sftpxy/sftpxy.db"`,
		`static_path: "/usr/local/share/sftpxy/web/dist"`,
		`session_secret: "$SESSION_SECRET"`,
		`cors_origins:`,
		`    - "https://files.example.com"`,
	}
	for _, needle := range required {
		if !strings.Contains(content, needle) {
			t.Fatalf("systemd install script missing %q", needle)
		}
	}

	if strings.Contains(content, `cp config.yaml.example "$CONFIG_DIR/config.yaml"`) {
		t.Fatal("systemd install script should not copy the development config template verbatim")
	}
	if strings.Contains(content, `change-this-to-a-random-secret`) {
		t.Fatal("systemd install script should not ship the development session secret placeholder")
	}
	if strings.Contains(content, `    - "*"`) {
		t.Fatal("systemd install script should not ship wildcard CORS origins in production config")
	}
	if strings.Contains(content, `  host_keys: []`) {
		t.Fatal("systemd install script should not generate a production config with empty ssh.host_keys")
	}
}

func TestSystemdServiceUsesInstalledWorkingDirectory(t *testing.T) {
	t.Parallel()

	content := readFile(t, filepath.Join("systemd", "sftpxy.service"))
	if !strings.Contains(content, `WorkingDirectory=/usr/local/share/sftpxy`) {
		t.Fatal("systemd service should use /usr/local/share/sftpxy as the working directory")
	}
	if !strings.Contains(content, `ExecStart=/usr/local/bin/sftpxy --config /etc/sftpxy/config.yaml`) {
		t.Fatal("systemd service should start the current binary with the generated config")
	}
	if !strings.Contains(content, `UMask=0077`) {
		t.Fatal("systemd service should set a restrictive umask for production")
	}
}

func TestWindowsInstallScriptUsesServiceWrapper(t *testing.T) {
	t.Parallel()

	content := readFile(t, filepath.Join("windows", "install.ps1"))
	required := []string{
		`sftpxy-service.exe`,
		`Copying migrations...`,
		`Convert-ToYamlPath`,
		`./data/sftpxy.db`,
		`./logs/sftpxy.log`,
		`install --binary $DestBinary --config $ConfigPath --workdir $InstallPath`,
	}
	for _, needle := range required {
		if !strings.Contains(content, needle) {
			t.Fatalf("windows install script missing %q", needle)
		}
	}

	if strings.Contains(content, `& "$DestBinary" install`) {
		t.Fatal("windows install script should not call unsupported service commands on sftpxy.exe")
	}
}

func TestWindowsServiceWrapperPassesBinaryConfigAndWorkDir(t *testing.T) {
	t.Parallel()

	content := readFile(t, filepath.Join("windows", "service.go"))
	required := []string{
		`exec.Command(s.cfg.binaryPath, "--config", s.cfg.configPath)`,
		`cmd.Dir = s.cfg.workDir`,
		`"--binary", cfg.binaryPath, "--config", cfg.configPath, "--workdir", cfg.workDir`,
	}
	for _, needle := range required {
		if !strings.Contains(content, needle) {
			t.Fatalf("windows service wrapper missing %q", needle)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}
