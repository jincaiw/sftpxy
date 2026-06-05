//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName        = "SFTPxy"
	serviceDescription = "SFTPxy Enterprise File Transfer Platform"
	stopTimeout        = 15 * time.Second
)

type serviceConfig struct {
	binaryPath string
	configPath string
	workDir    string
}

type sftpxyService struct {
	cfg  serviceConfig
	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan error
}

func defaultServiceConfig() serviceConfig {
	exePath, err := os.Executable()
	if err != nil {
		return serviceConfig{
			binaryPath: "sftpxy.exe",
			configPath: "config.yaml",
			workDir:    ".",
		}
	}

	exeDir := filepath.Dir(exePath)
	return serviceConfig{
		binaryPath: filepath.Join(exeDir, "sftpxy.exe"),
		configPath: filepath.Join(exeDir, "config.yaml"),
		workDir:    exeDir,
	}
}

func parseServiceConfig(args []string) (serviceConfig, error) {
	cfg := defaultServiceConfig()
	fs := flag.NewFlagSet("sftpxy-service", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.binaryPath, "binary", cfg.binaryPath, "path to sftpxy.exe")
	fs.StringVar(&cfg.configPath, "config", cfg.configPath, "path to config.yaml")
	fs.StringVar(&cfg.workDir, "workdir", cfg.workDir, "working directory for runtime resources")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.binaryPath = normalizePath(cfg.binaryPath)
	cfg.configPath = normalizePath(cfg.configPath)
	cfg.workDir = normalizePath(cfg.workDir)
	if cfg.workDir == "" {
		cfg.workDir = filepath.Dir(cfg.binaryPath)
	}
	return cfg, nil
}

func normalizePath(path string) string {
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

func (s *sftpxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	if err := s.startProcess(); err != nil {
		log.Printf("start child process failed: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	done := s.processDone()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case change := <-r:
			switch change.Cmd {
			case svc.Interrogate:
				changes <- change.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				if err := s.stopProcess(stopTimeout); err != nil {
					log.Printf("stop child process failed: %v", err)
					changes <- svc.Status{State: svc.Stopped}
					return false, 1
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				log.Printf("unexpected control request: %d", change.Cmd)
			}
		case err := <-done:
			if err != nil {
				log.Printf("child process exited unexpectedly: %v", err)
				changes <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

func (s *sftpxyService) startProcess() error {
	if _, err := os.Stat(s.cfg.binaryPath); err != nil {
		return fmt.Errorf("service target binary not found: %w", err)
	}
	if _, err := os.Stat(s.cfg.configPath); err != nil {
		return fmt.Errorf("service config not found: %w", err)
	}

	cmd := exec.Command(s.cfg.binaryPath, "--config", s.cfg.configPath)
	cmd.Dir = s.cfg.workDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "SFTPXY_WINDOWS_SERVICE=1")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch sftpxy failed: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	s.mu.Lock()
	s.cmd = cmd
	s.done = done
	s.mu.Unlock()

	log.Printf("started child process pid=%d binary=%s config=%s workdir=%s", cmd.Process.Pid, s.cfg.binaryPath, s.cfg.configPath, s.cfg.workDir)
	return nil
}

func (s *sftpxyService) processDone() <-chan error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

func (s *sftpxyService) stopProcess(timeout time.Duration) error {
	s.mu.Lock()
	cmd := s.cmd
	done := s.done
	s.cmd = nil
	s.done = nil
	s.mu.Unlock()

	if cmd == nil || done == nil {
		return nil
	}

	if cmd.Process != nil {
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			log.Printf("interrupt child process failed, will fall back to kill: %v", err)
		}
	}

	select {
	case err := <-done:
		return normalizeProcessExit(err)
	case <-time.After(timeout):
	}

	if cmd.Process != nil {
		if err := cmd.Process.Kill(); err != nil {
			log.Printf("kill child process returned: %v", err)
		}
	}

	return normalizeProcessExit(<-done)
}

func normalizeProcessExit(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil
	}
	return err
}

func runService(name string, isDebug bool, cfg serviceConfig) {
	service := &sftpxyService{cfg: cfg}

	var err error
	if isDebug {
		err = debug.Run(name, service)
	} else {
		err = svc.Run(name, service)
	}
	if err != nil {
		log.Printf("%s service failed: %v", name, err)
	}
}

func installService(exePath string, cfg serviceConfig) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if existing, openErr := m.OpenService(serviceName); openErr == nil {
		_ = existing.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	service, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDescription,
		Description: "Runs sftpxy.exe with an explicit config path and working directory.",
		StartType:   mgr.StartAutomatic,
	}, "--binary", cfg.binaryPath, "--config", cfg.configPath, "--workdir", cfg.workDir)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer service.Close()

	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		log.Printf("install event log source returned: %v", err)
	}

	fmt.Printf("Service %s installed successfully.\n", serviceName)
	fmt.Printf("  binary : %s\n", cfg.binaryPath)
	fmt.Printf("  config : %s\n", cfg.configPath)
	fmt.Printf("  workdir: %s\n", cfg.workDir)
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", serviceName, err)
	}
	defer service.Close()

	if err := service.Delete(); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	if err := eventlog.Remove(serviceName); err != nil {
		log.Printf("remove event log source returned: %v", err)
	}

	fmt.Printf("Service %s removed successfully.\n", serviceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", serviceName, err)
	}
	defer service.Close()

	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Service %s started.\n", serviceName)
	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	service, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", serviceName, err)
	}
	defer service.Close()

	status, err := service.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	fmt.Printf("Service %s is stopping (state=%d).\n", serviceName, status.State)
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("determine service mode failed: %v", err)
	}

	if inService {
		cfg, err := parseServiceConfig(os.Args[1:])
		if err != nil {
			log.Fatalf("parse service arguments failed: %v", err)
		}
		runService(serviceName, false, cfg)
		return
	}

	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]
	switch command {
	case "install":
		cfg, err := parseServiceConfig(os.Args[2:])
		if err != nil {
			log.Fatalf("parse install arguments failed: %v", err)
		}
		exePath, err := os.Executable()
		if err != nil {
			log.Fatalf("resolve wrapper path failed: %v", err)
		}
		if err := installService(exePath, cfg); err != nil {
			log.Fatalf("install failed: %v", err)
		}
	case "remove":
		if err := removeService(); err != nil {
			log.Fatalf("remove failed: %v", err)
		}
	case "start":
		if err := startService(); err != nil {
			log.Fatalf("start failed: %v", err)
		}
	case "stop":
		if err := stopService(); err != nil {
			log.Fatalf("stop failed: %v", err)
		}
	case "debug":
		cfg, err := parseServiceConfig(os.Args[2:])
		if err != nil {
			log.Fatalf("parse debug arguments failed: %v", err)
		}
		runService(serviceName, true, cfg)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("SFTPxy Windows Service Wrapper")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  sftpxy-service install [--binary <path>] [--config <path>] [--workdir <path>]")
	fmt.Println("  sftpxy-service remove")
	fmt.Println("  sftpxy-service start")
	fmt.Println("  sftpxy-service stop")
	fmt.Println("  sftpxy-service debug [--binary <path>] [--config <path>] [--workdir <path>]")
}
