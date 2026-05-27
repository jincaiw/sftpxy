//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "SFTPxy"

type sftpxyService struct {
	stop chan struct{}
}

func (s *sftpxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	s.stop = make(chan struct{})

	// Start SFTPxy in a goroutine
	go func() {
		log.Println("Starting SFTPxy service...")

		// Get the executable path
		exePath, err := os.Executable()
		if err != nil {
			log.Printf("Failed to get executable path: %v", err)
			return
		}

		// Determine config directory (same directory as executable)
		configDir := filepath.Dir(exePath)

		// Set environment variable for config location
		os.Setenv("SFTPXY_CONFIG_DIR", configDir)

		// Call the actual SFTPxy main function
		// Import and call cmd/sftpxy package's main logic here
		runSFTPxy()

		log.Println("SFTPxy service started successfully")
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			log.Println("Stopping SFTPxy service...")
			close(s.stop)
			// Wait for graceful shutdown
			break
		default:
			log.Printf("Unexpected control request #%d", c)
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

// runSFTPxy starts the actual SFTPxy application
// This should be replaced with actual import and call to cmd/sftpxy
func runSFTPxy() {
	// Placeholder: In production, this would call the actual SFTPxy startup logic
	// For now, simulate running by waiting for stop signal
	select {}
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		err = debug.Run(name, &sftpxyService{})
	} else {
		err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
		if err != nil {
			// Ignore if event log already exists
			log.Printf("EventLog installation note: %v\n", err)
		}
		err = svc.Run(name, &sftpxyService{})
	}
	if err != nil {
		log.Printf("%s service failed: %v\n", name, err)
		return
	}
}

func installService(exePath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "SFTPxy Enterprise File Transfer Platform",
		Description: "Enterprise-grade file transfer platform supporting SFTP/SCP, FTP/FTPS, and WebDAV protocols",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("failed to install event log: %v", err)
	}

	fmt.Printf("Service %s installed successfully.\n", serviceName)
	fmt.Printf("Use 'net start %s' to start the service.\n", serviceName)
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %v", serviceName, err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	err = eventlog.Remove(serviceName)
	if err != nil {
		return fmt.Errorf("failed to remove event log: %v", err)
	}

	fmt.Printf("Service %s removed successfully.\n", serviceName)
	return nil
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %v", serviceName, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	fmt.Printf("Service %s started.\n", serviceName)
	return nil
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %v", serviceName, err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %v", err)
	}

	fmt.Printf("Service %s is stopping (current state: %v).\n", serviceName, status.State)
	return nil
}

func main() {
	// Check if running as service
	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as service: %v", err)
	}

	if inService {
		runService(serviceName, false)
		return
	}

	// Handle command line arguments for service management
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			exePath, err := os.Executable()
			if err != nil {
				log.Fatalf("Failed to get executable path: %v", err)
			}
			if err := installService(exePath); err != nil {
				log.Fatalf("Install failed: %v", err)
			}
		case "remove":
			if err := removeService(); err != nil {
				log.Fatalf("Remove failed: %v", err)
			}
		case "start":
			if err := startService(); err != nil {
				log.Fatalf("Start failed: %v", err)
			}
		case "stop":
			if err := stopService(); err != nil {
				log.Fatalf("Stop failed: %v", err)
			}
		case "debug":
			log.Println("Running in debug mode...")
			runService(serviceName, true)
		default:
			fmt.Printf("Unknown command: %s\n", os.Args[1])
			printUsage()
		}
		return
	}

	// Run as regular application
	printUsage()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
}

func printUsage() {
	fmt.Println("SFTPxy - Enterprise File Transfer Platform")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  sftpxy install    Install as Windows service")
	fmt.Println("  sftpxy remove     Remove Windows service")
	fmt.Println("  sftpxy start      Start the service")
	fmt.Println("  sftpxy stop       Stop the service")
	fmt.Println("  sftpxy debug      Run in debug mode")
	fmt.Println("  sftpxy            Show this help message")
}
