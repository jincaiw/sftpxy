package main

import (
	"fmt"
	"log"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const serviceName = "SFTPxy"

type sftpxyService struct{}

func (s *sftpxyService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Start SFTPxy
	go func() {
		log.Println("Starting SFTPxy service...")
		// In production, call the actual main function
		// For now, just simulate running
		select {}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			log.Println("Stopping SFTPxy service...")
			// Perform cleanup here
			break
		default:
			log.Printf("Unexpected control request #%d", c)
		}
	}

	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		err = debug.Run(name, &sftpxyService{})
	} else {
		err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info)
		if err != nil {
			if err != eventlog.ErrEventLogRegistryExists {
				log.Printf("EventLog installation failed: %v\n", err)
				return
			}
		}
		err = svc.Run(name, &sftpxyService{})
	}
	if err != nil {
		log.Printf("%s service failed: %v\n", name, err)
		return
	}
}

func main() {
	// Check if running as service
	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as service: %v", err)
	}

	if inService {
		runService(serviceName, false)
	} else {
		// Run as regular application
		fmt.Println("SFTPxy - Enterprise File Transfer Platform")
		fmt.Println("Use 'sftpxy install' to install as Windows service")
		fmt.Println("Use 'sftpxy start' to start the service")
		fmt.Println("Use 'sftpxy stop' to stop the service")
	}
}
