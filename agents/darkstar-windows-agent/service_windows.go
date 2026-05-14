//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceDisplayName = "Darkstar Endpoint Agent"

type agentService struct {
	opts options
}

func runServiceOrLoop(opts options) error {
	isService, err := svc.IsWindowsService()
	if err == nil && isService && !opts.Once && !opts.PrintInventory {
		return svc.Run(opts.ServiceName, agentService{opts: opts})
	}
	return runLoop(context.Background(), opts)
}

func (service agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes <- svc.Status{State: svc.StartPending}
	go func() {
		if err := runLoop(ctx, service.opts); err != nil && !errors.Is(err, context.Canceled) {
			// The service manager does not receive arbitrary log text. runLoop logs
			// to the file configured by setupLogging.
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for request := range requests {
		switch request.Cmd {
		case svc.Interrogate:
			changes <- request.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			time.Sleep(2 * time.Second)
			return false, 0
		}
	}
	return false, 0
}

func runInstall(opts options) error {
	if opts.URL == "" || opts.Org == "" || opts.EnrollmentToken == "" {
		return errors.New("install requires --url, --org and --enrollment-token")
	}
	cfg := Config{
		URL:             opts.URL,
		Org:             opts.Org,
		EnrollmentToken: opts.EnrollmentToken,
		StateFile:       opts.StateFile,
		IntervalSeconds: opts.Interval,
	}
	if err := writeConfig(opts.ConfigFile, cfg); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService(opts.ServiceName); err == nil {
		existing.Close()
		return fmt.Errorf("service %s already exists", opts.ServiceName)
	}
	service, err := manager.CreateService(
		opts.ServiceName,
		executable,
		mgr.Config{
			DisplayName:      serviceDisplayName,
			Description:      "Collects endpoint inventory and reports it to Darkstar.",
			StartType:        mgr.StartAutomatic,
			DelayedAutoStart: true,
		},
		"run",
		"--config", opts.ConfigFile,
		"--state-file", opts.StateFile,
		"--service-name", opts.ServiceName,
	)
	if err != nil {
		return err
	}
	defer service.Close()
	return nil
}

func runUninstall(serviceName string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Delete()
}

func runServiceStart(serviceName string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Start()
}

func runServiceStop(serviceName string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	_, err = service.Control(svc.Stop)
	return err
}

func installedExecutablePath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Clean(executable)
}
