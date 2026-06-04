//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	serviceName    = "printcap"
	serviceDisplay = "printcap Print Capture"
	serviceDesc    = "Captures network print jobs (Raw/9100, LPR, IPP, IPPS), answers SNMP discovery, and serves a web dashboard."
)

// printcapService adapts the Engine to the Windows Service Control Manager.
type printcapService struct{}

func (printcapService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.StartPending}
	if _, err := engine.Start(); err != nil {
		logErr("svc", "service start failed: %v", err)
		return true, 1
	}
	logInfo("svc", "service running")
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			engine.Stop()
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

// runService is the entry point when the SCM launched us. Logging was already
// configured in main() (to printcap.log next to the exe by default); here we
// also attach the Windows Event Log sink.
func runService() {
	setupEventLog()
	logInfo("svc", "service starting (config %q)", configFilePath)
	if err := svc.Run(serviceName, printcapService{}); err != nil {
		logErr("svc", "service run error: %v", err)
	}
	logInfo("svc", "service stopped")
}

// --- service management (used by both the CLI -service flag and the GUI) ----

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q is already installed", serviceName)
	}

	args := []string{}
	if configFilePath != "" {
		args = append(args, "-config", configFilePath)
	}
	scmCfg := mgr.Config{
		DisplayName:      serviceDisplay,
		Description:      serviceDesc,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		DelayedAutoStart: true, // start after the network stack is up
	}
	// Run as a dedicated account if configured; blank = LocalSystem.
	if cfg.Service.Account != "" {
		scmCfg.ServiceStartName = cfg.Service.Account
		scmCfg.Password = cfg.Service.Password
	}
	s, err := m.CreateService(serviceName, exe, scmCfg, args...)
	if err != nil {
		return err
	}
	defer s.Close()

	// Ask the SCM to auto-restart the service if it crashes.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400 /* reset failure count after 1 day, in seconds */); err != nil {
		logWarn("svc", "could not set service recovery actions: %v", err)
	}

	installEventLogSource() // register the Event Log source for service logging
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator?): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop) // best-effort stop before delete
	removeEventLogSource()
	return s.Delete()
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed", serviceName)
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}

// serviceInstalled reports whether the service exists.
func serviceInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// serviceState returns a human-readable state string.
func serviceState() string {
	m, err := mgr.Connect()
	if err != nil {
		return "unknown"
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "not installed"
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "unknown"
	}
	switch st.State {
	case svc.Running:
		return "running"
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Paused:
		return "paused"
	default:
		return "unknown"
	}
}

// serviceControl handles the -service CLI flag.
func serviceControl(cmd string) {
	var err error
	switch cmd {
	case "install":
		if err = installService(); err == nil {
			fmt.Println("service installed:", serviceName)
		}
	case "remove", "uninstall":
		if err = removeService(); err == nil {
			fmt.Println("service removed:", serviceName)
		}
	case "start":
		if err = startService(); err == nil {
			fmt.Println("service started")
		}
	case "stop":
		if err = stopService(); err == nil {
			fmt.Println("service stopped")
		}
	case "status":
		fmt.Println("service:", serviceState())
		return
	default:
		fmt.Fprintln(os.Stderr, "unknown -service command:", cmd, "(want install|remove|start|stop|status)")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
