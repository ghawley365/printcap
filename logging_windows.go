//go:build windows

package main

import "golang.org/x/sys/windows/svc/eventlog"

// Windows Event Log integration. When running as a service with event_log
// enabled, notable events (warnings and errors) are mirrored into the Windows
// Application event log under the "printcap" source, so they show up in Event
// Viewer alongside other system services.

var winEventLog *eventlog.Log

// setupEventLog attaches the Event Log as a system sink on the global logger.
func setupEventLog() {
	if !cfg.Log.EventLog {
		return
	}
	el, err := eventlog.Open(serviceName)
	if err != nil {
		logWarn("svc", "could not open Event Log source (run -service install as Administrator): %v", err)
		return
	}
	winEventLog = el
	logger.mu.Lock()
	logger.sysSink = func(level Level, msg string) {
		switch level {
		case LevelError:
			_ = el.Error(1, msg)
		case LevelWarn:
			_ = el.Warning(1, msg)
		default:
			_ = el.Info(1, msg)
		}
	}
	logger.mu.Unlock()
	logInfo("svc", "Windows Event Log sink attached (source %q)", serviceName)
}

// installEventLogSource registers the "printcap" event source (idempotent).
func installEventLogSource() {
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
}

// removeEventLogSource unregisters the event source.
func removeEventLogSource() {
	_ = eventlog.Remove(serviceName)
}
