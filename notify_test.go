package main

import "testing"

func TestNotifyCaptureRespectsConfig(t *testing.T) {
	// Save and restore the package-level globals the hook touches.
	prevCfg, prevHook := cfg, onCapture
	t.Cleanup(func() { cfg, onCapture = prevCfg, prevHook })

	cfg = defaultConfig()

	called := false
	onCapture = func(j *job) { called = true }

	// Disabled: the hook must NOT fire.
	cfg.Notifications = false
	called = false
	notifyCapture(&job{})
	if called {
		t.Fatal("notifyCapture fired the hook while Notifications was disabled")
	}

	// Enabled: the hook MUST fire.
	cfg.Notifications = true
	called = false
	notifyCapture(&job{})
	if !called {
		t.Fatal("notifyCapture did not fire the hook while Notifications was enabled")
	}

	// Enabled but no hook set: must be a no-op (no panic).
	onCapture = nil
	notifyCapture(&job{})
}
