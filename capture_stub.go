//go:build (windows && !npcap) || (!windows && !darwin && !linux)

package main

import (
	"net/netip"
	"runtime"
)

// This file is the fallback for build configurations without a real live-capture
// backend: Windows built without the npcap tag, and any OS other than
// macOS/Linux/Windows. Capture reports "unsupported" and the ARP/forwarding
// controls are inert, so the whole orchestrator still links and unit-tests.
// macOS uses capture_darwin.go (BPF), Linux uses capture_linux.go (AF_PACKET),
// and Windows+npcap uses capture_windows.go (Npcap).

// openLiveSource returns an error: this build has no capture backend.
func openLiveSource(c InterceptConf) (packetSource, error) {
	return nil, unsupportedLiveCapture(runtime.GOOS)
}

// newForwardingControl returns an inert controller.
func newForwardingControl() forwardingControl { return noopForwarding{} }

// newARPController is never reached because openLiveSource fails first, but it is
// defined so the orchestrator links on every platform.
func newARPController(c ARPConf, targets []netip.Addr, gw netip.Addr) (arpController, error) {
	return nil, unsupportedLiveCapture(runtime.GOOS)
}
