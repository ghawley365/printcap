package main

import (
	"fmt"
	"net"
)

// Platform-neutral capture helpers shared by every live-source backend
// (BPF on macOS, AF_PACKET on Linux, Npcap on Windows, and the stub). Keeping
// these here means each platform file only implements the OS-specific parts.

// noopForwarding is an inert IP-forwarding controller. Passive capture does not
// need kernel forwarding (that only matters for active on-path positioning), so
// every non-Windows backend uses this.
type noopForwarding struct{}

func (noopForwarding) Enable() error  { return nil }
func (noopForwarding) Restore() error { return nil }

// defaultCaptureInterface picks a sensible capture NIC when none is configured:
// the first interface that is up, not loopback, and has an IPv4 address.
func defaultCaptureInterface() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return i.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no suitable capture interface found; set intercept.interface explicitly")
}
