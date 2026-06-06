package main

import "strings"

// captureDevice describes a network adapter available for packet capture, used to
// pre-fill the interface picker in the GUI and the capture window. The Name is
// the value stored in intercept.interface — on a Windows/Npcap build that is the
// pcap device name (matched exactly by the capture backend); otherwise it is the
// OS interface name.
type captureDevice struct {
	Name     string
	Desc     string
	Addrs    []string
	Loopback bool
}

// captureDeviceLabel renders a friendly one-line label for a device picker.
func captureDeviceLabel(d captureDevice) string {
	s := d.Desc
	if s == "" {
		s = d.Name
	}
	if len(d.Addrs) > 0 {
		s += "  [" + strings.Join(d.Addrs, ", ") + "]"
	}
	if d.Loopback {
		s += "  (loopback)"
	}
	return s
}
