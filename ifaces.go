package main

import (
	"net"
	"strings"
)

// connectionNames returns the OS network-connection names (on Windows these are
// the friendly connection aliases like "Ethernet"/"Wi-Fi" that ICS/HNetCfg use),
// excluding loopback. Used to pre-fill the ICS pickers.
func connectionNames() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, i.Name)
	}
	return out
}

// osInterfaceDevices enumerates the OS network interfaces as capture devices.
// It is the fallback adapter list used when the Npcap device list is empty or
// unavailable, so the GUI picker is never empty.
func osInterfaceDevices() []captureDevice {
	var out []captureDevice
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		d := captureDevice{Name: i.Name, Desc: i.Name, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				d.Addrs = append(d.Addrs, ipn.IP.String())
			}
		}
		out = append(out, d)
	}
	return out
}

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
