//go:build !(windows && npcap)

package main

import "net"

// listCaptureDevices enumerates OS network interfaces. This is the fallback used
// on every build except Windows+Npcap (which lists actual pcap devices). The
// stored Name is the OS interface name; the macOS BPF and Linux AF_PACKET
// backends bind by that name directly.
func listCaptureDevices() []captureDevice {
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
