//go:build windows && npcap

package main

import (
	"strings"

	"github.com/google/gopacket/pcap"
)

// listCaptureDevices enumerates the Npcap capture devices so the GUI picker
// offers exactly what the capture backend can open. The stored Name is the pcap
// device name (\Device\NPF_{GUID}), matched exactly by openDevice.
func listCaptureDevices() []captureDevice {
	var out []captureDevice
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return out
	}
	for _, dv := range devs {
		d := captureDevice{Name: dv.Name, Desc: dv.Description}
		if d.Desc == "" {
			d.Desc = dv.Name
		}
		for _, a := range dv.Addresses {
			if a.IP != nil {
				d.Addrs = append(d.Addrs, a.IP.String())
			}
		}
		d.Loopback = strings.Contains(strings.ToLower(dv.Description+" "+dv.Name), "loopback")
		out = append(out, d)
	}
	return out
}
