//go:build !(windows && npcap)

package main

// listCaptureDevices enumerates OS network interfaces. This is the fallback used
// on every build except Windows+Npcap (which lists actual pcap devices). The
// stored Name is the OS interface name; the macOS BPF and Linux AF_PACKET
// backends bind by that name directly.
func listCaptureDevices() []captureDevice {
	return osInterfaceDevices()
}
