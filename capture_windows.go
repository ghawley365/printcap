//go:build windows && npcap

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// capture_windows.go is the real, Npcap-backed capture path. It requires cgo and
// the Npcap SDK at build time and the Npcap runtime on the host. Everything here
// is Windows-only; the platform-neutral orchestrator (intercept.go) talks to it
// solely through openLiveSource / newForwardingControl.
//
// NOTE: this file cannot be compiled on the non-Windows dev machine (no cgo
// pcap). Build and run the test pass on a Windows host with Npcap installed:
//   set CGO_ENABLED=1 && go build -tags=npcap ./...

// liveHandle wraps the shared *pcap.Handle so both capture and ARP injection use
// one open device (Npcap allows read+write on the same handle).
type liveHandle struct {
	dev    string
	handle *pcap.Handle
}

// openDevice resolves the configured interface to an Npcap device and opens it.
// c.Interface may be the Npcap device name (\Device\NPF_{GUID}) or a friendly
// substring of the adapter description; blank picks the first up, non-loopback
// device that has an address.
func openDevice(c InterceptConf) (*liveHandle, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("intercept: enumerate devices: %w", err)
	}
	var chosen *pcap.Interface
	for i := range devs {
		d := &devs[i]
		switch {
		case c.Interface == "" && len(d.Addresses) > 0 && !strings.Contains(strings.ToLower(d.Description), "loopback"):
			chosen = d
		case c.Interface != "" && (d.Name == c.Interface ||
			strings.Contains(strings.ToLower(d.Description), strings.ToLower(c.Interface))):
			chosen = d
		}
		if chosen != nil {
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("intercept: no capture device matched %q", c.Interface)
	}

	snap := c.SnapLen
	if snap <= 0 {
		snap = defaultSnapLen
	}
	// A short read timeout keeps the capture goroutine responsive to shutdown.
	h, err := pcap.OpenLive(chosen.Name, int32(snap), c.Promiscuous, 250*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("intercept: open %q (is Npcap installed?): %w", chosen.Name, err)
	}
	if c.BPF != "" {
		if err := h.SetBPFFilter(c.BPF); err != nil {
			h.Close()
			return nil, fmt.Errorf("intercept: bad bpf %q: %w", c.BPF, err)
		}
	}
	logInfo("intercept", "opened capture device %q (%s)", chosen.Name, chosen.Description)
	return &liveHandle{dev: chosen.Name, handle: h}, nil
}

// windowsLiveSource is the packetSource backed by an Npcap handle.
type windowsLiveSource struct {
	lh        *liveHandle
	link      int
	ch        chan capturedPacket
	done      chan struct{}
	closeOnce sync.Once
}

func openLiveSource(c InterceptConf) (packetSource, error) {
	lh, err := openDevice(c)
	if err != nil {
		return nil, err
	}
	s := &windowsLiveSource{
		lh:   lh,
		link: int(lh.handle.LinkType()),
		ch:   make(chan capturedPacket, 1024),
		done: make(chan struct{}),
	}
	go s.read()
	return s, nil
}

// read pulls frames off the handle and forwards copies onto the channel. Each
// frame is copied because gopacket reuses the read buffer between calls.
func (s *windowsLiveSource) read() {
	defer close(s.ch)
	src := gopacket.NewPacketSource(s.lh.handle, s.lh.handle.LinkType())
	src.NoCopy = true
	in := src.Packets()
	for {
		select {
		case <-s.done:
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			raw := pkt.Data()
			buf := make([]byte, len(raw))
			copy(buf, raw)
			ts := pkt.Metadata().Timestamp
			select {
			case s.ch <- capturedPacket{ts: ts, data: buf}:
			case <-s.done:
				return
			}
		}
	}
}

func (s *windowsLiveSource) Packets() <-chan capturedPacket { return s.ch }
func (s *windowsLiveSource) LinkType() int                  { return s.link }

func (s *windowsLiveSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.lh.handle.Close()
	})
	return nil
}

// --- forwarding control (Windows) ---------------------------------------------

// winForwarding toggles OS IP forwarding so traffic drawn on-path is still
// delivered. It uses netsh to flip the global IPEnableRouter behavior and
// records the prior value to restore on stop.
//
// CAVEAT: Windows historically requires a reboot for IPEnableRouter to fully
// engage the routing path. For an immediate, no-reboot transparent relay you
// generally want per-interface forwarding via the Routing service or a userspace
// relay; this controller does the netsh per-interface toggle which works without
// reboot on modern builds. Treat reboot-free forwarding as host-dependent and
// verify on the target before relying on it in an engagement.
// ipRouterKey holds IPEnableRouter, the documented registry value that enables
// global IPv4 routing on Windows. (Per-interface "forwarding" via netsh exists
// too, but it is keyed by the connection alias, which differs from the Npcap
// device name we capture on — so the global switch is what we can reliably set.)
const ipRouterKey = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

type winForwarding struct {
	printerIface string // adapter the printer/MFP is on (capture side)
	uplinkIface  string // adapter with internet access (multi-homed); "" = single-homed
	prior        string // prior IPEnableRouter value: "0", "1", or "" (absent/unknown)
	set          bool   // WE changed it (so Restore puts it back)
}

func newForwardingControl(printerIface, uplinkIface string) forwardingControl {
	return &winForwarding{printerIface: printerIface, uplinkIface: uplinkIface}
}

func (w *winForwarding) Enable() error {
	// Snapshot the prior value so cleanup only undoes what we changed.
	w.prior = regIPEnableRouter()
	if w.prior == "1" {
		logInfo("intercept", "global IP routing (IPEnableRouter) already enabled; leaving it as-is")
		return nil
	}
	if err := exec.Command("reg", "add", ipRouterKey, "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f").Run(); err != nil {
		return fmt.Errorf("enable IP routing (IPEnableRouter): %w", err)
	}
	w.set = true
	logWarn("intercept", "enabled global IP routing to relay the printer to the internet (printer=%q uplink=%q). "+
		"IPEnableRouter takes full effect after a reboot or restarting the 'Routing and Remote Access' service; for an immediate transparent relay, enable per-interface forwarding / ICS. "+
		"Different-subnet uplink also needs NAT — turn on Internet Connection Sharing on the internet adapter.",
		w.printerIface, w.uplinkIface)
	return nil
}

func (w *winForwarding) Restore() error {
	if !w.set { // already on before us, or never set — nothing to undo
		return nil
	}
	restore := w.prior
	if restore == "" { // value was absent before; remove our addition by zeroing
		restore = "0"
	}
	if err := exec.Command("reg", "add", ipRouterKey, "/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", restore, "/f").Run(); err != nil {
		return err
	}
	logInfo("intercept", "global IP routing (IPEnableRouter) restored to %s", restore)
	return nil
}

// regIPEnableRouter returns the current IPEnableRouter value as "0"/"1", or ""
// if the value is absent or unreadable.
func regIPEnableRouter() string {
	out, err := exec.Command("reg", "query", ipRouterKey, "/v", "IPEnableRouter").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, tok := range fields {
		if strings.EqualFold(tok, "IPEnableRouter") && i+2 < len(fields) {
			if strings.HasSuffix(strings.ToLower(fields[i+2]), "x1") {
				return "1"
			}
			return "0"
		}
	}
	return ""
}
