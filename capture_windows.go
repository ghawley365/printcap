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
type winForwarding struct {
	prior string // previous global forwarding state to restore
	set   bool
}

func newForwardingControl() forwardingControl { return &winForwarding{} }

func (w *winForwarding) Enable() error {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "global").Output()
	if err == nil {
		w.prior = strings.TrimSpace(string(out)) // best-effort snapshot for the log/audit
	}
	if err := exec.Command("netsh", "interface", "ipv4", "set", "global", "forwarding=enabled").Run(); err != nil {
		return fmt.Errorf("netsh set global forwarding: %w", err)
	}
	w.set = true
	return nil
}

func (w *winForwarding) Restore() error {
	if !w.set {
		return nil
	}
	return exec.Command("netsh", "interface", "ipv4", "set", "global", "forwarding=disabled").Run()
}
