package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// interceptModule is the process-wide interceptor, built by the Engine at Start
// when cfg.Intercept.Enabled (nil otherwise). It implements io.Closer so the
// engine tears it down through the same closer slice as every listener.
var interceptModule *interceptor

// arpController is the active on-path positioner (ARP cache poisoning). The real
// implementation is Windows-only (arp_windows.go); other platforms get a stub.
// Start begins poisoning the scoped targets; Close restores every cache touched.
type arpController interface {
	Start() error
	Close() error
}

// forwardingControl toggles OS IP forwarding so traffic we draw on-path is still
// delivered to its real destination (the "don't stop any traffic" requirement).
// Enable records the prior state; Restore puts it back exactly as it was.
type forwardingControl interface {
	Enable() error
	Restore() error
}

// interceptor owns the capture pipeline: a packet source feeding a pcap writer,
// plus the optional forwarding toggle and ARP positioner. Everything platform-
// specific is injected as an interface so the pump loop is unit-testable.
type interceptor struct {
	conf InterceptConf
	src  packetSource
	pw   *pcapWriter
	cv   *carver           // nil when stream carving is disabled
	fwd  forwardingControl // nil when IP forwarding control is disabled/unsupported
	arp  arpController     // nil when active poisoning is disabled/unsupported

	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

// validateARPScope resolves and validates the ARP allow-list. It is the single
// safety gate for active poisoning and is deliberately fail-closed:
//
//   - active is false (poisoning stays OFF) unless ARP.Enabled AND at least one
//     valid target IP is configured. There is no whole-subnet mode.
//   - every Targets entry must parse as an IP; a bad entry is a hard error so a
//     typo can never silently widen or narrow the intended scope.
//   - the gateway, when given, must parse; blank means "auto-detect at start".
func validateARPScope(c ARPConf) (targets []netip.Addr, gw netip.Addr, active bool, err error) {
	if !c.Enabled {
		return nil, netip.Addr{}, false, nil
	}
	seen := map[netip.Addr]bool{}
	for _, raw := range c.Targets {
		a, perr := netip.ParseAddr(raw)
		if perr != nil {
			return nil, netip.Addr{}, false, fmt.Errorf("arp target %q: not a valid IP", raw)
		}
		if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
			return nil, netip.Addr{}, false, fmt.Errorf("arp target %q: refusing loopback/multicast/unspecified address", raw)
		}
		if !seen[a] {
			seen[a] = true
			targets = append(targets, a)
		}
	}
	if c.Gateway != "" {
		gw, err = netip.ParseAddr(c.Gateway)
		if err != nil {
			return nil, netip.Addr{}, false, fmt.Errorf("arp gateway %q: not a valid IP", c.Gateway)
		}
	}
	// Fail-closed: enabled but no in-scope targets => poisoning stays off.
	if len(targets) == 0 {
		logWarn("intercept", "arp.enabled is true but no valid targets are configured; active poisoning stays OFF (capture-only)")
		return nil, gw, false, nil
	}
	return targets, gw, true, nil
}

// authorizeIntercept is the fail-closed authorization gate for intercept mode.
// It mirrors validateIntercept's error checks but as a single returned error so a
// failure aborts startup. It refuses to start unless the operator has explicitly
// acknowledged authorization and supplied an operator + engagement reference, and
// unless any configured expiry is still in the future.
func authorizeIntercept(c InterceptConf) error {
	a := c.Authorization
	if !a.Acknowledged {
		return fmt.Errorf("authorization not acknowledged: refusing to capture. Set intercept.authorization.acknowledged=true (or -authorize) only on networks you are authorized to capture")
	}
	if strings.TrimSpace(a.Operator) == "" {
		return fmt.Errorf("authorization.operator is blank: set it (or -operator) to the person running this capture")
	}
	if strings.TrimSpace(a.Engagement) == "" {
		return fmt.Errorf("authorization.engagement is blank: set it (or -engagement) to the ticket/SOW reference granting authority")
	}
	exp, ok := parseAuthExpiry(a.Expiry)
	if !ok {
		return fmt.Errorf("authorization.expiry %q is not a valid date (use RFC3339 or YYYY-MM-DD)", a.Expiry)
	}
	if !exp.IsZero() && time.Now().After(exp) {
		return fmt.Errorf("authorization expired at %s: renew the engagement window before capturing", exp.Format(time.RFC3339))
	}
	return nil
}

// logAuthBanner prints a prominent, unmissable record of the authority a capture
// is running under, so an operator can never claim they didn't see it. It is
// logged at WARN so it surfaces even at reduced verbosity.
func logAuthBanner(c InterceptConf) {
	a := c.Authorization
	exp := strings.TrimSpace(a.Expiry)
	if exp == "" {
		exp = "none"
	}
	logWarn("intercept", "================ AUTHORIZED CAPTURE ================")
	logWarn("intercept", " operator:   %s", a.Operator)
	logWarn("intercept", " engagement: %s", a.Engagement)
	logWarn("intercept", " expiry:     %s", exp)
	logWarn("intercept", " capturing ALL traffic on iface %q to %s", c.Interface, interceptPcapPath(c))
	if c.ARP.Enabled {
		logWarn("intercept", " active ARP positioning is configured (scope: %d target(s))", len(c.ARP.Targets))
	}
	logWarn("intercept", " use only on networks you are authorized to capture")
	logWarn("intercept", "===================================================")
}

// writeAuthSidecar writes a provenance record next to the pcap. The classic
// libpcap format has no comment field, so the who/why/when of a capture lives in
// a "<pcap>.authorization.txt" sidecar that travels with the evidence. Best-effort:
// a sidecar failure is logged but never blocks the capture.
func writeAuthSidecar(c InterceptConf) {
	a := c.Authorization
	path := interceptPcapPath(c) + ".authorization.txt"
	body := fmt.Sprintf(""+
		"printcap intercept capture — authorization record\n"+
		"started:    %s\n"+
		"operator:   %s\n"+
		"engagement: %s\n"+
		"expiry:     %s\n"+
		"interface:  %s\n"+
		"pcap:       %s\n"+
		"arp_active: %t\n"+
		"arp_scope:  %v\n",
		time.Now().Format(time.RFC3339),
		a.Operator, a.Engagement, fallback(a.Expiry, "none"),
		c.Interface, interceptPcapPath(c),
		c.ARP.Enabled && len(c.ARP.Targets) > 0, c.ARP.Targets)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		logWarn("intercept", "could not write authorization sidecar %s: %v", path, err)
		return
	}
	logInfo("intercept", "authorization record written to %s", path)
}

// fallback returns s, or def when s is blank.
func fallback(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// interceptPcapPath returns the configured pcap path or a default under the
// capture output directory.
func interceptPcapPath(c InterceptConf) string {
	if c.PcapFile != "" {
		return c.PcapFile
	}
	return filepath.Join(captureDir(), "capture.pcap")
}

// startInterceptor builds and starts the interceptor: it opens the live source,
// the pcap writer, optionally enables forwarding, and optionally starts ARP
// poisoning, then launches the pump loop. Returns the running *interceptor (an
// io.Closer) or an error if a hard precondition fails. Capture continues even if
// the ARP/forwarding extras are unavailable — those are logged, not fatal.
func startInterceptor(c InterceptConf) (*interceptor, error) {
	// Authorization is a hard precondition, enforced here as well as in -check, so
	// the gate cannot be bypassed by skipping validation. No capture starts without
	// an acknowledged operator + engagement (and an unexpired window).
	if err := authorizeIntercept(c); err != nil {
		return nil, err
	}

	targets, gw, arpActive, err := validateARPScope(c.ARP)
	if err != nil {
		return nil, err
	}

	src, err := openLiveSource(c) // platform hook (Npcap on Windows, stub elsewhere)
	if err != nil {
		return nil, err
	}

	pw, err := newPcapFile(interceptPcapPath(c), c.SnapLen, src.LinkType())
	if err != nil {
		_ = src.Close()
		return nil, err
	}

	it := &interceptor{conf: c, src: src, pw: pw, done: make(chan struct{})}

	// Stream carving: reconstruct print jobs from the captured traffic and feed
	// them through the same sink as the live listeners, so documents land as typed
	// files alongside the raw pcap. Wired to the global sink when one exists.
	if c.Carve.Enabled && sink != nil {
		it.cv = newCarver(c.Carve, src.LinkType(), func(j *job) {
			if err := sink.save(j); err != nil {
				logWarn("carve", "saving carved job reported: %v", err)
			}
		})
		logInfo("intercept", "stream carving enabled on ports %v", c.Carve.Ports)
	}

	// Now that the capture is committed, record who/why: a loud banner and a
	// provenance sidecar beside the pcap.
	logAuthBanner(c)
	writeAuthSidecar(c)

	if c.IPForward {
		it.fwd = newForwardingControl() // platform hook
		if err := it.fwd.Enable(); err != nil {
			logWarn("intercept", "could not enable IP forwarding (traffic to poisoned hosts may stall): %v", err)
			it.fwd = nil
		} else {
			logInfo("intercept", "IP forwarding enabled for transparent pass-through")
		}
	}

	if arpActive {
		arp, err := newARPController(c.ARP, targets, gw) // platform hook
		if err != nil {
			logWarn("intercept", "ARP positioner unavailable, continuing capture-only: %v", err)
		} else if err := arp.Start(); err != nil {
			logWarn("intercept", "ARP positioner failed to start, continuing capture-only: %v", err)
			_ = arp.Close()
		} else {
			it.arp = arp
			logInfo("intercept", "ARP positioning active for %d scoped target(s)", len(targets))
		}
	}

	// Reset the live-view ring for this run; the pump feeds it per packet.
	captureLive.reset(src.LinkType())

	it.wg.Add(1)
	trackGo(func() { defer it.wg.Done(); it.pump() })
	// Periodically flush the pcap so the file-backed viewer/follow-stream reflects
	// the in-progress capture (the live view uses the in-memory ring instead).
	it.wg.Add(1)
	trackGo(func() { defer it.wg.Done(); it.flushLoop() })
	logInfo("intercept", "capturing to %s (iface=%q, link=%d)", interceptPcapPath(c), c.Interface, src.LinkType())
	return it, nil
}

// flushLoop flushes the pcap writer once a second until the interceptor closes.
func (it *interceptor) flushLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-it.done:
			return
		case <-t.C:
			_ = it.pw.flush()
		}
	}
}

// pump copies frames from the source into the pcap writer until the source
// drains or Close is called. The writer is internally synchronized, so this is
// the only required reader of the source channel.
func (it *interceptor) pump() {
	ch := it.src.Packets()
	for {
		select {
		case <-it.done:
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			ts := p.ts
			if ts.IsZero() {
				ts = time.Now()
			}
			if err := it.pw.writePacket(ts, p.data); err != nil {
				logErr("intercept", "pcap write failed, stopping capture: %v", err)
				return
			}
			captureLive.record(capturedPacket{ts: ts, data: p.data}) // live-view ring
			if it.cv != nil {
				it.cv.consume(p.data, ts)
			}
		}
	}
}

// Close tears the interceptor down in the safe order: stop drawing traffic on-
// path (restore ARP caches) BEFORE we stop forwarding, so no host is left
// pointing at us with forwarding already off; then stop the pump, flush the
// pcap, and restore the forwarding sysctl. Idempotent.
func (it *interceptor) Close() error {
	it.closeOnce.Do(func() {
		if it.arp != nil {
			if err := it.arp.Close(); err != nil {
				logWarn("intercept", "ARP restore on stop reported: %v", err)
			} else {
				logInfo("intercept", "ARP caches restored")
			}
		}
		close(it.done)
		_ = it.src.Close()
		it.wg.Wait()
		// Pump has stopped: no concurrent consume, so flush any in-flight stream
		// (a job still transferring when capture stopped) into the sink.
		if it.cv != nil {
			it.cv.flush()
		}
		if it.fwd != nil {
			if err := it.fwd.Restore(); err != nil {
				logWarn("intercept", "restoring IP forwarding state reported: %v", err)
			} else {
				logInfo("intercept", "IP forwarding state restored")
			}
		}
		pkts, by := it.pw.stats()
		if err := it.pw.Close(); err != nil {
			logWarn("intercept", "closing pcap reported: %v", err)
		}
		logInfo("intercept", "capture stopped: %d packet(s), %d byte(s) written", pkts, by)
	})
	return nil
}
