package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
)

// Engine owns every listener and lets callers Start and Stop the whole capture
// service in-process. The console front-end, the Windows service, and the GUI
// all drive the same Engine, so capture behavior is identical no matter how the
// tool is launched.
type Engine struct {
	mu      sync.Mutex
	running bool
	closers []io.Closer // listeners, packet conns, and *http.Server instances
	active  []string    // human-readable names of the listeners that came up
}

var engine = &Engine{}

// engineLog, when set (by the GUI), receives listener start/stop diagnostics in
// addition to the standard logger.
var engineLog func(string)

// Start brings up every enabled listener. It returns the number that came up
// and an error only for a fatal precondition (e.g. the output directory can't
// be created). Individual listeners that fail to bind are logged and skipped so
// one busy port never stops the rest.
func (e *Engine) Start() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return len(e.active), nil
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return 0, err
	}
	// (Re)initialize the capture sink and dashboard store for this run.
	sink = &captureSink{dir: cfg.OutDir}
	store = newJobStore(200)

	if cfg.Forward.Enabled {
		if fw, err := newForwarder(cfg.Forward); err != nil {
			e.logf("forward: %v", err)
		} else {
			forward = fw
			e.closers = append(e.closers, fw)
			logInfo("engine", "forwarding enabled: %d target(s)", len(fw.targets))
		}
	} else {
		forward = nil
	}

	// Resolve the auto-TLS override on a local copy so we never mutate config.
	ports := cfg.Ports
	if ports.AutoTLS > 0 {
		if ports.IPP == ports.AutoTLS {
			ports.IPP = 0
		}
		if ports.IPPS == ports.AutoTLS {
			ports.IPPS = 0
		}
	}

	bindAddr := func(port int) string { return net.JoinHostPort(cfg.Bind, itoa(port)) }

	var bl boundListeners

	addTCP := func(name string, port int, serve func(net.Listener)) bool {
		if port <= 0 {
			return false
		}
		ln, err := net.Listen("tcp", bindAddr(port))
		if err != nil {
			e.logf("%s: %v", name, err)
			return false
		}
		e.closers = append(e.closers, ln)
		e.active = append(e.active, name+":"+itoa(port))
		logInfo("engine", "listening %s on %s", name, bindAddr(port))
		go serve(ln)
		return true
	}

	addHTTP := func(name string, port int, tlsCfg *tls.Config, h http.Handler) bool {
		if port <= 0 {
			return false
		}
		ln, err := net.Listen("tcp", bindAddr(port))
		if err != nil {
			e.logf("%s: %v", name, err)
			return false
		}
		srv := hardenedServer("", h)
		if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg)
		}
		e.closers = append(e.closers, srv)
		e.active = append(e.active, name+":"+itoa(port))
		logInfo("engine", "listening %s on %s%s", name, bindAddr(port), tlsLabel(tlsCfg))
		go srv.Serve(ln)
		return true
	}

	// Auto-TLS single port (serves both IPP and IPPS).
	if ports.AutoTLS > 0 {
		if tlsCfg, err := tlsConfig(); err != nil {
			e.logf("IPP/IPPS: %v", err)
		} else if ln, err := net.Listen("tcp", bindAddr(ports.AutoTLS)); err != nil {
			e.logf("IPP/IPPS: %v", err)
		} else {
			e.closers = append(e.closers, ln)
			e.active = append(e.active, "IPP/IPPS:"+itoa(ports.AutoTLS))
			go serveAutoTLS(ln, tlsCfg)
			bl.IPP, bl.IPPS = ports.AutoTLS, ports.AutoTLS
		}
	}

	if addTCP("9100", ports.Raw9100, serveRaw9100) {
		bl.Raw9100 = ports.Raw9100
	}
	for _, ep := range cfg.Raw.ExtraPorts {
		addTCP("9100", ep, serveRaw9100) // multi-port raw servers (9101, 9102, …)
	}
	if addTCP("LPR", ports.LPR, serveLPD) {
		bl.LPR = ports.LPR
	}
	if addHTTP("IPP", ports.IPP, nil, http.HandlerFunc(ippHandler)) {
		bl.IPP = ports.IPP
	}
	if ports.IPPS > 0 {
		if tlsCfg, err := tlsConfig(); err != nil {
			e.logf("IPPS: %v", err)
		} else {
			if addHTTP("IPPS", ports.IPPS, tlsCfg, http.HandlerFunc(ippHandler)) {
				bl.IPPS = ports.IPPS
			}
		}
	}

	if cfg.SNMP.Enabled && ports.SNMP > 0 {
		if pc, err := net.ListenPacket("udp", bindAddr(ports.SNMP)); err != nil {
			e.logf("SNMP: %v", err)
		} else {
			buildMIB()
			e.closers = append(e.closers, pc)
			e.active = append(e.active, "SNMP:"+itoa(ports.SNMP))
			go serveSNMP(pc)
		}
	}

	if cfg.Dashboard.Enabled && ports.Dashboard > 0 {
		if addHTTP("dashboard", ports.Dashboard, nil, dashboardHandler()) {
			bl.Dash = ports.Dashboard
		}
	}

	if cfg.SMB.Enabled {
		addTCP("SMB", cfg.SMB.Port, serveSMB)
	}

	if cfg.WSD.Enabled {
		if w := startWSD(); w != nil {
			e.closers = append(e.closers, w)
		}
	}

	if cfg.MDNS.Enabled {
		host := resolveHost()
		v4, v6 := localAddrs(cfg.Bind)
		svcs := buildServices(bl, cfg.MDNS.AirPrint, resolveInstance())
		if len(svcs) > 0 {
			if r := startResponder(svcs, svcAddrs{host: host, v4: v4, v6: v6}); r != nil {
				e.closers = append(e.closers, r)
			}
		}
	}

	e.running = len(e.active) > 0
	logInfo("engine", "started: %d listener(s) [%s]", len(e.active), join(e.active, ", "))
	return len(e.active), nil
}

func tlsLabel(c *tls.Config) string {
	if c != nil {
		return " (TLS)"
	}
	return ""
}

func join(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}

// Stop closes every listener; the accept-loop goroutines then unwind on their
// own as Accept/ReadFrom return errors.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return
	}
	for _, c := range e.closers {
		_ = c.Close()
	}
	e.closers = nil
	e.active = nil
	e.running = false
	logInfo("engine", "stopped (all listeners closed)")
}

func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Active returns a copy of the active listener descriptions ("9100:9100", ...).
func (e *Engine) Active() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.active))
	copy(out, e.active)
	return out
}

func (e *Engine) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	logWarn("engine", "%s", msg)
	if engineLog != nil {
		engineLog(msg)
	}
}

// localAddrs returns the IPv4 and IPv6 addresses to advertise. A specific bind
// address is advertised as-is; 0.0.0.0/:: expands to all non-loopback
// interface addresses.
func localAddrs(bind string) (v4, v6 []net.IP) {
	if bind != "" && bind != "0.0.0.0" && bind != "::" {
		if ip := net.ParseIP(bind); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return []net.IP{ip4}, nil
			}
			return nil, []net.IP{ip}
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue // skip loopback and link-local (v4 APIPA 169.254/16 and v6 fe80::/10)
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		} else if ipNet.IP.To16() != nil {
			v6 = append(v6, ipNet.IP)
		}
	}
	return v4, v6
}
