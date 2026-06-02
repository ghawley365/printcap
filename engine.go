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

	addTCP := func(name string, port int, serve func(net.Listener)) {
		if port <= 0 {
			return
		}
		ln, err := net.Listen("tcp", bindAddr(port))
		if err != nil {
			e.logf("%s: %v", name, err)
			return
		}
		e.closers = append(e.closers, ln)
		e.active = append(e.active, name+":"+itoa(port))
		logInfo("engine", "listening %s on %s", name, bindAddr(port))
		go serve(ln)
	}

	addHTTP := func(name string, port int, tlsCfg *tls.Config, h http.Handler) {
		if port <= 0 {
			return
		}
		ln, err := net.Listen("tcp", bindAddr(port))
		if err != nil {
			e.logf("%s: %v", name, err)
			return
		}
		srv := hardenedServer("", h)
		if tlsCfg != nil {
			ln = tls.NewListener(ln, tlsCfg)
		}
		e.closers = append(e.closers, srv)
		e.active = append(e.active, name+":"+itoa(port))
		logInfo("engine", "listening %s on %s%s", name, bindAddr(port), tlsLabel(tlsCfg))
		go srv.Serve(ln)
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
		}
	}

	addTCP("9100", ports.Raw9100, serveRaw9100)
	for _, ep := range cfg.Raw.ExtraPorts {
		addTCP("9100", ep, serveRaw9100) // multi-port raw servers (9101, 9102, …)
	}
	addTCP("LPR", ports.LPR, serveLPD)
	addHTTP("IPP", ports.IPP, nil, http.HandlerFunc(ippHandler))
	if ports.IPPS > 0 {
		if tlsCfg, err := tlsConfig(); err != nil {
			e.logf("IPPS: %v", err)
		} else {
			addHTTP("IPPS", ports.IPPS, tlsCfg, http.HandlerFunc(ippHandler))
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
		addHTTP("dashboard", ports.Dashboard, nil, dashboardHandler())
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
