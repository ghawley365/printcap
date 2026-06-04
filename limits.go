package main

import (
	"io"
	"net"
	"net/http"
	"time"
)

// Resource limits and timeouts. These keep the tool robust against slow,
// half-open, or hostile clients — the difference between a lab demo and
// something safe to leave running on a network.
const (
	// idleReadTimeout bounds how long a print connection may stall between
	// reads before we give up and close it (prevents goroutine leaks from
	// half-open sockets). Print jobs stream continuously, so a per-read idle
	// timeout is correct: it resets as data arrives.
	idleReadTimeout = 60 * time.Second

	// maxControlFileBytes caps an LPD control file (metadata only — always
	// tiny in practice).
	maxControlFileBytes = 1 << 20 // 1 MiB

	// HTTP server hardening.
	httpReadHeaderTimeout = 15 * time.Second
	httpWriteTimeout      = 10 * time.Minute
	httpIdleTimeout       = 2 * time.Minute
	maxHTTPHeaderBytes    = 1 << 20
)

// jobByteCap returns the per-job read ceiling in bytes (0 = unlimited), derived
// from cfg.MaxJobMB. Applied at read time so memory tracks the cap, not just
// what we ultimately save.
func jobByteCap() int64 {
	if cfg.MaxJobMB > 0 {
		return int64(cfg.MaxJobMB) << 20
	}
	return 0
}

// idleConn wraps a net.Conn so every Read first arms an idle deadline. Reading
// through it via bufio/io.Copy gives the whole stream an inactivity timeout
// without a separate watchdog goroutine.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c idleConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	return c.Conn.Read(p)
}

// appendCapped appends src to dst but never lets dst grow past cap bytes
// (cap <= 0 means unlimited). The SMB capture path receives data as discrete
// WRITE/WritePrinter PDUs rather than one bounded stream, so io.LimitReader
// doesn't apply; this bounds the retained spool buffer the same way jobByteCap
// bounds the streaming listeners, keeping a hostile client from exhausting RAM.
func appendCapped(dst, src []byte, cap int64) []byte {
	if cap > 0 {
		room := cap - int64(len(dst))
		if room <= 0 {
			return dst
		}
		if int64(len(src)) > room {
			src = src[:room]
		}
	}
	return append(dst, src...)
}

// readStream reads r to EOF, bounded by cap bytes when cap > 0.
func readStream(r io.Reader, cap int64) []byte {
	if cap > 0 {
		r = io.LimitReader(r, cap)
	}
	b, _ := io.ReadAll(r)
	return b
}

// hardenedServer builds an http.Server with production timeouts so it cannot be
// tied up by slow or idle clients.
func hardenedServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}
}
