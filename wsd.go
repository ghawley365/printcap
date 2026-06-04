package main

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
)

// deviceUUID derives a STABLE WSD device EPR (urn:uuid:...) from the host name,
// so the same machine always presents the same WSD endpoint reference across
// restarts. The UUID is a SHA-1-derived value formatted 8-4-4-4-12 with the
// RFC 4122 version (5) and variant bits set.
func deviceUUID(host string) string {
	// Namespace the digest so it is printcap-specific and stable per host.
	sum := sha1.Sum([]byte("printcap-wsd:" + host))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// wsdServer owns the WSD SOAP HTTP listener and (optionally) the WS-Discovery
// multicast responder. The protocol stages fill this in; the skeleton lets the
// Engine start/stop it like any other closer.
type wsdServer struct {
	closers []io.Closer
}

// startWSD brings up the WSD service. It returns nil (and logs) if nothing could
// be started, so WSD failure never stops other listeners. The HTTP endpoint and
// discovery responder are wired in later stages.
func startWSD() *wsdServer {
	// Protocol wiring lands in later stages; for now this is a no-op server so
	// the Engine integration and config plumbing are testable independently.
	return &wsdServer{}
}

// Close shuts the WSD service (sends WS-Discovery Bye in a later stage).
func (w *wsdServer) Close() error {
	for _, c := range w.closers {
		_ = c.Close()
	}
	return nil
}
