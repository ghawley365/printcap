package main

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
)

// maxWSDBody bounds the SOAP request body we will read, protecting memory
// against oversized or hostile POSTs.
const maxWSDBody = 32 << 20

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
	w := &wsdServer{}
	wsdEndpoint = wsdEndpointURL(cfg.Bind, cfg.WSD.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/wsd", wsdHandler)

	ln, err := net.Listen("tcp", net.JoinHostPort(cfg.Bind, itoa(cfg.WSD.Port)))
	if err != nil {
		logWarn("WSD", "SOAP listen %d: %v", cfg.WSD.Port, err)
		return nil
	}
	srv := hardenedServer("", mux)
	// Append a graceful httpCloser (not the bare listener/server) so Close()
	// drains in-flight SOAP handlers via Shutdown before force-closing, then
	// closes the listener it is serving.
	w.closers = append(w.closers, httpCloser{srv})
	trackGo(func() { _ = srv.Serve(ln) })
	logInfo("WSD", "SOAP print service on %s", wsdEndpoint)

	if cfg.WSD.Discovery {
		if d := startWSDDiscovery(); d != nil {
			w.closers = append(w.closers, d)
		}
	}
	return w
}

// wsdHandler serves the WSD SOAP endpoint. It reads the (bounded) request body,
// parses the SOAP envelope, and dispatches on the WS-Addressing Action. It never
// panics on malformed input and always replies with a SOAP 1.2 message.
func wsdHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWSDBody))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// MTOM/XOP: when the request is multipart/related the SOAP envelope is the
	// root part and binary documents arrive as separate attachments keyed by CID.
	root := body
	var parts map[string][]byte
	if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/related") {
		root, parts, err = extractMTOM(ct, body)
		if err != nil {
			http.Error(w, "bad MTOM", http.StatusBadRequest)
			return
		}
	}

	env, ok := parseSOAP(root)
	if !ok {
		http.Error(w, "bad SOAP", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")

	switch {
	case env.Action == actTransferGet:
		_, _ = w.Write(buildMetadataResponse(env.MessageID))
		return
	default:
		if resp, handled := wsprintHandle(env, parts, r.RemoteAddr); handled {
			_, _ = w.Write(resp)
			return
		}
		_, _ = w.Write(soapFault(env.MessageID, "Sender", "wsa:ActionNotSupported", "Action not supported"))
	}
}

// Close shuts the WSD service (sends WS-Discovery Bye in a later stage).
func (w *wsdServer) Close() error {
	for _, c := range w.closers {
		_ = c.Close()
	}
	return nil
}
