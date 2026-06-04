package main

import (
	"bytes"
	"encoding/xml"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// WS-Discovery multicast groups (SOAP-over-UDP, port 3702).
const (
	wsdDiscAddr4 = "239.255.255.250:3702"
	wsdDiscAddr6 = "[ff02::c]:3702"
)

// WS-Discovery / device-profile namespaces. We use the 2005/04 discovery
// namespace because that is what Windows WSD (and "Add a device") expects.
const (
	nsDisc      = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
	nsDevProf   = "http://schemas.xmlsoap.org/ws/2006/02/devprof"
	nsWdpPrint  = "http://schemas.microsoft.com/windows/2006/08/wdp/print"
	wsdDiscTo   = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
	wsdDevTypes = "wsdp:Device wprt:PrintDeviceType"
)

// WS-Discovery action URIs.
const (
	actProbe        = nsDisc + "/Probe"
	actProbeMatches = nsDisc + "/ProbeMatches"
	actResolve      = nsDisc + "/Resolve"
	actResolveMatch = nsDisc + "/ResolveMatches"
	actHello        = nsDisc + "/Hello"
	actBye          = nsDisc + "/Bye"
	wsdMetadataVer  = "1"
)

// wsdEndpoint is the transport URL (our SOAP endpoint) advertised in XAddrs.
// The runtime sets it at startup via wsdEndpointURL; tests set it directly.
var wsdEndpoint string

// wsdMsgCounter makes per-message MessageIDs unique without leaking state.
var wsdMsgCounter uint64

// wsdHost returns a stable host label for the device UUID. It prefers the
// configured printer name (so the EPR is deterministic and human-meaningful),
// falling back to "printcap". It never consults os.Hostname so the EPR is
// reproducible in tests and across machines with the same config.
func wsdHost() string {
	if cfg != nil && strings.TrimSpace(cfg.Printer.Name) != "" {
		return strings.TrimSpace(cfg.Printer.Name)
	}
	return "printcap"
}

// wsdMessageID returns a fresh urn:uuid message identifier. It derives the value
// from the stable device UUID plus a monotonic counter so each message is unique
// but no randomness/global clock is required.
func wsdMessageID() string {
	n := atomic.AddUint64(&wsdMsgCounter, 1)
	return "urn:uuid:" + strings.TrimPrefix(deviceUUID(wsdHost()), "urn:uuid:") + "-" + strconv.FormatUint(n, 10)
}

// xmlEsc returns s XML-escaped for safe interpolation into element text.
func xmlEsc(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// matchBody is the common inner XML shared by ProbeMatch/ResolveMatch/Hello.
// withXAddrs controls whether the transport address + metadata version are
// included (Hello/Bye carry the EPR; Bye omits XAddrs/metadata).
func metadataBlock(withXAddrs bool) string {
	var b strings.Builder
	b.WriteString(`<wsa:EndpointReference><wsa:Address>`)
	b.WriteString(xmlEsc(deviceUUID(wsdHost())))
	b.WriteString(`</wsa:Address></wsa:EndpointReference>`)
	b.WriteString(`<d:Types>`)
	b.WriteString(wsdDevTypes)
	b.WriteString(`</d:Types>`)
	if withXAddrs {
		b.WriteString(`<d:XAddrs>`)
		b.WriteString(xmlEsc(wsdEndpoint))
		b.WriteString(`</d:XAddrs>`)
		b.WriteString(`<d:MetadataVersion>`)
		b.WriteString(wsdMetadataVer)
		b.WriteString(`</d:MetadataVersion>`)
	}
	return b.String()
}

// discNamespaces is the namespace declaration block placed on the top element of
// every discovery body. buildSOAP only declares s/a on the Envelope, so each
// body must declare d/wsdp/wprt/wsa itself.
const discNamespaces = ` xmlns:d="` + nsDisc + `"` +
	` xmlns:wsdp="` + nsDevProf + `"` +
	` xmlns:wprt="` + nsWdpPrint + `"` +
	` xmlns:wsa="` + nsAddr + `"`

// probeTypes is the unmarshal target used to extract the d:Types text from a
// Probe body. Local-name matching keeps it namespace-prefix independent.
type probeTypes struct {
	XMLName xml.Name
	Types   string `xml:"Types"`
}

// handleProbe parses a Probe body and, if it targets our device, returns a
// ProbeMatches SOAP envelope. Matching is lenient: an empty/absent d:Types
// matches any device (WS-Discovery semantics), otherwise the Types text must
// mention "PrintDeviceType" (prefixes/namespaces vary across clients).
func handleProbe(body []byte) (resp []byte, matched bool) {
	if !probeMatches(body) {
		return nil, false
	}
	inner := `<d:ProbeMatches` + discNamespaces + `><d:ProbeMatch>` +
		metadataBlock(true) +
		`</d:ProbeMatch></d:ProbeMatches>`
	env := soapEnvelope{
		Action:    actProbeMatches,
		MessageID: wsdMessageID(),
		To:        wsdDiscTo,
		BodyXML:   []byte(inner),
	}
	return buildSOAP(env), true
}

// probeMatches reports whether a Probe body targets our print device. Best-effort
// and panic-free on malformed input: a parse failure is treated as "match all"
// only when no Types element is detectable, otherwise as no match.
func probeMatches(body []byte) bool {
	var p probeTypes
	if err := xml.Unmarshal(body, &p); err != nil {
		// Lenient fallback: scan the raw bytes. If it mentions a Types element
		// at all, require PrintDeviceType; otherwise treat as empty Probe.
		if bytes.Contains(body, []byte("Types")) {
			return bytes.Contains(body, []byte("PrintDeviceType"))
		}
		return true
	}
	types := strings.TrimSpace(p.Types)
	if types == "" {
		return true
	}
	return strings.Contains(types, "PrintDeviceType")
}

// handleResolve returns a ResolveMatches SOAP envelope. We expose a single
// device, so a Resolve always resolves to it.
func handleResolve(body []byte) (resp []byte, ok bool) {
	inner := `<d:ResolveMatches` + discNamespaces + `><d:ResolveMatch>` +
		metadataBlock(true) +
		`</d:ResolveMatch></d:ResolveMatches>`
	env := soapEnvelope{
		Action:    actResolveMatch,
		MessageID: wsdMessageID(),
		To:        wsdDiscTo,
		BodyXML:   []byte(inner),
	}
	return buildSOAP(env), true
}

// helloMessage builds the unsolicited Hello announcement (EPR + Types + XAddrs +
// MetadataVersion).
func helloMessage() []byte {
	inner := `<d:Hello` + discNamespaces + `>` + metadataBlock(true) + `</d:Hello>`
	env := soapEnvelope{
		Action:    actHello,
		MessageID: wsdMessageID(),
		To:        wsdDiscTo,
		BodyXML:   []byte(inner),
	}
	return buildSOAP(env)
}

// byeMessage builds the unsolicited Bye withdrawal. Bye needs only the EPR
// (plus Types for completeness); XAddrs/metadata are omitted.
func byeMessage() []byte {
	inner := `<d:Bye` + discNamespaces + `>` + metadataBlock(false) + `</d:Bye>`
	env := soapEnvelope{
		Action:    actBye,
		MessageID: wsdMessageID(),
		To:        wsdDiscTo,
		BodyXML:   []byte(inner),
	}
	return buildSOAP(env)
}

// wsdEndpointURL returns the transport URL advertised in XAddrs:
// http://<host>:<port>/wsd, where host is a non-loopback local IPv4 (or the
// specific bind address if one was configured). Falls back to the bind string.
func wsdEndpointURL(bind string, port int) string {
	host := bind
	if host == "" || host == "0.0.0.0" || host == "::" {
		if v4, v6 := localAddrs(bind); len(v4) > 0 {
			host = v4[0].String()
		} else if len(v6) > 0 {
			host = "[" + v6[0].String() + "]"
		} else {
			host = "127.0.0.1"
		}
	} else if ip := net.ParseIP(bind); ip != nil && ip.To4() == nil {
		host = "[" + bind + "]" // bracket a literal IPv6 bind
	}
	return "http://" + host + ":" + strconv.Itoa(port) + "/wsd"
}

// wsdDiscoveryResponder owns the WS-Discovery multicast sockets. It mirrors
// mdnsResponder: dual-stack, graceful degradation, Hello on start, Bye on close.
//
// Multicast I/O (serve/writeMulticast/Hello/Bye) is exercised by manual and
// loopback acceptance tests, not by socket-level unit tests; the pure message
// logic above is unit-tested.
type wsdDiscoveryResponder struct {
	conns  []*net.UDPConn
	grp4   *net.UDPAddr
	grp6   *net.UDPAddr
	mu     sync.Mutex
	closed bool
	done   chan struct{}
}

// startWSDDiscovery opens whatever multicast sockets it can, announces Hello,
// and answers Probe/Resolve. It returns nil (and logs) if no socket could be
// opened, so discovery failure never stops the rest of WSD.
func startWSDDiscovery() *wsdDiscoveryResponder {
	r := &wsdDiscoveryResponder{done: make(chan struct{})}
	r.grp4, _ = net.ResolveUDPAddr("udp4", wsdDiscAddr4)
	r.grp6, _ = net.ResolveUDPAddr("udp6", wsdDiscAddr6)

	ifaces, err := net.Interfaces()
	if err != nil {
		logWarn("WSD", "cannot enumerate interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 ||
			ifi.Flags&net.FlagLoopback != 0 ||
			ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		ifi := ifi
		if c, err := net.ListenMulticastUDP("udp4", &ifi, r.grp4); err == nil {
			r.conns = append(r.conns, c)
		} else {
			logDebug("WSD", "IPv4 3702 join on %s failed: %v", ifi.Name, err)
		}
		if c, err := net.ListenMulticastUDP("udp6", &ifi, r.grp6); err == nil {
			r.conns = append(r.conns, c)
		} else {
			logDebug("WSD", "IPv6 3702 join on %s failed: %v", ifi.Name, err)
		}
	}
	if len(r.conns) == 0 {
		logWarn("WSD", "no multicast socket available; WS-Discovery disabled")
		return nil
	}

	// Build conns fully before launching goroutines (race-free, like mdns).
	for _, c := range r.conns {
		go r.serve(c)
	}
	hello := helloMessage()
	for _, c := range r.conns {
		r.writeMulticast(c, hello)
	}
	logInfo("WSD", "WS-Discovery responder up on %d socket(s); XAddrs %s", len(r.conns), wsdEndpoint)
	return r
}

// serve reads datagrams, parses the SOAP, and answers Probe/Resolve by unicast
// to the sender (WS-Discovery replies are unicast to the prober). It never
// panics on untrusted input and ignores anything it cannot answer.
func (r *wsdDiscoveryResponder) serve(c *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		env, ok := parseSOAP(buf[:n])
		if !ok {
			continue
		}
		var resp []byte
		switch {
		case strings.HasSuffix(env.Action, "/Probe"):
			if r, matched := handleProbe(env.BodyXML); matched {
				resp = r
			}
		case strings.HasSuffix(env.Action, "/Resolve"):
			if r, matched := handleResolve(env.BodyXML); matched {
				resp = r
			}
		}
		if resp == nil {
			continue
		}
		if _, err := c.WriteToUDP(resp, src); err != nil {
			logDebug("WSD", "unicast reply to %s failed: %v", src, err)
		}
	}
}

// writeMulticast sends msg to the WS-Discovery group on the family of c.
func (r *wsdDiscoveryResponder) writeMulticast(c *net.UDPConn, msg []byte) {
	grp := r.grp4
	if c.LocalAddr() != nil && strings.Contains(c.LocalAddr().String(), "::") {
		grp = r.grp6
	}
	_, _ = c.WriteToUDP(msg, grp)
}

// Close sends Bye and shuts the sockets. It is idempotent: a second Close must
// not re-close r.done or double-close sockets.
func (r *wsdDiscoveryResponder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	close(r.done)
	bye := byeMessage()
	for _, c := range r.conns {
		r.writeMulticast(c, bye)
		_ = c.Close()
	}
	logInfo("WSD", "WSD discovery withdrawn")
	return nil
}
