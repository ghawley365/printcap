package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// pcapview turns captured frames into per-packet summaries for the dashboard's
// capture viewer: a one-line description plus a coarse class the UI color-codes
// (resets and ICMP errors in red, connection setup/teardown highlighted, bulk
// data normal). It reuses stepToL3 (frameparse.go) for the L2 walk.

const (
	ipProtoICMP   = 1
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58

	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20
)

// packetSummary is one row in the capture viewer.
type packetSummary struct {
	No    int    `json:"no"`
	Time  string `json:"time"` // seconds since the first packet, e.g. "0.001234"
	Src   string `json:"src"`  // ip:port (or ip for non-port protocols)
	Dst   string `json:"dst"`
	Sport int    `json:"sport,omitempty"`
	Dport int    `json:"dport,omitempty"`
	Proto string `json:"proto"`           // TCP | UDP | ICMP | ICMPv6 | IPv4 | IPv6 | non-IP
	Svc   string `json:"svc,omitempty"`   // recognized service by port (http/https/ipp/raw/...)
	Len   int    `json:"len"`             // captured frame length
	Info  string `json:"info"`            // human-readable summary
	Class string `json:"class"`           // reset | syn | fin | error | data | other
	Color string `json:"color,omitempty"` // red | green | blue — UI row color
}

// packetColor maps a packet to a viewer row color:
//   - red:   errors and resets
//   - green: print jobs (raw/9100, LPR, IPP) and SNMP
//   - blue:  HTTPS (443)
//
// "" means default (no special color). Errors/resets take priority over service.
func packetColor(class, svc string) string {
	switch class {
	case "reset", "error":
		return "red"
	}
	switch svc {
	case "raw", "lpr", "ipp", "snmp":
		return "green"
	case "https":
		return "blue"
	}
	return ""
}

// portService names the application/API protocol of a well-known port so the
// viewer can highlight printer management/API traffic (HTTP EWS/REST, IPP, ...).
func portService(p uint16) string {
	switch p {
	case 80, 8000, 8080:
		return "http"
	case 443, 8443:
		return "https"
	case 631:
		return "ipp"
	case 515:
		return "lpr"
	case 9100, 9101, 9102:
		return "raw"
	case 161, 162:
		return "snmp"
	case 137, 138, 139, 445:
		return "smb"
	case 3702, 5357, 5358:
		return "wsd"
	case 5353:
		return "mdns"
	}
	return ""
}

// svcForPorts returns the recognized service for a flow, preferring the
// destination port (the server side).
func svcForPorts(sport, dport uint16) string {
	if s := portService(dport); s != "" {
		return s
	}
	return portService(sport)
}

// looksHTTP reports whether a reassembled stream begins like HTTP (a request
// method or a response status line) — used to render printer API traffic as text.
func looksHTTP(b []byte) bool {
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "HTTP/"} {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

// dissectSummary fills Src/Dst/Proto/Info/Class for one frame. No/Time/Len are
// set by the caller. It never panics on truncated input — anything it can't parse
// becomes a "non-IP"/"other" row rather than an error.
func dissectSummary(linkType int, frame []byte) packetSummary {
	s := packetSummary{Proto: "non-IP", Class: "other", Info: "non-IP frame"}
	ethertype, l3, ok := stepToL3(linkType, frame)
	if !ok {
		return s
	}
	src, dst, proto, l4, ok := parseIPHeader(ethertype, l3)
	if !ok {
		if ethertype == etherTypeIPv6 {
			s.Proto, s.Info = "IPv6", "IPv6 packet"
		} else if ethertype == etherTypeIPv4 {
			s.Proto, s.Info = "IPv4", "IPv4 packet"
		}
		return s
	}

	switch proto {
	case ipProtoTCP:
		s.Proto = "TCP"
		if len(l4) < 20 {
			s.Info = "truncated TCP"
			return s
		}
		thl := int(l4[12]>>4) * 4
		sp := uint16(l4[0])<<8 | uint16(l4[1])
		dp := uint16(l4[2])<<8 | uint16(l4[3])
		flags := l4[13]
		payload := 0
		if thl >= 20 && len(l4) >= thl {
			payload = len(l4) - thl
		}
		s.Src = netip.AddrPortFrom(src, sp).String()
		s.Dst = netip.AddrPortFrom(dst, dp).String()
		s.Sport, s.Dport = int(sp), int(dp)
		s.Svc = svcForPorts(sp, dp)
		fl := tcpFlagString(flags)
		s.Info = fmt.Sprintf("%d → %d [%s] len=%d", sp, dp, fl, payload)
		if s.Svc != "" {
			s.Info += " ·" + s.Svc
		}
		switch {
		case flags&tcpFlagRST != 0:
			s.Class = "reset"
		case flags&tcpFlagSYN != 0:
			s.Class = "syn"
		case flags&tcpFlagFIN != 0:
			s.Class = "fin"
		case payload > 0:
			s.Class = "data"
		default:
			s.Class = "other"
		}
	case ipProtoUDP:
		s.Proto = "UDP"
		s.Src, s.Dst = src.String(), dst.String()
		if len(l4) >= 8 {
			sp := uint16(l4[0])<<8 | uint16(l4[1])
			dp := uint16(l4[2])<<8 | uint16(l4[3])
			s.Src = netip.AddrPortFrom(src, sp).String()
			s.Dst = netip.AddrPortFrom(dst, dp).String()
			s.Sport, s.Dport = int(sp), int(dp)
			s.Svc = svcForPorts(sp, dp)
			s.Info = fmt.Sprintf("%d → %d len=%d", sp, dp, len(l4)-8)
			if s.Svc != "" {
				s.Info += " ·" + s.Svc
			}
		} else {
			s.Info = "truncated UDP"
		}
		s.Class = "data"
	case ipProtoICMP, ipProtoICMPv6:
		s.Proto = "ICMP"
		if proto == ipProtoICMPv6 {
			s.Proto = "ICMPv6"
		}
		s.Src, s.Dst = src.String(), dst.String()
		if len(l4) >= 2 {
			typ, code := l4[0], l4[1]
			s.Info = fmt.Sprintf("type=%d code=%d", typ, code)
			if isICMPError(proto, typ) {
				s.Class = "error"
				s.Info += " (" + icmpErrorName(proto, typ) + ")"
			}
		} else {
			s.Info = "truncated ICMP"
		}
	default:
		s.Proto = fmt.Sprintf("IP/%d", proto)
		s.Src, s.Dst = src.String(), dst.String()
		s.Info = fmt.Sprintf("IP protocol %d", proto)
	}
	s.Color = packetColor(s.Class, s.Svc)
	return s
}

// parseIPHeader returns the source/destination address, the L4 protocol number,
// and the L4 payload slice for an IPv4 or IPv6 packet. IPv6 extension-header
// chains are not unwound — the first next-header value is reported as the proto.
func parseIPHeader(ethertype uint16, l3 []byte) (src, dst netip.Addr, proto byte, l4 []byte, ok bool) {
	switch ethertype {
	case etherTypeIPv4:
		if len(l3) < 20 {
			return
		}
		ihl := int(l3[0]&0x0f) * 4
		if ihl < 20 || len(l3) < ihl {
			return
		}
		total := int(uint16(l3[2])<<8 | uint16(l3[3]))
		end := l3
		if total >= ihl && total <= len(l3) {
			end = l3[:total]
		}
		src = netip.AddrFrom4([4]byte{l3[12], l3[13], l3[14], l3[15]})
		dst = netip.AddrFrom4([4]byte{l3[16], l3[17], l3[18], l3[19]})
		return src, dst, l3[9], end[ihl:], true
	case etherTypeIPv6:
		if len(l3) < 40 {
			return
		}
		var s, d [16]byte
		copy(s[:], l3[8:24])
		copy(d[:], l3[24:40])
		return netip.AddrFrom16(s), netip.AddrFrom16(d), l3[6], l3[40:], true
	}
	return
}

func tcpFlagString(flags byte) string {
	var parts []string
	for _, f := range []struct {
		bit  byte
		name string
	}{
		{tcpFlagSYN, "SYN"}, {tcpFlagACK, "ACK"}, {tcpFlagFIN, "FIN"},
		{tcpFlagRST, "RST"}, {tcpFlagPSH, "PSH"}, {tcpFlagURG, "URG"},
	} {
		if flags&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// isICMPError reports whether an ICMP(v6) type indicates an error (as opposed to
// an echo/info message). For ICMPv6, every type below 128 is an error message.
func isICMPError(proto, typ byte) bool {
	if proto == ipProtoICMPv6 {
		return typ < 128
	}
	switch typ { // ICMPv4 error types
	case 3, 4, 5, 11, 12: // unreachable, source-quench, redirect, time-exceeded, param-problem
		return true
	}
	return false
}

func icmpErrorName(proto, typ byte) string {
	if proto == ipProtoICMPv6 {
		switch typ {
		case 1:
			return "destination unreachable"
		case 2:
			return "packet too big"
		case 3:
			return "time exceeded"
		case 4:
			return "parameter problem"
		}
		return "error"
	}
	switch typ {
	case 3:
		return "destination unreachable"
	case 4:
		return "source quench"
	case 5:
		return "redirect"
	case 11:
		return "time exceeded"
	case 12:
		return "parameter problem"
	}
	return "error"
}

// captureFilter narrows the viewer's packet list. Empty fields match everything.
type captureFilter struct {
	class  string // reset | syn | fin | error | data | other
	proto  string // tcp | udp | icmp (matched case-insensitively as a prefix)
	svc    string // http | https | ipp | raw | snmp | ... (recognized service)
	port   int    // match flows with this source OR destination port (0 = any)
	host   string // match packets whose source OR destination IP equals this (e.g. the MFP)
	q      string // substring over src/dst/info/proto
	offset int
	limit  int
}

// normHost normalizes a host filter value to canonical IP form (so "10.0.0.09"
// or odd spacing still matches), or returns the trimmed input if not an IP.
func normHost(s string) string {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return s
}

// ipOf extracts the bare IP from a "ip:port" or "ip" endpoint string.
func ipOf(s string) string {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return ""
}

// captureResult is the JSON payload returned to the viewer.
type captureResult struct {
	File        string          `json:"file"`
	LinkType    int             `json:"link_type"`
	TotalParsed int             `json:"total_parsed"` // records dissected (after the parse cap)
	Truncated   bool            `json:"truncated"`    // the file held more than the parse cap
	Matched     int             `json:"matched"`      // packets passing the filter
	Offset      int             `json:"offset"`
	Limit       int             `json:"limit"`
	Packets     []packetSummary `json:"packets"`
}

// maxCaptureParse bounds how many records the viewer dissects per request so a
// huge capture can't stall the dashboard; older packets beyond this are ignored.
const maxCaptureParse = 50000

// capturePackets reads the pcap at path, dissects up to maxCaptureParse records,
// applies the filter, and returns the matching page.
func capturePackets(path string, f captureFilter) (*captureResult, error) {
	data, err := readPcap(path, maxCaptureParse)
	if err != nil {
		return nil, err
	}
	var t0 time.Time
	if len(data.packets) > 0 {
		t0 = data.packets[0].ts
	}
	res := &captureResult{
		File:        filepath.Base(path),
		LinkType:    data.linkType,
		TotalParsed: len(data.packets),
		Truncated:   data.truncated,
		Offset:      f.offset,
		Limit:       f.limit,
	}
	matched := make([]packetSummary, 0, len(data.packets))
	for i, p := range data.packets {
		s := dissectSummary(data.linkType, p.data)
		s.No = i + 1
		s.Len = len(p.data)
		s.Time = fmt.Sprintf("%.6f", p.ts.Sub(t0).Seconds())
		if captureMatch(s, f) {
			matched = append(matched, s)
		}
	}
	res.Matched = len(matched)
	lo := f.offset
	if lo < 0 {
		lo = 0
	}
	if lo > len(matched) {
		lo = len(matched)
	}
	hi := lo + f.limit
	if f.limit <= 0 || hi > len(matched) {
		hi = len(matched)
	}
	res.Packets = matched[lo:hi]
	return res, nil
}

// maxFollowBytes caps each direction of a reassembled stream returned to the
// viewer's "follow stream" feature.
const maxFollowBytes = 256 * 1024

// followStream reassembles both directions of the TCP conversation between a and
// b from the pcap at path, reusing the carve reassembler. Returns the a→b and b→a
// byte streams (each capped at maxFollowBytes) and the number of packets parsed.
func followStream(path string, a, b netip.AddrPort) (ab, ba []byte, parsed int, err error) {
	data, rerr := readPcap(path, maxCaptureParse)
	if rerr != nil {
		return nil, nil, 0, rerr
	}
	collected := map[flowKey][]byte{}
	// Both ports are in scope so both directions (dst=b and dst=a) reassemble; the
	// flowKey separates them by full 4-tuple.
	ports := map[uint16]bool{a.Port(): true, b.Port(): true}
	re := newStreamReassembler(ports, false, maxFollowBytes, 0, func(fs *flowState) {
		collected[flowKey{src: fs.src, dst: fs.dst}] = fs.buf
	})
	for _, p := range data.packets {
		if seg, ok := parseTCPSegment(data.linkType, p.data); ok {
			re.consume(seg, p.ts)
		}
	}
	re.flush()
	return collected[flowKey{src: a, dst: b}], collected[flowKey{src: b, dst: a}], len(data.packets), nil
}

func captureMatch(s packetSummary, f captureFilter) bool {
	if f.class != "" && !strings.EqualFold(f.class, s.Class) {
		return false
	}
	if f.proto != "" && !strings.HasPrefix(strings.ToLower(s.Proto), strings.ToLower(f.proto)) {
		return false
	}
	if f.svc != "" && !strings.EqualFold(f.svc, s.Svc) {
		return false
	}
	if f.port > 0 && s.Sport != f.port && s.Dport != f.port {
		return false
	}
	if f.host != "" && ipOf(s.Src) != f.host && ipOf(s.Dst) != f.host {
		return false
	}
	if f.q != "" {
		hay := strings.ToLower(s.Src + " " + s.Dst + " " + s.Proto + " " + s.Info)
		if !strings.Contains(hay, strings.ToLower(f.q)) {
			return false
		}
	}
	return true
}
