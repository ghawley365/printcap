package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	mdnsAddr4 = "224.0.0.251:5353"
	mdnsAddr6 = "[ff02::fb]:5353"
	metaQuery = "_services._dns-sd._udp.local"
)

// srvAndTxt returns the SRV, TXT, and host A/AAAA records for one service.
func srvAndTxt(s service, a svcAddrs) []dnsRecord {
	recs := []dnsRecord{
		{name: s.instanceName(), rtype: dnsTypeSRV, ttl: ttlDNSSD, flush: true,
			data: rdataSRV(0, 0, s.port, a.host)},
		{name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD, flush: true,
			data: rdataTXT(s.txt)},
	}
	recs = append(recs, hostRecords(a)...)
	return recs
}

func hostRecords(a svcAddrs) []dnsRecord {
	var recs []dnsRecord
	for _, ip := range a.v4 {
		recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeA, ttl: ttlHost, flush: true, data: rdataA(ip)})
	}
	for _, ip := range a.v6 {
		recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeAAAA, ttl: ttlHost, flush: true, data: rdataAAAA(ip)})
	}
	return recs
}

// answersFor returns the records that answer one question, or nil if the
// question targets nothing we advertise.
func answersFor(q dnsQuestion, svcs []service, a svcAddrs) []dnsRecord {
	var out []dnsRecord
	matchesType := func(want uint16) bool { return q.qtype == want || q.qtype == dnsTypeANY }

	if q.name == metaQuery && matchesType(dnsTypePTR) {
		for _, s := range svcs {
			out = append(out, dnsRecord{name: metaQuery, rtype: dnsTypePTR, ttl: ttlDNSSD,
				data: rdataPTR(s.browseName())})
		}
		return out
	}

	for _, s := range svcs {
		switch {
		case q.name == s.browseName() && matchesType(dnsTypePTR):
			out = append(out, dnsRecord{name: s.browseName(), rtype: dnsTypePTR, ttl: ttlDNSSD,
				data: rdataPTR(s.instanceName())})
			out = append(out, srvAndTxt(s, a)...)
		case q.name == s.instanceName() && matchesType(dnsTypeSRV):
			out = append(out, srvAndTxt(s, a)...)
		case q.name == s.instanceName() && matchesType(dnsTypeTXT):
			out = append(out, dnsRecord{name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD,
				flush: true, data: rdataTXT(s.txt)})
		case q.name == a.host && (matchesType(dnsTypeA) || matchesType(dnsTypeAAAA)):
			out = append(out, hostRecords(a)...)
		}
		for _, sub := range s.subtypes {
			subName := sub + "._sub." + s.svcType + ".local"
			if q.name == subName && matchesType(dnsTypePTR) {
				out = append(out, dnsRecord{name: subName, rtype: dnsTypePTR, ttl: ttlDNSSD,
					data: rdataPTR(s.instanceName())})
			}
		}
	}
	return out
}

// uniqueInstance returns base if it is not in taken; otherwise it appends
// " (2)", " (3)", … until it finds a name not in taken (RFC 6762 §9 style).
func uniqueInstance(base string, taken map[string]bool) string {
	if !taken[base] {
		return base
	}
	for n := 2; ; n++ {
		cand := base + " (" + strconv.Itoa(n) + ")"
		if !taken[cand] {
			return cand
		}
	}
}

// mdnsResponder owns the multicast sockets and the advertised service set.
type mdnsResponder struct {
	conns []*net.UDPConn
	svcs  []service
	addrs svcAddrs
	grp4  *net.UDPAddr
	grp6  *net.UDPAddr
	mu    sync.Mutex
	done  chan struct{}
}

// startResponder opens whatever multicast sockets it can and begins answering.
// It returns nil (and logs) if no socket could be opened, so mDNS failure never
// stops other listeners.
func startResponder(svcs []service, addrs svcAddrs) *mdnsResponder {
	r := &mdnsResponder{svcs: svcs, addrs: addrs, done: make(chan struct{})}
	r.grp4, _ = net.ResolveUDPAddr("udp4", mdnsAddr4)
	r.grp6, _ = net.ResolveUDPAddr("udp6", mdnsAddr6)

	ifaces, err := net.Interfaces()
	if err != nil {
		logWarn("mDNS", "cannot enumerate interfaces: %v", err)
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
			logDebug("mDNS", "IPv4 5353 join on %s failed: %v", ifi.Name, err)
		}
		if c, err := net.ListenMulticastUDP("udp6", &ifi, r.grp6); err == nil {
			r.conns = append(r.conns, c)
		} else {
			logDebug("mDNS", "IPv6 5353 join on %s failed: %v", ifi.Name, err)
		}
	}
	if len(r.conns) == 0 {
		logWarn("mDNS", "no multicast socket available; discovery advertisement disabled")
		return nil
	}

	// Best-effort RFC 6762 §9 collision probe. Done synchronously here, BEFORE
	// the serve goroutines start, so no socket is read by two goroutines at
	// once (race-free). Any error is ignored and we proceed with our name.
	r.probeAndResolve()

	for _, c := range r.conns {
		go r.serve(c)
	}
	go r.announce()
	names := make([]string, len(r.svcs))
	for i, s := range r.svcs {
		names[i] = s.svcType
	}
	logInfo("mDNS", "advertising %d service(s) as %q [%s]", len(r.svcs), addrs.host, strings.Join(names, ", "))
	return r
}

// probeAndResolve sends an ANY probe for our instance name and collects any
// instance names already claimed for our service types, then renames our
// services if our chosen instance is taken. Best-effort: every error is
// ignored and advertising proceeds with the original name.
func (r *mdnsResponder) probeAndResolve() {
	base := resolveInstance()
	if base == "" || len(r.svcs) == 0 {
		return
	}
	// Probe each of our service types' instance names (type ANY).
	taken := map[string]bool{}
	for _, c := range r.conns {
		for _, s := range r.svcs {
			probe := buildProbe(s.instanceName())
			r.writeMulticast(c, probe)
		}
	}
	// Set of our browse names so we only record collisions on types we own.
	ourTypes := map[string]bool{}
	for _, s := range r.svcs {
		ourTypes[s.browseName()] = true
	}
	deadline := time.Now().Add(250 * time.Millisecond)
	buf := make([]byte, 9000)
	for _, c := range r.conns {
		_ = c.SetReadDeadline(deadline)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
			for _, rec := range knownAnswers(buf[:n]) {
				inst := instanceFromAnswer(rec)
				if inst == "" {
					continue
				}
				// Record names belonging to our service types.
				for t := range ourTypes {
					suffix := "." + t
					if strings.HasSuffix(inst, suffix) {
						label := strings.TrimSuffix(inst, suffix)
						taken[label] = true
					}
				}
			}
		}
		_ = c.SetReadDeadline(time.Time{})
	}
	name := uniqueInstance(base, taken)
	if name != base {
		logWarn("mDNS", "instance %q in use, advertising as %q", base, name)
		renamed := make([]service, len(r.svcs))
		for i, s := range r.svcs {
			s.instance = name
			renamed[i] = s
		}
		r.svcs = renamed
	}
}

// instanceFromAnswer extracts the advertised instance name referenced by a
// browse PTR (rdata is a domain name) or returns the record name for SRV/TXT.
func instanceFromAnswer(rec dnsRecord) string {
	switch rec.rtype {
	case dnsTypePTR:
		name, _, ok := parseName(rec.data, 0)
		if !ok {
			return ""
		}
		return name
	case dnsTypeSRV, dnsTypeTXT:
		return rec.name
	}
	return ""
}

// buildProbe builds a one-question mDNS query (type ANY, multicast) used by the
// collision probe. Mirrors the wire format of the test helper buildQuery but is
// a distinct name to avoid a package-scope redeclaration.
func buildProbe(name string) []byte {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:], 1) // qdcount = 1
	b = append(b, hdr...)
	b = append(b, encodeName(name)...)
	qt := make([]byte, 4)
	binary.BigEndian.PutUint16(qt[0:], dnsTypeANY)
	binary.BigEndian.PutUint16(qt[2:], dnsClassIN)
	return append(b, qt...)
}

func (r *mdnsResponder) serve(c *net.UDPConn) {
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		qs, ok := parseQuestions(buf[:n])
		if !ok {
			continue
		}
		known := knownAnswers(buf[:n])
		var answers []dnsRecord
		wantUnicast := false
		for _, q := range qs {
			recs := answersFor(q, r.svcs, r.addrs)
			for _, rec := range recs {
				if recordKnown(rec, known) {
					continue
				}
				answers = append(answers, rec)
				if q.unicast {
					wantUnicast = true
				}
			}
			if len(recs) > 0 {
				logTrace("mDNS", "answered %s for %s from %s", dnsTypeName(q.qtype), q.name, src)
			}
		}
		if len(answers) == 0 {
			continue
		}
		msg := buildResponse(answers)
		if wantUnicast {
			_, _ = c.WriteToUDP(msg, src)
		} else {
			r.writeMulticast(c, msg)
		}
	}
}

func (r *mdnsResponder) writeMulticast(c *net.UDPConn, msg []byte) {
	grp := r.grp4
	if c.LocalAddr() != nil && strings.Contains(c.LocalAddr().String(), "::") {
		grp = r.grp6
	}
	_, _ = c.WriteToUDP(msg, grp)
}

// announce sends unsolicited responses for all records twice ~1s apart.
func (r *mdnsResponder) announce() {
	msg := buildResponse(r.allRecords())
	for i := 0; i < 2; i++ {
		for _, c := range r.conns {
			r.writeMulticast(c, msg)
		}
		select {
		case <-time.After(time.Second):
		case <-r.done:
			return
		}
	}
}

// allRecords returns the full record set used for announce/goodbye.
func (r *mdnsResponder) allRecords() []dnsRecord {
	var recs []dnsRecord
	for _, s := range r.svcs {
		recs = append(recs, dnsRecord{name: s.browseName(), rtype: dnsTypePTR, ttl: ttlDNSSD,
			data: rdataPTR(s.instanceName())})
		for _, sub := range s.subtypes {
			subName := sub + "._sub." + s.svcType + ".local"
			recs = append(recs, dnsRecord{name: subName, rtype: dnsTypePTR, ttl: ttlDNSSD,
				data: rdataPTR(s.instanceName())})
		}
		recs = append(recs, srvAndTxt(s, r.addrs)...)
	}
	return recs
}

// Close sends goodbye packets (TTL 0) and shuts the sockets.
func (r *mdnsResponder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.done)
	goodbye := r.allRecords()
	for i := range goodbye {
		goodbye[i].ttl = 0
	}
	msg := buildResponse(goodbye)
	for _, c := range r.conns {
		r.writeMulticast(c, msg)
		_ = c.Close()
	}
	logInfo("mDNS", "withdrawn")
	return nil
}

func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypePTR:
		return "PTR"
	case dnsTypeTXT:
		return "TXT"
	case dnsTypeSRV:
		return "SRV"
	case dnsTypeANY:
		return "ANY"
	default:
		return "?"
	}
}

// knownAnswers parses the answer section of an incoming query (RFC 6762 §7.1
// known-answer suppression). Best-effort: on any parse error it returns whatever
// it decoded so far so suppression does less, never more.
func knownAnswers(b []byte) []dnsRecord {
	if len(b) < 12 {
		return nil
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, ok := parseName(b, off)
		if !ok || next+4 > len(b) {
			return nil
		}
		off = next + 4
	}
	var out []dnsRecord
	for i := 0; i < an; i++ {
		name, next, ok := parseName(b, off)
		if !ok || next+10 > len(b) {
			return out
		}
		rtype := binary.BigEndian.Uint16(b[next:])
		ttl := binary.BigEndian.Uint32(b[next+4:])
		rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
		rdStart := next + 10
		if rdStart+rdlen > len(b) {
			return out
		}
		out = append(out, dnsRecord{
			name:  name,
			rtype: rtype,
			ttl:   ttl,
			data:  append([]byte{}, b[rdStart:rdStart+rdlen]...),
		})
		off = rdStart + rdlen
	}
	return out
}

// recordKnown reports whether the querier already knows rec (same name+type and
// a known-answer TTL of at least half ours, RFC 6762 §7.1).
func recordKnown(rec dnsRecord, known []dnsRecord) bool {
	for _, k := range known {
		if k.name == rec.name && k.rtype == rec.rtype && k.ttl >= rec.ttl/2 {
			return true
		}
	}
	return false
}
