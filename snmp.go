package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A compact SNMP v1/v2c agent. It serves a small, sorted MIB covering the three
// OID trees printer-discovery tools query — the system group (RFC 1213), the
// Host Resources MIB (RFC 2790, where hrDeviceType marks us as a printer), and
// the Printer MIB (RFC 3805) — and answers Get, GetNext and GetBulk so a
// scanner can both probe known OIDs and walk us.

var snmpStart = time.Now()

// BER application tags used by SNMP.
const (
	berInteger   = 0x02
	berOctet     = 0x04
	berNull      = 0x05
	berOID       = 0x06
	berSequence  = 0x30
	berCounter32 = 0x41
	berGauge32   = 0x42
	berTimeTicks = 0x43

	pduGet     = 0xA0
	pduGetNext = 0xA1
	pduResp    = 0xA2
	pduGetBulk = 0xA5

	// v2c per-varbind exception values (zero-length).
	excNoSuchObject   = 0x80
	excNoSuchInstance = 0x81
	excEndOfMibView   = 0x82
)

type mibEntry struct {
	oid []int
	val func() (tag byte, content []byte)
}

var mib []mibEntry

func buildMIB() {
	mib = nil // reset so an engine restart doesn't duplicate entries
	str := func(s string) func() (byte, []byte) {
		return func() (byte, []byte) { return berOctet, []byte(s) }
	}
	num := func(n int64) func() (byte, []byte) {
		return func() (byte, []byte) { return berInteger, intContent(n) }
	}
	counter := func(n uint64) func() (byte, []byte) {
		return func() (byte, []byte) { return berCounter32, uintContent(n) }
	}
	oidVal := func(s string) func() (byte, []byte) {
		o := parseOID(s)
		return func() (byte, []byte) { return berOID, encodeOID(o) }
	}

	p := cfg.Printer
	s := cfg.SNMP
	add := func(oid string, v func() (byte, []byte)) {
		mib = append(mib, mibEntry{parseOID(oid), v})
	}

	// System group (RFC 1213).
	add("1.3.6.1.2.1.1.1.0", str(s.SysDescr))        // sysDescr
	add("1.3.6.1.2.1.1.2.0", oidVal(s.SysObjectID))  // sysObjectID
	add("1.3.6.1.2.1.1.3.0", func() (byte, []byte) { // sysUpTime (1/100 s)
		ticks := uint64(time.Since(snmpStart) / (10 * time.Millisecond))
		return berTimeTicks, uintContent(ticks)
	})
	add("1.3.6.1.2.1.1.4.0", str(s.SysContact))  // sysContact
	add("1.3.6.1.2.1.1.5.0", str(s.SysName))     // sysName
	add("1.3.6.1.2.1.1.6.0", str(s.SysLocation)) // sysLocation
	add("1.3.6.1.2.1.1.7.0", num(72))            // sysServices

	// Host Resources MIB (RFC 2790) — hrDeviceType=printer is the key signal.
	add("1.3.6.1.2.1.25.3.2.1.2.1", oidVal("1.3.6.1.2.1.25.3.1.5"))                          // hrDeviceType=hrDevicePrinter
	add("1.3.6.1.2.1.25.3.2.1.3.1", str(p.MakeAndModel))                                     // hrDeviceDescr
	add("1.3.6.1.2.1.25.3.2.1.5.1", num(2))                                                  // hrDeviceStatus=running
	add("1.3.6.1.2.1.25.3.5.1.1.1", num(3))                                                  // hrPrinterStatus=idle
	add("1.3.6.1.2.1.25.3.5.1.2.1", func() (byte, []byte) { return berOctet, []byte{0x00} }) // hrPrinterDetectedErrorState

	// Printer MIB (RFC 3805).
	add("1.3.6.1.2.1.43.5.1.1.16.1", str(p.Name))                    // prtGeneralPrinterName
	add("1.3.6.1.2.1.43.5.1.1.17.1", str(p.Serial))                  // prtGeneralSerialNumber
	add("1.3.6.1.2.1.43.10.2.1.4.1.1", counter(uint64(s.PageCount))) // prtMarkerLifeCount (pages)
	add("1.3.6.1.2.1.43.11.1.1.8.1.1", num(100))                     // prtMarkerSuppliesMaxCapacity
	add("1.3.6.1.2.1.43.11.1.1.9.1.1", num(int64(s.TonerLevelPct)))  // prtMarkerSuppliesLevel
	add("1.3.6.1.2.1.43.16.5.1.2.1.1", str("Ready"))                 // prtConsoleDisplayBufferText

	sort.Slice(mib, func(i, j int) bool { return compareOID(mib[i].oid, mib[j].oid) < 0 })

	initEngineID()
}

// initEngineID sets snmpEngineID from the configured hex value, or derives a
// stable one from the hostname (falling back to "printcap").
func initEngineID() {
	if cfg.SNMP.EngineID != "" {
		if id, err := hex.DecodeString(cfg.SNMP.EngineID); err == nil && len(id) > 0 {
			snmpEngineID = id
			return
		}
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "printcap"
	}
	snmpEngineID = generateEngineID(host)
}

// serveSNMP answers SNMP requests on pc until it is closed by the Engine.
func serveSNMP(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			logDebug("SNMP", "receive loop exiting: %v", err)
			return
		}
		logTrace("SNMP", "received %d bytes from %s", n, peer)
		req := make([]byte, n)
		copy(req, buf[:n])
		if resp := handleSNMP(req, peer); resp != nil {
			pc.WriteTo(resp, peer)
		}
	}
}

// handleSNMP parses one SNMP message and returns the response bytes (or nil to
// stay silent, e.g. on a community mismatch or malformed packet).
func handleSNMP(b []byte, peer net.Addr) []byte {
	tag, msg, _, ok := readTLV(b, 0)
	if !ok || tag != berSequence {
		logDebug("SNMP", "dropped malformed packet from %s", peer)
		return nil
	}
	// version, community, pdu
	_, verC, p, ok := readTLV(msg, 0)
	if !ok {
		logDebug("SNMP", "dropped packet from %s: cannot parse version", peer)
		return nil
	}
	version := int(decodeInt(verC)) // 0 = v1, 1 = v2c, 3 = v3
	if version == 3 {
		if !cfg.SNMP.V3Enabled {
			logDebug("SNMP", "dropped v3 request from %s: SNMPv3 not enabled", peer)
			return nil
		}
		return handleSNMPv3(b)
	}
	if !cfg.SNMP.AllowV1V2c {
		logDebug("SNMP", "dropped v%d request from %s: v1/v2c not allowed", version+1, peer)
		return nil
	}
	_, commC, p2, ok := readTLV(msg, p)
	if !ok {
		return nil
	}
	if string(commC) != cfg.SNMP.Community {
		// Do NOT log the supplied community: it is a credential, and logging it
		// would write secrets to disk and let a brute-force dump every guess.
		logWarn("SNMP", "dropped request from %s: community mismatch (%d-byte value)", peer, len(commC))
		return nil // wrong community: drop silently
	}
	pduTag, pdu, _, ok := readTLV(msg, p2)
	if !ok {
		return nil
	}

	respPDU := servePDU(pduTag, pdu, version, peer)
	if respPDU == nil {
		return nil
	}

	out := tlv(berInteger, intContent(int64(version)))
	out = append(out, tlv(berOctet, []byte(cfg.SNMP.Community))...)
	out = append(out, respPDU...)
	return tlv(berSequence, out)
}

// servePDU serves one request PDU against the shared MIB and returns the full
// response PDU bytes (tlv(pduResp, ...)). version: 0 = v1 (noSuchName errors),
// anything else uses v2c semantics (exception varbinds). Used by both the
// v1/v2c and v3 paths. Returns nil for an unsupported/malformed PDU.
func servePDU(pduTag byte, pdu []byte, version int, peer net.Addr) []byte {
	// PDU: request-id, field2, field3, varbind-list
	_, reqID, q, ok := readTLV(pdu, 0)
	if !ok {
		return nil
	}
	_, f2, q2, ok := readTLV(pdu, q)
	if !ok {
		return nil
	}
	_, f3, q3, ok := readTLV(pdu, q2)
	if !ok {
		return nil
	}
	_, vbList, _, ok := readTLV(pdu, q3)
	if !ok {
		return nil
	}

	// Collect requested OIDs.
	var oids [][]int
	for pos := 0; pos < len(vbList); {
		vbTag, vb, next, ok := readTLV(vbList, pos)
		if !ok {
			break
		}
		pos = next
		if vbTag != berSequence {
			continue
		}
		nameTag, name, _, ok := readTLV(vb, 0)
		if ok && nameTag == berOID {
			oids = append(oids, decodeOID(name))
		}
	}

	verLabel := "v1"
	switch version {
	case 1:
		verLabel = "v2c"
	case 3:
		verLabel = "v3"
	}
	logProto("SNMP", "%s %s from %s, %d OID(s)", verLabel, snmpPduName(pduTag), peer, len(oids))
	if logger.Level() >= LevelTrace {
		for _, o := range oids {
			logTrace("SNMP", "  requested %s", oidString(o))
		}
	}

	var results [][]byte
	errStatus, errIndex := 0, 0

	switch pduTag {
	case pduGet:
		for i, o := range oids {
			if e := exactEntry(o); e != nil {
				results = append(results, encodeVarbind(o, e))
			} else if version == 0 { // v1 has no exception values
				errStatus, errIndex = 2, i+1 // noSuchName
				results = nil
				for _, oo := range oids {
					results = append(results, encodeRaw(oo, berNull, nil))
				}
			} else {
				results = append(results, encodeRaw(o, excNoSuchInstance, nil))
			}
			if errStatus != 0 {
				break
			}
		}
	case pduGetNext:
		for i, o := range oids {
			if e, no := nextEntry(o); e != nil {
				results = append(results, encodeVarbind(no, e))
			} else if version == 0 {
				errStatus, errIndex = 2, i+1
				break
			} else {
				results = append(results, encodeRaw(o, excEndOfMibView, nil))
			}
		}
	case pduGetBulk:
		// Clamp the attacker-supplied repetition counts to bound the response work
		// (defense-in-depth; the loop also self-limits at end-of-MIB).
		nonRep := clampInt(decodeInt(f2), 0, 256)
		maxRep := clampInt(decodeInt(f3), 0, 1024)
		for i, o := range oids {
			if i < int(nonRep) {
				if e, no := nextEntry(o); e != nil {
					results = append(results, encodeVarbind(no, e))
				} else {
					results = append(results, encodeRaw(o, excEndOfMibView, nil))
				}
				continue
			}
			cur := o
			for r := 0; r < int(maxRep); r++ {
				e, no := nextEntry(cur)
				if e == nil {
					results = append(results, encodeRaw(cur, excEndOfMibView, nil))
					break
				}
				results = append(results, encodeVarbind(no, e))
				cur = no
			}
		}
	default:
		return nil
	}

	// Assemble the response PDU.
	pduBody := tlv(berInteger, reqID)
	pduBody = append(pduBody, tlv(berInteger, intContent(int64(errStatus)))...)
	pduBody = append(pduBody, tlv(berInteger, intContent(int64(errIndex)))...)
	var vbAll []byte
	for _, r := range results {
		vbAll = append(vbAll, r...)
	}
	pduBody = append(pduBody, tlv(berSequence, vbAll)...)
	return tlv(pduResp, pduBody)
}

func snmpPduName(tag byte) string {
	switch tag {
	case pduGet:
		return "Get"
	case pduGetNext:
		return "GetNext"
	case pduGetBulk:
		return "GetBulk"
	default:
		return "PDU"
	}
}

// oidString renders a numeric OID for logging.
func oidString(o []int) string {
	parts := make([]string, len(o))
	for i, n := range o {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

func exactEntry(o []int) func() (byte, []byte) {
	i := sort.Search(len(mib), func(i int) bool { return compareOID(mib[i].oid, o) >= 0 })
	if i < len(mib) && compareOID(mib[i].oid, o) == 0 {
		return mib[i].val
	}
	return nil
}

// nextEntry returns the value func and OID of the first MIB entry strictly
// greater than o (the heart of snmpwalk).
func nextEntry(o []int) (func() (byte, []byte), []int) {
	i := sort.Search(len(mib), func(i int) bool { return compareOID(mib[i].oid, o) > 0 })
	if i < len(mib) {
		return mib[i].val, mib[i].oid
	}
	return nil, nil
}

func encodeVarbind(oid []int, val func() (byte, []byte)) []byte {
	tag, content := val()
	return encodeRaw(oid, tag, content)
}

func encodeRaw(oid []int, valTag byte, content []byte) []byte {
	body := tlv(berOID, encodeOID(oid))
	body = append(body, tlv(valTag, content)...)
	return tlv(berSequence, body)
}

// --- BER primitives ---------------------------------------------------------

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, berLen(len(content))...)
	return append(out, content...)
}

func berLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func readTLV(b []byte, p int) (tag byte, content []byte, next int, ok bool) {
	if p+2 > len(b) {
		return 0, nil, p, false
	}
	tag = b[p]
	p++
	l := int(b[p])
	p++
	if l&0x80 != 0 {
		n := l & 0x7f
		// Reject a length-of-length wider than 4 bytes: it exceeds any real SNMP
		// PDU and, unchecked, would overflow int below into a negative l that
		// slips past the p+l bounds test and panics b[p:p+l]. (Reached via a
		// SNMPv3 scoped PDU that decrypts to garbage, e.g. a wrong priv key.)
		if n == 0 || n > 4 || p+n > len(b) {
			return 0, nil, p, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = (l << 8) | int(b[p])
			p++
		}
	}
	if l < 0 || p+l > len(b) {
		return 0, nil, p, false
	}
	return tag, b[p : p+l], p + l, true
}

func intContent(v int64) []byte {
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(v))
	neg := v < 0
	i := 0
	for i < 7 {
		if !neg && tmp[i] == 0x00 && tmp[i+1]&0x80 == 0 {
			i++
			continue
		}
		if neg && tmp[i] == 0xff && tmp[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return tmp[i:]
}

func uintContent(v uint64) []byte {
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, v)
	i := 0
	for i < 7 && tmp[i] == 0x00 {
		i++
	}
	out := tmp[i:]
	if out[0]&0x80 != 0 { // keep unsigned: prepend a zero byte
		out = append([]byte{0x00}, out...)
	}
	return out
}

// clampInt bounds v to [lo, hi]. Used to tame attacker-supplied counts.
func clampInt(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func decodeInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1 // sign-extend
	}
	for _, c := range b {
		v = (v << 8) | int64(c)
	}
	return v
}

func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return []byte{0}
	}
	out := []byte{byte(oid[0]*40 + oid[1])}
	for _, s := range oid[2:] {
		out = append(out, base128(s)...)
	}
	return out
}

func base128(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0x7f)}, b...)
		n >>= 7
	}
	for i := 0; i < len(b)-1; i++ {
		b[i] |= 0x80
	}
	return b
}

func decodeOID(b []byte) []int {
	if len(b) == 0 {
		return nil
	}
	oid := []int{int(b[0]) / 40, int(b[0]) % 40}
	n := 0
	for _, c := range b[1:] {
		n = (n << 7) | int(c&0x7f)
		if c&0x80 == 0 {
			oid = append(oid, n)
			n = 0
		}
	}
	return oid
}

func parseOID(s string) []int {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(s), ".") {
		if part == "" {
			continue
		}
		n, _ := strconv.Atoi(part)
		out = append(out, n)
	}
	return out
}

func compareOID(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
