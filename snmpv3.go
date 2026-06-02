package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"time"
)

// snmpEngineID is this agent's authoritative USM engine ID. It is initialized
// by buildMIB (initEngineID) from cfg.SNMP.EngineID or the hostname.
var snmpEngineID []byte

// snmpEngineBoots is the authoritative engine boot counter. The agent does not
// persist boots across restarts, so it stays 1 for a given process lifetime.
const snmpEngineBoots uint32 = 1

// snmpEngineTime returns seconds since the agent started, the authoritative
// msgAuthoritativeEngineTime used for USM timeliness checks.
func snmpEngineTime() uint32 { return uint32(time.Since(snmpStart).Seconds()) }

// usmStats Report OIDs (RFC 3414 §5).
var (
	oidUnsupportedSecLevels = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0}
	oidNotInTimeWindows     = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0}
	oidUnknownUserNames     = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}
	oidUnknownEngineIDs     = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
	oidWrongDigests         = []int{1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0}
)

const pduReport = 0xA8

// handleSNMPv3 runs the full USM receive pipeline for one v3 message and returns
// the response bytes (a Report, a GetResponse, or nil to stay silent).
func handleSNMPv3(b []byte) []byte {
	m, ok := parseV3Message(b)
	if !ok {
		return nil
	}

	wantAuth := m.flags&0x01 != 0
	wantPriv := m.flags&0x02 != 0

	// Engine discovery: an empty authoritative engine ID means the manager is
	// probing for ours. Reply with a noAuth Report carrying our engine ID.
	if len(m.engineID) == 0 {
		return buildDiscoveryReport(m)
	}

	// Reject requests addressed to a different engine.
	if string(m.engineID) != string(snmpEngineID) {
		return buildDiscoveryReport(m)
	}

	u, ok := lookupUser(m.userName)
	if !ok {
		return buildReport(m, oidUnknownUserNames)
	}
	if !levelAllowed(u, wantAuth, wantPriv) {
		return buildReport(m, oidUnsupportedSecLevels)
	}

	var authKey []byte
	if wantAuth {
		ap, ok := authProtocol(u.AuthProtocol)
		if !ok {
			return buildReport(m, oidUnsupportedSecLevels)
		}
		authKey = ap.localize(u.AuthPass, snmpEngineID)
		if !verifyAuth(ap, authKey, b, m.authParams) {
			return buildReport(m, oidWrongDigests)
		}
		if !inTimeWindow(m.boots, m.time) {
			return buildReport(m, oidNotInTimeWindows)
		}
	}

	// Recover the scoped PDU (decrypt under privacy if requested).
	scoped := m.payload
	if wantPriv {
		pp, ok := privProtocol(u.PrivProtocol)
		if !ok {
			return buildReport(m, oidUnsupportedSecLevels)
		}
		privKey := privKeyFor(u, snmpEngineID)
		pt, err := pp.decrypt(privKey, m.boots, m.time, m.privParams, m.payload)
		if err != nil {
			return nil
		}
		scoped = pt
	}

	respScoped, ok := serveScopedPDU(scoped)
	if !ok {
		return nil
	}
	return assembleV3Response(m, u, wantAuth, wantPriv, authKey, respScoped)
}

// lookupUser finds a configured USM user by name.
func lookupUser(name string) (SNMPUser, bool) {
	for _, u := range cfg.SNMP.Users {
		if u.Name == name {
			return u, true
		}
	}
	return SNMPUser{}, false
}

// levelAllowed reports whether a request at the (wantAuth, wantPriv) security
// level is permitted for user u given u.Level. A request may not ask for more
// security than the user is configured for.
func levelAllowed(u SNMPUser, wantAuth, wantPriv bool) bool {
	var okAuth, okPriv bool
	switch u.Level {
	case "authPriv":
		okAuth, okPriv = true, true
	case "authNoPriv":
		okAuth, okPriv = true, false
	default: // noAuthNoPriv
		okAuth, okPriv = false, false
	}
	if wantAuth && !okAuth {
		return false
	}
	if wantPriv && !okPriv {
		return false
	}
	return true
}

// privKeyFor derives the privacy key for u against engineID: the privacy
// passphrase is localized with the AUTH hash, then extended to the cipher's key
// length (Blumenthal).
func privKeyFor(u SNMPUser, engineID []byte) []byte {
	ap, _ := authProtocol(u.AuthProtocol)
	k := ap.localize(u.PrivPass, engineID)
	pp, _ := privProtocol(u.PrivProtocol)
	return extendKey(k, pp.keyLen, ap.newHash)
}

// inTimeWindow applies the RFC 3414 §3.2 timeliness check against our
// authoritative boots/time (±150 s).
func inTimeWindow(boots, t uint32) bool {
	if boots != snmpEngineBoots {
		return false
	}
	d := int64(t) - int64(snmpEngineTime())
	if d < 0 {
		d = -d
	}
	return d <= 150
}

// zeroAuthParams returns a copy of full with the authParams region zeroed. ap
// must be a subslice of full (as returned by readTLV), so its absolute offset is
// cap(full)-cap(ap). Returns full unchanged if the offset cannot be trusted.
func zeroAuthParams(full, ap []byte) []byte {
	pos := cap(full) - cap(ap)
	if pos < 0 || pos+len(ap) > len(full) {
		return full
	}
	cp := append([]byte(nil), full...)
	for i := range ap {
		cp[pos+i] = 0
	}
	return cp
}

// verifyAuth recomputes the HMAC over the message with zeroed authParams and
// constant-time compares it to the received params.
func verifyAuth(a authProto, key, full, gotParams []byte) bool {
	if len(gotParams) != a.macLen {
		return false
	}
	want := a.sign(key, zeroAuthParams(full, gotParams))
	return hmac.Equal(want, gotParams)
}

// serveScopedPDU parses a scoped PDU (SEQUENCE{ ctxEngineID, ctxName, PDU }),
// serves the inner request, and rebuilds a scoped response PDU.
func serveScopedPDU(scoped []byte) ([]byte, bool) {
	_, seq, _, ok := readTLV(scoped, 0)
	if !ok {
		return nil, false
	}
	_, ctxEngineID, p, ok := readTLV(seq, 0)
	if !ok {
		return nil, false
	}
	_, ctxName, p2, ok := readTLV(seq, p)
	if !ok {
		return nil, false
	}
	pduTag, pduContent, _, ok := readTLV(seq, p2)
	if !ok {
		return nil, false
	}
	respPDU := servePDU(pduTag, pduContent, 3, &v3Peer{})
	if respPDU == nil {
		return nil, false
	}
	body := tlv(berOctet, ctxEngineID)
	body = append(body, tlv(berOctet, ctxName)...)
	body = append(body, respPDU...)
	return tlv(berSequence, body), true
}

// v3Peer is a placeholder net.Addr for logging v3-sourced PDUs.
type v3Peer struct{}

func (*v3Peer) Network() string { return "udp" }
func (*v3Peer) String() string  { return "snmpv3" }

// assembleV3Response builds the response message at the request's security
// level: it encrypts (if priv), signs (if auth), and stamps our authoritative
// boots/time.
func assembleV3Response(m v3Message, u SNMPUser, wantAuth, wantPriv bool, authKey, respScoped []byte) []byte {
	rb := snmpEngineBoots
	rt := snmpEngineTime()

	var payload, privParams []byte
	encrypted := false
	if wantPriv {
		pp, _ := privProtocol(u.PrivProtocol)
		privKey := privKeyFor(u, snmpEngineID)
		ct, salt, err := pp.encrypt(privKey, rb, rt, respScoped)
		if err != nil {
			return nil
		}
		payload, privParams, encrypted = ct, salt, true
	} else {
		payload = respScoped
	}

	var flags byte
	var authParams []byte
	if wantAuth {
		flags |= 0x01
		ap, _ := authProtocol(u.AuthProtocol)
		authParams = make([]byte, ap.macLen)
	}
	if wantPriv {
		flags |= 0x02
	}

	out := v3Message{
		msgID:      m.msgID,
		maxSize:    65507,
		flags:      flags,
		engineID:   snmpEngineID,
		boots:      rb,
		time:       rt,
		userName:   u.Name,
		authParams: authParams,
		privParams: privParams,
		payload:    payload,
		encrypted:  encrypted,
	}
	msg := buildV3Message(out)

	if wantAuth {
		ap, _ := authProtocol(u.AuthProtocol)
		if authKey == nil {
			authKey = ap.localize(u.AuthPass, snmpEngineID)
		}
		parsed, ok := parseV3Message(msg)
		if !ok {
			return nil
		}
		pos := cap(msg) - cap(parsed.authParams)
		if pos < 0 || pos+len(parsed.authParams) > len(msg) {
			return nil
		}
		mac := ap.sign(authKey, zeroAuthParams(msg, parsed.authParams))
		copy(msg[pos:pos+len(mac)], mac)
	}
	return msg
}

// buildReport builds a noAuthNoPriv Report PDU carrying a single usmStats
// varbind, scoped to our engine ID. Used for USM error reporting.
func buildReport(m v3Message, oid []int) []byte {
	varbind := encodeRaw(oid, berCounter32, uintContent(1))
	pduBody := tlv(berInteger, intContent(0)) // request-id
	pduBody = append(pduBody, tlv(berInteger, intContent(0))...)
	pduBody = append(pduBody, tlv(berInteger, intContent(0))...)
	pduBody = append(pduBody, tlv(berSequence, varbind)...)
	reportPDU := tlv(pduReport, pduBody)

	scoped := tlv(berOctet, snmpEngineID)
	scoped = append(scoped, tlv(berOctet, nil)...)
	scoped = append(scoped, reportPDU...)
	scoped = tlv(berSequence, scoped)

	out := v3Message{
		msgID:    m.msgID,
		maxSize:  65507,
		flags:    0, // reports are sent noAuthNoPriv
		engineID: snmpEngineID,
		boots:    snmpEngineBoots,
		time:     snmpEngineTime(),
		userName: m.userName,
		payload:  scoped,
	}
	return buildV3Message(out)
}

// buildDiscoveryReport answers an engine-ID discovery probe with an
// usmStatsUnknownEngineIDs Report disclosing our engine ID.
func buildDiscoveryReport(m v3Message) []byte {
	return buildReport(m, oidUnknownEngineIDs)
}

// generateEngineID builds an RFC 3411 "new format" engine ID: high bit set,
// enterprise number (placeholder 0x00000C5A), format 0x05 (octets), then a
// host-derived suffix.
func generateEngineID(host string) []byte {
	id := []byte{0x80, 0x00, 0x0C, 0x5A, 0x05}
	sum := sha1.Sum([]byte(host))
	suffix := sum[:11]
	r := make([]byte, 1)
	_, _ = rand.Read(r)
	id = append(id, suffix...)
	id = append(id, r...)
	return id
}

type v3Message struct {
	msgID      uint32
	maxSize    uint32
	flags      byte // bit0 auth, bit1 priv, bit2 reportable
	engineID   []byte
	boots      uint32
	time       uint32
	userName   string
	authParams []byte
	privParams []byte
	payload    []byte // scoped PDU (plaintext) or encrypted OCTET STRING contents
	encrypted  bool
}

// buildV3Message assembles a full SNMPv3 message (version 3) from m.
func buildV3Message(m v3Message) []byte {
	// msgGlobalData = SEQUENCE { msgID, msgMaxSize, msgFlags(1 octet), msgSecurityModel(3) }
	global := tlv(berInteger, intContent(int64(m.msgID)))
	global = append(global, tlv(berInteger, intContent(int64(m.maxSize)))...)
	global = append(global, tlv(berOctet, []byte{m.flags})...)
	global = append(global, tlv(berInteger, intContent(3))...) // USM
	globalSeq := tlv(berSequence, global)

	// USM security params SEQUENCE
	usm := tlv(berOctet, m.engineID)
	usm = append(usm, tlv(berInteger, intContent(int64(m.boots)))...)
	usm = append(usm, tlv(berInteger, intContent(int64(m.time)))...)
	usm = append(usm, tlv(berOctet, []byte(m.userName))...)
	usm = append(usm, tlv(berOctet, m.authParams)...)
	usm = append(usm, tlv(berOctet, m.privParams)...)
	secParams := tlv(berOctet, tlv(berSequence, usm)) // wrapped in an OCTET STRING

	// msgData: encrypted => OCTET STRING; plaintext => the scoped PDU SEQUENCE as-is
	var data []byte
	if m.encrypted {
		data = tlv(berOctet, m.payload)
	} else {
		data = m.payload // already a SEQUENCE
	}

	body := tlv(berInteger, intContent(3)) // msgVersion = 3
	body = append(body, globalSeq...)
	body = append(body, secParams...)
	body = append(body, data...)
	return tlv(berSequence, body)
}

// parseV3Message parses a version-3 message. Caller has already confirmed version 3.
func parseV3Message(b []byte) (v3Message, bool) {
	var m v3Message
	_, msg, _, ok := readTLV(b, 0)
	if !ok {
		return m, false
	}
	// version
	_, _, p, ok := readTLV(msg, 0)
	if !ok {
		return m, false
	}
	// msgGlobalData
	_, global, p2, ok := readTLV(msg, p)
	if !ok {
		return m, false
	}
	if !parseGlobal(global, &m) {
		return m, false
	}
	// msgSecurityParameters (OCTET STRING wrapping a SEQUENCE)
	_, secOct, p3, ok := readTLV(msg, p2)
	if !ok {
		return m, false
	}
	if !parseUSM(secOct, &m) {
		return m, false
	}
	// msgData
	tag, data, _, ok := readTLV(msg, p3)
	if !ok {
		return m, false
	}
	if tag == berOctet {
		m.encrypted = true
		m.payload = data
	} else {
		// plaintext scoped PDU: re-wrap the SEQUENCE bytes for the caller.
		m.payload = tlv(tag, data)
	}
	return m, true
}

func parseGlobal(global []byte, m *v3Message) bool {
	_, id, p, ok := readTLV(global, 0)
	if !ok {
		return false
	}
	_, max, p2, ok := readTLV(global, p)
	if !ok {
		return false
	}
	_, flags, p3, ok := readTLV(global, p2)
	if !ok || len(flags) < 1 {
		return false
	}
	_, _, _, ok = readTLV(global, p3) // security model (3)
	if !ok {
		return false
	}
	m.msgID = uint32(decodeInt(id))
	m.maxSize = uint32(decodeInt(max))
	m.flags = flags[0]
	return true
}

func parseUSM(secOct []byte, m *v3Message) bool {
	_, seq, _, ok := readTLV(secOct, 0)
	if !ok {
		return false
	}
	_, eng, p, ok := readTLV(seq, 0)
	if !ok {
		return false
	}
	_, boots, p2, ok := readTLV(seq, p)
	if !ok {
		return false
	}
	_, tm, p3, ok := readTLV(seq, p2)
	if !ok {
		return false
	}
	_, user, p4, ok := readTLV(seq, p3)
	if !ok {
		return false
	}
	_, ap, p5, ok := readTLV(seq, p4)
	if !ok {
		return false
	}
	_, pp, _, ok := readTLV(seq, p5)
	if !ok {
		return false
	}
	m.engineID = eng
	m.boots = uint32(decodeInt(boots))
	m.time = uint32(decodeInt(tm))
	m.userName = string(user)
	m.authParams = ap
	m.privParams = pp
	return true
}
