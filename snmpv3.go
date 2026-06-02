package main

import "encoding/binary"

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
	_ = binary.BigEndian
	return true
}
