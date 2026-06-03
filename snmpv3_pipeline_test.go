package main

import "testing"

func TestV3AuthPrivGetSysDescr(t *testing.T) {
	cfg = defaultConfig()
	cfg.SNMP.V3Enabled = true
	cfg.SNMP.Users = []SNMPUser{{Name: "admin", Level: "authPriv",
		AuthProtocol: "SHA-1", AuthPass: "maplesyrup", PrivProtocol: "AES-128", PrivPass: "maplesyrup"}}
	buildMIB()
	snmpEngineID = generateEngineID("test")

	req := buildV3GetForTest(t, "admin", "SHA-1", "maplesyrup", "AES-128", "maplesyrup",
		snmpEngineID, 1, snmpEngineTime(), []int{1, 3, 6, 1, 2, 1, 1, 1, 0})

	resp := handleSNMP(req, testAddr{})
	if resp == nil {
		t.Fatal("nil response to authPriv Get")
	}
	val := decodeV3GetResponseForTest(t, resp, "admin", "SHA-1", "maplesyrup", "AES-128", "maplesyrup", snmpEngineID)
	if val != cfg.SNMP.SysDescr {
		t.Fatalf("sysDescr=%q want %q", val, cfg.SNMP.SysDescr)
	}
}

type testAddr struct{}

func (testAddr) Network() string { return "udp" }
func (testAddr) String() string  { return "127.0.0.1:9999" }

// TestV2cGetSysDescr guards the servePDU refactor: a plain v2c Get for
// sysDescr.0 under community "public" must still return the configured value.
func TestV2cGetSysDescr(t *testing.T) {
	cfg = defaultConfig()
	cfg.SNMP.AllowV1V2c = true
	cfg.SNMP.Community = "public"
	buildMIB()

	oid := []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	varbind := tlv(berSequence, append(tlv(berOID, encodeOID(oid)), tlv(berNull, nil)...))
	getPDU := tlv(berInteger, intContent(1))
	getPDU = append(getPDU, tlv(berInteger, intContent(0))...)
	getPDU = append(getPDU, tlv(berInteger, intContent(0))...)
	getPDU = append(getPDU, tlv(berSequence, varbind)...)

	msg := tlv(berInteger, intContent(1)) // version 1 == v2c
	msg = append(msg, tlv(berOctet, []byte("public"))...)
	msg = append(msg, tlv(pduGet, getPDU)...)
	req := tlv(berSequence, msg)

	resp := handleSNMP(req, testAddr{})
	if resp == nil {
		t.Fatal("nil response to v2c Get")
	}

	// Walk: SEQUENCE{ version, community, respPDU{ reqID, errStat, errIdx, vbList } }.
	_, body, _, ok := readTLV(resp, 0)
	if !ok {
		t.Fatal("response not a SEQUENCE")
	}
	_, _, p, _ := readTLV(body, 0)      // version
	_, _, p2, _ := readTLV(body, p)     // community
	_, pduC, _, ok := readTLV(body, p2) // response PDU
	if !ok {
		t.Fatal("missing response PDU")
	}
	_, _, q, _ := readTLV(pduC, 0)
	_, _, q2, _ := readTLV(pduC, q)
	_, _, q3, _ := readTLV(pduC, q2)
	_, vbList, _, _ := readTLV(pduC, q3)
	_, vb, _, _ := readTLV(vbList, 0)
	_, _, vp, _ := readTLV(vb, 0)
	_, val, _, ok := readTLV(vb, vp)
	if !ok {
		t.Fatal("missing varbind value")
	}
	if string(val) != cfg.SNMP.SysDescr {
		t.Fatalf("v2c sysDescr=%q want %q", string(val), cfg.SNMP.SysDescr)
	}
}

// privKeyForTest derives the privacy key the same way the agent does, given the
// raw protocol names and passwords (so the test acts as a real manager).
func privKeyForTest(authName, privName, authPass, privPass string, engineID []byte) []byte {
	return privKeyFor(SNMPUser{
		AuthProtocol: authName, AuthPass: authPass,
		PrivProtocol: privName, PrivPass: privPass,
	}, engineID)
}

// buildV3GetForTest builds a complete authPriv SNMPv3 Get request, acting as a
// USM manager: scoped PDU -> encrypt -> assemble -> splice real HMAC.
func buildV3GetForTest(t *testing.T, userName, authName, authPass, privName, privPass string,
	engineID []byte, boots, etime uint32, oid []int) []byte {
	t.Helper()

	// Scoped PDU = SEQUENCE{ OCTET(engineID), OCTET(""), GetPDU }.
	varbind := tlv(berSequence, append(tlv(berOID, encodeOID(oid)), tlv(berNull, nil)...))
	getPDU := tlv(berInteger, intContent(1))                   // request-id
	getPDU = append(getPDU, tlv(berInteger, intContent(0))...) // error-status
	getPDU = append(getPDU, tlv(berInteger, intContent(0))...) // error-index
	getPDU = append(getPDU, tlv(berSequence, varbind)...)      // varbind-list
	pdu := tlv(pduGet, getPDU)

	scoped := tlv(berOctet, engineID)
	scoped = append(scoped, tlv(berOctet, []byte(""))...)
	scoped = append(scoped, pdu...)
	scoped = tlv(berSequence, scoped)

	// Encrypt the scoped PDU.
	pp, ok := privProtocol(privName)
	if !ok {
		t.Fatalf("unknown priv protocol %q", privName)
	}
	privKey := privKeyForTest(authName, privName, authPass, privPass, engineID)
	ct, salt, err := pp.encrypt(privKey, boots, etime, scoped)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ap, ok := authProtocol(authName)
	if !ok {
		t.Fatalf("unknown auth protocol %q", authName)
	}

	out := v3Message{
		msgID:      1,
		maxSize:    65507,
		flags:      0x03, // auth+priv (not reportable)
		engineID:   engineID,
		boots:      boots,
		time:       etime,
		userName:   userName,
		authParams: make([]byte, ap.macLen),
		privParams: salt,
		payload:    ct,
		encrypted:  true,
	}
	msg := buildV3Message(out)

	// Splice the real HMAC over the message with zeroed authParams.
	parsed, ok := parseV3Message(msg)
	if !ok {
		t.Fatal("parseV3Message failed on built request")
	}
	pos := cap(msg) - cap(parsed.authParams)
	authKey := ap.localize(authPass, engineID)
	mac := ap.sign(authKey, zeroAuthParams(msg, parsed.authParams))
	copy(msg[pos:pos+len(mac)], mac)
	return msg
}

// decodeV3GetResponseForTest decrypts and parses an authPriv response, returning
// the first varbind's OCTET STRING value.
func decodeV3GetResponseForTest(t *testing.T, resp []byte, userName, authName, authPass, privName, privPass string, engineID []byte) string {
	t.Helper()

	m, ok := parseV3Message(resp)
	if !ok {
		t.Fatal("parseV3Message failed on response")
	}
	if !m.encrypted {
		t.Fatal("response not encrypted")
	}
	pp, ok := privProtocol(privName)
	if !ok {
		t.Fatalf("unknown priv protocol %q", privName)
	}
	privKey := privKeyForTest(authName, privName, authPass, privPass, engineID)
	scoped, err := pp.decrypt(privKey, m.boots, m.time, m.privParams, m.payload)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	// scoped = SEQUENCE{ ctxEngineID OCTET, ctxName OCTET, respPDU }
	_, seq, _, ok := readTLV(scoped, 0)
	if !ok {
		t.Fatal("scoped not a SEQUENCE")
	}
	_, _, p, ok := readTLV(seq, 0) // contextEngineID
	if !ok {
		t.Fatal("missing contextEngineID")
	}
	_, _, p2, ok := readTLV(seq, p) // contextName
	if !ok {
		t.Fatal("missing contextName")
	}
	_, pduC, _, ok := readTLV(seq, p2) // response PDU
	if !ok {
		t.Fatal("missing response PDU")
	}
	// PDU: request-id, error-status, error-index, varbind-list
	_, _, q, ok := readTLV(pduC, 0)
	if !ok {
		t.Fatal("missing request-id")
	}
	_, _, q2, ok := readTLV(pduC, q)
	if !ok {
		t.Fatal("missing error-status")
	}
	_, _, q3, ok := readTLV(pduC, q2)
	if !ok {
		t.Fatal("missing error-index")
	}
	_, vbList, _, ok := readTLV(pduC, q3)
	if !ok {
		t.Fatal("missing varbind-list")
	}
	_, vb, _, ok := readTLV(vbList, 0)
	if !ok {
		t.Fatal("missing first varbind")
	}
	_, _, vp, ok := readTLV(vb, 0) // OID
	if !ok {
		t.Fatal("missing varbind OID")
	}
	_, val, _, ok := readTLV(vb, vp) // value
	if !ok {
		t.Fatal("missing varbind value")
	}
	return string(val)
}
