package main

import (
	"encoding/binary"
	"testing"
)

// buildNegotiateRequest constructs a valid NEGOTIATE request ([MS-SMB2]
// §2.2.3): a 64-byte SMB2 header followed by the request body. When
// withContexts is set and 3.1.1 is among the offered dialects, a
// PREAUTH_INTEGRITY context (SHA-512 + 32-byte salt) and an ENCRYPTION context
// (offering AES-128-GCM and AES-128-CCM) are appended, each 8-byte aligned.
func buildNegotiateRequest(dialects []uint16, withContexts bool) []byte {
	hdr := smb2Header{Command: smb2Negotiate}.encode()

	has311 := false
	for _, d := range dialects {
		if d == 0x0311 {
			has311 = true
		}
	}
	emitContexts := withContexts && has311

	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects)))
	binary.LittleEndian.PutUint16(body[4:6], 0x0001) // SecurityMode: signing enabled
	// body[6:8] Reserved
	binary.LittleEndian.PutUint32(body[8:12], 0) // Capabilities
	// body[12:28] ClientGuid (zero)
	// body[28:36] NegotiateContextOffset/Count/Reserved2 (filled below if 3.1.1)

	// Dialects array.
	for _, d := range dialects {
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], d)
		body = append(body, tmp[:]...)
	}

	if emitContexts {
		// Pad the dialect list to an 8-byte boundary relative to header start.
		for (len(hdr)+len(body))%8 != 0 {
			body = append(body, 0)
		}
		ncOffset := len(hdr) + len(body) // from start of header

		// PREAUTH_INTEGRITY context: SHA-512, 32-byte salt.
		preauthData := make([]byte, 4+2+32)
		binary.LittleEndian.PutUint16(preauthData[0:2], 1)      // HashAlgorithmCount
		binary.LittleEndian.PutUint16(preauthData[2:4], 32)     // SaltLength
		binary.LittleEndian.PutUint16(preauthData[4:6], 0x0001) // SHA-512
		// salt bytes [6:38] left zero
		body = appendNegContext(body, len(hdr), 0x0001, preauthData)

		// ENCRYPTION context: offer GCM then CCM.
		encData := make([]byte, 2+4)
		binary.LittleEndian.PutUint16(encData[0:2], 2)      // CipherCount
		binary.LittleEndian.PutUint16(encData[2:4], 0x0002) // AES-128-GCM
		binary.LittleEndian.PutUint16(encData[4:6], 0x0001) // AES-128-CCM
		body = appendNegContext(body, len(hdr), 0x0002, encData)

		binary.LittleEndian.PutUint32(body[28:32], uint32(ncOffset))
		binary.LittleEndian.PutUint16(body[32:34], 2) // NegotiateContextCount
	}

	return append(hdr, body...)
}

// appendNegContext appends one 8-byte-aligned NEGOTIATE_CONTEXT. hdrLen is the
// length of the SMB2 header so alignment is computed from the header start.
func appendNegContext(body []byte, hdrLen int, ctxType uint16, data []byte) []byte {
	for (hdrLen+len(body))%8 != 0 {
		body = append(body, 0)
	}
	hdrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint16(hdrBytes[0:2], ctxType)
	binary.LittleEndian.PutUint16(hdrBytes[2:4], uint16(len(data)))
	// hdrBytes[4:8] Reserved
	body = append(body, hdrBytes...)
	body = append(body, data...)
	return body
}

func TestHandleNegotiateSelects311(t *testing.T) {
	req := buildNegotiateRequest([]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, true)
	resp, st, ok := handleNegotiate(req)
	if !ok || st != negStateOK {
		t.Fatalf("ok=%v st=%v", ok, st)
	}
	hdr, _ := parseSMB2Header(resp)
	if hdr.Command != smb2Negotiate || hdr.Flags&smb2FlagsServerToRedir == 0 {
		t.Fatalf("response header wrong: %+v", hdr)
	}
	body := resp[64:]
	// StructureSize 65, DialectRevision 0x0311
	if body[0] != 65 || body[1] != 0 {
		t.Fatalf("StructureSize")
	}
	dialect := uint16(body[4]) | uint16(body[5])<<8
	if dialect != 0x0311 {
		t.Fatalf("dialect=0x%04x want 0x0311", dialect)
	}
	ncc := uint16(body[6]) | uint16(body[7])<<8
	if ncc < 2 {
		t.Fatalf("expected >=2 negotiate contexts, got %d", ncc)
	}
	// The negotiate-context parsing helper must find a SHA-512 preauth context
	// and a chosen cipher.
	preauth, cipher, found := negotiatedContexts(resp)
	if !found || preauth != 0x0001 {
		t.Fatalf("preauth hash not SHA-512: %v %x", found, preauth)
	}
	if cipher != 0x0001 && cipher != 0x0002 {
		t.Fatalf("no cipher selected: %x", cipher)
	}
}

func TestHandleNegotiateFallbackTo300(t *testing.T) {
	req := buildNegotiateRequest([]uint16{0x0202, 0x0210, 0x0300}, false)
	resp, st, ok := handleNegotiate(req)
	if !ok || st != negStateOK {
		t.Fatalf("ok=%v st=%v", ok, st)
	}
	body := resp[64:]
	dialect := uint16(body[4]) | uint16(body[5])<<8
	if dialect != 0x0300 {
		t.Fatalf("dialect=0x%04x want 0x0300 (highest offered)", dialect)
	}
	ncc := uint16(body[6]) | uint16(body[7])<<8
	if ncc != 0 {
		t.Fatalf("non-3.1.1 must have 0 negotiate contexts, got %d", ncc)
	}
}

func TestHandleNegotiateRejectsGarbage(t *testing.T) {
	if _, _, ok := handleNegotiate([]byte("too short")); ok {
		t.Fatal("garbage must be rejected")
	}
}

func TestHandleNegotiateResultExposesParams(t *testing.T) {
	req := buildNegotiateRequest([]uint16{0x0202, 0x0311}, true)
	res, ok := handleNegotiateResult(req)
	if !ok {
		t.Fatal("handleNegotiateResult ok=false")
	}
	if res.dialect != 0x0311 {
		t.Fatalf("dialect=0x%04x want 0x0311", res.dialect)
	}
	if res.preauthHash != 0x0001 {
		t.Fatalf("preauthHash=%x want SHA-512", res.preauthHash)
	}
	// GCM was offered first, so it must be chosen.
	if res.cipher != 0x0002 {
		t.Fatalf("cipher=%x want AES-128-GCM", res.cipher)
	}
	if len(res.clientPreauthCtxBytes) == 0 {
		t.Fatal("client preauth context bytes not captured")
	}
}
