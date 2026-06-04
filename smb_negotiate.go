package main

import (
	"crypto/rand"
	"encoding/binary"
)

// SMB2 dialect revision numbers ([MS-SMB2] §2.2.3, §2.2.4). All little-endian
// uint16 on the wire.
const (
	dialect202 uint16 = 0x0202
	dialect210 uint16 = 0x0210
	dialect300 uint16 = 0x0300
	dialect302 uint16 = 0x0302
	dialect311 uint16 = 0x0311
)

// supportedDialects lists the dialects we accept, highest first so selection
// can short-circuit on the first match.
var supportedDialects = []uint16{dialect311, dialect302, dialect300, dialect210, dialect202}

// Negotiate-context types ([MS-SMB2] §2.2.3.1).
const (
	ctxPreauthIntegrity uint16 = 0x0001
	ctxEncryption       uint16 = 0x0002
)

// Preauth-integrity hash algorithm IDs ([MS-SMB2] §2.2.3.1.1).
const hashSHA512 uint16 = 0x0001

// Encryption cipher IDs ([MS-SMB2] §2.2.3.1.2).
const (
	cipherAESCCM uint16 = 0x0001 // AES-128-CCM
	cipherAESGCM uint16 = 0x0002 // AES-128-GCM
)

// SMB2 NEGOTIATE sizing and mode constants.
const (
	negReqStructureSize  = 36
	negRespStructureSize = 65
	negSecurityMode      = 0x0001     // SMB2_NEGOTIATE_SIGNING_ENABLED
	negMaxTransactSize   = 0x00100000 // 1 MiB
	negMaxReadSize       = 0x00100000
	negMaxWriteSize      = 0x00100000
	preauthSaltLen       = 32
)

// negState reports the outcome of NEGOTIATE processing.
type negState int

const (
	negStateOK negState = iota
	negStateBadRequest
	negStateNoCommonDialect
)

// negotiateResult captures the parameters chosen during NEGOTIATE so a later
// session-setup / key-derivation stage can read them. clientPreauthCtxBytes
// holds the raw client PREAUTH_INTEGRITY context (or nil when not 3.1.1) for
// preauth-hash chaining.
type negotiateResult struct {
	dialect               uint16
	cipher                uint16
	preauthHash           uint16
	serverSalt            []byte
	clientPreauthCtxBytes []byte
}

// serverGUID is a stable per-process GUID used in NEGOTIATE responses. It is
// generated once at startup; the value is opaque and need not be a true UUID.
var serverGUID = func() [16]byte {
	var g [16]byte
	if _, err := rand.Read(g[:]); err != nil {
		// rand.Read should not fail; fall back to a fixed, non-zero pattern.
		for i := range g {
			g[i] = byte(0xA0 + i)
		}
	}
	return g
}()

// handleNegotiate parses an untrusted NEGOTIATE request ([MS-SMB2] §2.2.3) and
// builds the matching response ([MS-SMB2] §2.2.4). It returns the full response
// (64-byte header || body), a negState, and ok=false for any malformed input.
// It never panics on hostile input.
func handleNegotiate(req []byte) (resp []byte, st negState, ok bool) {
	hdr, hok := parseSMB2Header(req)
	if !hok || hdr.Command != smb2Negotiate {
		return nil, negStateBadRequest, false
	}
	body := req[smb2HeaderSize:]
	if len(body) < negReqStructureSize {
		return nil, negStateBadRequest, false
	}
	if binary.LittleEndian.Uint16(body[0:2]) != negReqStructureSize {
		return nil, negStateBadRequest, false
	}
	dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
	if dialectCount == 0 {
		return nil, negStateBadRequest, false
	}
	// Dialects[] starts at body offset 36; bounds-check the whole array.
	dialectsStart := 36
	dialectsEnd := dialectsStart + dialectCount*2
	if dialectsEnd < dialectsStart || dialectsEnd > len(body) {
		return nil, negStateBadRequest, false
	}
	offered := make([]uint16, 0, dialectCount)
	for i := 0; i < dialectCount; i++ {
		off := dialectsStart + i*2
		offered = append(offered, binary.LittleEndian.Uint16(body[off:off+2]))
	}

	chosen, found := selectDialect(offered)
	if !found {
		return nil, negStateNoCommonDialect, false
	}

	res := negotiateResult{dialect: chosen}

	var contexts []byte
	var ncc uint16
	if chosen == dialect311 {
		// Learn the offered ciphers and the client's preauth context from the
		// request context list (offset/count at body[28:36]).
		cipher, clientPreauth := parseRequestContexts(body, hdr)
		res.cipher = cipher
		res.preauthHash = hashSHA512
		res.serverSalt = make([]byte, preauthSaltLen)
		if _, err := rand.Read(res.serverSalt); err != nil {
			for i := range res.serverSalt {
				res.serverSalt[i] = 0
			}
		}
		res.clientPreauthCtxBytes = clientPreauth
		contexts, ncc = buildResponseContexts(res.serverSalt, cipher)
	}

	resp = buildNegotiateResponse(hdr, chosen, ncc, contexts)
	// res holds the negotiated parameters (dialect, cipher, preauth hash,
	// server salt, client preauth context) for the session-setup / key-
	// derivation stage. It is recomputed there via handleNegotiateResult.
	_ = res
	return resp, negStateOK, true
}

// handleNegotiateResult parses an untrusted NEGOTIATE request and returns the
// negotiated parameters without encoding a response. Later stages (session
// setup, key derivation) use this to obtain the server salt and chosen cipher.
// It returns ok=false on malformed input.
func handleNegotiateResult(req []byte) (negotiateResult, bool) {
	hdr, hok := parseSMB2Header(req)
	if !hok || hdr.Command != smb2Negotiate || len(req) < smb2HeaderSize+negReqStructureSize {
		return negotiateResult{}, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != negReqStructureSize {
		return negotiateResult{}, false
	}
	dialectCount := int(binary.LittleEndian.Uint16(body[2:4]))
	if dialectCount == 0 {
		return negotiateResult{}, false
	}
	dialectsStart, dialectsEnd := 36, 36+dialectCount*2
	if dialectsEnd < dialectsStart || dialectsEnd > len(body) {
		return negotiateResult{}, false
	}
	offered := make([]uint16, 0, dialectCount)
	for i := 0; i < dialectCount; i++ {
		off := dialectsStart + i*2
		offered = append(offered, binary.LittleEndian.Uint16(body[off:off+2]))
	}
	chosen, found := selectDialect(offered)
	if !found {
		return negotiateResult{}, false
	}
	res := negotiateResult{dialect: chosen}
	if chosen == dialect311 {
		cipher, clientPreauth := parseRequestContexts(body, hdr)
		res.cipher = cipher
		res.preauthHash = hashSHA512
		res.clientPreauthCtxBytes = clientPreauth
	}
	return res, true
}

// selectDialect picks the highest mutually supported dialect. supportedDialects
// is ordered highest-first so the first match wins.
func selectDialect(offered []uint16) (uint16, bool) {
	// supportedDialects is ordered highest-first.
	for _, sup := range supportedDialects {
		for _, o := range offered {
			if o == sup {
				return sup, true
			}
		}
	}
	return 0, false
}

// parseRequestContexts walks the 3.1.1 request negotiate-context list to pick a
// cipher (prefer GCM, else CCM, else default GCM) and capture the raw client
// PREAUTH_INTEGRITY context bytes. It is fully bounds-checked.
func parseRequestContexts(body []byte, hdr smb2Header) (cipher uint16, clientPreauth []byte) {
	cipher = cipherAESGCM // default if the client offers no usable cipher
	if len(body) < 36 {
		return cipher, nil
	}
	ncOffsetFromHdr := int64(binary.LittleEndian.Uint32(body[28:32]))
	ncCount := int(binary.LittleEndian.Uint16(body[32:34]))
	// Offset is relative to the SMB2 header start; translate into body.
	start := ncOffsetFromHdr - int64(smb2HeaderSize)
	if start < 0 || start > int64(len(body)) {
		return cipher, nil
	}
	pos := int(start)
	offeredGCM, offeredCCM := false, false
	for i := 0; i < ncCount; i++ {
		// Align to 8 bytes relative to header start.
		for (pos+smb2HeaderSize)%8 != 0 {
			pos++
		}
		if pos+8 > len(body) {
			break
		}
		cType := binary.LittleEndian.Uint16(body[pos : pos+2])
		dLen := int(binary.LittleEndian.Uint16(body[pos+2 : pos+4]))
		dataStart := pos + 8
		dataEnd := dataStart + dLen
		if dataEnd < dataStart || dataEnd > len(body) {
			break
		}
		data := body[dataStart:dataEnd]
		switch cType {
		case ctxPreauthIntegrity:
			// Capture the full 8-byte header + data for preauth chaining.
			clientPreauth = append([]byte(nil), body[pos:dataEnd]...)
		case ctxEncryption:
			if len(data) >= 2 {
				count := int(binary.LittleEndian.Uint16(data[0:2]))
				for c := 0; c < count; c++ {
					off := 2 + c*2
					if off+2 > len(data) {
						break
					}
					switch binary.LittleEndian.Uint16(data[off : off+2]) {
					case cipherAESGCM:
						offeredGCM = true
					case cipherAESCCM:
						offeredCCM = true
					}
				}
			}
		}
		pos = dataEnd
	}
	switch {
	case offeredGCM:
		cipher = cipherAESGCM
	case offeredCCM:
		cipher = cipherAESCCM
	default:
		cipher = cipherAESGCM
	}
	return cipher, clientPreauth
}

// buildResponseContexts builds the 3.1.1 response context list: a
// PREAUTH_INTEGRITY context selecting SHA-512 with the given salt, followed by
// an ENCRYPTION context selecting the chosen cipher. Each context is 8-byte
// aligned relative to the SMB2 header start; the list begins on an 8-byte
// boundary, so internal alignment is computed from offset 0 of the list.
func buildResponseContexts(salt []byte, cipher uint16) (list []byte, count uint16) {
	// PREAUTH_INTEGRITY data: HashAlgorithmCount(2), SaltLength(2),
	// HashAlgorithms[1](2) = SHA-512, Salt[SaltLength].
	preauthData := make([]byte, 4+2+len(salt))
	binary.LittleEndian.PutUint16(preauthData[0:2], 1)
	binary.LittleEndian.PutUint16(preauthData[2:4], uint16(len(salt)))
	binary.LittleEndian.PutUint16(preauthData[4:6], hashSHA512)
	copy(preauthData[6:], salt)
	list = appendContext(list, ctxPreauthIntegrity, preauthData)

	// ENCRYPTION data: CipherCount(2), Ciphers[1](2) = chosen.
	encData := make([]byte, 2+2)
	binary.LittleEndian.PutUint16(encData[0:2], 1)
	binary.LittleEndian.PutUint16(encData[2:4], cipher)
	list = appendContext(list, ctxEncryption, encData)

	return list, 2
}

// appendContext appends one NEGOTIATE_CONTEXT (header 8 bytes + data),
// 8-byte aligning the start of this context within the list. The list itself
// starts on an 8-byte boundary in the response, so list-relative alignment
// equals header-relative alignment.
func appendContext(list []byte, ctxType uint16, data []byte) []byte {
	for len(list)%8 != 0 {
		list = append(list, 0)
	}
	h := make([]byte, 8)
	binary.LittleEndian.PutUint16(h[0:2], ctxType)
	binary.LittleEndian.PutUint16(h[2:4], uint16(len(data)))
	// h[4:8] Reserved stays zero.
	list = append(list, h...)
	list = append(list, data...)
	return list
}

// buildNegotiateResponse encodes the SMB2 header + NEGOTIATE response body
// ([MS-SMB2] §2.2.4). The security buffer is empty (length 0) to use the
// client-initiated NTLM-raw authentication path. When contexts is non-empty
// (3.1.1), it is placed at an 8-byte-aligned offset past the security buffer
// and NegotiateContextOffset is set accordingly.
func buildNegotiateResponse(reqHdr smb2Header, dialect uint16, ncc uint16, contexts []byte) []byte {
	respHdr := smb2Header{
		Command:    smb2Negotiate,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	hdr := respHdr.encode()

	body := make([]byte, 64) // fixed part of the response body
	binary.LittleEndian.PutUint16(body[0:2], negRespStructureSize)
	binary.LittleEndian.PutUint16(body[2:4], negSecurityMode)
	binary.LittleEndian.PutUint16(body[4:6], dialect)
	binary.LittleEndian.PutUint16(body[6:8], ncc)
	copy(body[8:24], serverGUID[:])
	binary.LittleEndian.PutUint32(body[24:28], 0) // Capabilities
	binary.LittleEndian.PutUint32(body[28:32], negMaxTransactSize)
	binary.LittleEndian.PutUint32(body[32:36], negMaxReadSize)
	binary.LittleEndian.PutUint32(body[36:40], negMaxWriteSize)
	// body[40:48] SystemTime = 0, body[48:56] ServerStartTime = 0.

	// Empty security buffer placed immediately after the fixed body.
	secBufOffset := smb2HeaderSize + 64 // from header start
	binary.LittleEndian.PutUint16(body[56:58], uint16(secBufOffset))
	binary.LittleEndian.PutUint16(body[58:60], 0) // SecurityBufferLength

	if len(contexts) == 0 {
		// Non-3.1.1: NegotiateContextOffset reserved = 0.
		binary.LittleEndian.PutUint32(body[60:64], 0)
		return append(hdr, body...)
	}

	// 3.1.1: pad the body to an 8-byte boundary (relative to header start),
	// then append the context list. The security buffer is empty so padding
	// follows the fixed body directly.
	for (smb2HeaderSize+len(body))%8 != 0 {
		body = append(body, 0)
	}
	ncOffset := smb2HeaderSize + len(body)
	binary.LittleEndian.PutUint32(body[60:64], uint32(ncOffset))
	body = append(body, contexts...)

	return append(hdr, body...)
}

// negotiatedContexts parses a NEGOTIATE response's context list ([MS-SMB2]
// §2.2.4) and returns the selected preauth hash and cipher. found is false if
// the response is not 3.1.1 or the contexts cannot be parsed. Bounds-safe.
func negotiatedContexts(resp []byte) (preauthHash, cipher uint16, found bool) {
	if len(resp) < smb2HeaderSize+64 {
		return 0, 0, false
	}
	body := resp[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != negRespStructureSize {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint16(body[4:6]) != dialect311 {
		return 0, 0, false
	}
	count := int(binary.LittleEndian.Uint16(body[6:8]))
	if count == 0 {
		return 0, 0, false
	}
	ncOffsetFromHdr := int64(binary.LittleEndian.Uint32(body[60:64]))
	start := ncOffsetFromHdr - int64(smb2HeaderSize)
	if start < 0 || start > int64(len(body)) {
		return 0, 0, false
	}
	pos := int(start)
	var gotPreauth, gotCipher bool
	for i := 0; i < count; i++ {
		for (pos+smb2HeaderSize)%8 != 0 {
			pos++
		}
		if pos+8 > len(body) {
			break
		}
		cType := binary.LittleEndian.Uint16(body[pos : pos+2])
		dLen := int(binary.LittleEndian.Uint16(body[pos+2 : pos+4]))
		dataStart := pos + 8
		dataEnd := dataStart + dLen
		if dataEnd < dataStart || dataEnd > len(body) {
			break
		}
		data := body[dataStart:dataEnd]
		switch cType {
		case ctxPreauthIntegrity:
			// HashAlgorithmCount(2), SaltLength(2), HashAlgorithms[](2..).
			if len(data) >= 6 {
				preauthHash = binary.LittleEndian.Uint16(data[4:6])
				gotPreauth = true
			}
		case ctxEncryption:
			// CipherCount(2), Ciphers[](2..).
			if len(data) >= 4 {
				cipher = binary.LittleEndian.Uint16(data[2:4])
				gotCipher = true
			}
		}
		pos = dataEnd
	}
	return preauthHash, cipher, gotPreauth && gotCipher
}
