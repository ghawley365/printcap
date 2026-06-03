package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// NOTE: NTLMv2, MD4 and MD5-as-used-here are legacy primitives mandated by the
// [MS-NLMP] protocol for interop with Windows/SMB clients. They are NOT chosen
// for their security properties; we implement them only because the wire
// protocol requires them.

// utf16le encodes s as UTF-16 little-endian, the string form used throughout
// [MS-NLMP]. Each UTF-16 code unit is serialized low byte first.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

// ntowfv2 computes the NTLMv2 one-way function ([MS-NLMP] §3.3.2):
//
//	NTOWFv2 = HMAC_MD5( MD4(UTF16LE(password)), UTF16LE( UpperCase(user) + domain ) )
//
// Only the user is upper-cased; the domain case is preserved.
func ntowfv2(user, domain, password string) []byte {
	key := md4Sum(utf16le(password))
	mac := hmac.New(md5.New, key)
	mac.Write(utf16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}

// AV_PAIR IDs ([MS-NLMP] §2.2.2.1).
const (
	msvAvEOL          = 0x0000
	msvAvNbComputerNm = 0x0001
	msvAvNbDomainNm   = 0x0002
)

// ntlmTargetInfo builds the AV_PAIR list used as the temp blob's TargetInfo
// ([MS-NLMP] §2.2.2.1, §4.2.4.1.3). Each pair is: 2-byte LE AvId, 2-byte LE
// AvLen (byte length of value), then the UTF-16LE value. The list is terminated
// by an MsvAvEOL pair (AvId=0, AvLen=0). The §4.2.4 worked example orders the
// NetBIOS domain name (id 2) before the NetBIOS computer name (id 1).
func ntlmTargetInfo(domain, computer string) []byte {
	var b []byte
	avPair := func(id uint16, val []byte) {
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:], id)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(val)))
		b = append(b, hdr...)
		b = append(b, val...)
	}
	avPair(msvAvNbDomainNm, utf16le(domain))
	avPair(msvAvNbComputerNm, utf16le(computer))
	avPair(msvAvEOL, nil) // EOL: id=0, len=0
	return b
}

// ntlmv2Temp assembles the NTLMv2 "temp" blob, i.e. the NTLMv2_CLIENT_CHALLENGE
// structure ([MS-NLMP] §3.3.2, §2.2.2.7) minus the leading NTProofStr:
//
//	RespType(0x01) HiRespType(0x01) Reserved1(2,=0) Reserved2(4,=0)
//	TimeStamp(8 LE) ChallengeFromClient(8) Reserved3(4,=0) TargetInfo Reserved4(4,=0)
//
// The 6 zero bytes after the two type bytes are Reserved1(2)+Reserved2(4).
func ntlmv2Temp(timestamp uint64, clientChallenge, targetInfo []byte) []byte {
	var b []byte
	b = append(b, 0x01, 0x01)       // RespType, HiRespType
	b = append(b, 0, 0, 0, 0, 0, 0) // Reserved1 (2) + Reserved2 (4)
	ts := make([]byte, 8)           // TimeStamp (8, LE)
	binary.LittleEndian.PutUint64(ts, timestamp)
	b = append(b, ts...)
	b = append(b, clientChallenge...) // ChallengeFromClient (8)
	b = append(b, 0, 0, 0, 0)         // Reserved3 (4)
	b = append(b, targetInfo...)      // TargetInfo (AV_PAIR list incl. EOL)
	b = append(b, 0, 0, 0, 0)         // Reserved4 / terminator (4)
	return b
}

// ntlmv2Response computes NTProofStr and SessionBaseKey from NTOWFv2, the
// 8-byte ServerChallenge and the temp blob ([MS-NLMP] §3.3.2):
//
//	NTProofStr      = HMAC_MD5(NTOWFv2, ServerChallenge || temp)
//	SessionBaseKey  = HMAC_MD5(NTOWFv2, NTProofStr)
func ntlmv2Response(ntowf, serverChallenge, temp []byte) (ntProofStr, sessionBaseKey []byte) {
	mac := hmac.New(md5.New, ntowf)
	mac.Write(serverChallenge)
	mac.Write(temp)
	ntProofStr = mac.Sum(nil)

	mac2 := hmac.New(md5.New, ntowf)
	mac2.Write(ntProofStr)
	sessionBaseKey = mac2.Sum(nil)
	return ntProofStr, sessionBaseKey
}

const ntlmSignature = "NTLMSSP\x00"

// buildChallenge produces a CHALLENGE_MESSAGE ([MS-NLMP] §2.2.1.2). The fixed
// 48-byte header is followed by the TargetInfo payload. Fields:
//
//	0  Signature        "NTLMSSP\0"
//	8  MessageType      2 (LE)
//	12 TargetNameFields Len/MaxLen/Offset (empty here)
//	20 NegotiateFlags   (LE)
//	24 ServerChallenge  (8)
//	32 Reserved         (8, =0)
//	40 TargetInfoFields Len/MaxLen/Offset
//	48 Payload          (TargetInfo)
func buildChallenge(serverChallenge, targetInfo []byte) []byte {
	const headerLen = 48
	// Flags advertising Unicode, NTLM, request target, and TargetInfo present.
	const (
		negotiateUnicode    = 0x00000001
		negotiateNTLM       = 0x00000200
		negotiateTargetInfo = 0x00800000
		requestTarget       = 0x00000004
	)
	flags := uint32(negotiateUnicode | negotiateNTLM | requestTarget | negotiateTargetInfo)

	b := make([]byte, headerLen)
	copy(b[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(b[8:], 2) // MessageType

	// TargetName fields (empty), pointed just past the header for cleanliness.
	binary.LittleEndian.PutUint16(b[12:], 0)
	binary.LittleEndian.PutUint16(b[14:], 0)
	binary.LittleEndian.PutUint32(b[16:], headerLen)

	binary.LittleEndian.PutUint32(b[20:], flags)

	sc := make([]byte, 8)
	copy(sc, serverChallenge)
	copy(b[24:], sc) // ServerChallenge (8)
	// b[32:40] Reserved stays zero.

	tiLen := uint16(len(targetInfo))
	binary.LittleEndian.PutUint16(b[40:], tiLen)
	binary.LittleEndian.PutUint16(b[42:], tiLen)
	binary.LittleEndian.PutUint32(b[44:], headerLen)

	b = append(b, targetInfo...)
	return b
}

// utf16leDecode decodes a UTF-16LE byte slice into a Go string. A trailing odd
// byte (malformed input) is ignored rather than panicking.
func utf16leDecode(b []byte) string {
	n := len(b) / 2
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units))
}

// ntlmField reads a Len/MaxLen/Offset security-buffer triple ([MS-NLMP]
// §2.2.2.10) at header offset off and returns the referenced payload slice.
// It bounds-checks every access against the full message and returns ok=false
// on any out-of-range condition (this parses untrusted network input).
func ntlmField(msg []byte, off int) (payload []byte, ok bool) {
	if off < 0 || off+8 > len(msg) {
		return nil, false
	}
	flen := int(binary.LittleEndian.Uint16(msg[off:]))
	poff := int(binary.LittleEndian.Uint32(msg[off+4:]))
	if poff < 0 || flen < 0 || poff+flen > len(msg) {
		return nil, false
	}
	return msg[poff : poff+flen], true
}

// parseAuthenticate parses an AUTHENTICATE_MESSAGE ([MS-NLMP] §2.2.1.3),
// extracting the domain, user and NtChallengeResponse. The fixed header offsets
// used here are:
//
//	0  Signature "NTLMSSP\0"
//	8  MessageType 3 (LE)
//	12 LmChallengeResponseFields  (Len/MaxLen/Offset)
//	20 NtChallengeResponseFields  (Len/MaxLen/Offset)
//	28 DomainNameFields           (Len/MaxLen/Offset)
//	36 UserNameFields             (Len/MaxLen/Offset)
//
// It is panic-proof: every offset is bounds-checked before slicing, and any
// malformed/truncated input yields ok=false.
func parseAuthenticate(b []byte) (domain, user string, ntResp []byte, ok bool) {
	// Need at least the header through the UserNameFields triple.
	if len(b) < 44 {
		return "", "", nil, false
	}
	if string(b[:8]) != ntlmSignature {
		return "", "", nil, false
	}
	if binary.LittleEndian.Uint32(b[8:12]) != 3 {
		return "", "", nil, false
	}
	nt, ok := ntlmField(b, 20)
	if !ok {
		return "", "", nil, false
	}
	dom, ok := ntlmField(b, 28)
	if !ok {
		return "", "", nil, false
	}
	usr, ok := ntlmField(b, 36)
	if !ok {
		return "", "", nil, false
	}
	return utf16leDecode(dom), utf16leDecode(usr), nt, true
}

// buildAuthenticate constructs a minimal AUTHENTICATE_MESSAGE ([MS-NLMP]
// §2.2.1.3) carrying the domain, user and NtChallengeResponse. Only the fields
// required by parseAuthenticate/verifyNTLMv2 are populated; LM response, session
// key and flags are left empty/zero. The fixed header is 64 bytes (through the
// Version field) and all payloads follow it.
func buildAuthenticate(domain, user string, ntResp []byte) []byte {
	const headerLen = 64
	domB := utf16le(domain)
	usrB := utf16le(user)

	header := make([]byte, headerLen)
	copy(header[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(header[8:], 3) // MessageType

	var payload []byte
	// setField writes a Len/MaxLen/Offset triple at header offset off and
	// appends val to the payload, returning nothing.
	setField := func(off int, val []byte) {
		o := headerLen + len(payload)
		binary.LittleEndian.PutUint16(header[off:], uint16(len(val)))
		binary.LittleEndian.PutUint16(header[off+2:], uint16(len(val)))
		binary.LittleEndian.PutUint32(header[off+4:], uint32(o))
		payload = append(payload, val...)
	}

	// LmChallengeResponseFields (12): empty.
	binary.LittleEndian.PutUint32(header[16:], headerLen)
	// NtChallengeResponseFields (20), DomainNameFields (28), UserNameFields (36).
	setField(20, ntResp)
	setField(28, domB)
	setField(36, usrB)
	// EncryptedRandomSessionKeyFields (52): empty, offset to end.
	binary.LittleEndian.PutUint32(header[56:], uint32(headerLen+len(payload)))

	return append(header, payload...)
}

// verifyNTLMv2 validates an AUTHENTICATE_MESSAGE against the expected
// credentials and the ServerChallenge previously sent in the CHALLENGE_MESSAGE.
// It recomputes NTProofStr from the temp blob carried in the client's
// NtChallengeResponse and constant-time compares it with the client's value.
// On success it returns the derived SessionBaseKey. It never panics on
// malformed input and rejects on any verification failure.
func verifyNTLMv2(user, password, domain string, serverChallenge, authMsg []byte) (sessionBaseKey []byte, ok bool) {
	_, _, ntResp, ok := parseAuthenticate(authMsg)
	if !ok || len(ntResp) < 16 {
		return nil, false
	}
	clientProof := ntResp[:16]
	temp := ntResp[16:]

	ntowf := ntowfv2(user, domain, password)
	mac := hmac.New(md5.New, ntowf)
	mac.Write(serverChallenge)
	mac.Write(temp)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, clientProof) {
		return nil, false
	}
	mac2 := hmac.New(md5.New, ntowf)
	mac2.Write(clientProof)
	return mac2.Sum(nil), true
}
