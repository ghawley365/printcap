package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"strings"
)

// smbSession holds the per-connection SMB2/3 session state established by the
// NTLM-over-SMB2 SESSION_SETUP exchange ([MS-SMB2] §3.3.5.5). For 3.1.1 it
// also carries the preauth-integrity hash and the derived signing / cipher
// keys ([MS-SMB2] §3.1.4.2).
type smbSession struct {
	sessionID       uint64
	dialect         uint16
	cipher          uint16
	user, domain    string
	guest           bool
	sessionKey      []byte
	signingKey      []byte
	c2sKey          []byte
	s2cKey          []byte
	preauth         []byte // 64-byte running SHA-512 preauth-integrity hash.
	serverChallenge []byte // 8-byte NTLM ServerChallenge sent in leg 1.
	authComplete    bool
	signingRequired bool
	encryptData     bool

	// Tree-connect and named-pipe state ([MS-SMB2] §2.2.10, §2.2.14). trees
	// maps an assigned TreeId to its share path; handles maps the hex of an
	// open FileId to its \spoolss pipe instance.
	trees      map[uint32]string
	printTrees map[uint32]bool // TreeIds that are PRINT shares (spool capture).
	nextTreeID uint32
	handles    map[string]*pipeHandle

	// remoteAddr is the client's "ip:port", recorded as the capture Source. It
	// is set by the connection driver; "" in unit tests.
	remoteAddr string
}

// SESSION_SETUP request/response structure sizes ([MS-SMB2] §2.2.5, §2.2.6).
const (
	sessionSetupReqStructureSize  = 25
	sessionSetupRespStructureSize = 9
)

// SessionFlags bit ([MS-SMB2] §2.2.6): the session is a guest session.
const smb2SessionFlagIsGuest uint16 = 0x0001

// NTLM message-type values read from offset 8 (LE uint32) of an NTLMSSP
// message ([MS-NLMP] §2.2.1).
const (
	ntlmTypeNegotiate    uint32 = 1
	ntlmTypeChallenge    uint32 = 2
	ntlmTypeAuthenticate uint32 = 3
)

// serverComputerName is the NetBIOS computer name advertised in the NTLM
// CHALLENGE TargetInfo.
const serverComputerName = "PRINTCAP"

// newSMBSession allocates a session with a random non-zero SessionId and a
// zeroed 64-byte preauth-integrity hash.
func newSMBSession() *smbSession {
	s := &smbSession{
		preauth:    make([]byte, 64),
		trees:      make(map[uint32]string),
		printTrees: make(map[uint32]bool),
		handles:    make(map[string]*pipeHandle),
	}
	for {
		var id [8]byte
		if _, err := rand.Read(id[:]); err != nil {
			// rand.Read should not fail; fall back to a fixed non-zero value.
			s.sessionID = 0x1
			break
		}
		s.sessionID = binary.LittleEndian.Uint64(id[:])
		if s.sessionID != 0 {
			break
		}
	}
	return s
}

// smbKDF implements the SP800-108 CTR-HMAC-SHA256 key-derivation function used
// by SMB 3.x ([MS-SMB2] §3.1.4.2). With i a 4-byte big-endian counter starting
// at 1, each block is:
//
//	K_i = HMAC_SHA256(Ki, BE32(i) || label || 0x00 || context || BE32(L_bits))
//
// where label already includes its trailing NUL and 0x00 is the standard
// fixed separator. Blocks are concatenated until lbits/8 bytes are produced,
// then truncated. For SMB 3.1.1's 128-bit keys this is a single block.
func smbKDF(ki, label, context []byte, lbits int) []byte {
	outLen := lbits / 8
	out := make([]byte, 0, outLen)
	var lbe [4]byte
	binary.BigEndian.PutUint32(lbe[:], uint32(lbits))
	for i := uint32(1); len(out) < outLen; i++ {
		var ibe [4]byte
		binary.BigEndian.PutUint32(ibe[:], i)
		mac := hmac.New(sha256.New, ki)
		mac.Write(ibe[:])
		mac.Write(label)
		mac.Write([]byte{0x00})
		mac.Write(context)
		mac.Write(lbe[:])
		out = append(out, mac.Sum(nil)...)
	}
	return out[:outLen]
}

// updatePreauth folds one full SMB2 message into the running preauth-integrity
// hash ([MS-SMB2] §3.3.5.4): H = SHA512(H || msg).
func updatePreauth(s *smbSession, msg []byte) {
	h := sha512.New()
	h.Write(s.preauth)
	h.Write(msg)
	s.preauth = h.Sum(nil)
}

// extractNTLM locates the raw NTLMSSP message inside an SMB2 security buffer.
// The security buffer often wraps the NTLM token in SPNEGO/GSS DER; rather than
// parsing SPNEGO, we scan for the "NTLMSSP\0" signature and treat everything
// from there to the end of the buffer as the NTLM message. This works for both
// raw-NTLM and SPNEGO-wrapped tokens (the NTLMSSP blob is a DER octet string).
// Full SPNEGO support is a deliberate later step.
func extractNTLM(secBuf []byte) ([]byte, bool) {
	idx := bytes.Index(secBuf, []byte(ntlmSignature))
	if idx < 0 {
		return nil, false
	}
	return secBuf[idx:], true
}

// parseSessionSetupSecBuf parses a SESSION_SETUP request body ([MS-SMB2]
// §2.2.5) and returns the security buffer it carries. reqMsg is the full SMB2
// message (header + body). All offsets are bounds-checked; ok=false on any
// malformed input so we never panic on hostile data.
func parseSessionSetupSecBuf(reqMsg []byte) (secBuf []byte, ok bool) {
	if len(reqMsg) < smb2HeaderSize+sessionSetupReqStructureSize {
		return nil, false
	}
	body := reqMsg[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != sessionSetupReqStructureSize {
		return nil, false
	}
	// SecurityBufferOffset is measured from the SMB2 header start.
	secOff := int64(binary.LittleEndian.Uint16(body[12:14]))
	secLen := int64(binary.LittleEndian.Uint16(body[14:16]))
	start := secOff
	end := secOff + secLen
	if start < int64(smb2HeaderSize) || end < start || end > int64(len(reqMsg)) {
		return nil, false
	}
	return reqMsg[start:end], true
}

// buildSessionSetupResponse encodes an SMB2 header + SESSION_SETUP response
// body ([MS-SMB2] §2.2.6) carrying secBuf as its security buffer.
func buildSessionSetupResponse(reqHdr smb2Header, sessionID uint64, status uint32, sessionFlags uint16, secBuf []byte) []byte {
	respHdr := smb2Header{
		Command:    smb2SessionSetup,
		Status:     status,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  sessionID,
		TreeId:     reqHdr.TreeId,
	}
	hdr := respHdr.encode()

	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], sessionSetupRespStructureSize)
	binary.LittleEndian.PutUint16(body[2:4], sessionFlags)
	// SecurityBufferOffset is from the SMB2 header start; the buffer follows the
	// 8-byte fixed body.
	secOff := smb2HeaderSize + 8
	binary.LittleEndian.PutUint16(body[4:6], uint16(secOff))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(secBuf)))
	body = append(body, secBuf...)

	return append(hdr, body...)
}

// sessionSecBuf extracts the security buffer from a SESSION_SETUP response
// message ([MS-SMB2] §2.2.6). Bounds-safe; returns nil on malformed input.
func sessionSecBuf(respMsg []byte) []byte {
	if len(respMsg) < smb2HeaderSize+8 {
		return nil
	}
	body := respMsg[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != sessionSetupRespStructureSize {
		return nil
	}
	secOff := int64(binary.LittleEndian.Uint16(body[4:6]))
	secLen := int64(binary.LittleEndian.Uint16(body[6:8]))
	end := secOff + secLen
	if secOff < int64(smb2HeaderSize) || end < secOff || end > int64(len(respMsg)) {
		return nil
	}
	return respMsg[secOff:end]
}

// buildSessionSetupRequest builds a full SMB2 SESSION_SETUP request ([MS-SMB2]
// §2.2.5) wrapping ntlmToken raw in its security buffer. No SPNEGO wrapping is
// applied: extractNTLM scans for the NTLMSSP signature. Used by tests and as a
// reference encoder.
func buildSessionSetupRequest(sessionID uint64, ntlmToken []byte) []byte {
	hdr := smb2Header{
		Command:   smb2SessionSetup,
		SessionId: sessionID,
	}.encode()

	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], sessionSetupReqStructureSize)
	// body[2] Flags, body[3] SecurityMode, body[4:8] Capabilities,
	// body[8:12] Channel, body[16:24] PreviousSessionId all left zero.
	secOff := smb2HeaderSize + 24
	binary.LittleEndian.PutUint16(body[12:14], uint16(secOff))
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlmToken)))
	body = append(body, ntlmToken...)

	return append(hdr, body...)
}

// ntlmMessageType returns the NTLM message type at offset 8 (LE uint32) of an
// NTLMSSP message, validating the signature and length first.
func ntlmMessageType(msg []byte) (uint32, bool) {
	if len(msg) < 12 || string(msg[:8]) != ntlmSignature {
		return 0, false
	}
	return binary.LittleEndian.Uint32(msg[8:12]), true
}

// handleSessionSetup processes one leg of an SMB2 SESSION_SETUP exchange
// ([MS-SMB2] §3.3.5.5) for the NTLM (NTLMSSP) security mechanism. It returns
// the full SMB2 response message, the NTStatus to report, and whether the
// session is now complete (authenticated). It never panics on hostile input.
func handleSessionSetup(s *smbSession, reqMsg []byte) (respMsg []byte, status uint32, complete bool) {
	reqHdr, ok := parseSMB2Header(reqMsg)
	if !ok || reqHdr.Command != smb2SessionSetup {
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}
	secBuf, ok := parseSessionSetupSecBuf(reqMsg)
	if !ok {
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}
	ntlmMsg, ok := extractNTLM(secBuf)
	if !ok {
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}
	mtype, ok := ntlmMessageType(ntlmMsg)
	if !ok {
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}

	switch mtype {
	case ntlmTypeNegotiate:
		return handleSessionSetupLeg1(s, reqHdr, reqMsg)
	case ntlmTypeAuthenticate:
		return handleSessionSetupLeg2(s, reqHdr, reqMsg, ntlmMsg)
	default:
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}
}

// handleSessionSetupLeg1 handles the NTLM NEGOTIATE leg: it generates a fresh
// 8-byte ServerChallenge, builds an NTLM CHALLENGE wrapped in a SESSION_SETUP
// response with Status=MORE_PROCESSING_REQUIRED, and folds both leg-1 messages
// into the preauth-integrity hash ([MS-SMB2] §3.3.5.4).
func handleSessionSetupLeg1(s *smbSession, reqHdr smb2Header, reqMsg []byte) ([]byte, uint32, bool) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		for i := range challenge {
			challenge[i] = byte(i + 1)
		}
	}
	s.serverChallenge = challenge

	domainOrWorkgroup := smbDomainHint()
	targetInfo := ntlmTargetInfo(domainOrWorkgroup, serverComputerName)
	chalMsg := buildChallenge(challenge, targetInfo)
	// smbclient/Windows require the CHALLENGE token wrapped in SPNEGO
	// (NegTokenResp, accept-incomplete); a raw NTLMSSP token is rejected.
	secToken := spnegoWrapResponse(spnegoAcceptIncomplete, chalMsg)

	resp := buildSessionSetupResponse(reqHdr, s.sessionID, statusMoreProcessingRequired, 0, secToken)

	// Fold leg-1 request then leg-1 response into the preauth hash, in order.
	updatePreauth(s, reqMsg)
	updatePreauth(s, resp)

	return resp, statusMoreProcessingRequired, false
}

// handleSessionSetupLeg2 handles the NTLM AUTHENTICATE leg: it folds the leg-2
// request into the preauth hash (before key derivation), verifies the client's
// NTLMv2 response against a configured user, derives the SMB 3.1.1 signing and
// cipher keys, and builds the SUCCESS response. With RequireAuth disabled an
// unmatched/anonymous client is granted a GUEST session.
func handleSessionSetupLeg2(s *smbSession, reqHdr smb2Header, reqMsg, ntlmMsg []byte) ([]byte, uint32, bool) {
	// Fold the leg-2 request BEFORE deriving keys: the preauth hash used for
	// derivation is the value after this request is included.
	updatePreauth(s, reqMsg)

	domain, user, _, ok := parseAuthenticate(ntlmMsg)
	if !ok {
		if !cfg.SMB.RequireAuth {
			return finishGuestSession(s, reqHdr)
		}
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}

	var sbk []byte
	var verified bool
	if u, found := matchSMBUser(user); found {
		if key, vok := verifyNTLMv2(u.User, u.Password, u.Domain, s.serverChallenge, ntlmMsg); vok {
			sbk = key
			verified = true
		}
	}

	if !verified {
		if !cfg.SMB.RequireAuth {
			return finishGuestSession(s, reqHdr)
		}
		return buildSessionSetupResponse(reqHdr, s.sessionID, statusAccessDenied, 0, nil), statusAccessDenied, false
	}

	s.user = user
	s.domain = domain
	s.sessionKey = sbk
	deriveSessionKeys(s, sbk)
	s.authComplete = true
	s.signingRequired = cfg.SMB.Sign
	s.encryptData = cfg.SMB.Encrypt

	// Signal SPNEGO completion (NegTokenResp, accept-completed) on success.
	successToken := spnegoWrapResponse(spnegoAcceptCompleted, nil)
	resp := buildSessionSetupResponse(reqHdr, s.sessionID, statusSuccess, 0, successToken)
	return resp, statusSuccess, true
}

// finishGuestSession completes a session as an anonymous/guest login: it uses a
// 16-byte zero SessionBaseKey, derives keys, and flags SessionFlags GUEST.
func finishGuestSession(s *smbSession, reqHdr smb2Header) ([]byte, uint32, bool) {
	sbk := make([]byte, 16)
	s.guest = true
	s.sessionKey = sbk
	deriveSessionKeys(s, sbk)
	s.authComplete = true
	// Guest sessions are never signing-required ([MS-SMB2] §3.3.5.5.3).
	s.signingRequired = false
	// Signal SPNEGO completion (NegTokenResp, accept-completed) on success.
	successToken := spnegoWrapResponse(spnegoAcceptCompleted, nil)
	resp := buildSessionSetupResponse(reqHdr, s.sessionID, statusSuccess, smb2SessionFlagIsGuest, successToken)
	return resp, statusSuccess, true
}

// deriveSessionKeys derives the SMB 3.1.1 signing and cipher keys from the
// SessionBaseKey and the final preauth-integrity hash ([MS-SMB2] §3.1.4.2).
// Only the 3.1.1 derivation (preauth-hash context) is supported.
func deriveSessionKeys(s *smbSession, sbk []byte) {
	ctx := s.preauth
	s.signingKey = smbKDF(sbk, []byte("SMBSigningKey\x00"), ctx, 128)
	s.c2sKey = smbKDF(sbk, []byte("SMBC2SCipherKey\x00"), ctx, 128)
	s.s2cKey = smbKDF(sbk, []byte("SMBS2CCipherKey\x00"), ctx, 128)
}

// matchSMBUser finds a configured SMB user by case-insensitive user name.
func matchSMBUser(user string) (SMBUser, bool) {
	for _, u := range cfg.SMB.Users {
		if strings.EqualFold(u.User, user) {
			return u, true
		}
	}
	return SMBUser{}, false
}

// smbDomainHint returns the domain advertised in the NTLM CHALLENGE TargetInfo.
// It uses the first configured user's domain, falling back to "WORKGROUP".
func smbDomainHint() string {
	for _, u := range cfg.SMB.Users {
		if u.Domain != "" {
			return u.Domain
		}
	}
	return "WORKGROUP"
}
