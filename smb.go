package main

import (
	"encoding/binary"
	"net"
)

// serveSMB accepts connections on the SMB print-share listener and drives each
// through the per-connection SMB2/3 state machine.
func serveSMB(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSMBConn(c)
	}
}

// handleSMBConn drives one SMB connection through the SMB2/3 + NTLMv2 + spoolss
// state machine: NEGOTIATE -> SESSION_SETUP (two NTLM legs) -> TREE_CONNECT ->
// CREATE -> WRITE/READ (DCERPC to the spoolss backend) -> CLOSE. On any
// parse/decrypt/auth failure it returns, which closes the connection.
func handleSMBConn(c net.Conn) {
	defer c.Close()

	var s *smbSession

	for {
		frame, err := readTCPFrame(c)
		if err != nil {
			return
		}

		msg := frame
		reqEncrypted := false
		// SMB3 encrypted message? TRANSFORM_HEADER starts with 0xFD 'S' 'M' 'B'.
		if len(frame) >= 4 && frame[0] == 0xFD && frame[1] == 'S' && frame[2] == 'M' && frame[3] == 'B' {
			if s == nil || len(s.c2sKey) != 16 {
				return
			}
			pt, ok := smbDecrypt(s.c2sKey, frame)
			if !ok {
				return
			}
			msg = pt
			reqEncrypted = true
		}

		reqHdr, ok := parseSMB2Header(msg)
		if !ok {
			return
		}

		// Verify signing on authenticated, signed, non-guest requests. Lenient:
		// only enforced when signing was negotiated and the request is signed.
		if s != nil && s.authComplete && s.signingRequired && !s.guest && (reqHdr.Flags&0x08 != 0) {
			if !smbVerifySign(s.signingKey, msg) {
				return
			}
		}

		var resp []byte
		var ssStatus uint32 // SESSION_SETUP status, for preauth-fold decisions
		switch reqHdr.Command {
		case smb2Negotiate:
			r, st, ok := handleNegotiate(msg)
			if !ok || st != negStateOK {
				return
			}
			nr, _ := handleNegotiateResult(msg)
			s = newSMBSession()
			s.dialect, s.cipher = nr.dialect, nr.cipher
			s.remoteAddr = c.RemoteAddr().String()
			resp = r
		case smb2SessionSetup:
			if s == nil {
				return
			}
			// Fold the request into the preauth hash BEFORE the handler so the
			// leg-2 key derivation includes it (MS-SMB2 §3.3.5.4). The request
			// bytes are not rewritten by patchResponseHeader, so folding here is
			// the same bytes the client hashed.
			updatePreauth(s, msg)
			resp, ssStatus, _ = handleSessionSetup(s, msg)
		case smb2TreeConnect:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleTreeConnect(s, msg)
		case smb2Create:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleCreate(s, msg)
		case smb2Write:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleWrite(s, msg)
		case smb2Read:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleRead(s, msg)
		case smb2Close:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleClose(s, msg)
		case smb2TreeDisconnect:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleTreeDisconnect(s, msg)
		case smb2Logoff:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleLogoff(s, msg)
		case smb2Flush:
			if s == nil || !s.authComplete {
				return
			}
			resp, _, _ = handleFlush(s, msg)
		default:
			// Unsupported command: respond with STATUS_NOT_SUPPORTED so the
			// client never hangs waiting on a reply it expects.
			resp = buildErrorResponse(reqHdr, reqHdr.Command, statusNotSupported)
		}

		if len(resp) < smb2HeaderSize {
			continue
		}

		// Patch the response header for protocol correctness regardless of what
		// the handler set: echo MessageId, grant credits, set the response flag,
		// echo TreeId, set SessionId.
		patchResponseHeader(resp, reqHdr, s)

		// Preauth-integrity folding uses the FINAL on-the-wire response bytes
		// (post-patch), matching exactly what the client hashes (MS-SMB2
		// §3.3.5.4). Getting this wrong yields a signing/encryption key that
		// disagrees with the client.
		switch reqHdr.Command {
		case smb2Negotiate:
			updatePreauth(s, msg)  // NEGOTIATE request
			updatePreauth(s, resp) // NEGOTIATE response
		case smb2SessionSetup:
			// The request was folded before the handler; fold the response only
			// for the non-final (MORE_PROCESSING) leg. The final SUCCESS response
			// is signed with the derived key and is not part of the hash.
			if ssStatus == statusMoreProcessingRequired {
				updatePreauth(s, resp)
			}
		}

		// Sign authenticated non-guest responses if signing was negotiated.
		if s != nil && s.authComplete && s.signingRequired && !s.guest && len(s.signingKey) == 16 {
			resp = smbSign(s.signingKey, resp)
		}

		out := resp
		// Encrypt the response only if the request itself arrived encrypted
		// (mirror the client). The SESSION_SETUP responses are never encrypted —
		// encryption begins on the traffic AFTER the session is established, and
		// the client cannot decrypt before it has confirmed the session.
		if reqEncrypted && s != nil && len(s.s2cKey) == 16 {
			if enc, err := smbEncrypt(s.s2cKey, s.sessionID, resp); err == nil {
				out = enc
			}
		}

		if err := writeTCPFrame(c, out); err != nil {
			return
		}
	}
}

// patchResponseHeader overwrites the protocol-correctness fields in resp's
// first 64 bytes in place (little-endian, [MS-SMB2] §2.2.1.2): MessageId echoes
// the request, CreditResp grants at least one credit, the SERVER_TO_REDIR flag
// is set, TreeId echoes the request, and SessionId is taken from the request if
// non-zero else from the session. Status is left as the handler set it. It is a
// no-op on a resp shorter than 64 bytes.
func patchResponseHeader(resp []byte, req smb2Header, s *smbSession) {
	if len(resp) < smb2HeaderSize {
		return
	}

	// MessageId @24.
	binary.LittleEndian.PutUint64(resp[24:32], req.MessageId)

	// CreditResp @14 = max(1, req.CreditCharge).
	credits := req.CreditCharge
	if credits < 1 {
		credits = 1
	}
	binary.LittleEndian.PutUint16(resp[14:16], credits)

	// Flags @16 |= SMB2_FLAGS_SERVER_TO_REDIR.
	flags := binary.LittleEndian.Uint32(resp[16:20])
	flags |= smb2FlagsServerToRedir
	binary.LittleEndian.PutUint32(resp[16:20], flags)

	// TreeId @36 is left as the handler set it: TREE_CONNECT assigns a NEW
	// TreeId (the request's is 0), and every other handler already echoes the
	// request's TreeId. Overwriting it here would hand back TreeId 0 on
	// TREE_CONNECT and break all subsequent tree-scoped operations.

	// SessionId @40: request value if non-zero, else session value.
	sid := req.SessionId
	if sid == 0 && s != nil {
		sid = s.sessionID
	}
	binary.LittleEndian.PutUint64(resp[40:48], sid)
}
