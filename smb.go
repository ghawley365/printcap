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
			// PREAUTH FIX (MS-SMB2 §3.3.5.4): fold the NEGOTIATE request and
			// response into the preauth-integrity hash BEFORE any SESSION_SETUP
			// leg, so the session-setup preauth chain starts from the correct
			// base hash.
			updatePreauth(s, msg)
			updatePreauth(s, r)
			resp = r
		case smb2SessionSetup:
			if s == nil {
				return
			}
			resp, _, _ = handleSessionSetup(s, msg)
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
		default:
			// Unsupported command: ignore and keep looping.
			continue
		}

		if len(resp) < smb2HeaderSize {
			continue
		}

		// Patch the response header for protocol correctness regardless of what
		// the handler set: echo MessageId, grant credits, set the response flag,
		// echo TreeId, set SessionId.
		patchResponseHeader(resp, reqHdr, s)

		// Sign authenticated non-guest responses if signing was negotiated.
		if s != nil && s.authComplete && s.signingRequired && !s.guest && len(s.signingKey) == 16 {
			resp = smbSign(s.signingKey, resp)
		}

		out := resp
		// Encrypt after auth if the session enabled encryption.
		if s != nil && s.authComplete && s.encryptData && len(s.s2cKey) == 16 {
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

	// TreeId @36 echoes the request.
	binary.LittleEndian.PutUint32(resp[36:40], req.TreeId)

	// SessionId @40: request value if non-zero, else session value.
	sid := req.SessionId
	if sid == 0 && s != nil {
		sid = s.sessionID
	}
	binary.LittleEndian.PutUint64(resp[40:48], sid)
}
