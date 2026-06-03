package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// --- Test-side NTLM client helpers ---------------------------------------
//
// These build the client-side NTLM messages a real SMB2 client would send.
// They reuse the production NTLM primitives (ntowfv2, ntlmv2Temp,
// ntlmv2Response, buildAuthenticate) so the test exercises the same math the
// server verifies.

// ntlmNegotiateMessage builds a minimal NEGOTIATE_MESSAGE (type 1): the
// "NTLMSSP\0" signature, MessageType=1, and a minimal NegotiateFlags field.
func ntlmNegotiateMessage() []byte {
	b := make([]byte, 32)
	copy(b[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:], 1) // MessageType = NEGOTIATE
	// NegotiateFlags: Unicode | NTLM | RequestTarget.
	binary.LittleEndian.PutUint32(b[12:], 0x00000001|0x00000200|0x00000004)
	return b
}

// ntlmServerChallenge extracts the 8-byte ServerChallenge from a
// CHALLENGE_MESSAGE (bytes [24:32]).
func ntlmServerChallenge(chal []byte) []byte {
	if len(chal) < 32 {
		return nil
	}
	out := make([]byte, 8)
	copy(out, chal[24:32])
	return out
}

// ntlmChallengeTargetInfo extracts the TargetInfo payload from a
// CHALLENGE_MESSAGE using its TargetInfoFields triple at offset 40.
func ntlmChallengeTargetInfo(chal []byte) []byte {
	ti, ok := ntlmField(chal, 40)
	if !ok {
		return nil
	}
	out := make([]byte, len(ti))
	copy(out, ti)
	return out
}

// clientAuthenticate builds an AUTHENTICATE_MESSAGE (type 3) carrying an
// NtChallengeResponse computed for the given credentials, server challenge and
// target info (echoed from the CHALLENGE).
func clientAuthenticate(domain, user, password string, serverChallenge, targetInfo []byte) []byte {
	clientChallenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	temp := ntlmv2Temp(0, clientChallenge, targetInfo)
	ntowf := ntowfv2(user, domain, password)
	ntProof, _ := ntlmv2Response(ntowf, serverChallenge, temp)
	ntResp := append(append([]byte(nil), ntProof...), temp...)
	return buildAuthenticate(domain, user, ntResp)
}

func TestSP800108KDFGolden(t *testing.T) {
	// Pin the KDF against the MS-NLMP §4.2.4 SessionBaseKey and an all-zero
	// preauth hash so regressions in the KDF are caught.
	sbk, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	ph := make([]byte, 64)
	sign := smbKDF(sbk, []byte("SMBSigningKey\x00"), ph, 128)
	if len(sign) != 16 {
		t.Fatalf("len=%d", len(sign))
	}
	want := "73b8b93ec1fb3c18b1388af477a3296d"
	if got := hex.EncodeToString(sign); got != want {
		t.Fatalf("signing key %s != %s", got, want)
	}
	_ = sha512.Sum512
}

func TestSessionSetupTwoLegGuestlessAuth(t *testing.T) {
	cfg = defaultConfig()
	cfg.SMB.Enabled = true
	cfg.SMB.RequireAuth = true
	cfg.SMB.Users = []SMBUser{{User: "print", Password: "pass123", Domain: "WORKGROUP"}}

	s := newSMBSession()
	s.dialect = 0x0311
	// Leg 1: client sends NTLM NEGOTIATE.
	clientNeg := ntlmNegotiateMessage()
	leg1 := buildSessionSetupRequest(0, clientNeg)
	resp1, status1, sess1 := handleSessionSetup(s, leg1)
	if status1 != statusMoreProcessingRequired {
		t.Fatalf("leg1 status=0x%08x want MORE_PROCESSING", status1)
	}
	if sess1 {
		t.Fatal("session must not be complete after leg1")
	}
	// Extract the CHALLENGE the server returned.
	chal, ok := extractNTLM(sessionSecBuf(resp1))
	if !ok {
		t.Fatal("no CHALLENGE in leg1 response")
	}
	serverChallenge := ntlmServerChallenge(chal)
	// Leg 2: client computes AUTHENTICATE for the right user/pass.
	auth := clientAuthenticate("WORKGROUP", "print", "pass123", serverChallenge, ntlmChallengeTargetInfo(chal))
	leg2 := buildSessionSetupRequest(s.sessionID, auth)
	_, status2, sess2 := handleSessionSetup(s, leg2)
	if status2 != statusSuccess || !sess2 {
		t.Fatalf("leg2 status=0x%08x complete=%v want SUCCESS/true", status2, sess2)
	}
	if len(s.signingKey) != 16 {
		t.Fatalf("signing key not derived: %d", len(s.signingKey))
	}
	if len(s.c2sKey) != 16 || len(s.s2cKey) != 16 {
		t.Fatalf("cipher keys not derived: c2s=%d s2c=%d", len(s.c2sKey), len(s.s2cKey))
	}

	// Wrong password must fail. Fresh session, fresh two-leg flow.
	s2 := newSMBSession()
	s2.dialect = 0x0311
	resp1b, _, _ := handleSessionSetup(s2, buildSessionSetupRequest(0, clientNeg))
	chal2, _ := extractNTLM(sessionSecBuf(resp1b))
	_ = chal2
	_ = bytes.Equal
	badAuth := clientAuthenticate("WORKGROUP", "print", "WRONGPASS",
		ntlmServerChallenge(chal2), ntlmChallengeTargetInfo(chal2))
	_, statusBad, sessBad := handleSessionSetup(s2, buildSessionSetupRequest(s2.sessionID, badAuth))
	if sessBad || statusBad == statusSuccess {
		t.Fatal("wrong password must not establish a session")
	}
}
