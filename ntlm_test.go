package main

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// [MS-NLMP] §4.2.4: User="User", Domain="Domain", Password="Password".
func TestNTOWFv2Vector(t *testing.T) {
	got := ntowfv2("User", "Domain", "Password")
	want := "0c868a403bfd7a93a3001ef22ef02e3f"
	if hex.EncodeToString(got) != want {
		t.Fatalf("NTOWFv2\n got=%s\nwant=%s", hex.EncodeToString(got), want)
	}
}

// Domain is NOT uppercased; only the user is. A lowercase user must produce the
// same result as its uppercased form (the function uppercases internally).
func TestNTOWFv2UppercasesUserOnly(t *testing.T) {
	if hex.EncodeToString(ntowfv2("user", "Domain", "Password")) !=
		hex.EncodeToString(ntowfv2("USER", "Domain", "Password")) {
		t.Fatal("user must be uppercased before HMAC; domain case preserved")
	}
}

// [MS-NLMP] §4.2.4: locks NTProofStr and SessionBaseKey against the published
// worked example.
func TestNTLMv2ProofVector(t *testing.T) {
	ntowf := ntowfv2("User", "Domain", "Password")
	sc, _ := hex.DecodeString("0123456789abcdef")
	cc, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	ti := ntlmTargetInfo("Domain", "Server") // helper per §4.2.4.1.3
	temp := ntlmv2Temp(0, cc, ti)
	proof, sbk := ntlmv2Response(ntowf, sc, temp)
	if hex.EncodeToString(proof) != "68cd0ab851e51c96aabc927bebef6a1c" {
		t.Fatalf("NTProofStr got %s", hex.EncodeToString(proof))
	}
	if hex.EncodeToString(sbk) != "8de40ccadbc14a82f15cb0ad0de95ca3" {
		t.Fatalf("SessionBaseKey got %s", hex.EncodeToString(sbk))
	}
}

func TestVerifyNTLMv2AcceptsAndRejects(t *testing.T) {
	sc, _ := hex.DecodeString("0123456789abcdef")
	cc, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")
	ti := ntlmTargetInfo("Domain", "Server")
	temp := ntlmv2Temp(0, cc, ti)
	proof, _ := ntlmv2Response(ntowfv2("User", "Domain", "Password"), sc, temp)
	ntResp := append(append([]byte{}, proof...), temp...)
	auth := buildAuthenticate("Domain", "User", ntResp) // minimal AUTHENTICATE

	if _, ok := verifyNTLMv2("User", "Password", "Domain", sc, auth); !ok {
		t.Fatal("correct password must verify")
	}
	if _, ok := verifyNTLMv2("User", "WrongPassword", "Domain", sc, auth); ok {
		t.Fatal("wrong password must be rejected")
	}
}

// buildChallenge must emit a well-formed CHALLENGE_MESSAGE header
// ([MS-NLMP] §2.2.1.2) that embeds the server challenge at offset 24.
func TestBuildChallenge(t *testing.T) {
	sc, _ := hex.DecodeString("0123456789abcdef")
	ti := ntlmTargetInfo("Domain", "Server")
	msg := buildChallenge(sc, ti)
	if string(msg[:8]) != "NTLMSSP\x00" {
		t.Fatalf("signature got %q", msg[:8])
	}
	if mt := binary.LittleEndian.Uint32(msg[8:12]); mt != 2 {
		t.Fatalf("MessageType got %d want 2", mt)
	}
	if got := hex.EncodeToString(msg[24:32]); got != "0123456789abcdef" {
		t.Fatalf("embedded ServerChallenge got %s", got)
	}
}

// parseAuthenticate must never panic on truncated or garbage input.
func TestParseAuthenticatePanicProof(t *testing.T) {
	// These must all be rejected (too short, bad signature, or wrong type).
	cases := [][]byte{
		nil,
		{},
		[]byte("NTLMSSP\x00"),
		[]byte("NTLMSSP\x00\x03\x00\x00\x00"),
		[]byte("not an ntlm message at all"),
	}
	// Craft a header claiming a huge NtChallengeResponse offset/len. The
	// NtChallengeResponseFields triple lives at header offset 20.
	bad := make([]byte, 64)
	copy(bad, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(bad[8:], 3)
	binary.LittleEndian.PutUint16(bad[20:], 0xffff)     // NtResp Len
	binary.LittleEndian.PutUint16(bad[22:], 0xffff)     // NtResp MaxLen
	binary.LittleEndian.PutUint32(bad[24:], 0xffffffff) // NtResp Offset
	cases = append(cases, bad)
	for i, c := range cases {
		if _, _, _, ok := parseAuthenticate(c); ok {
			t.Fatalf("case %d: expected ok=false for malformed input", i)
		}
	}

	// A header with valid signature/type but all-zero (empty) field triples is
	// structurally valid; it must parse without panicking and yield empty data.
	ok64 := append([]byte("NTLMSSP\x00\x03\x00\x00\x00"), make([]byte, 200)...)
	if dom, usr, nt, ok := parseAuthenticate(ok64); !ok || dom != "" || usr != "" || len(nt) != 0 {
		t.Fatalf("empty-field message: ok=%v dom=%q usr=%q ntLen=%d", ok, dom, usr, len(nt))
	}
}
