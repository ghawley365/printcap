package main

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestSPNEGOWrapChallengeParses(t *testing.T) {
	challenge := []byte("NTLMSSP\x00\x02\x00\x00\x00fake-challenge-body")
	wrapped := spnegoWrapResponse(spnegoAcceptIncomplete, challenge)
	if wrapped[0] != 0xA1 { // negTokenResp [1]
		t.Fatalf("expected [1] context tag, got 0x%02x", wrapped[0])
	}
	// The NTLMSSP OID and the responseToken must be embedded.
	ntlmOID := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
	if !bytes.Contains(wrapped, ntlmOID) {
		t.Fatal("NTLMSSP OID not present in wrapped challenge")
	}
	if !bytes.Contains(wrapped, challenge) {
		t.Fatal("challenge responseToken not embedded")
	}
	// It must be DER-parseable as a [1]-tagged value.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &raw); err != nil {
		t.Fatalf("wrapped token is not valid DER: %v", err)
	}
	if raw.Class != 2 /*context*/ || raw.Tag != 1 {
		t.Fatalf("outer tag class=%d tag=%d want context [1]", raw.Class, raw.Tag)
	}
}

func TestSPNEGOWrapSuccessMinimal(t *testing.T) {
	wrapped := spnegoWrapResponse(spnegoAcceptCompleted, nil)
	if wrapped[0] != 0xA1 {
		t.Fatalf("expected [1] context tag, got 0x%02x", wrapped[0])
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &raw); err != nil {
		t.Fatalf("success token not valid DER: %v", err)
	}
	// Must encode negState accept-completed (0) and need not carry a responseToken.
	if !bytes.Contains(wrapped, []byte{0xA0, 0x03, 0x0A, 0x01, 0x00}) {
		t.Fatal("accept-completed negState not encoded")
	}
}

func TestSPNEGOLongFormLength(t *testing.T) {
	big := make([]byte, 300)
	copy(big, []byte("NTLMSSP\x00"))
	wrapped := spnegoWrapResponse(spnegoAcceptIncomplete, big)
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &raw); err != nil {
		t.Fatalf("long-form length not valid DER: %v", err)
	}
	if !bytes.Contains(wrapped, big) {
		t.Fatal("large responseToken not embedded")
	}
}
