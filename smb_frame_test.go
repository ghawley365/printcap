package main

import (
	"bytes"
	"testing"
)

func TestSMB2HeaderRoundTrip(t *testing.T) {
	h := smb2Header{
		Command:    smb2Negotiate,
		Status:     statusSuccess,
		Flags:      smb2FlagsServerToRedir,
		MessageId:  0x0102030405060708,
		TreeId:     0x11223344,
		SessionId:  0xAABBCCDD00112233,
		CreditResp: 1,
	}
	b := h.encode()
	if len(b) != 64 {
		t.Fatalf("header len=%d want 64", len(b))
	}
	if !bytes.Equal(b[0:4], []byte{0xFE, 'S', 'M', 'B'}) {
		t.Fatalf("bad ProtocolId %x", b[0:4])
	}
	if b[4] != 64 || b[5] != 0 {
		t.Fatalf("bad StructureSize")
	}
	got, ok := parseSMB2Header(b)
	if !ok {
		t.Fatal("parseSMB2Header ok=false")
	}
	if got.Command != smb2Negotiate || got.MessageId != 0x0102030405060708 ||
		got.TreeId != 0x11223344 || got.SessionId != 0xAABBCCDD00112233 ||
		got.Flags != smb2FlagsServerToRedir {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestParseSMB2HeaderRejectsShortOrBadMagic(t *testing.T) {
	if _, ok := parseSMB2Header(make([]byte, 63)); ok {
		t.Fatal("short header must be rejected")
	}
	bad := make([]byte, 64)
	copy(bad, []byte{0xFF, 'S', 'M', 'B'})
	if _, ok := parseSMB2Header(bad); ok {
		t.Fatal("bad ProtocolId must be rejected")
	}
}

func TestDirectTCPFrameRoundTrip(t *testing.T) {
	payload := []byte("hello smb2 payload")
	var buf bytes.Buffer
	if err := writeTCPFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	// 4-byte prefix: 0x00 then 24-bit big-endian length.
	raw := buf.Bytes()
	if raw[0] != 0x00 || int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(payload) {
		t.Fatalf("bad frame prefix: %x", raw[0:4])
	}
	got, err := readTCPFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("frame round-trip mismatch")
	}
}

func TestReadTCPFrameRejectsOversize(t *testing.T) {
	// A prefix claiming > 0x00FFFFFF must be rejected (top byte non-zero).
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00, 0x00})
	if _, err := readTCPFrame(r); err == nil {
		t.Fatal("oversize/invalid frame must error")
	}
}
