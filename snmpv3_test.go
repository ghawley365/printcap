package main

import "testing"

func TestV3MessageRoundTrip(t *testing.T) {
	msg := v3Message{
		msgID: 12345, maxSize: 65507, flags: 0x03, // auth+priv, not reportable
		engineID: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		boots:    1, time: 100, userName: "admin",
		authParams: make([]byte, 12),
		privParams: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		payload:    []byte{0x30, 0x03, 0x02, 0x01, 0x00}, // a tiny SEQUENCE
		encrypted:  true,
	}
	enc := buildV3Message(msg)
	got, ok := parseV3Message(enc)
	if !ok {
		t.Fatal("parseV3Message ok=false")
	}
	if got.msgID != 12345 || got.userName != "admin" || got.boots != 1 || got.time != 100 {
		t.Fatalf("header mismatch: %+v", got)
	}
	if string(got.privParams) != string(msg.privParams) || string(got.payload) != string(msg.payload) {
		t.Fatalf("body mismatch: %+v", got)
	}
}
