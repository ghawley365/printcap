package main

import "testing"

func TestEncodeName(t *testing.T) {
	got := encodeName("_ipp._tcp.local")
	want := []byte{4, '_', 'i', 'p', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0}
	if string(got) != string(want) {
		t.Fatalf("encodeName mismatch\n got=%v\nwant=%v", got, want)
	}
}

func TestParseNameRoundTrip(t *testing.T) {
	enc := encodeName("printcap._ipp._tcp.local")
	name, next, ok := parseName(enc, 0)
	if !ok {
		t.Fatal("parseName returned ok=false")
	}
	if name != "printcap._ipp._tcp.local" {
		t.Fatalf("got %q", name)
	}
	if next != len(enc) {
		t.Fatalf("next=%d want=%d", next, len(enc))
	}
}

func TestParseNameCompressionPointer(t *testing.T) {
	buf := append([]byte{}, encodeName("local")...)
	start := len(buf)
	buf = append(buf, 4, '_', 'i', 'p', 'p')
	buf = append(buf, 0xC0, 0x00)
	name, next, ok := parseName(buf, start)
	if !ok {
		t.Fatal("ok=false")
	}
	if name != "_ipp.local" {
		t.Fatalf("got %q", name)
	}
	if next != len(buf) {
		t.Fatalf("next=%d want=%d", next, len(buf))
	}
}
