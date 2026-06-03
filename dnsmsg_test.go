package main

import (
	"encoding/binary"
	"net"
	"testing"
)

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

func TestParseNameForwardPointerRejected(t *testing.T) {
	// A pointer that references its own or a later offset is illegal
	// (RFC 1035 §4.1.4) and must be rejected, not followed.
	buf := []byte{4, '_', 'i', 'p', 'p', 0xC0, 0x05} // pointer at off=5 targets off=5
	if _, _, ok := parseName(buf, 0); ok {
		t.Fatal("forward/self compression pointer should be rejected")
	}
}

func TestRdataSRV(t *testing.T) {
	got := rdataSRV(0, 0, 631, "printcap.local")
	want := append([]byte{0, 0, 0, 0, 0x02, 0x77}, encodeName("printcap.local")...)
	if string(got) != string(want) {
		t.Fatalf("rdataSRV\n got=%v\nwant=%v", got, want)
	}
}

func TestRdataTXT(t *testing.T) {
	got := rdataTXT([]string{"txtvers=1", "rp=ipp/print"})
	want := []byte{9}
	want = append(want, "txtvers=1"...)
	want = append(want, 12)
	want = append(want, "rp=ipp/print"...)
	if string(got) != string(want) {
		t.Fatalf("rdataTXT\n got=%v\nwant=%v", got, want)
	}
}

func TestRdataA(t *testing.T) {
	got := rdataA(net.IPv4(192, 168, 1, 50))
	if len(got) != 4 || got[0] != 192 || got[3] != 50 {
		t.Fatalf("rdataA got=%v", got)
	}
}

func TestRdataAAAA(t *testing.T) {
	got := rdataAAAA(net.ParseIP("fe80::1"))
	if len(got) != 16 {
		t.Fatalf("rdataAAAA len=%d", len(got))
	}
}

func buildQuery(name string, qtype uint16, unicast bool) []byte {
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[4:], 1)
	b = append(b, hdr...)
	b = append(b, encodeName(name)...)
	qt := make([]byte, 4)
	binary.BigEndian.PutUint16(qt[0:], qtype)
	qclass := dnsClassIN
	if unicast {
		qclass |= dnsFlushBit
	}
	binary.BigEndian.PutUint16(qt[2:], qclass)
	return append(b, qt...)
}

func TestParseQuestions(t *testing.T) {
	q := buildQuery("_ipp._tcp.local", dnsTypePTR, true)
	qs, ok := parseQuestions(q)
	if !ok || len(qs) != 1 {
		t.Fatalf("ok=%v n=%d", ok, len(qs))
	}
	if qs[0].name != "_ipp._tcp.local" || qs[0].qtype != dnsTypePTR || !qs[0].unicast {
		t.Fatalf("got %+v", qs[0])
	}
}

func TestBuildResponseParsesBack(t *testing.T) {
	recs := []dnsRecord{
		{name: "_ipp._tcp.local", rtype: dnsTypePTR, ttl: ttlDNSSD, data: rdataPTR("printcap._ipp._tcp.local")},
	}
	resp := buildResponse(recs)
	if binary.BigEndian.Uint16(resp[2:]) != 0x8400 {
		t.Fatalf("flags=0x%04x", binary.BigEndian.Uint16(resp[2:]))
	}
	if binary.BigEndian.Uint16(resp[6:]) != 1 {
		t.Fatalf("ancount=%d", binary.BigEndian.Uint16(resp[6:]))
	}
}
