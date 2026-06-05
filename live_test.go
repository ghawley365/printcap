package main

import (
	"testing"
	"time"
)

func liveFrame(marker byte) capturedPacket {
	// minimal ethernet+ip+tcp frame is overkill here; the ring stores raw bytes.
	return capturedPacket{ts: time.Unix(1717459200, 0), data: []byte{marker, marker, marker}}
}

func TestLiveTapSinceAndCursor(t *testing.T) {
	tap := &liveTap{max: 100}
	tap.reset(linkTypeEthernet)
	for i := 0; i < 5; i++ {
		tap.record(liveFrame(byte(i)))
	}
	recs, link, cursor, firstNo, dropped := tap.since(0, 100)
	if link != linkTypeEthernet {
		t.Fatalf("link=%d", link)
	}
	if len(recs) != 5 || cursor != 5 || firstNo != 1 || dropped != 0 {
		t.Fatalf("recs=%d cursor=%d firstNo=%d dropped=%d", len(recs), cursor, firstNo, dropped)
	}
	// Incremental: nothing new since cursor 5.
	recs2, _, c2, _, _ := tap.since(cursor, 100)
	if len(recs2) != 0 || c2 != 5 {
		t.Fatalf("expected no new packets; got %d cursor %d", len(recs2), c2)
	}
	// Two more, read incrementally.
	tap.record(liveFrame(9))
	tap.record(liveFrame(10))
	recs3, _, c3, firstNo3, _ := tap.since(cursor, 100)
	if len(recs3) != 2 || c3 != 7 || firstNo3 != 6 {
		t.Fatalf("incremental: recs=%d cursor=%d firstNo=%d", len(recs3), c3, firstNo3)
	}
}

func TestLiveTapDropsOldestAndReportsDropped(t *testing.T) {
	tap := &liveTap{max: 3}
	tap.reset(linkTypeEthernet)
	for i := 0; i < 10; i++ { // 10 in, capacity 3 -> 7 dropped
		tap.record(liveFrame(byte(i)))
	}
	recs, _, cursor, firstNo, dropped := tap.since(0, 100)
	if len(recs) != 3 || cursor != 10 {
		t.Fatalf("recs=%d cursor=%d, want 3/10", len(recs), cursor)
	}
	if dropped != 7 || firstNo != 8 {
		t.Fatalf("dropped=%d firstNo=%d, want 7/8", dropped, firstNo)
	}
}

func TestPortServiceAndHTTPDetect(t *testing.T) {
	if portService(80) != "http" || portService(631) != "ipp" || portService(9100) != "raw" || portService(443) != "https" {
		t.Fatal("portService mapping wrong")
	}
	if portService(12345) != "" {
		t.Fatal("unknown port should map to empty service")
	}
	if !looksHTTP([]byte("GET /hp/device/info HTTP/1.1\r\n")) {
		t.Fatal("HTTP request not detected")
	}
	if !looksHTTP([]byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatal("HTTP response not detected")
	}
	if looksHTTP([]byte{0x1b, 'E', 'P', 'C', 'L'}) {
		t.Fatal("PCL must not be detected as HTTP")
	}
}

func TestDissectLabelsHTTPService(t *testing.T) {
	// client 10.0.0.1:50000 -> printer EWS on :80
	f := ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 80, 1, tcpFlagACK, []byte("GET / HTTP/1.1\r\n"))
	s := dissectSummary(linkTypeEthernet, f)
	if s.Svc != "http" {
		t.Fatalf("svc=%q, want http", s.Svc)
	}
	if s.Dport != 80 || s.Sport != 50000 {
		t.Fatalf("ports sport=%d dport=%d", s.Sport, s.Dport)
	}
}

func TestCaptureFilterByPortAndService(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 80, 1, tcpFlagACK, []byte("GET / HTTP/1.1")),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 40000, 9100, 1, tcpFlagACK, []byte("PCLDATA")),
	}
	path := writeTestPcap(t, frames)
	if r, _ := capturePackets(path, captureFilter{port: 80, limit: 100}); r.Matched != 1 {
		t.Fatalf("port=80 matched=%d, want 1", r.Matched)
	}
	if r, _ := capturePackets(path, captureFilter{svc: "raw", limit: 100}); r.Matched != 1 {
		t.Fatalf("svc=raw matched=%d, want 1", r.Matched)
	}
	if r, _ := capturePackets(path, captureFilter{svc: "http", limit: 100}); r.Matched != 1 {
		t.Fatalf("svc=http matched=%d, want 1", r.Matched)
	}
}
