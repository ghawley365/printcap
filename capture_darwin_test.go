//go:build darwin

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// bpfRecord builds one synthetic BPF record (bpf_hdr + data, padded to the BPF
// 4-byte alignment) matching the macOS layout parseBPFRecords expects.
func bpfRecord(sec, usec uint32, data []byte) []byte {
	const hdrlen = 18
	rec := make([]byte, hdrlen)
	binary.LittleEndian.PutUint32(rec[0:], sec)
	binary.LittleEndian.PutUint32(rec[4:], usec)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data)))  // caplen
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(data))) // datalen
	binary.LittleEndian.PutUint16(rec[16:], hdrlen)
	rec = append(rec, data...)
	for len(rec)%4 != 0 { // word-align the whole record
		rec = append(rec, 0)
	}
	return rec
}

func TestParseBPFRecords(t *testing.T) {
	buf := append(bpfRecord(1000, 500000, []byte("AAA")), bpfRecord(1001, 0, []byte("BBBB"))...)
	var got [][]byte
	var times []time.Time
	parseBPFRecords(buf, func(ts time.Time, data []byte) bool {
		got = append(got, append([]byte(nil), data...))
		times = append(times, ts)
		return true
	})
	if len(got) != 2 {
		t.Fatalf("parsed %d records, want 2", len(got))
	}
	if string(got[0]) != "AAA" || string(got[1]) != "BBBB" {
		t.Fatalf("records = %q, %q", got[0], got[1])
	}
	if times[0].Unix() != 1000 || times[0].Nanosecond() != 500000*1000 {
		t.Fatalf("timestamp decode wrong: %v", times[0])
	}
}

func TestParseBPFRecordsStopsOnTruncation(t *testing.T) {
	buf := bpfRecord(1, 0, []byte("hello"))
	parseBPFRecords(buf[:len(buf)-2], func(ts time.Time, data []byte) bool {
		t.Fatalf("should not emit from a truncated record")
		return true
	})
}

func TestParseBPFRecordsEmitStop(t *testing.T) {
	buf := append(bpfRecord(1, 0, []byte("one")), bpfRecord(2, 0, []byte("two"))...)
	n := 0
	cont := parseBPFRecords(buf, func(ts time.Time, data []byte) bool { n++; return false })
	if cont || n != 1 {
		t.Fatalf("emit-stop not honored: cont=%v n=%d", cont, n)
	}
}

// TestBPFLiveCaptureLoopback is an integration test: it captures on lo0 while
// generating loopback TCP traffic and confirms the marker bytes are seen. It is
// skipped when BPF can't be opened (no root / not in the access_bpf group).
func TestBPFLiveCaptureLoopback(t *testing.T) {
	src, err := openLiveSource(InterceptConf{Interface: "lo0", Promiscuous: false})
	if err != nil {
		t.Skipf("live capture unavailable (need BPF access): %v", err)
	}
	defer src.Close()

	marker := []byte("PRINTCAP-BPF-LIVE-TEST-MARKER")
	found := make(chan bool, 1)
	go func() {
		for p := range src.Packets() {
			if bytes.Contains(p.data, marker) {
				select {
				case found <- true:
				default:
				}
			}
		}
	}()

	// Generate loopback traffic carrying the marker.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		io := make([]byte, 64)
		_, _ = c.Read(io)
		_ = c.Close()
	}()
	time.Sleep(100 * time.Millisecond) // let the capture loop spin up
	for i := 0; i < 20; i++ {
		c, e := net.Dial("tcp", ln.Addr().String())
		if e == nil {
			_, _ = c.Write(marker)
			_ = c.Close()
		}
		select {
		case <-found:
			return // captured our marker — success
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("did not capture the loopback marker packet within timeout")
}

// TestLiveCaptureToPcapToViewer exercises the whole chain: live BPF capture on
// lo0 -> pcap file (DLT_NULL) -> the dashboard viewer's dissector. Skipped when
// BPF can't be opened.
func TestLiveCaptureToPcapToViewer(t *testing.T) {
	src, err := openLiveSource(InterceptConf{Interface: "lo0"})
	if err != nil {
		t.Skipf("live capture unavailable: %v", err)
	}
	path := filepath.Join(t.TempDir(), "live.pcap")
	pw, err := newPcapFile(path, 0, src.LinkType())
	if err != nil {
		src.Close()
		t.Fatalf("newPcapFile: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for p := range src.Packets() {
			_ = pw.writePacket(p.ts, p.data)
		}
		close(done)
	}()

	// Generate loopback TCP traffic.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			b := make([]byte, 64)
			_, _ = c.Read(b)
			_ = c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 10; i++ {
		if c, e := net.Dial("tcp", ln.Addr().String()); e == nil {
			_, _ = c.Write([]byte("hello-over-loopback"))
			_ = c.Close()
		}
		time.Sleep(40 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	src.Close()
	<-done
	pw.Close()

	// Read it back through the viewer pipeline and confirm TCP packets dissected.
	res, err := capturePackets(path, captureFilter{proto: "tcp", limit: 10000})
	if err != nil {
		t.Fatalf("capturePackets: %v", err)
	}
	if res.TotalParsed == 0 {
		t.Fatal("captured pcap had no packets")
	}
	if res.Matched == 0 {
		t.Fatalf("no TCP packets dissected from %d parsed (DLT_NULL handling?)", res.TotalParsed)
	}
}
