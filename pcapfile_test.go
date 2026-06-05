package main

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// nopCloser lets the test reuse a bytes.Buffer as both writer and closer.
type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestPcapWriterGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	w, err := newPcapWriter(&buf, nopCloser{}, 65536, linkTypeEthernet)
	if err != nil {
		t.Fatalf("newPcapWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := buf.Bytes()
	if len(got) != 24 {
		t.Fatalf("header length = %d, want 24", len(got))
	}
	if magic := binary.LittleEndian.Uint32(got[0:4]); magic != pcapMagic {
		t.Errorf("magic = %#x, want %#x", magic, pcapMagic)
	}
	if v := binary.LittleEndian.Uint16(got[4:6]); v != pcapVerMajor {
		t.Errorf("version major = %d, want %d", v, pcapVerMajor)
	}
	if sl := binary.LittleEndian.Uint32(got[16:20]); sl != 65536 {
		t.Errorf("snaplen = %d, want 65536", sl)
	}
	if lt := binary.LittleEndian.Uint32(got[20:24]); lt != linkTypeEthernet {
		t.Errorf("linktype = %d, want %d", lt, linkTypeEthernet)
	}
}

func TestPcapWriterRecordsRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := newPcapWriter(&buf, nopCloser{}, 0, 0) // exercise the defaults
	if err != nil {
		t.Fatalf("newPcapWriter: %v", err)
	}
	ts := time.Unix(1717459200, 123456000) // 2024-06-04, .123456 s
	frames := [][]byte{
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11},
		{0xde, 0xad, 0xbe, 0xef},
	}
	for _, f := range frames {
		if err := w.writePacket(ts, f); err != nil {
			t.Fatalf("writePacket: %v", err)
		}
	}
	if pkts, by := w.stats(); pkts != 2 || by != 12 {
		t.Fatalf("stats = (%d,%d), want (2,12)", pkts, by)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Parse it back: skip the 24-byte global header, then read each record.
	b := buf.Bytes()[24:]
	for i, f := range frames {
		if len(b) < 16 {
			t.Fatalf("frame %d: truncated record header", i)
		}
		tsSec := binary.LittleEndian.Uint32(b[0:4])
		tsUsec := binary.LittleEndian.Uint32(b[4:8])
		inclLen := binary.LittleEndian.Uint32(b[8:12])
		origLen := binary.LittleEndian.Uint32(b[12:16])
		if tsSec != 1717459200 || tsUsec != 123456 {
			t.Errorf("frame %d: ts = %d.%06d, want 1717459200.123456", i, tsSec, tsUsec)
		}
		if int(inclLen) != len(f) || int(origLen) != len(f) {
			t.Errorf("frame %d: incl=%d orig=%d, want %d", i, inclLen, origLen, len(f))
		}
		payload := b[16 : 16+inclLen]
		if !bytes.Equal(payload, f) {
			t.Errorf("frame %d: payload = %x, want %x", i, payload, f)
		}
		b = b[16+inclLen:]
	}
	if len(b) != 0 {
		t.Errorf("%d trailing bytes after last record", len(b))
	}
}

func TestPcapWriterTruncatesToSnapLen(t *testing.T) {
	var buf bytes.Buffer
	w, _ := newPcapWriter(&buf, nopCloser{}, 4, linkTypeEthernet) // snaplen 4
	ts := time.Unix(0, 0)
	if err := w.writePacket(ts, []byte{1, 2, 3, 4, 5, 6}); err != nil {
		t.Fatalf("writePacket: %v", err)
	}
	w.Close()
	b := buf.Bytes()[24:]
	inclLen := binary.LittleEndian.Uint32(b[8:12])
	origLen := binary.LittleEndian.Uint32(b[12:16])
	if inclLen != 4 || origLen != 6 {
		t.Fatalf("incl=%d orig=%d, want incl=4 orig=6", inclLen, origLen)
	}
	if got := b[16 : 16+inclLen]; !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Errorf("truncated payload = %x, want 01020304", got)
	}
}

func TestPcapWriterWriteAfterClose(t *testing.T) {
	var buf bytes.Buffer
	w, _ := newPcapWriter(&buf, nopCloser{}, 0, 0)
	w.Close()
	if err := w.writePacket(time.Unix(0, 0), []byte{1}); err == nil {
		t.Fatal("writePacket after Close: want error, got nil")
	}
	if err := w.Close(); err != nil { // idempotent
		t.Errorf("second Close: %v", err)
	}
}
