package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// pcap (libpcap) save-file constants. The format is tiny and stable, so we
// hand-roll it rather than pull a dependency in just to write a file — matching
// how the rest of printcap hand-rolls its wire formats. The bytes produced are
// the classic little-endian libpcap layout that Wireshark/tshark read directly.
const (
	pcapMagic    = 0xa1b2c3d4 // microsecond-resolution, host (little-endian) order
	pcapVerMajor = 2
	pcapVerMinor = 4

	// Link-layer header types (tcpdump LINKTYPE_*).
	linkTypeNull     = 0   // BSD loopback: 4-byte address-family header, then IP
	linkTypeEthernet = 1   // Ethernet frames
	linkTypeRaw      = 101 // raw IP, used when no L2 header is present

	defaultSnapLen = 262144 // 256 KiB: capture full frames by default
)

// pcapWriter streams captured frames to a libpcap-format file. It is safe for
// concurrent use: the capture loop and any flush/teardown can call it from
// different goroutines. Writes are buffered; Close flushes and releases the file.
type pcapWriter struct {
	mu      sync.Mutex
	bw      *bufio.Writer
	closer  io.Closer
	snaplen uint32
	count   uint64 // packets written (for stats/teardown logging)
	bytes   uint64 // captured bytes written (incl_len sum)
	closed  bool
}

// newPcapFile opens path for writing and emits the global header. snaplen <= 0
// selects defaultSnapLen. linkType is one of the linkType* constants.
func newPcapFile(path string, snaplen, linkType int) (*pcapWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("pcap: open %q: %w", path, err)
	}
	w, err := newPcapWriter(f, f, snaplen, linkType)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// newPcapWriter writes the global header to w and returns a writer. closer is
// closed by Close (pass the same file as w and closer; pass nil closer for an
// in-memory buffer in tests).
func newPcapWriter(w io.Writer, closer io.Closer, snaplen, linkType int) (*pcapWriter, error) {
	if snaplen <= 0 {
		snaplen = defaultSnapLen
	}
	if linkType < 0 {
		linkType = linkTypeEthernet // negative = "unset"; 0 is a valid type (DLT_NULL)
	}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:6], pcapVerMajor)
	binary.LittleEndian.PutUint16(hdr[6:8], pcapVerMinor)
	// hdr[8:12]  thiszone (GMT offset)  = 0
	// hdr[12:16] sigfigs (accuracy)     = 0
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(snaplen))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(linkType))

	bw := bufio.NewWriterSize(w, 1<<16)
	if _, err := bw.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("pcap: write header: %w", err)
	}
	return &pcapWriter{bw: bw, closer: closer, snaplen: uint32(snaplen)}, nil
}

// writePacket appends one captured frame stamped at ts. Frames longer than the
// snap length are truncated on disk (incl_len < orig_len), exactly as libpcap
// does, so the original length is still recorded for analysis.
func (p *pcapWriter) writePacket(ts time.Time, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return fmt.Errorf("pcap: write after close")
	}
	origLen := uint32(len(data))
	inclLen := origLen
	if inclLen > p.snaplen {
		inclLen = p.snaplen
	}
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:8], uint32(ts.Nanosecond()/1000)) // microseconds
	binary.LittleEndian.PutUint32(rec[8:12], inclLen)
	binary.LittleEndian.PutUint32(rec[12:16], origLen)
	if _, err := p.bw.Write(rec[:]); err != nil {
		return err
	}
	if _, err := p.bw.Write(data[:inclLen]); err != nil {
		return err
	}
	p.count++
	p.bytes += uint64(inclLen)
	return nil
}

// flush writes any buffered frames to the underlying file without closing it, so
// a viewer reading the file mid-capture sees recent packets. Safe for concurrent
// use; a no-op after Close.
func (p *pcapWriter) flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	return p.bw.Flush()
}

// stats returns the number of packets and captured bytes written so far.
func (p *pcapWriter) stats() (packets, bytes uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count, p.bytes
}

// Close flushes buffered frames and closes the underlying file. It is idempotent
// so the engine teardown can call it unconditionally.
func (p *pcapWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	ferr := p.bw.Flush()
	if p.closer != nil {
		if cerr := p.closer.Close(); cerr != nil && ferr == nil {
			ferr = cerr
		}
	}
	return ferr
}
