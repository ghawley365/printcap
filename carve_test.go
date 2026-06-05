package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// ethIPv4TCP builds an Ethernet/IPv4/TCP frame carrying payload, for parser and
// carver tests. Checksums are left zero (the parser does not validate them).
func ethIPv4TCP(src, dst string, sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	sip := netip.MustParseAddr(src).As4()
	dip := netip.MustParseAddr(dst).As4()

	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4 // data offset = 5 32-bit words (20 bytes)
	tcp[13] = flags
	copy(tcp[20:], payload)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
	ip[9] = ipProtoTCP
	copy(ip[12:16], sip[:])
	copy(ip[16:20], dip[:])
	ip = append(ip, tcp...)

	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], etherTypeIPv4)
	return append(eth, ip...)
}

func TestParseTCPSegmentEthernetIPv4(t *testing.T) {
	frame := ethIPv4TCP("192.168.1.10", "192.168.1.20", 50000, 9100, 4242, tcpFlagSYN, []byte("hi"))
	seg, ok := parseTCPSegment(linkTypeEthernet, frame)
	if !ok {
		t.Fatal("expected a parseable TCP segment")
	}
	if seg.src.String() != "192.168.1.10:50000" || seg.dst.String() != "192.168.1.20:9100" {
		t.Fatalf("flow = %s -> %s", seg.src, seg.dst)
	}
	if seg.seq != 4242 || !seg.syn || seg.fin || seg.rst {
		t.Fatalf("seq/flags wrong: seq=%d syn=%v fin=%v rst=%v", seg.seq, seg.syn, seg.fin, seg.rst)
	}
	if string(seg.payload) != "hi" {
		t.Fatalf("payload = %q", seg.payload)
	}
}

func TestParseTCPSegmentRejectsNonTCP(t *testing.T) {
	// A short/garbage frame must not parse.
	if _, ok := parseTCPSegment(linkTypeEthernet, []byte{0x00, 0x01, 0x02}); ok {
		t.Fatal("short frame should not parse")
	}
}

// collectStreams runs frames through a carver and returns the jobs it produced.
func collectStreams(t *testing.T, c CarveConf, frames [][]byte) []*job {
	t.Helper()
	var got []*job
	cv := newCarver(c, linkTypeEthernet, func(j *job) { got = append(got, j) })
	ts := time.Unix(1717459200, 0)
	for _, f := range frames {
		cv.consume(f, ts)
	}
	cv.flush()
	return got
}

func TestCarveRaw9100JPEG(t *testing.T) {
	jpeg := append([]byte{0xff, 0xd8, 0xff, 0xe0}, []byte("....JFIF....pixels....")...)
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1000, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1001, 0, jpeg),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1001+uint32(len(jpeg)), tcpFlagFIN, nil),
	}
	jobs := collectStreams(t, CarveConf{Enabled: true, Ports: []int{9100}}, frames)
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	j := jobs[0]
	if !bytes.Equal(j.data, jpeg) {
		t.Fatalf("carved bytes differ from sent stream")
	}
	if name, ext, _ := detectPDL(j.data); name != "JPEG" || ext != ".jpg" {
		t.Fatalf("detectPDL = %q %q, want JPEG .jpg", name, ext)
	}
	if j.Protocol != "intercept/9100" {
		t.Fatalf("protocol = %q", j.Protocol)
	}
}

func TestCarveReassemblesOutOfOrder(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 0, tcpFlagSYN, nil),
		// Send the second half first; the carver must buffer and reorder.
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 4, 0, []byte("BBB")),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1, 0, []byte("AAA")),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 7, tcpFlagFIN, nil),
	}
	jobs := collectStreams(t, CarveConf{Enabled: true, Ports: []int{9100}}, frames)
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1", len(jobs))
	}
	if string(jobs[0].data) != "AAABBB" {
		t.Fatalf("reassembled = %q, want AAABBB", jobs[0].data)
	}
}

func TestCarveDropsDuplicateSegments(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 0, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1, 0, []byte("AAA")),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1, 0, []byte("AAA")), // retransmit
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 4, tcpFlagFIN, nil),
	}
	jobs := collectStreams(t, CarveConf{Enabled: true, Ports: []int{9100}}, frames)
	if len(jobs) != 1 || string(jobs[0].data) != "AAA" {
		t.Fatalf("got %v, want a single AAA stream", jobs)
	}
}

func TestCarveIgnoresNonPrintPorts(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 80, 1, 0, []byte("GET / HTTP/1.1")),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 80, 15, tcpFlagFIN, nil),
	}
	jobs := collectStreams(t, CarveConf{Enabled: true, Ports: []int{9100}}, frames)
	if len(jobs) != 0 {
		t.Fatalf("got %d jobs, want 0 (port 80 is not a carve port)", len(jobs))
	}
}

func TestCarveFlushEmitsInFlightStream(t *testing.T) {
	// No FIN: the stream must still be emitted on flush (capture-stop teardown).
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 0, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.5", "10.0.0.9", 40000, 9100, 1, 0, []byte("%!PS-Adobe")),
	}
	jobs := collectStreams(t, CarveConf{Enabled: true, Ports: []int{9100}}, frames)
	if len(jobs) != 1 || !bytes.HasPrefix(jobs[0].data, []byte("%!")) {
		t.Fatalf("flush did not emit the in-flight PostScript stream: %v", jobs)
	}
}

func TestUnwrapIPPExtractsDocument(t *testing.T) {
	// Minimal IPP Print-Job body: 8-byte header, operation-attrs group with a
	// document-format value, end-of-attributes tag, then the document.
	pdf := []byte("%PDF-1.7\n...document...")
	var ipp bytes.Buffer
	ipp.Write([]byte{0x02, 0x00}) // version 2.0
	ipp.Write([]byte{0x00, 0x02}) // operation Print-Job
	ipp.Write([]byte{0, 0, 0, 1}) // request-id
	ipp.WriteByte(0x01)           // operation-attributes-tag
	// one attribute: tag(0x49 mimeMediaType) name "document-format" value "application/pdf"
	ipp.WriteByte(0x49)
	name := "document-format"
	binary.Write(&ipp, binary.BigEndian, uint16(len(name)))
	ipp.WriteString(name)
	val := "application/pdf"
	binary.Write(&ipp, binary.BigEndian, uint16(len(val)))
	ipp.WriteString(val)
	ipp.WriteByte(0x03) // end-of-attributes-tag
	ipp.Write(pdf)

	stream := append([]byte("POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\n\r\n"), ipp.Bytes()...)
	doc, fmtHint, ok := unwrapIPP(stream)
	if !ok {
		t.Fatal("expected IPP unwrap to succeed")
	}
	if !bytes.Equal(doc, pdf) {
		t.Fatalf("document = %q, want the PDF bytes", doc)
	}
	if fmtHint != "application/pdf" {
		t.Fatalf("docFormat = %q", fmtHint)
	}
}

func TestDechunk(t *testing.T) {
	body := []byte("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
	if got := dechunk(body); string(got) != "Wikipedia" {
		t.Fatalf("dechunk = %q, want Wikipedia", got)
	}
}
