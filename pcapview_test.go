package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ethIPv4Proto builds an Ethernet/IPv4 frame with an arbitrary L4 protocol and
// raw payload (used to synthesize ICMP packets for the viewer tests).
func ethIPv4Proto(src, dst string, proto byte, payload []byte) []byte {
	sip := netip.MustParseAddr(src).As4()
	dip := netip.MustParseAddr(dst).As4()
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload)))
	ip[9] = proto
	copy(ip[12:16], sip[:])
	copy(ip[16:20], dip[:])
	ip = append(ip, payload...)
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], etherTypeIPv4)
	return append(eth, ip...)
}

func writeFileHelper(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

// writeTestPcap writes a small libpcap file (our LE/microsecond format) with the
// given Ethernet frames and returns its path.
func writeTestPcap(t *testing.T, frames [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	pw, err := newPcapFile(path, 0, linkTypeEthernet)
	if err != nil {
		t.Fatalf("newPcapFile: %v", err)
	}
	ts := time.Unix(1717459200, 0)
	for i, f := range frames {
		if err := pw.writePacket(ts.Add(time.Duration(i)*time.Millisecond), f); err != nil {
			t.Fatalf("writePacket: %v", err)
		}
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

func TestReadPcapRoundTrip(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.2", 1111, 9100, 1, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.1", "10.0.0.2", 1111, 9100, 2, 0, []byte("hello")),
	}
	path := writeTestPcap(t, frames)
	d, err := readPcap(path, 0)
	if err != nil {
		t.Fatalf("readPcap: %v", err)
	}
	if d.linkType != linkTypeEthernet {
		t.Fatalf("linkType=%d", d.linkType)
	}
	if len(d.packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(d.packets))
	}
}

func TestReadPcapRejectsBadMagic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := writeFileHelper(path, []byte("not a pcap file at all............")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPcap(path, 0); err == nil {
		t.Fatal("expected error on bad magic")
	}
}

func TestDissectClassifiesResetAndSyn(t *testing.T) {
	rst := ethIPv4TCP("10.0.0.9", "10.0.0.1", 9100, 50000, 5, tcpFlagRST|tcpFlagACK, nil)
	s := dissectSummary(linkTypeEthernet, rst)
	if s.Class != "reset" {
		t.Fatalf("RST class=%q, want reset; info=%q", s.Class, s.Info)
	}
	if s.Proto != "TCP" {
		t.Fatalf("proto=%q", s.Proto)
	}

	syn := ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 9100, 1, tcpFlagSYN, nil)
	if c := dissectSummary(linkTypeEthernet, syn).Class; c != "syn" {
		t.Fatalf("SYN class=%q, want syn", c)
	}

	data := ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 9100, 2, tcpFlagACK|tcpFlagPSH, []byte("PCL"))
	if c := dissectSummary(linkTypeEthernet, data).Class; c != "data" {
		t.Fatalf("data class=%q, want data", c)
	}
}

func TestDissectICMPError(t *testing.T) {
	// IPv4 ICMP destination-unreachable (type 3).
	icmp := ethIPv4Proto("10.0.0.2", "10.0.0.1", ipProtoICMP, []byte{3, 1, 0, 0})
	s := dissectSummary(linkTypeEthernet, icmp)
	if s.Class != "error" {
		t.Fatalf("ICMP class=%q, want error; info=%q", s.Class, s.Info)
	}
	if s.Proto != "ICMP" {
		t.Fatalf("proto=%q", s.Proto)
	}
}

func TestPacketColor(t *testing.T) {
	cases := []struct{ class, svc, want string }{
		{"reset", "raw", "red"}, {"error", "", "red"},
		{"data", "raw", "green"}, {"data", "ipp", "green"}, {"syn", "snmp", "green"},
		{"data", "https", "blue"},
		{"data", "http", ""}, {"other", "", ""},
	}
	for _, c := range cases {
		if got := packetColor(c.class, c.svc); got != c.want {
			t.Errorf("packetColor(%q,%q)=%q want %q", c.class, c.svc, got, c.want)
		}
	}
}

func TestDissectAssignsColor(t *testing.T) {
	// 443 -> blue
	if s := dissectSummary(linkTypeEthernet, ethIPv4TCP("10.0.0.1", "10.0.0.2", 5000, 443, 1, tcpFlagACK, []byte("x"))); s.Color != "blue" {
		t.Fatalf("443 color=%q want blue", s.Color)
	}
	// 9100 data -> green
	if s := dissectSummary(linkTypeEthernet, ethIPv4TCP("10.0.0.1", "10.0.0.2", 5000, 9100, 1, tcpFlagACK, []byte("x"))); s.Color != "green" {
		t.Fatalf("9100 color=%q want green", s.Color)
	}
	// RST on a print port -> red (reset beats service)
	if s := dissectSummary(linkTypeEthernet, ethIPv4TCP("10.0.0.2", "10.0.0.1", 9100, 5000, 1, tcpFlagRST, nil)); s.Color != "red" {
		t.Fatalf("rst color=%q want red", s.Color)
	}
}

func TestCarveAllPorts(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 40000, 12345, 1, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 40000, 12345, 2, 0, []byte("ARBITRARY")),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 40000, 12345, 11, tcpFlagFIN, nil),
	}
	ts := time.Unix(1, 0)
	// AllPorts: an unlisted port (12345) IS carved.
	var got []*job
	cv := newCarver(CarveConf{Enabled: true, AllPorts: true}, linkTypeEthernet, func(j *job) { got = append(got, j) })
	for _, f := range frames {
		cv.consume(f, ts)
	}
	cv.flush()
	if len(got) != 1 || string(got[0].data) != "ARBITRARY" {
		t.Fatalf("all-ports carve = %v", got)
	}
	// Targeted: the same unlisted port is NOT carved.
	var got2 []*job
	cv2 := newCarver(CarveConf{Enabled: true, Ports: []int{9100}}, linkTypeEthernet, func(j *job) { got2 = append(got2, j) })
	for _, f := range frames {
		cv2.consume(f, ts)
	}
	cv2.flush()
	if len(got2) != 0 {
		t.Fatalf("targeted carve should skip unlisted port, got %d", len(got2))
	}
}

func TestCaptureFilterByHost(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 5000, 9100, 1, tcpFlagACK, []byte("to-mfp")),
		ethIPv4TCP("10.0.0.9", "10.0.0.1", 9100, 5000, 1, tcpFlagACK, []byte("from-mfp")),
		ethIPv4TCP("10.0.0.2", "10.0.0.3", 5000, 9100, 1, tcpFlagACK, []byte("unrelated")),
	}
	path := writeTestPcap(t, frames)
	// host=10.0.0.9 (the MFP) matches the two packets to/from it, not the third.
	r, _ := capturePackets(path, captureFilter{host: "10.0.0.9", limit: 100})
	if r.Matched != 2 {
		t.Fatalf("host filter matched=%d, want 2", r.Matched)
	}
}

func TestFrameIsIPv6(t *testing.T) {
	eth := make([]byte, 54)
	eth[12], eth[13] = 0x86, 0xdd // IPv6 ethertype
	if !frameIsIPv6(linkTypeEthernet, eth) {
		t.Fatal("IPv6 frame not detected")
	}
	if frameIsIPv6(linkTypeEthernet, ethIPv4TCP("10.0.0.1", "10.0.0.2", 1, 2, 1, tcpFlagACK, nil)) {
		t.Fatal("IPv4 frame misdetected as IPv6")
	}
}

func TestFollowStreamReassemblesBothDirections(t *testing.T) {
	// A two-way conversation: client 10.0.0.1:5000 <-> server 10.0.0.9:9100.
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 5000, 9100, 100, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.9", "10.0.0.1", 9100, 5000, 200, tcpFlagSYN|tcpFlagACK, nil),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 5000, 9100, 101, tcpFlagACK, []byte("REQUEST-BYTES")),
		ethIPv4TCP("10.0.0.9", "10.0.0.1", 9100, 5000, 201, tcpFlagACK, []byte("RESPONSE-BYTES")),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 5000, 9100, 114, tcpFlagFIN, nil),
	}
	path := writeTestPcap(t, frames)
	a := netip.MustParseAddrPort("10.0.0.1:5000")
	b := netip.MustParseAddrPort("10.0.0.9:9100")
	ab, ba, parsed, err := followStream(path, a, b)
	if err != nil {
		t.Fatalf("followStream: %v", err)
	}
	if parsed != len(frames) {
		t.Fatalf("parsed=%d want %d", parsed, len(frames))
	}
	if string(ab) != "REQUEST-BYTES" {
		t.Fatalf("a->b = %q, want REQUEST-BYTES", ab)
	}
	if string(ba) != "RESPONSE-BYTES" {
		t.Fatalf("b->a = %q, want RESPONSE-BYTES", ba)
	}
}

func TestCapturePacketsFilters(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 9100, 1, tcpFlagSYN, nil),
		ethIPv4TCP("10.0.0.1", "10.0.0.9", 50000, 9100, 2, tcpFlagACK, []byte("data")),
		ethIPv4TCP("10.0.0.9", "10.0.0.1", 9100, 50000, 9, tcpFlagRST, nil),
	}
	path := writeTestPcap(t, frames)

	all, err := capturePackets(path, captureFilter{limit: 100})
	if err != nil {
		t.Fatalf("capturePackets: %v", err)
	}
	if all.Matched != 3 || all.TotalParsed != 3 {
		t.Fatalf("matched=%d parsed=%d, want 3/3", all.Matched, all.TotalParsed)
	}

	resets, _ := capturePackets(path, captureFilter{class: "reset", limit: 100})
	if resets.Matched != 1 || resets.Packets[0].Class != "reset" {
		t.Fatalf("reset filter matched=%d", resets.Matched)
	}

	byIP, _ := capturePackets(path, captureFilter{q: "9100", limit: 100})
	if byIP.Matched != 3 {
		t.Fatalf("port filter matched=%d, want 3", byIP.Matched)
	}
}
