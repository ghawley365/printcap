package main

import (
	"encoding/binary"
	"net"
	"strings"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypePTR  uint16 = 12
	dnsTypeTXT  uint16 = 16
	dnsTypeAAAA uint16 = 28
	dnsTypeSRV  uint16 = 33
	dnsTypeANY  uint16 = 255

	dnsClassIN   uint16 = 1
	dnsFlushBit  uint16 = 0x8000
	dnsClassMask uint16 = 0x7fff
)

// encodeName encodes a dotted DNS name as length-prefixed labels terminated by
// a zero byte. No compression (mDNS permits uncompressed responses).
func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	var out []byte
	if name == "" {
		return []byte{0}
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// parseName decodes a DNS name starting at off, following compression pointers.
func parseName(b []byte, off int) (name string, next int, ok bool) {
	var labels []string
	jumped := false
	next = -1
	safety := 0
	for {
		if off < 0 || off >= len(b) {
			return "", 0, false
		}
		safety++
		if safety > 128 {
			return "", 0, false
		}
		l := int(b[off])
		if l == 0 {
			off++
			if !jumped {
				next = off
			}
			return strings.Join(labels, "."), next, true
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(b) {
				return "", 0, false
			}
			ptr := (l&0x3F)<<8 | int(b[off+1])
			if !jumped {
				next = off + 2
			}
			jumped = true
			off = ptr
			continue
		}
		if off+1+l > len(b) {
			return "", 0, false
		}
		labels = append(labels, string(b[off+1:off+1+l]))
		off += 1 + l
	}
}

func rdataPTR(target string) []byte { return encodeName(target) }

func rdataSRV(priority, weight, port uint16, target string) []byte {
	out := make([]byte, 6)
	binary.BigEndian.PutUint16(out[0:], priority)
	binary.BigEndian.PutUint16(out[2:], weight)
	binary.BigEndian.PutUint16(out[4:], port)
	return append(out, encodeName(target)...)
}

// rdataTXT encodes each "key=value" string as a length-prefixed character-string
// (truncated to 255 bytes per DNS-SD). An empty set encodes as a single 0 byte.
func rdataTXT(pairs []string) []byte {
	if len(pairs) == 0 {
		return []byte{0}
	}
	var out []byte
	for _, p := range pairs {
		if len(p) > 255 {
			p = p[:255]
		}
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return out
}

func rdataA(ip net.IP) []byte    { return append([]byte{}, ip.To4()...) }
func rdataAAAA(ip net.IP) []byte { return append([]byte{}, ip.To16()...) }

type dnsQuestion struct {
	name    string
	qtype   uint16
	unicast bool
}

type dnsRecord struct {
	name  string
	rtype uint16
	ttl   uint32
	data  []byte
	flush bool
}

// TTLs (RFC 6762 §10). Declared here so dnsmsg tests compile independently;
// mdns.go references the same identifiers.
const (
	ttlDNSSD uint32 = 4500
	ttlHost  uint32 = 120
)

// parseQuestions parses the question section of a DNS message.
func parseQuestions(b []byte) ([]dnsQuestion, bool) {
	if len(b) < 12 {
		return nil, false
	}
	qd := int(binary.BigEndian.Uint16(b[4:]))
	off := 12
	var out []dnsQuestion
	for i := 0; i < qd; i++ {
		name, next, ok := parseName(b, off)
		if !ok {
			return nil, false
		}
		off = next
		if off+4 > len(b) {
			return nil, false
		}
		qtype := binary.BigEndian.Uint16(b[off:])
		qclass := binary.BigEndian.Uint16(b[off+2:])
		off += 4
		out = append(out, dnsQuestion{
			name:    name,
			qtype:   qtype,
			unicast: qclass&dnsFlushBit != 0,
		})
	}
	return out, true
}

// buildResponse assembles an mDNS response message carrying the given answer
// records. QR + Authoritative are set (0x8400); query ID is 0 per RFC 6762.
func buildResponse(answers []dnsRecord) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[2:], 0x8400)
	binary.BigEndian.PutUint16(hdr[6:], uint16(len(answers)))
	out := hdr
	for _, r := range answers {
		out = append(out, encodeRR(r)...)
	}
	return out
}

func encodeRR(r dnsRecord) []byte {
	out := encodeName(r.name)
	tc := make([]byte, 8)
	binary.BigEndian.PutUint16(tc[0:], r.rtype)
	class := dnsClassIN
	if r.flush {
		class |= dnsFlushBit
	}
	binary.BigEndian.PutUint16(tc[2:], class)
	binary.BigEndian.PutUint32(tc[4:], r.ttl)
	out = append(out, tc...)
	rl := make([]byte, 2)
	binary.BigEndian.PutUint16(rl, uint16(len(r.data)))
	out = append(out, rl...)
	return append(out, r.data...)
}
