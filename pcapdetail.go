package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// pcapdetail.go produces a Wireshark-style per-packet decode: a one-line summary,
// a list of protocol layers (Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP) each with named
// fields, and a hex+ASCII dump. It powers the "packet details" popup in both the
// web viewer and the native capture window, and reuses the same hand-rolled
// header parsing as the carver/summary so it builds and unit-tests on any OS.

type packetField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type packetLayer struct {
	Name   string        `json:"name"`
	Fields []packetField `json:"fields"`
}

type packetDetail struct {
	No      int           `json:"no"`
	Len     int           `json:"len"`
	Summary string        `json:"summary"`
	Layers  []packetLayer `json:"layers"`
	Hex     string        `json:"hex"`
}

func fld(name, format string, a ...interface{}) packetField {
	return packetField{Name: name, Value: fmt.Sprintf(format, a...)}
}

func (d *packetDetail) add(name string, fields ...packetField) {
	d.Layers = append(d.Layers, packetLayer{Name: name, Fields: fields})
}

// dissectDetail decodes one frame into layers + a hex dump.
func dissectDetail(linkType int, frame []byte) packetDetail {
	d := packetDetail{Len: len(frame), Hex: hexDump(frame)}
	s := dissectSummary(linkType, frame)
	d.Summary = strings.TrimSpace(s.Proto + "  " + s.Src + " → " + s.Dst + "   " + s.Info)

	ethertype, l3 := d.decodeL2(linkType, frame)
	if l3 == nil {
		return d
	}
	switch ethertype {
	case etherTypeARP:
		d.decodeARP(l3)
	case etherTypeIPv4:
		proto, l4 := d.decodeIPv4(l3)
		d.decodeL4(proto, l4)
	case etherTypeIPv6:
		proto, l4 := d.decodeIPv6(l3)
		d.decodeL4(proto, l4)
	}
	return d
}

func (d *packetDetail) decodeL2(linkType int, frame []byte) (uint16, []byte) {
	et, l3, ok := stepToL3(linkType, frame)
	if !ok {
		if linkType == linkTypeEthernet && len(frame) >= 14 {
			d.add("Ethernet II",
				fld("Destination", "%s", net.HardwareAddr(frame[0:6])),
				fld("Source", "%s", net.HardwareAddr(frame[6:12])),
				fld("EtherType", "0x%04x", binary.BigEndian.Uint16(frame[12:14])))
		} else {
			d.add("Link layer", fld("Link type", "%d", linkType), fld("Note", "unparsed or truncated frame"))
		}
		return 0, nil
	}
	switch linkType {
	case linkTypeRaw:
		d.add("Raw IP", fld("Link type", "raw — no L2 header"))
	case linkTypeNull:
		d.add("Loopback (DLT_NULL)", fld("Address family", "0x%08x", binary.LittleEndian.Uint32(frame[0:4])))
	default:
		onWire := binary.BigEndian.Uint16(frame[12:14])
		d.add("Ethernet II",
			fld("Destination", "%s", net.HardwareAddr(frame[0:6])),
			fld("Source", "%s", net.HardwareAddr(frame[6:12])),
			fld("EtherType", "0x%04x (%s)", onWire, etherTypeName(onWire)))
	}
	return et, l3
}

func (d *packetDetail) decodeIPv4(ip []byte) (byte, []byte) {
	if len(ip) < 20 {
		d.add("Internet Protocol v4", fld("Note", "truncated header"))
		return 0, nil
	}
	ihl := int(ip[0]&0x0f) * 4
	proto := ip[9]
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	src := netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
	dst := netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
	d.add("Internet Protocol v4",
		fld("Version", "4"),
		fld("Header length", "%d bytes", ihl),
		fld("Total length", "%d", total),
		fld("TTL", "%d", ip[8]),
		fld("Protocol", "%d (%s)", proto, ipProtoName(proto)),
		fld("Flags", "0x%02x%s", ip[6]>>5, ipv4FlagStr(ip[6])),
		fld("Source", "%s", src),
		fld("Destination", "%s", dst))
	if ihl < 20 || ihl > len(ip) {
		return proto, nil
	}
	end := len(ip)
	if total >= ihl && total <= len(ip) {
		end = total
	}
	return proto, ip[ihl:end]
}

func (d *packetDetail) decodeIPv6(ip []byte) (byte, []byte) {
	if len(ip) < 40 {
		d.add("Internet Protocol v6", fld("Note", "truncated header"))
		return 0, nil
	}
	next := ip[6]
	payLen := int(binary.BigEndian.Uint16(ip[4:6]))
	var s, dd [16]byte
	copy(s[:], ip[8:24])
	copy(dd[:], ip[24:40])
	d.add("Internet Protocol v6",
		fld("Version", "6"),
		fld("Payload length", "%d", payLen),
		fld("Next header", "%d (%s)", next, ipProtoName(next)),
		fld("Hop limit", "%d", ip[7]),
		fld("Source", "%s", netip.AddrFrom16(s)),
		fld("Destination", "%s", netip.AddrFrom16(dd)))
	end := 40 + payLen
	if payLen == 0 || end > len(ip) {
		end = len(ip)
	}
	return next, ip[40:end]
}

func (d *packetDetail) decodeL4(proto byte, l4 []byte) {
	switch proto {
	case ipProtoTCP:
		if len(l4) < 20 {
			d.add("Transmission Control Protocol", fld("Note", "truncated header"))
			return
		}
		thl := int(l4[12]>>4) * 4
		flags := l4[13]
		d.add("Transmission Control Protocol",
			fld("Source port", "%d", binary.BigEndian.Uint16(l4[0:2])),
			fld("Destination port", "%d", binary.BigEndian.Uint16(l4[2:4])),
			fld("Sequence", "%d", binary.BigEndian.Uint32(l4[4:8])),
			fld("Acknowledgment", "%d", binary.BigEndian.Uint32(l4[8:12])),
			fld("Header length", "%d bytes", thl),
			fld("Flags", "%s (0x%02x)", tcpFlagString(flags), flags),
			fld("Window", "%d", binary.BigEndian.Uint16(l4[14:16])))
		if thl >= 20 && thl <= len(l4) && len(l4) > thl {
			d.add("Payload", fld("Length", "%d bytes", len(l4)-thl))
		}
	case ipProtoUDP:
		if len(l4) < 8 {
			d.add("User Datagram Protocol", fld("Note", "truncated header"))
			return
		}
		d.add("User Datagram Protocol",
			fld("Source port", "%d", binary.BigEndian.Uint16(l4[0:2])),
			fld("Destination port", "%d", binary.BigEndian.Uint16(l4[2:4])),
			fld("Length", "%d", binary.BigEndian.Uint16(l4[4:6])))
	case ipProtoICMP, ipProtoICMPv6:
		name := "Internet Control Message Protocol"
		if proto == ipProtoICMPv6 {
			name = "ICMPv6"
		}
		if len(l4) < 2 {
			d.add(name, fld("Note", "truncated"))
			return
		}
		d.add(name, fld("Type", "%d", l4[0]), fld("Code", "%d", l4[1]))
	}
}

func (d *packetDetail) decodeARP(b []byte) {
	if len(b) < 28 {
		d.add("Address Resolution Protocol", fld("Note", "truncated"))
		return
	}
	op := binary.BigEndian.Uint16(b[6:8])
	d.add("Address Resolution Protocol",
		fld("Opcode", "%d (%s)", op, arpOpName(op)),
		fld("Sender MAC", "%s", net.HardwareAddr(b[8:14])),
		fld("Sender IP", "%s", netip.AddrFrom4([4]byte{b[14], b[15], b[16], b[17]})),
		fld("Target MAC", "%s", net.HardwareAddr(b[18:24])),
		fld("Target IP", "%s", netip.AddrFrom4([4]byte{b[24], b[25], b[26], b[27]})))
}

func etherTypeName(et uint16) string {
	switch et {
	case etherTypeIPv4:
		return "IPv4"
	case etherTypeIPv6:
		return "IPv6"
	case etherTypeARP:
		return "ARP"
	case etherTypeVLAN:
		return "802.1Q VLAN"
	case etherTypeQinQ:
		return "802.1ad QinQ"
	}
	return "unknown"
}

func ipProtoName(p byte) string {
	switch p {
	case ipProtoICMP:
		return "ICMP"
	case ipProtoTCP:
		return "TCP"
	case ipProtoUDP:
		return "UDP"
	case ipProtoICMPv6:
		return "ICMPv6"
	}
	return "other"
}

func arpOpName(op uint16) string {
	switch op {
	case 1:
		return "request"
	case 2:
		return "reply"
	}
	return "?"
}

func ipv4FlagStr(b byte) string {
	s := ""
	if b&0x40 != 0 {
		s += " DF"
	}
	if b&0x20 != 0 {
		s += " MF"
	}
	return s
}

// hexDump renders bytes as an offset / hex / ASCII dump (16 bytes per line).
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		fmt.Fprintf(&sb, "%04x  ", i)
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&sb, "%02x ", b[j])
			} else {
				sb.WriteString("   ")
			}
			if j == i+7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" ")
		for j := i; j < end; j++ {
			c := b[j]
			if c < 0x20 || c > 0x7e {
				c = '.'
			}
			sb.WriteByte(c)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

// detailText renders a packetDetail as plain monospace text for the native GUI's
// detail dialog (the web renders the structured JSON instead).
func detailText(d packetDetail) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Packet #%d   %d bytes\n%s\n\n", d.No, d.Len, d.Summary)
	for _, l := range d.Layers {
		sb.WriteString(l.Name + "\n")
		for _, f := range l.Fields {
			fmt.Fprintf(&sb, "    %-18s %s\n", f.Name+":", f.Value)
		}
		sb.WriteByte('\n')
	}
	sb.WriteString("Hex dump:\n")
	sb.WriteString(d.Hex)
	return sb.String()
}
