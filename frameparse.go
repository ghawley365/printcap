package main

import (
	"encoding/binary"
	"net/netip"
)

// Pure-Go frame dissection for the pcap-carver. We hand-roll the Ethernet/IPv4/
// IPv6/TCP header walk (matching how the rest of printcap hand-rolls wire
// formats) so the carver compiles and unit-tests on any OS — the cgo/Npcap
// dependency stays quarantined in the live-source files. Only the fields the
// reassembler needs are lifted out; everything else in the headers is ignored.

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100 // 802.1Q
	etherTypeQinQ = 0x88a8 // 802.1ad (stacked VLAN)

	ipProtoTCP = 6

	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
)

// l4Segment is one TCP segment lifted out of a captured frame: the flow identity,
// sequence number, the control flags the reassembler cares about, and the TCP
// payload. The payload aliases the input frame; callers that retain it across
// frames must copy (the reassembler does).
type l4Segment struct {
	src, dst netip.AddrPort
	seq      uint32
	syn      bool
	fin      bool
	rst      bool
	payload  []byte
}

// parseTCPSegment dissects one captured frame. linkType selects the L2 framing:
// linkTypeEthernet expects a 14-byte Ethernet header (with optional one/two
// 802.1Q VLAN tags); linkTypeRaw expects the IP header at offset 0. Returns
// ok=false for anything that is not IPv4/IPv6-over-TCP, or that is truncated.
// stepToL3 walks the link-layer header for linkType and returns the ethertype of
// the network-layer payload plus the slice beginning at the L3 (IP) header. It
// handles raw-IP framing (no L2 header) and Ethernet with up to two stacked
// 802.1Q VLAN tags. Shared by parseTCPSegment (the carver) and the pcap viewer.
func stepToL3(linkType int, frame []byte) (ethertype uint16, l3 []byte, ok bool) {
	switch linkType {
	case linkTypeRaw:
		// No L2 header; decide v4 vs v6 from the IP version nibble.
		if len(frame) < 1 {
			return 0, nil, false
		}
		switch frame[0] >> 4 {
		case 4:
			return etherTypeIPv4, frame, true
		case 6:
			return etherTypeIPv6, frame, true
		default:
			return 0, nil, false
		}
	case linkTypeNull:
		// BSD loopback (DLT_NULL): a 4-byte address-family header, then the IP
		// packet. The family is host-endian; we just sniff the IP version nibble.
		if len(frame) < 5 {
			return 0, nil, false
		}
		ip := frame[4:]
		switch ip[0] >> 4 {
		case 4:
			return etherTypeIPv4, ip, true
		case 6:
			return etherTypeIPv6, ip, true
		default:
			return 0, nil, false
		}
	default: // linkTypeEthernet (and 0, which defaults to Ethernet)
		if len(frame) < 14 {
			return 0, nil, false
		}
		ethertype = binary.BigEndian.Uint16(frame[12:14])
		off := 14
		// Step over up to two stacked VLAN tags.
		for i := 0; i < 2 && (ethertype == etherTypeVLAN || ethertype == etherTypeQinQ); i++ {
			if len(frame) < off+4 {
				return 0, nil, false
			}
			ethertype = binary.BigEndian.Uint16(frame[off+2 : off+4])
			off += 4
		}
		return ethertype, frame[off:], true
	}
}

func parseTCPSegment(linkType int, frame []byte) (seg l4Segment, ok bool) {
	ethertype, l3, ok := stepToL3(linkType, frame)
	if !ok {
		return l4Segment{}, false
	}

	var srcIP, dstIP netip.Addr
	var l4 []byte

	switch ethertype {
	case etherTypeIPv4:
		ip := l3
		if len(ip) < 20 {
			return l4Segment{}, false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return l4Segment{}, false
		}
		if ip[9] != ipProtoTCP {
			return l4Segment{}, false
		}
		// Honor the IP total-length field so trailing padding isn't carved in.
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if total >= ihl && total <= len(ip) {
			ip = ip[:total]
		}
		srcIP = netip.AddrFrom4([4]byte{ip[12], ip[13], ip[14], ip[15]})
		dstIP = netip.AddrFrom4([4]byte{ip[16], ip[17], ip[18], ip[19]})
		l4 = ip[ihl:]

	case etherTypeIPv6:
		ip := l3
		if len(ip) < 40 {
			return l4Segment{}, false
		}
		// Only bare TCP (no extension-header chain) is carved; uncommon for print.
		if ip[6] != ipProtoTCP {
			return l4Segment{}, false
		}
		payLen := int(binary.BigEndian.Uint16(ip[4:6]))
		end := 40 + payLen
		if payLen == 0 || end > len(ip) {
			end = len(ip)
		}
		var s, d [16]byte
		copy(s[:], ip[8:24])
		copy(d[:], ip[24:40])
		srcIP = netip.AddrFrom16(s)
		dstIP = netip.AddrFrom16(d)
		l4 = ip[40:end]

	default:
		return l4Segment{}, false
	}

	if len(l4) < 20 {
		return l4Segment{}, false
	}
	thl := int(l4[12]>>4) * 4
	if thl < 20 || len(l4) < thl {
		return l4Segment{}, false
	}
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])
	flags := l4[13]

	seg = l4Segment{
		src:     netip.AddrPortFrom(srcIP, srcPort),
		dst:     netip.AddrPortFrom(dstIP, dstPort),
		seq:     binary.BigEndian.Uint32(l4[4:8]),
		syn:     flags&tcpFlagSYN != 0,
		fin:     flags&tcpFlagFIN != 0,
		rst:     flags&tcpFlagRST != 0,
		payload: l4[thl:],
	}
	return seg, true
}
