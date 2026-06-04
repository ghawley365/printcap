package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- test PDU builders ---------------------------------------------------

// putRPCHeader writes the 16-byte common DCERPC header.
func putRPCHeader(ptype byte, flags byte, fragLen uint16, callID uint32) []byte {
	h := make([]byte, 16)
	h[0] = 5 // rpc_vers
	h[1] = 0 // rpc_vers_minor
	h[2] = ptype
	h[3] = flags
	h[4], h[5], h[6], h[7] = 0x10, 0x00, 0x00, 0x00 // packed_drep (LE)
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint16(h[10:12], 0) // auth_length
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

// buildBindPDU constructs a single-fragment BIND with one presentation context
// carrying the given abstract syntax and one transfer syntax.
func buildBindPDU(callID uint32, absUUID, absVer, txUUID, txVer string) []byte {
	body := make([]byte, 0, 64)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], 4280)
	body = append(body, u16[:]...)  // max_xmit_frag
	body = append(body, u16[:]...)  // max_recv_frag
	body = append(body, 0, 0, 0, 0) // assoc_group_id
	// p_context_elem
	body = append(body, 1, 0, 0, 0) // n_context_elem=1, reserved, reserved2
	body = append(body, 0, 0)       // p_cont_id=0
	body = append(body, 1, 0)       // n_transfer_syn=1, reserved
	body = append(body, testUUIDBytes(absUUID)...)
	body = append(body, testVerBytes(absVer)...)
	body = append(body, testUUIDBytes(txUUID)...)
	body = append(body, testVerBytes(txVer)...)
	return append(putRPCHeader(11, 0x03, uint16(16+len(body)), callID), body...)
}

func buildRequestFrag(callID uint32, opnum uint16, stub []byte, first, last bool) []byte {
	var flags byte
	if first {
		flags |= 0x01
	}
	if last {
		flags |= 0x02
	}
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(body[4:6], 0)                 // p_cont_id
	binary.LittleEndian.PutUint16(body[6:8], opnum)             // opnum
	body = append(body, stub...)
	return append(putRPCHeader(0, flags, uint16(16+len(body)), callID), body...)
}

func buildRequestPDU(callID uint32, opnum uint16, stub []byte) []byte {
	return buildRequestFrag(callID, opnum, stub, true, true)
}

// testUUIDBytes mirrors the mixed-endian encoding for the test side.
func testUUIDBytes(s string) []byte { return uuidBytes(s) }

// testVerBytes encodes "major.minor" as uint16 LE major + uint16 LE minor.
func testVerBytes(ver string) []byte {
	maj, min := uint16(1), uint16(0)
	var a, b int
	if n, _ := fmtSscan(ver, &a, &b); n == 2 {
		maj, min = uint16(a), uint16(b)
	}
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:2], maj)
	binary.LittleEndian.PutUint16(out[2:4], min)
	return out
}

// fmtSscan parses "x.y" without pulling fmt into the hot path of the impl file.
func fmtSscan(s string, a, b *int) (int, error) {
	n := 0
	cur := a
	val := 0
	seen := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
			seen = true
		} else if c == '.' {
			if seen {
				*cur = val
				n++
			}
			cur = b
			val = 0
			seen = false
		}
	}
	if seen {
		*cur = val
		n++
	}
	return n, nil
}

// --- tests ---------------------------------------------------------------

func TestDcerpcBindAck(t *testing.T) {
	bind := buildBindPDU(0x1111, mrprnUUID, "1.0", ndrUUID, "2.0")
	d := newDcerpc(nil)
	out := d.onWrite(bind)
	if len(out) < 16 {
		t.Fatal("no BIND_ACK")
	}
	if out[2] != 12 {
		t.Fatalf("PTYPE=%d want 12 (bind_ack)", out[2])
	}
	if binary.LittleEndian.Uint32(out[12:]) != 0x1111 {
		t.Fatal("call_id not echoed")
	}
}

func TestDcerpcRequestDispatch(t *testing.T) {
	disp := func(opnum uint16, stub []byte) ([]byte, bool) {
		r := append([]byte{byte(opnum)}, stub...)
		return r, true
	}
	d := newDcerpc(disp)
	d.onWrite(buildBindPDU(1, mrprnUUID, "1.0", ndrUUID, "2.0"))
	req := buildRequestPDU(7, 17, []byte("STUBDATA"))
	out := d.onWrite(req)
	if out[2] != 2 {
		t.Fatalf("PTYPE=%d want 2 (response)", out[2])
	}
	stub := out[24:]
	if len(stub) == 0 || stub[0] != 17 {
		t.Fatalf("dispatcher opnum not reflected: %v", stub)
	}
	if !bytes.Contains(stub, []byte("STUBDATA")) {
		t.Fatal("stub not passed through")
	}
}

func TestDcerpcFragmentReassembly(t *testing.T) {
	got := []byte{}
	disp := func(opnum uint16, stub []byte) ([]byte, bool) { got = append(got, stub...); return []byte{1}, true }
	d := newDcerpc(disp)
	d.onWrite(buildBindPDU(1, mrprnUUID, "1.0", ndrUUID, "2.0"))
	f1 := buildRequestFrag(9, 19, []byte("AAAA"), true, false)
	f2 := buildRequestFrag(9, 19, []byte("BBBB"), false, true)
	d.onWrite(f1)
	d.onWrite(f2)
	if string(got) != "AAAABBBB" {
		t.Fatalf("reassembled stub=%q", got)
	}
}

func TestDcerpcRejectsGarbage(t *testing.T) {
	d := newDcerpc(nil)
	if out := d.onWrite([]byte("xx")); out != nil && len(out) != 0 {
		t.Fatalf("garbage should yield nil/empty, got %v", out)
	}
}

func TestUUIDBytesMixedEndian(t *testing.T) {
	b := uuidBytes(ndrUUID)
	want := []byte{
		0x04, 0x5d, 0x88, 0x8a, // Data1 LE
		0xeb, 0x1c, // Data2 LE
		0xc9, 0x11, // Data3 LE
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, // Data4 big-endian as-written
	}
	if !bytes.Equal(b, want) {
		t.Fatalf("uuidBytes=%x want %x", b, want)
	}
	if !uuidEqual(b, uuidBytes(ndrUUID)) {
		t.Fatal("uuidEqual mismatch")
	}
	if uuidEqual(uuidBytes(ndrUUID), uuidBytes(mrprnUUID)) {
		t.Fatal("distinct UUIDs compared equal")
	}
}
