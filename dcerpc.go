package main

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// DCERPC connection-oriented (CO) transport over the \spoolss named pipe.
//
// This implements the minimal subset of the DCE/RPC 1.1 connection-oriented
// protocol ([C706] chapter 12, [MS-RPCE] §2.2) needed to accept a BIND for the
// MS-RPRN (spoolss) interface, dispatch REQUEST PDUs to a higher-level handler,
// and return RESPONSE/FAULT PDUs. Fragmented requests are reassembled across
// PFC_FIRST_FRAG .. PFC_LAST_FRAG. All parsing is bounds-checked against hostile
// input; malformed PDUs yield nil (never a panic).

// Well-known interface UUIDs (string form, RFC 4122 textual layout).
const (
	// mrprnUUID is the MS-RPRN (Print System Remote Protocol) abstract syntax.
	mrprnUUID = "12345678-1234-abcd-ef00-0123456789ab"
	// ndrUUID is the NDR (Network Data Representation) transfer syntax, v2.0.
	ndrUUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"
)

// DCERPC CO PDU types ([C706] §12.1.2.1).
const (
	rpcPTRequest  = 0
	rpcPTResponse = 2
	rpcPTFault    = 3
	rpcPTBind     = 11
	rpcPTBindAck  = 12
	rpcPTBindNak  = 13
)

// PFC (protocol control) flags ([C706] §12.1.2.2).
const (
	rpcPFCFirstFrag  = 0x01
	rpcPFCLastFrag   = 0x02
	rpcPFCObjectUUID = 0x80
)

// reasmMax caps the reassembly buffer so a stream of FIRST/middle fragments
// without a LAST fragment cannot exhaust memory.
const reasmMax = 4 << 20 // 4 MiB

// rpcStatusProtocolError is the nca_proto_error fault code returned when no
// dispatcher can service a request ([MS-RPCE] §3.1.1.5.5 / nca status codes).
const rpcStatusProtocolError uint32 = 0x1c01000b

// rpcDispatcher services a fully reassembled request stub for a given opnum and
// returns the response stub. ok=false produces a FAULT PDU. Stage 4.3 (spoolss)
// supplies a real dispatcher.
type rpcDispatcher func(opnum uint16, stub []byte) (respStub []byte, ok bool)

// dcerpc is a per-pipe DCERPC connection-oriented backend implementing
// pipeBackend. It is not safe for concurrent use; the named-pipe layer drives a
// single handle sequentially.
type dcerpc struct {
	disp        rpcDispatcher
	bound       bool
	reasm       []byte // accumulated request stub across fragments
	reasmActive bool   // a FIRST fragment has opened a reassembly
	reasmCallID uint32
	reasmOpnum  uint16
	reasmCont   uint16
}

// newDcerpc creates a DCERPC backend dispatching requests to disp (may be nil).
func newDcerpc(disp rpcDispatcher) *dcerpc { return &dcerpc{disp: disp} }

// spoolssDispatcher builds the spoolss request dispatcher for a session. It is a
// package var so Stage 4.3 can replace it; the placeholder returns nil (BIND
// still succeeds; REQUESTs fault).
var spoolssDispatcher = func(s *smbSession) rpcDispatcher { return nil }

func init() {
	newSpoolssBackend = func(s *smbSession) pipeBackend { return newDcerpc(spoolssDispatcher(s)) }
}

// onWrite consumes one client-written DCERPC PDU and returns the response PDU
// bytes (or nil if none is due yet, e.g. a non-final fragment, or on garbage).
func (d *dcerpc) onWrite(p []byte) []byte {
	ptype, flags, callID, body, ok := parseRPCHeader(p)
	if !ok {
		return nil
	}
	switch ptype {
	case rpcPTBind:
		return d.handleBind(callID, body)
	case rpcPTRequest:
		return d.handleRequest(flags, callID, body)
	default:
		// Unsupported PDU type: ignore rather than fault, to stay lenient for
		// capture peers (e.g. ALTER_CONTEXT, AUTH3). Never panic.
		return nil
	}
}

// parseRPCHeader validates and decodes the 16-byte common header, returning the
// PDU body. frag_length is used to bound the body but len(p) is the hard limit.
func parseRPCHeader(p []byte) (ptype, flags byte, callID uint32, body []byte, ok bool) {
	if len(p) < 16 {
		return 0, 0, 0, nil, false
	}
	if p[0] != 5 { // rpc_vers
		return 0, 0, 0, nil, false
	}
	ptype = p[2]
	flags = p[3]
	fragLen := int(binary.LittleEndian.Uint16(p[8:10]))
	callID = binary.LittleEndian.Uint32(p[12:16])

	end := len(p)
	if fragLen >= 16 && fragLen <= len(p) {
		end = fragLen
	}
	return ptype, flags, callID, p[16:end], true
}

// handleBind parses the BIND body far enough to learn the requested abstract
// syntax, then returns a BIND_ACK accepting it with the NDR transfer syntax. A
// malformed body returns nil (no ack); we are lenient about the abstract syntax
// identity (any interface is accepted for capture purposes).
func (d *dcerpc) handleBind(callID uint32, body []byte) []byte {
	// BIND body: max_xmit_frag(2), max_recv_frag(2), assoc_group_id(4),
	// then p_context_elem. We only need the negotiated frag sizes; the context
	// list is parsed defensively but its contents are not required to ACK.
	if len(body) < 8 {
		return nil
	}
	maxXmit := binary.LittleEndian.Uint16(body[0:2])
	maxRecv := binary.LittleEndian.Uint16(body[2:4])
	if maxXmit == 0 {
		maxXmit = 4280
	}
	if maxRecv == 0 {
		maxRecv = 4280
	}
	d.bound = true
	return buildRPCBindAck(callID, maxXmit, maxRecv)
}

// handleRequest parses a REQUEST body, performs fragment reassembly, and on the
// final fragment dispatches the full stub and returns a RESPONSE (or FAULT).
func (d *dcerpc) handleRequest(flags byte, callID uint32, body []byte) []byte {
	// REQUEST body: alloc_hint(4), p_cont_id(2), opnum(2),
	// [object UUID(16) iff PFC_OBJECT_UUID], stub_data.
	if len(body) < 8 {
		return nil
	}
	contID := binary.LittleEndian.Uint16(body[4:6])
	opnum := binary.LittleEndian.Uint16(body[6:8])
	off := 8
	if flags&rpcPFCObjectUUID != 0 {
		if len(body) < off+16 {
			return nil
		}
		off += 16
	}
	stub := body[off:]

	first := flags&rpcPFCFirstFrag != 0
	last := flags&rpcPFCLastFrag != 0

	if first {
		// A new logical request begins; drop any stale partial.
		d.reasm = append(d.reasm[:0], stub...)
		d.reasmActive = true
		d.reasmCallID = callID
		d.reasmOpnum = opnum
		d.reasmCont = contID
	} else {
		if !d.reasmActive {
			// Continuation without a FIRST: ignore defensively.
			return nil
		}
		if len(d.reasm)+len(stub) > reasmMax {
			// Refuse unbounded growth; abandon and fault.
			d.resetReasm()
			return buildFault(callID, contID, rpcStatusProtocolError)
		}
		d.reasm = append(d.reasm, stub...)
	}

	if !last {
		return nil // await further fragments
	}

	fullStub := d.reasm
	rCallID := d.reasmCallID
	rOpnum := d.reasmOpnum
	rCont := d.reasmCont
	d.resetReasm()

	if d.disp == nil {
		return buildFault(rCallID, rCont, rpcStatusProtocolError)
	}
	respStub, ok := d.disp(rOpnum, fullStub)
	if !ok {
		return buildFault(rCallID, rCont, rpcStatusProtocolError)
	}
	return buildRPCResponse(rCallID, rCont, respStub)
}

func (d *dcerpc) resetReasm() {
	d.reasm = d.reasm[:0]
	d.reasmActive = false
	d.reasmCallID = 0
	d.reasmOpnum = 0
	d.reasmCont = 0
}

// --- PDU assembly --------------------------------------------------------

// buildRPCHeader builds the 16-byte common CO header with a little-endian data
// representation and auth_length=0.
func buildRPCHeader(ptype byte, flags byte, fragLen uint16, callID uint32) []byte {
	h := make([]byte, 16)
	h[0] = 5 // rpc_vers
	h[1] = 0 // rpc_vers_minor
	h[2] = ptype
	h[3] = flags
	// packed_drep: little-endian, ASCII, IEEE float.
	h[4], h[5], h[6], h[7] = 0x10, 0x00, 0x00, 0x00
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint16(h[10:12], 0) // auth_length
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

// secAddr is the spoolss secondary address advertised in BIND_ACK.
const secAddr = "\\PIPE\\spoolss"

// buildBindAck assembles a BIND_ACK accepting one presentation context with the
// NDR transfer syntax. Layout ([C706] §12.6.4.4):
//
//	max_xmit_frag(2), max_recv_frag(2), assoc_group_id(4),
//	sec_addr: length(2) + ASCII string + NUL (length counts the NUL),
//	pad to 4-octet alignment from PDU start,
//	p_result_list: n_results(1), reserved(1), reserved2(2),
//	  result(2)=acceptance(0), reason(2)=0, transfer_syntax(uuid(16)+ver(4)).
func buildRPCBindAck(callID uint32, maxXmit, maxRecv uint16) []byte {
	body := make([]byte, 0, 64)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], maxXmit)
	body = append(body, u16[:]...)
	binary.LittleEndian.PutUint16(u16[:], maxRecv)
	body = append(body, u16[:]...)
	// assoc_group_id: a fixed nonzero value is sufficient for our peers.
	body = append(body, 0x01, 0x00, 0x00, 0x00)

	// sec_addr (port_any_t): length includes the trailing NUL.
	sa := []byte(secAddr)
	saLen := len(sa) + 1
	binary.LittleEndian.PutUint16(u16[:], uint16(saLen))
	body = append(body, u16[:]...)
	body = append(body, sa...)
	body = append(body, 0x00) // NUL terminator

	// pad2: restore 4-octet alignment relative to the start of the PDU (the
	// 16-byte header is already 4-aligned, so align on the body length).
	for len(body)%4 != 0 {
		body = append(body, 0x00)
	}

	// p_result_list with a single accepted result.
	body = append(body, 1, 0, 0, 0) // n_results=1, reserved, reserved2
	body = append(body, 0, 0)       // result = acceptance
	body = append(body, 0, 0)       // reason = 0
	body = append(body, uuidBytes(ndrUUID)...)
	body = append(body, verBytes(2, 0)...)

	hdr := buildRPCHeader(rpcPTBindAck, rpcPFCFirstFrag|rpcPFCLastFrag, uint16(16+len(body)), callID)
	return append(hdr, body...)
}

// buildResponse assembles a RESPONSE PDU ([C706] §12.6.4.10):
//
//	alloc_hint(4), p_cont_id(2), cancel_count(1), reserved(1), stub_data.
func buildRPCResponse(callID uint32, contID uint16, stub []byte) []byte {
	body := make([]byte, 8+len(stub))
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(body[4:6], contID)            // p_cont_id
	body[6] = 0                                                 // cancel_count
	body[7] = 0                                                 // reserved
	copy(body[8:], stub)
	hdr := buildRPCHeader(rpcPTResponse, rpcPFCFirstFrag|rpcPFCLastFrag, uint16(16+len(body)), callID)
	return append(hdr, body...)
}

// buildFault assembles a FAULT PDU ([C706] §12.6.4.7):
//
//	alloc_hint(4), p_cont_id(2), cancel_count(1), reserved(1), status(4), reserved2(4).
func buildFault(callID uint32, contID uint16, status uint32) []byte {
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:4], 0)      // alloc_hint
	binary.LittleEndian.PutUint16(body[4:6], contID) // p_cont_id
	body[6] = 0                                      // cancel_count
	body[7] = 0                                      // reserved
	binary.LittleEndian.PutUint32(body[8:12], status)
	// body[12:16] reserved2 = 0
	hdr := buildRPCHeader(rpcPTFault, rpcPFCFirstFrag|rpcPFCLastFrag, uint16(16+len(body)), callID)
	return append(hdr, body...)
}

// verBytes encodes an interface version as uint16 LE major + uint16 LE minor.
func verBytes(maj, min uint16) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b[0:2], maj)
	binary.LittleEndian.PutUint16(b[2:4], min)
	return b
}

// --- UUID encoding -------------------------------------------------------

// uuidBytes encodes a textual UUID into its 16-byte DCE/RPC wire form for a
// little-endian data representation: the first three fields (Data1 uint32,
// Data2 uint16, Data3 uint16) are little-endian; the final 8 bytes (Data4) are
// written in big-endian / textual order. An unparseable input yields 16 zero
// bytes.
func uuidBytes(s string) []byte {
	out := make([]byte, 16)
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return out
	}
	raw := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(clean[2*i:2*i+2], 16, 8)
		if err != nil {
			return make([]byte, 16)
		}
		raw[i] = byte(v)
	}
	// Data1 (4 bytes) little-endian.
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	// Data2 (2 bytes) little-endian.
	out[4], out[5] = raw[5], raw[4]
	// Data3 (2 bytes) little-endian.
	out[6], out[7] = raw[7], raw[6]
	// Data4 (8 bytes) as-written.
	copy(out[8:16], raw[8:16])
	return out
}

// uuidEqual reports whether two 16-byte wire-form UUIDs are identical.
func uuidEqual(a, b []byte) bool {
	if len(a) != 16 || len(b) != 16 {
		return false
	}
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
