package main

import (
	"encoding/binary"
	"unicode/utf16"
)

// MS-RPRN (Print System Remote Protocol) spoolss handlers.
//
// This turns an SMB print job carried over the \spoolss named pipe into a
// captured `job`. The DCERPC layer (dcerpc.go) reassembles each REQUEST PDU and
// hands us the opnum plus the NDR-marshalled [in] parameter stub; we decode the
// handful of opnums an end-to-end print job uses (OpenPrinter[Ex], StartDoc,
// Write, EndDoc, Close), accumulate the spooled bytes, and on EndDoc build and
// capture the job.
//
// All NDR decoding is bounds-checked against hostile input; a malformed stub
// yields (nil, false) — a DCERPC FAULT — never a panic.

// MS-RPRN opnums ([MS-RPRN] §3.1.4). The spoolss_test.go canonical sequence
// backstops these values.
const (
	opRpcOpenPrinter     uint16 = 1
	opRpcStartDocPrinter uint16 = 17
	opRpcWritePrinter    uint16 = 19
	opRpcEndDocPrinter   uint16 = 23
	opRpcClosePrinter    uint16 = 29
	opRpcOpenPrinterEx   uint16 = 69
)

// ndrHandleLen is the size of an NDR context handle: 4-byte attributes + a
// 16-byte GUID ([MS-RPCE] §2.2.4.1 / [C706] ndr_context_handle).
const ndrHandleLen = 20

// smbCaptureJob is the indirection through which a finished SMB job reaches the
// global sink. Tests override it to capture in memory without touching disk.
var smbCaptureJob = func(j *job) error { return sink.save(j) }

// spoolssJob is the per-session capture state carried by the dispatcher
// closure: the job/document name, the accumulated spool bytes, and whether a
// StartDoc has opened a document.
type spoolssJob struct {
	name string
	buf  []byte
	open bool
}

// ndrReader is a bounds-checked cursor over an NDR-marshalled stub. Every read
// validates remaining length and reports failure via ok=false instead of
// panicking, because the stub is attacker-controlled.
type ndrReader struct {
	b   []byte
	off int
}

// u32 reads a little-endian uint32 and advances.
func (r *ndrReader) u32() (uint32, bool) {
	if r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}

// skip advances n bytes (e.g. past a context handle).
func (r *ndrReader) skip(n int) bool {
	if n < 0 || r.off+n > len(r.b) {
		return false
	}
	r.off += n
	return true
}

// bytes returns the next n bytes and advances.
func (r *ndrReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, true
}

// align advances the cursor to the next multiple of a (a power of two).
func (r *ndrReader) align(a int) bool {
	rem := r.off % a
	if rem == 0 {
		return true
	}
	return r.skip(a - rem)
}

// ndrString decodes an NDR conformant+varying UTF-16LE string ([MS-RPCE]
// §2.2.3): MaxCount(4), Offset(4), ActualCount(4), then ActualCount UTF-16LE
// code units, then padding to a 4-byte boundary. A trailing NUL unit is
// stripped. Counts are validated against the remaining buffer.
func (r *ndrReader) ndrString() (string, bool) {
	maxCount, ok := r.u32()
	if !ok {
		return "", false
	}
	offset, ok := r.u32()
	if !ok {
		return "", false
	}
	actual, ok := r.u32()
	if !ok {
		return "", false
	}
	// Sanity: ActualCount must fit within MaxCount and within the buffer.
	if offset != 0 || actual > maxCount {
		return "", false
	}
	// 2 bytes per UTF-16 code unit. Guard the multiplication against overflow
	// by checking against the remaining buffer length directly.
	if actual > uint32(len(r.b)) { // cheap pre-bound before *2
		return "", false
	}
	raw, ok := r.bytes(int(actual) * 2)
	if !ok {
		return "", false
	}
	units := make([]uint16, actual)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i : 2*i+2])
	}
	// Strip a single trailing NUL terminator if present.
	if len(units) > 0 && units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	// Re-align to a 4-byte boundary for any following NDR element.
	r.align(4)
	return string(utf16.Decode(units)), true
}

func init() { spoolssDispatcher = realSpoolssDispatcher }

// realSpoolssDispatcher returns a closure holding per-session spoolss capture
// state. It services the print-job opnums and faults (ok=false) on malformed
// stubs.
func realSpoolssDispatcher(s *smbSession) rpcDispatcher {
	st := &spoolssJob{}

	return func(opnum uint16, stub []byte) ([]byte, bool) {
		switch opnum {
		case opRpcOpenPrinter, opRpcOpenPrinterEx:
			// Reset per-handle state. We do not need the printer name to capture
			// a job, so we accept any [in] stub. Respond: 20-byte handle + RC=0.
			*st = spoolssJob{}
			resp := make([]byte, ndrHandleLen+4)
			return resp, true

		case opRpcStartDocPrinter:
			name, ok := parseStartDoc(stub)
			if !ok {
				return nil, false
			}
			st.name = name
			st.buf = st.buf[:0]
			st.open = true
			// [out]: pJobId(4)=1, return code(4)=0.
			resp := make([]byte, 8)
			binary.LittleEndian.PutUint32(resp[0:4], 1)
			return resp, true

		case opRpcWritePrinter:
			data, ok := parseWrite(stub)
			if !ok {
				return nil, false
			}
			st.buf = append(st.buf, data...)
			// [out]: pcWritten(4)=len, return code(4)=0.
			resp := make([]byte, 8)
			binary.LittleEndian.PutUint32(resp[0:4], uint32(len(data)))
			return resp, true

		case opRpcEndDocPrinter:
			// [in]: a 20-byte handle.
			if len(stub) < ndrHandleLen {
				return nil, false
			}
			if st.open {
				j := newJob("SMB", s.remoteAddr)
				j.JobName = st.name
				j.data = append([]byte(nil), st.buf...)
				j.Bytes = len(j.data)
				_ = smbCaptureJob(j)
				st.open = false
				st.buf = st.buf[:0]
			}
			// [out]: return code(4).
			return make([]byte, 4), true

		case opRpcClosePrinter:
			// [in]: a 20-byte handle. [out]: zeroed 20-byte handle + RC=0.
			*st = spoolssJob{}
			return make([]byte, ndrHandleLen+4), true

		default:
			// Unhandled opnum: respond with a minimal success (return code 0) so
			// real clients can proceed past optional calls, but log it.
			logDebug("SMB", "unhandled spoolss opnum %d", opnum)
			return make([]byte, 4), true
		}
	}
}

// parseStartDoc decodes RpcStartDocPrinter [in]: a 20-byte handle, a
// DOC_INFO_CONTAINER {Level, pointer->DOC_INFO_1}, then DOC_INFO_1's three
// unique pointers {pDocName, pOutputFile, pDatatype}, then the deferred
// conformant+varying string for each non-NULL pointer in order. The document
// name (pDocName) becomes the job name.
func parseStartDoc(stub []byte) (string, bool) {
	r := &ndrReader{b: stub}
	if !r.skip(ndrHandleLen) {
		return "", false
	}
	// DOC_INFO_CONTAINER: Level, then a unique pointer to DOC_INFO_1.
	if _, ok := r.u32(); !ok { // Level
		return "", false
	}
	infoRef, ok := r.u32()
	if !ok {
		return "", false
	}
	if infoRef == 0 {
		// No DOC_INFO_1 supplied; a nameless document is still valid.
		return "", true
	}
	// DOC_INFO_1: three unique pointers, in declaration order.
	docRef, ok := r.u32()
	if !ok {
		return "", false
	}
	outRef, ok := r.u32()
	if !ok {
		return "", false
	}
	dtRef, ok := r.u32()
	if !ok {
		return "", false
	}
	// Deferred string data follows for each non-NULL pointer, IN ORDER.
	var name string
	if docRef != 0 {
		name, ok = r.ndrString()
		if !ok {
			return "", false
		}
	}
	if outRef != 0 {
		if _, ok := r.ndrString(); !ok {
			return "", false
		}
	}
	if dtRef != 0 {
		if _, ok := r.ndrString(); !ok {
			return "", false
		}
	}
	return name, true
}

// parseWrite decodes RpcWritePrinter [in]: a 20-byte handle, then pBuf as an
// NDR conformant byte array {MaxCount(4), MaxCount bytes}, then cbBuf(4). The
// returned slice is the spool data for this call. cbBuf is honored as the
// authoritative length when it is <= MaxCount.
func parseWrite(stub []byte) ([]byte, bool) {
	r := &ndrReader{b: stub}
	if !r.skip(ndrHandleLen) {
		return nil, false
	}
	maxCount, ok := r.u32()
	if !ok {
		return nil, false
	}
	if maxCount > uint32(len(stub)) { // cheap pre-bound
		return nil, false
	}
	raw, ok := r.bytes(int(maxCount))
	if !ok {
		return nil, false
	}
	// Optional trailing cbBuf after 4-byte alignment; if present and within
	// bounds, trust it as the real byte count.
	out := raw
	r.align(4)
	if cb, ok := r.u32(); ok && cb <= maxCount {
		out = raw[:cb]
	}
	return out, true
}
