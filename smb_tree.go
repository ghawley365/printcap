package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

// Additional NTStatus codes used by the tree/pipe handlers ([MS-ERREF] §2.3.1).
const (
	statusObjectNameNotFound uint32 = 0xC0000034
	statusInvalidParameter   uint32 = 0xC000000D
)

// SMB2 share types ([MS-SMB2] §2.2.10 ShareType). IPC$ is a named-pipe share.
const (
	smb2ShareTypeDisk  uint8 = 0x01
	smb2ShareTypePipe  uint8 = 0x02
	smb2ShareTypePrint uint8 = 0x03
)

// TREE_CONNECT/CREATE/READ/WRITE/CLOSE structure sizes ([MS-SMB2] §2.2.9-§2.2.22).
const (
	treeConnectReqStructureSize  = 9
	treeConnectRespStructureSize = 16
	createReqStructureSize       = 57
	createRespStructureSize      = 89
	writeReqStructureSize        = 49
	writeRespStructureSize       = 17
	readReqStructureSize         = 49
	readRespStructureSize        = 17
	closeReqStructureSize        = 24
	closeRespStructureSize       = 60
)

// maximalAccessAllPipe is the MaximalAccess granted on the IPC$ pipe share
// ([MS-SMB2] §2.2.10); 0x001F01FF is the standard "all access" mask.
const maximalAccessAllPipe uint32 = 0x001F01FF

// pipeBackend consumes client WRITE bytes and produces READ bytes. The DCERPC/
// spoolss layer (Stage 4.2/4.3) implements this; tests use a fake.
type pipeBackend interface {
	// onWrite is called with the bytes the client WROTE to the pipe; it returns
	// the bytes that should become available for the next READ (a DCERPC
	// response), or nil if none yet.
	onWrite(p []byte) []byte
}

// pipeHandle is an open \spoolss pipe instance.
type pipeHandle struct {
	fileID  [16]byte
	backend pipeBackend
	readBuf []byte // pending bytes for READ

	// Print-share spool state. When printSpool is set the handle is an open
	// spool file on a PRINT tree (not a \spoolss DCERPC pipe): writes are
	// accumulated in spoolBuf and captured as a job on CLOSE.
	printSpool bool
	docName    string
	spoolBuf   []byte
}

// newSpoolssBackend builds the DCERPC/spoolss backend for a new \spoolss handle.
// Overridable in tests. Stage 4.2 replaces the default.
var newSpoolssBackend = func(s *smbSession) pipeBackend { return nil }

// parseUTF16LE decodes a UTF-16LE byte slice (an even number of bytes) into a
// Go string. An odd trailing byte is ignored.
func parseUTF16LE(b []byte) string {
	n := len(b) / 2
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// fileIDKey returns the map key for a 16-byte FileId.
func fileIDKey(fid [16]byte) string { return hex.EncodeToString(fid[:]) }

// buildErrorResponse builds a bare SMB2 header (no body) carrying status for a
// failed command ([MS-SMB2] §3.3.4.4 — the ERROR response StructureSize/9 body
// is optional for our capture peers; a header-only error suffices here).
func buildErrorResponse(reqHdr smb2Header, command uint16, status uint32) []byte {
	respHdr := smb2Header{
		Command:    command,
		Status:     status,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	// SMB2 ERROR response body ([MS-SMB2] §2.2.2): StructureSize=9, the rest 0.
	body := make([]byte, 9)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	return append(respHdr.encode(), body...)
}

// handleTreeConnect processes an SMB2 TREE_CONNECT request ([MS-SMB2] §2.2.9).
// IPC$ (case-insensitive) is accepted and modeled as a PIPE share; any other
// share is rejected with STATUS_OBJECT_NAME_NOT_FOUND. It never panics on
// hostile input.
func handleTreeConnect(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2TreeConnect {
		return buildErrorResponse(reqHdr, smb2TreeConnect, statusInvalidParameter), statusInvalidParameter, false
	}
	if len(req) < smb2HeaderSize+8 {
		return buildErrorResponse(reqHdr, smb2TreeConnect, statusInvalidParameter), statusInvalidParameter, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != treeConnectReqStructureSize {
		return buildErrorResponse(reqHdr, smb2TreeConnect, statusInvalidParameter), statusInvalidParameter, false
	}
	pathOff := int64(binary.LittleEndian.Uint16(body[4:6]))
	pathLen := int64(binary.LittleEndian.Uint16(body[6:8]))
	end := pathOff + pathLen
	if pathOff < int64(smb2HeaderSize) || end < pathOff || end > int64(len(req)) {
		return buildErrorResponse(reqHdr, smb2TreeConnect, statusInvalidParameter), statusInvalidParameter, false
	}
	path := parseUTF16LE(req[pathOff:end])

	// The path is a UNC of the form \\server\share; route on the final segment.
	share := path
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		share = path[i+1:]
	}
	// IPC$ is the named-pipe (spoolss RPC) share; the configured share name
	// (e.g. "PRINTER") is the classic SMB print share that smbclient writes the
	// spool file to. Anything else is unknown.
	isPipe := strings.EqualFold(share, "IPC$")
	isPrint := strings.EqualFold(share, cfg.SMB.ShareName)
	if !isPipe && !isPrint {
		return buildErrorResponse(reqHdr, smb2TreeConnect, statusObjectNameNotFound), statusObjectNameNotFound, false
	}

	s.nextTreeID++
	if s.nextTreeID == 0 {
		s.nextTreeID = 1
	}
	treeID := s.nextTreeID
	if s.trees == nil {
		s.trees = make(map[uint32]string)
	}
	s.trees[treeID] = path

	shareType := smb2ShareTypePipe
	if isPrint {
		shareType = smb2ShareTypePrint
		if s.printTrees == nil {
			s.printTrees = make(map[uint32]bool)
		}
		s.printTrees[treeID] = true
	}

	respHdr := smb2Header{
		Command:    smb2TreeConnect,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     treeID,
	}
	rbody := make([]byte, treeConnectRespStructureSize)
	binary.LittleEndian.PutUint16(rbody[0:2], treeConnectRespStructureSize)
	rbody[2] = shareType // ShareType
	// rbody[3] Reserved = 0
	// rbody[4:8] ShareFlags = 0
	// rbody[8:12] Capabilities = 0
	binary.LittleEndian.PutUint32(rbody[12:16], maximalAccessAllPipe)
	return append(respHdr.encode(), rbody...), statusSuccess, true
}

// handleCreate processes an SMB2 CREATE request ([MS-SMB2] §2.2.13). Only the
// \spoolss named pipe is accepted; any other name is denied. On success a
// random 16-byte FileId is minted and a pipeHandle is opened. Panic-proof.
func handleCreate(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Create {
		return buildErrorResponse(reqHdr, smb2Create, statusInvalidParameter), statusInvalidParameter, false
	}
	if len(req) < smb2HeaderSize+56 {
		return buildErrorResponse(reqHdr, smb2Create, statusInvalidParameter), statusInvalidParameter, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != createReqStructureSize {
		return buildErrorResponse(reqHdr, smb2Create, statusInvalidParameter), statusInvalidParameter, false
	}
	nameOff := int64(binary.LittleEndian.Uint16(body[44:46]))
	nameLen := int64(binary.LittleEndian.Uint16(body[46:48]))
	name := ""
	if nameLen > 0 {
		end := nameOff + nameLen
		if nameOff < int64(smb2HeaderSize) || end < nameOff || end > int64(len(req)) {
			return buildErrorResponse(reqHdr, smb2Create, statusInvalidParameter), statusInvalidParameter, false
		}
		name = parseUTF16LE(req[nameOff:end])
	}
	name = strings.TrimPrefix(name, "\\")

	// On a PRINT tree the CREATE opens the spool/document file under any name;
	// on the IPC$ tree only the \spoolss DCERPC pipe is accepted.
	isPrintTree := s.printTrees != nil && s.printTrees[reqHdr.TreeId]
	if !isPrintTree && !strings.EqualFold(name, "spoolss") {
		return buildErrorResponse(reqHdr, smb2Create, statusAccessDenied), statusAccessDenied, false
	}

	var fid [16]byte
	if _, err := rand.Read(fid[:]); err != nil {
		// rand.Read should not fail; fall back to a deterministic non-zero id.
		for i := range fid {
			fid[i] = byte(i + 1)
		}
	}
	var h *pipeHandle
	if isPrintTree {
		h = &pipeHandle{fileID: fid, printSpool: true, docName: name}
	} else {
		h = &pipeHandle{fileID: fid, backend: newSpoolssBackend(s)}
	}
	if s.handles == nil {
		s.handles = make(map[string]*pipeHandle)
	}
	s.handles[fileIDKey(fid)] = h

	respHdr := smb2Header{
		Command:    smb2Create,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	// CREATE response fixed part is 88 bytes; StructureSize=89 accounts for the
	// 1-byte variable Buffer placeholder ([MS-SMB2] §2.2.14).
	rbody := make([]byte, 88)
	binary.LittleEndian.PutUint16(rbody[0:2], createRespStructureSize)
	// rbody[2] OplockLevel = 0, rbody[3] Flags = 0
	binary.LittleEndian.PutUint32(rbody[4:8], 1) // CreateAction = FILE_OPENED
	// Times[8:40], AllocationSize[40:48], EndOfFile[48:56] = 0 (named pipe)
	// FileAttributes[56:60], Reserved2[60:64] = 0
	copy(rbody[64:80], fid[:]) // FileId
	// CreateContextsOffset[80:84], CreateContextsLength[84:88] = 0
	return append(respHdr.encode(), rbody...), statusSuccess, true
}

// lookupHandle parses a 16-byte FileId at body offset fidOff and returns the
// matching open pipeHandle, or ok=false if absent or out of bounds.
func lookupHandle(s *smbSession, body []byte, fidOff int) (*pipeHandle, bool) {
	if fidOff+16 > len(body) {
		return nil, false
	}
	var fid [16]byte
	copy(fid[:], body[fidOff:fidOff+16])
	h, found := s.handles[fileIDKey(fid)]
	return h, found
}

// handleWrite processes an SMB2 WRITE request ([MS-SMB2] §2.2.21): it shuttles
// the written bytes to the pipe backend and buffers any reply for the next
// READ. Unknown FileId is denied. Panic-proof.
func handleWrite(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Write {
		return buildErrorResponse(reqHdr, smb2Write, statusInvalidParameter), statusInvalidParameter, false
	}
	if len(req) < smb2HeaderSize+writeReqStructureSize-1 {
		return buildErrorResponse(reqHdr, smb2Write, statusInvalidParameter), statusInvalidParameter, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != writeReqStructureSize {
		return buildErrorResponse(reqHdr, smb2Write, statusInvalidParameter), statusInvalidParameter, false
	}
	dataOff := int64(binary.LittleEndian.Uint16(body[2:4]))
	dataLen := int64(binary.LittleEndian.Uint32(body[4:8]))
	end := dataOff + dataLen
	if dataOff < int64(smb2HeaderSize) || end < dataOff || end > int64(len(req)) {
		return buildErrorResponse(reqHdr, smb2Write, statusInvalidParameter), statusInvalidParameter, false
	}
	h, found := lookupHandle(s, body, 16)
	if !found {
		return buildErrorResponse(reqHdr, smb2Write, statusAccessDenied), statusAccessDenied, false
	}
	data := req[dataOff:end]
	if h.printSpool {
		// Print-share spool write: accumulate the raw spool bytes for capture
		// on CLOSE; there is no DCERPC backend to shuttle through.
		h.spoolBuf = append(h.spoolBuf, data...)
	} else if h.backend != nil {
		if out := h.backend.onWrite(data); out != nil {
			h.readBuf = append(h.readBuf, out...)
		}
	}

	respHdr := smb2Header{
		Command:    smb2Write,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	rbody := make([]byte, writeRespStructureSize)
	binary.LittleEndian.PutUint16(rbody[0:2], writeRespStructureSize)
	// rbody[2:4] Reserved = 0
	binary.LittleEndian.PutUint32(rbody[4:8], uint32(dataLen)) // Count
	// rbody[8:12] Remaining = 0
	// rbody[12:14] WriteChannelInfoOffset = 0
	// rbody[14:16] WriteChannelInfoLength = 0
	return append(respHdr.encode(), rbody...), statusSuccess, true
}

// handleRead processes an SMB2 READ request ([MS-SMB2] §2.2.19): it drains up
// to Length bytes of the handle's pending read buffer into the §2.2.20
// response. An empty buffer yields a 0-byte success. Unknown FileId is denied.
// Panic-proof.
func handleRead(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Read {
		return buildErrorResponse(reqHdr, smb2Read, statusInvalidParameter), statusInvalidParameter, false
	}
	if len(req) < smb2HeaderSize+readReqStructureSize-1 {
		return buildErrorResponse(reqHdr, smb2Read, statusInvalidParameter), statusInvalidParameter, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != readReqStructureSize {
		return buildErrorResponse(reqHdr, smb2Read, statusInvalidParameter), statusInvalidParameter, false
	}
	length := int64(binary.LittleEndian.Uint32(body[4:8]))
	h, found := lookupHandle(s, body, 16)
	if !found {
		return buildErrorResponse(reqHdr, smb2Read, statusAccessDenied), statusAccessDenied, false
	}

	n := int64(len(h.readBuf))
	if length < n {
		n = length
	}
	if n < 0 {
		n = 0
	}
	data := h.readBuf[:n]
	h.readBuf = h.readBuf[n:]

	respHdr := smb2Header{
		Command:    smb2Read,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	// READ response ([MS-SMB2] §2.2.20): fixed part is 16 bytes; StructureSize=17
	// accounts for the 1-byte variable Buffer placeholder.
	rbody := make([]byte, 16)
	binary.LittleEndian.PutUint16(rbody[0:2], readRespStructureSize)
	rbody[2] = uint8(smb2HeaderSize + 16) // DataOffset from header start
	// rbody[3] Reserved = 0
	binary.LittleEndian.PutUint32(rbody[4:8], uint32(len(data))) // DataLength
	// rbody[8:12] DataRemaining = 0
	// rbody[12:16] Reserved2/Flags = 0
	return append(append(respHdr.encode(), rbody...), data...), statusSuccess, true
}

// handleClose processes an SMB2 CLOSE request ([MS-SMB2] §2.2.15): it removes
// the handle and returns a §2.2.16 response. Unknown FileId is denied.
// Panic-proof.
func handleClose(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Close {
		return buildErrorResponse(reqHdr, smb2Close, statusInvalidParameter), statusInvalidParameter, false
	}
	if len(req) < smb2HeaderSize+closeReqStructureSize {
		return buildErrorResponse(reqHdr, smb2Close, statusInvalidParameter), statusInvalidParameter, false
	}
	body := req[smb2HeaderSize:]
	if binary.LittleEndian.Uint16(body[0:2]) != closeReqStructureSize {
		return buildErrorResponse(reqHdr, smb2Close, statusInvalidParameter), statusInvalidParameter, false
	}
	// CLOSE req: StructureSize(2), Flags(2), Reserved(4), FileId(16 @ offset 8).
	h, found := lookupHandle(s, body, 8)
	if !found {
		return buildErrorResponse(reqHdr, smb2Close, statusAccessDenied), statusAccessDenied, false
	}
	// On a print-spool handle, CLOSE finalizes the document: capture the spooled
	// bytes as a job before discarding the handle.
	if h.printSpool && len(h.spoolBuf) > 0 {
		j := newJob("SMB", s.remoteAddr)
		j.JobName = h.docName
		j.User = s.user
		j.data = h.spoolBuf
		j.Bytes = len(h.spoolBuf)
		_ = smbCaptureJob(j)
	}
	delete(s.handles, fileIDKey(h.fileID))

	respHdr := smb2Header{
		Command:    smb2Close,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	// CLOSE response ([MS-SMB2] §2.2.16): StructureSize=60, all other fields 0.
	rbody := make([]byte, closeRespStructureSize)
	binary.LittleEndian.PutUint16(rbody[0:2], closeRespStructureSize)
	return append(respHdr.encode(), rbody...), statusSuccess, true
}

// buildSimpleAck builds an SMB2 response with a 4-byte fixed body of
// StructureSize(2)=4, Reserved(2)=0 — the shape shared by TREE_DISCONNECT
// (§2.2.12), LOGOFF (§2.2.8), and FLUSH (§2.2.18) responses.
func buildSimpleAck(reqHdr smb2Header, command uint16) []byte {
	respHdr := smb2Header{
		Command:    command,
		Status:     statusSuccess,
		Flags:      reqHdr.Flags | smb2FlagsServerToRedir,
		CreditResp: 1,
		MessageId:  reqHdr.MessageId,
		SessionId:  reqHdr.SessionId,
		TreeId:     reqHdr.TreeId,
	}
	rbody := make([]byte, 4)
	binary.LittleEndian.PutUint16(rbody[0:2], 4) // StructureSize
	// rbody[2:4] Reserved = 0
	return append(respHdr.encode(), rbody...)
}

// handleTreeDisconnect processes an SMB2 TREE_DISCONNECT ([MS-SMB2] §2.2.11),
// tears down the referenced tree, and returns the §2.2.12 success response.
func handleTreeDisconnect(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2TreeDisconnect {
		return buildErrorResponse(reqHdr, smb2TreeDisconnect, statusInvalidParameter), statusInvalidParameter, false
	}
	if s.trees != nil {
		delete(s.trees, reqHdr.TreeId)
	}
	if s.printTrees != nil {
		delete(s.printTrees, reqHdr.TreeId)
	}
	return buildSimpleAck(reqHdr, smb2TreeDisconnect), statusSuccess, true
}

// handleLogoff processes an SMB2 LOGOFF ([MS-SMB2] §2.2.7) and returns the
// §2.2.8 success response.
func handleLogoff(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Logoff {
		return buildErrorResponse(reqHdr, smb2Logoff, statusInvalidParameter), statusInvalidParameter, false
	}
	return buildSimpleAck(reqHdr, smb2Logoff), statusSuccess, true
}

// handleFlush processes an SMB2 FLUSH ([MS-SMB2] §2.2.17) and returns the
// §2.2.18 success response.
func handleFlush(s *smbSession, req []byte) (resp []byte, status uint32, ok bool) {
	reqHdr, hok := parseSMB2Header(req)
	if !hok || reqHdr.Command != smb2Flush {
		return buildErrorResponse(reqHdr, smb2Flush, statusInvalidParameter), statusInvalidParameter, false
	}
	return buildSimpleAck(reqHdr, smb2Flush), statusSuccess, true
}
