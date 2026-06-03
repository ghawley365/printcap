package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type fakePipe struct {
	got   []byte
	reply []byte
}

func (f *fakePipe) onWrite(p []byte) []byte { f.got = append(f.got, p...); return f.reply }

// buildTreeConnectRequest builds an SMB2 TREE_CONNECT request ([MS-SMB2]
// §2.2.9) for path. StructureSize=9, PathOffset/PathLength point at a UTF-16LE
// path that follows the 8-byte fixed body.
func buildTreeConnectRequest(path string) []byte {
	hdr := smb2Header{Command: smb2TreeConnect}.encode()
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9) // StructureSize
	// body[2:4] Flags/Reserved = 0
	pathBytes := utf16le(path)
	pathOff := smb2HeaderSize + 8
	binary.LittleEndian.PutUint16(body[4:6], uint16(pathOff))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathBytes)))
	return append(append(hdr, body...), pathBytes...)
}

// buildCreateRequest builds a minimal SMB2 CREATE request ([MS-SMB2] §2.2.13)
// whose only meaningful fields are NameOffset(@44)/NameLength(@46) pointing at
// a UTF-16LE name following the 56-byte fixed body.
func buildCreateRequest(name string) []byte {
	hdr := smb2Header{Command: smb2Create}.encode()
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:2], 57) // StructureSize
	nameBytes := utf16le(name)
	nameOff := smb2HeaderSize + 56
	binary.LittleEndian.PutUint16(body[44:46], uint16(nameOff))
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameBytes)))
	// CreateContextsOffset@48, CreateContextsLength@52 = 0
	return append(append(hdr, body...), nameBytes...)
}

// buildWriteRequest builds an SMB2 WRITE request ([MS-SMB2] §2.2.21) writing
// data to the pipe identified by fid.
func buildWriteRequest(fid [16]byte, data []byte) []byte {
	hdr := smb2Header{Command: smb2Write}.encode()
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:2], 49) // StructureSize
	dataOff := smb2HeaderSize + 48
	binary.LittleEndian.PutUint16(body[2:4], uint16(dataOff))
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	// Offset@8 = 0 (pipe)
	copy(body[16:32], fid[:])
	return append(append(hdr, body...), data...)
}

// buildReadRequest builds an SMB2 READ request ([MS-SMB2] §2.2.19) for length
// bytes from the pipe identified by fid.
func buildReadRequest(fid [16]byte, length uint32) []byte {
	hdr := smb2Header{Command: smb2Read}.encode()
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:2], 49) // StructureSize
	// Padding@2, Flags@3 = 0
	binary.LittleEndian.PutUint32(body[4:8], length)
	// Offset@8 = 0 (pipe)
	copy(body[16:32], fid[:])
	// MinimumCount@32, Channel@36, RemainingBytes@40,
	// ReadChannelInfoOffset@44, ReadChannelInfoLength@46 = 0
	return append(hdr, body...)
}

// createRespFileID reads the 16-byte FileId from a CREATE response ([MS-SMB2]
// §2.2.14): it sits at body offset 64, i.e. absolute offset 128.
func createRespFileID(resp []byte) [16]byte {
	var fid [16]byte
	if len(resp) < smb2HeaderSize+80 {
		return fid
	}
	copy(fid[:], resp[smb2HeaderSize+64:smb2HeaderSize+80])
	return fid
}

func TestTreeConnectIPC(t *testing.T) {
	s := newSMBSession()
	req := buildTreeConnectRequest(`\\PRINTCAP\IPC$`)
	resp, status, ok := handleTreeConnect(s, req)
	if !ok || status != statusSuccess {
		t.Fatalf("IPC$ connect failed: ok=%v st=0x%08x", ok, status)
	}
	hdr, _ := parseSMB2Header(resp)
	if hdr.TreeId == 0 {
		t.Fatal("no TreeId assigned")
	}
	if resp[64] != 16 || resp[66] != 0x02 {
		t.Fatalf("bad share resp (ShareType PIPE)")
	}
}

func TestCreateSpoolssVsDenied(t *testing.T) {
	s := newSMBSession()
	// Inject a fake backend.
	newSpoolssBackend = func(_ *smbSession) pipeBackend { return &fakePipe{reply: []byte("RPCRESP")} }
	defer func() { newSpoolssBackend = func(_ *smbSession) pipeBackend { return nil } }()

	resp, status, ok := handleCreate(s, buildCreateRequest("spoolss"))
	if !ok || status != statusSuccess {
		t.Fatalf("spoolss CREATE failed st=0x%08x", status)
	}
	fid := createRespFileID(resp)
	if fid == ([16]byte{}) {
		t.Fatal("zero FileId")
	}

	_, status2, _ := handleCreate(s, buildCreateRequest("notspoolss"))
	if status2 == statusSuccess {
		t.Fatal("non-spoolss path must be denied")
	}
}

func TestWriteReadShuttlesToBackend(t *testing.T) {
	s := newSMBSession()
	newSpoolssBackend = func(_ *smbSession) pipeBackend { return &fakePipe{reply: []byte("RPCRESP")} }
	defer func() { newSpoolssBackend = func(_ *smbSession) pipeBackend { return nil } }()
	cresp, _, _ := handleCreate(s, buildCreateRequest("spoolss"))
	fid := createRespFileID(cresp)

	wresp, st, ok := handleWrite(s, buildWriteRequest(fid, []byte("RPCBINDREQ")))
	if !ok || st != statusSuccess {
		t.Fatalf("WRITE failed st=0x%08x", st)
	}
	_ = wresp
	// READ should return the backend's reply bytes.
	rresp, st2, ok2 := handleRead(s, buildReadRequest(fid, 1024))
	if !ok2 || st2 != statusSuccess {
		t.Fatalf("READ failed st=0x%08x", st2)
	}
	if !bytes.Contains(rresp, []byte("RPCRESP")) {
		t.Fatalf("READ did not return backend reply")
	}
}
