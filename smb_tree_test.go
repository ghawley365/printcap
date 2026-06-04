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

// buildCreateRequestOnTree is buildCreateRequest with the request header TreeId
// set to treeID, so handleCreate routes against that tree.
func buildCreateRequestOnTree(treeID uint32, name string) []byte {
	req := buildCreateRequest(name)
	binary.LittleEndian.PutUint32(req[36:40], treeID)
	return req
}

// buildWriteRequestOnTree is buildWriteRequest with the request header TreeId
// set to treeID.
func buildWriteRequestOnTree(treeID uint32, fid [16]byte, data []byte) []byte {
	req := buildWriteRequest(fid, data)
	binary.LittleEndian.PutUint32(req[36:40], treeID)
	return req
}

// buildCloseRequest builds an SMB2 CLOSE request ([MS-SMB2] §2.2.15):
// StructureSize=24, Flags(2), Reserved(4), FileId(16 @ body offset 8).
func buildCloseRequest(fid [16]byte) []byte {
	hdr := smb2Header{Command: smb2Close}.encode()
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24) // StructureSize
	// Flags@2, Reserved@4 = 0
	copy(body[8:24], fid[:])
	return append(hdr, body...)
}

// buildCloseRequestOnTree is buildCloseRequest with the request header TreeId
// set to treeID.
func buildCloseRequestOnTree(treeID uint32, fid [16]byte) []byte {
	req := buildCloseRequest(fid)
	binary.LittleEndian.PutUint32(req[36:40], treeID)
	return req
}

func TestPrintShareCaptureFlow(t *testing.T) {
	cfg = defaultConfig()
	cfg.SMB.ShareName = "PRINTER"
	var captured *job
	old := smbCaptureJob
	smbCaptureJob = func(j *job) error { captured = j; return nil }
	defer func() { smbCaptureJob = old }()

	s := newSMBSession()
	s.user = "alice"
	s.remoteAddr = "10.0.0.9:5000"

	// TREE_CONNECT to the PRINTER share → ShareType PRINT (0x03).
	tcResp, st, ok := handleTreeConnect(s, buildTreeConnectRequest(`\\PRINTCAP\PRINTER`))
	if !ok || st != statusSuccess {
		t.Fatalf("PRINTER tree connect failed st=0x%08x", st)
	}
	if tcResp[66] != 0x03 {
		t.Fatalf("ShareType=0x%02x want 0x03 (PRINT)", tcResp[66])
	}
	tcHdr, _ := parseSMB2Header(tcResp)
	treeID := tcHdr.TreeId

	// CREATE a spool file on the print tree (arbitrary name, not "spoolss").
	crResp, st2, ok2 := handleCreate(s, buildCreateRequestOnTree(treeID, "MyDocument.pcl"))
	if !ok2 || st2 != statusSuccess {
		t.Fatalf("print CREATE failed st=0x%08x", st2)
	}
	fid := createRespFileID(crResp)

	// WRITE the spool data, then CLOSE → job captured.
	if _, st3, _ := handleWrite(s, buildWriteRequestOnTree(treeID, fid, []byte("PCLSPOOL"))); st3 != statusSuccess {
		t.Fatalf("print WRITE failed st=0x%08x", st3)
	}
	if _, st4, _ := handleClose(s, buildCloseRequestOnTree(treeID, fid)); st4 != statusSuccess {
		t.Fatalf("print CLOSE failed st=0x%08x", st4)
	}
	if captured == nil {
		t.Fatal("no print job captured")
	}
	if captured.Protocol != "SMB" || string(captured.data) != "PCLSPOOL" {
		t.Fatalf("job=%+v data=%q", captured, captured.data)
	}
	if captured.JobName != "MyDocument.pcl" || captured.User != "alice" {
		t.Fatalf("JobName=%q User=%q", captured.JobName, captured.User)
	}
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
