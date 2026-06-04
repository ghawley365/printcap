package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// parseSMB2HeaderSessionID extracts the SessionId (LE uint64 at offset 40) from
// a framed SMB2 message. Test-only helper for the end-to-end flow.
func parseSMB2HeaderSessionID(resp []byte) uint64 {
	if len(resp) < smb2HeaderSize {
		return 0
	}
	return binary.LittleEndian.Uint64(resp[40:48])
}

// TestSMBEndToEndCapturesJob drives the full SMB2/3 + NTLM + DCERPC/spoolss
// sequence over net.Pipe and asserts a print job is captured end to end.
func TestSMBEndToEndCapturesJob(t *testing.T) {
	cfg = defaultConfig()
	cfg.SMB.Enabled = true
	cfg.SMB.RequireAuth = false // guest path (no real signing/encryption needed)
	cfg.SMB.Encrypt = false
	cfg.SMB.Sign = false

	var captured *job
	old := smbCaptureJob
	smbCaptureJob = func(j *job) error { captured = j; return nil }
	defer func() { smbCaptureJob = old }()

	cli, srv := net.Pipe()
	defer cli.Close()
	go handleSMBConn(srv)

	// Helper to send a framed SMB2 request and read the framed reply.
	rt := func(reqMsg []byte) []byte {
		if err := writeTCPFrame(cli, reqMsg); err != nil {
			t.Fatal(err)
		}
		resp, err := readTCPFrame(cli)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 1) NEGOTIATE (offer 3.1.1 w/ contexts)
	rt(buildNegotiateRequest([]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, true))

	// 2) SESSION_SETUP leg1 (NTLM NEGOTIATE) -> CHALLENGE
	resp1 := rt(buildSessionSetupRequest(0, ntlmNegotiateMessage()))
	chal, ok := extractNTLM(sessionSecBuf(resp1))
	if !ok {
		t.Fatal("no challenge")
	}
	sc := ntlmServerChallenge(chal)
	ti := ntlmChallengeTargetInfo(chal)

	// 3) SESSION_SETUP leg2 (AUTHENTICATE) -> SUCCESS (guest: any creds accepted)
	auth := clientAuthenticate("WORKGROUP", "guest", "", sc, ti)
	rt(buildSessionSetupRequest(parseSMB2HeaderSessionID(resp1), auth))

	// 4) TREE_CONNECT IPC$
	tcResp := rt(buildTreeConnectRequest(`\\PRINTCAP\IPC$`))

	// 5) CREATE \spoolss
	crResp := rt(buildCreateRequest("spoolss"))
	fid := createRespFileID(crResp)

	// 6) WRITE DCERPC BIND, then the spoolss RPC sequence wrapped in DCERPC
	// REQUEST PDUs. Each WRITE is followed by a READ to drain the pipe reply.
	rpcWrite := func(pdu []byte) {
		rt(buildWriteRequest(fid, pdu))
		rt(buildReadRequest(fid, 4096))
	}
	rpcWrite(buildBindPDU(1, mrprnUUID, "1.0", ndrUUID, "2.0"))
	rpcWrite(buildRequestPDU(2, 69 /*OpenPrinterEx*/, ndrOpenPrinterStub("\\\\PRINTCAP\\PRINTER")))
	rpcWrite(buildRequestPDU(3, 17 /*StartDoc*/, ndrStartDocStub("Report")))
	rpcWrite(buildRequestPDU(4, 19 /*Write*/, ndrWriteStub([]byte("PCLDATA"))))
	rpcWrite(buildRequestPDU(5, 23 /*EndDoc*/, ndrEndDocStub()))

	_ = tcResp
	if captured == nil {
		t.Fatal("no SMB job captured end to end")
	}
	if captured.Protocol != "SMB" || captured.JobName != "Report" {
		t.Fatalf("job=%+v", captured)
	}
	if string(captured.data) != "PCLDATA" {
		t.Fatalf("data=%q want PCLDATA", captured.data)
	}
}
