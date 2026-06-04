package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ndrString marshals s as an NDR conformant+varying UTF-16LE string ([MS-RPCE]
// §2.2.3): MaxCount(4 LE), Offset(4 LE)=0, ActualCount(4 LE), then ActualCount
// UTF-16LE code units (the last being the NUL terminator), padded to a 4-byte
// boundary. ActualCount/MaxCount include the trailing NUL.
func ndrString(s string) []byte {
	units := make([]uint16, 0, len(s)+1)
	for _, r := range s {
		units = append(units, uint16(r)) // BMP-only test inputs
	}
	units = append(units, 0) // NUL terminator
	n := uint32(len(units))

	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:4], n)  // MaxCount
	binary.LittleEndian.PutUint32(b[4:8], 0)  // Offset
	binary.LittleEndian.PutUint32(b[8:12], n) // ActualCount
	for _, u := range units {
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], u)
		b = append(b, tmp[:]...)
	}
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32le(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// ndrOpenPrinterStub builds an [in] stub for RpcOpenPrinterEx/RpcOpenPrinter: a
// unique pointer (referent id) to the printer name string, then a few trailing
// fields we don't parse.
func ndrOpenPrinterStub(name string) []byte {
	var b []byte
	b = append(b, u32le(1)...) // referent id for pPrinterName (non-NULL)
	b = append(b, ndrString(name)...)
	// pDatatype (NULL), pDevModeContainer, AccessRequired — ignored by parser.
	b = append(b, u32le(0)...)
	return b
}

// handleBytes is a fixed 20-byte context handle used in test stubs.
func handleBytes() []byte { return make([]byte, 20) }

// ndrStartDocStub builds an [in] stub for RpcStartDocPrinter: handle(20),
// then a DOC_INFO_CONTAINER {Level, pointer->DOC_INFO_1}, then DOC_INFO_1 =
// {pDocName, pOutputFile(NULL), pDatatype(NULL)} unique pointers, then the
// conformant+varying string for each non-NULL pointer in order.
func ndrStartDocStub(docName string) []byte {
	var b []byte
	b = append(b, handleBytes()...)
	b = append(b, u32le(1)...) // Level = 1
	b = append(b, u32le(4)...) // referent id -> DOC_INFO_1 (non-NULL)
	// DOC_INFO_1: three unique pointers in order.
	b = append(b, u32le(2)...) // pDocName (non-NULL)
	b = append(b, u32le(0)...) // pOutputFile (NULL)
	b = append(b, u32le(0)...) // pDatatype (NULL)
	// Deferred string data for non-NULL pointers, in order: only pDocName.
	b = append(b, ndrString(docName)...)
	return b
}

// ndrWriteStub builds an [in] stub for RpcWritePrinter: handle(20), then pBuf
// as an NDR conformant byte array {MaxCount, bytes...}, then cbBuf.
func ndrWriteStub(data []byte) []byte {
	var b []byte
	b = append(b, handleBytes()...)
	b = append(b, u32le(uint32(len(data)))...) // MaxCount
	b = append(b, data...)
	for len(b)%4 != 0 { // align after the array
		b = append(b, 0)
	}
	b = append(b, u32le(uint32(len(data)))...) // cbBuf
	return b
}

func ndrEndDocStub() []byte { return handleBytes() }
func ndrCloseStub() []byte  { return handleBytes() }

func TestSpoolssCapturesJob(t *testing.T) {
	var captured *job
	old := smbCaptureJob
	smbCaptureJob = func(j *job) error { captured = j; return nil }
	defer func() { smbCaptureJob = old }()

	s := newSMBSession()
	s.remoteAddr = "10.0.0.5:12345"
	disp := spoolssDispatcher(s)

	// OpenPrinterEx -> StartDoc(pDocName="Report") -> Write("PCL")x3 -> EndDoc -> Close
	if _, ok := disp(opRpcOpenPrinterEx, ndrOpenPrinterStub("\\\\PRINTCAP\\PRINTER")); !ok {
		t.Fatal("OpenPrinterEx failed")
	}
	if _, ok := disp(opRpcStartDocPrinter, ndrStartDocStub("Report")); !ok {
		t.Fatal("StartDoc failed")
	}
	for i := 0; i < 3; i++ {
		if _, ok := disp(opRpcWritePrinter, ndrWriteStub([]byte("PCL"))); !ok {
			t.Fatal("Write failed")
		}
	}
	if _, ok := disp(opRpcEndDocPrinter, ndrEndDocStub()); !ok {
		t.Fatal("EndDoc failed")
	}
	disp(opRpcClosePrinter, ndrCloseStub())

	if captured == nil {
		t.Fatal("no job captured")
	}
	if captured.Protocol != "SMB" {
		t.Fatalf("Protocol=%q want SMB", captured.Protocol)
	}
	if captured.JobName != "Report" {
		t.Fatalf("JobName=%q want Report", captured.JobName)
	}
	if !bytes.Equal(captured.data, []byte("PCLPCLPCL")) {
		t.Fatalf("data=%q want PCLPCLPCL", captured.data)
	}
	if captured.Bytes != 9 {
		t.Fatalf("Bytes=%d want 9", captured.Bytes)
	}
	if captured.Source != "10.0.0.5:12345" {
		t.Fatalf("Source=%q", captured.Source)
	}
}

// TestSpoolssMalformedNoPanic ensures hostile/truncated stubs never panic and
// are rejected (ok=false) rather than capturing garbage.
func TestSpoolssMalformedNoPanic(t *testing.T) {
	old := smbCaptureJob
	smbCaptureJob = func(j *job) error { return nil }
	defer func() { smbCaptureJob = old }()

	s := newSMBSession()
	disp := spoolssDispatcher(s)

	// Truncated StartDoc (no handle).
	if _, ok := disp(opRpcStartDocPrinter, []byte{0x01, 0x02}); ok {
		t.Fatal("expected failure on truncated StartDoc")
	}
	// Write with a MaxCount that overruns the buffer.
	bad := append(handleBytes(), u32le(0xffffffff)...)
	if _, ok := disp(opRpcWritePrinter, bad); ok {
		t.Fatal("expected failure on overrun WritePrinter")
	}
	// EndDoc with too-short handle.
	if _, ok := disp(opRpcEndDocPrinter, []byte{0x00}); ok {
		t.Fatal("expected failure on truncated EndDoc")
	}
}
