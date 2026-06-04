package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// scanJobID extracts the integer inside <wprt:JobId>N</...> (namespace-prefix
// agnostic) from a SOAP response, for test correlation.
func scanJobID(resp []byte) int {
	s := string(resp)
	i := strings.Index(s, "JobId>")
	if i < 0 {
		return 0
	}
	rest := s[i+len("JobId>"):]
	j := strings.IndexByte(rest, '<')
	if j < 0 {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(rest[:j]))
	return n
}

func TestWSPrintCreateThenSendCaptures(t *testing.T) {
	cfg = defaultConfig()
	var captured *job
	old := wsdCaptureJob
	wsdCaptureJob = func(j *job) error { captured = j; return nil }
	defer func() { wsdCaptureJob = old }()

	// CreatePrintJob
	cpjBody := []byte(`<wprt:CreatePrintJobRequest xmlns:wprt="http://schemas.microsoft.com/windows/2006/08/wdp/print">` +
		`<wprt:PrintJobDescription><wprt:JobName>Quarterly</wprt:JobName>` +
		`<wprt:JobOriginatingUserName>bob</wprt:JobOriginatingUserName></wprt:PrintJobDescription>` +
		`<wprt:DocumentDescriptionList><wprt:DocumentDescription><wprt:Format>application/pdf</wprt:Format>` +
		`</wprt:DocumentDescription></wprt:DocumentDescriptionList></wprt:CreatePrintJobRequest>`)
	resp, ok := wsprintHandle(soapEnvelope{Action: actCreatePrintJob, MessageID: "urn:uuid:c1", BodyXML: cpjBody}, nil, "192.0.2.5:5000")
	if !ok || !bytes.Contains(resp, []byte("JobId")) {
		t.Fatalf("CreatePrintJob failed: ok=%v resp=%s", ok, resp)
	}
	// Extract the JobId the server returned.
	jobID := scanJobID(resp)

	// SendDocument referencing the JobId, with the doc in parts["doc"].
	sdBody := []byte(`<wprt:SendDocumentRequest xmlns:wprt="http://schemas.microsoft.com/windows/2006/08/wdp/print" xmlns:xop="http://www.w3.org/2004/08/xop/include">` +
		`<wprt:JobId>` + itoa(jobID) + `</wprt:JobId>` +
		`<wprt:Document><xop:Include href="cid:doc"/></wprt:Document></wprt:SendDocumentRequest>`)
	parts := map[string][]byte{"doc": []byte("%PDF-1.7 fake pdf bytes")}
	resp2, ok2 := wsprintHandle(soapEnvelope{Action: actSendDocument, MessageID: "urn:uuid:s1", BodyXML: sdBody}, parts, "192.0.2.5:5000")
	if !ok2 {
		t.Fatal("SendDocument not handled")
	}
	_ = resp2
	if captured == nil {
		t.Fatal("no WSD job captured")
	}
	if captured.Protocol != "WSD" || captured.JobName != "Quarterly" || captured.User != "bob" ||
		captured.DocFormat != "application/pdf" || string(captured.data) != "%PDF-1.7 fake pdf bytes" {
		t.Fatalf("captured job wrong: %+v data=%q", captured, captured.data)
	}
}
