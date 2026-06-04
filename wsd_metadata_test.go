package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildMetadataHasDeviceAndPrintService(t *testing.T) {
	cfg = defaultConfig()
	cfg.Printer.Name = "Lobby MFP"
	cfg.Printer.MakeAndModel = "printcap Virtual MFP"
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	md := buildMetadata()
	for _, want := range []string{"Lobby MFP", "printcap Virtual MFP", "Relationship", "PrintDeviceType", deviceUUID(wsdHost())} {
		if !bytes.Contains(md, []byte(want)) {
			t.Fatalf("metadata missing %q:\n%s", want, md)
		}
	}
}

func TestWSDHandlerGetReturnsMetadata(t *testing.T) {
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	reqEnv := soapEnvelope{
		Action:    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
		MessageID: "urn:uuid:req-1",
		To:        deviceUUID(wsdHost()),
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/wsd", bytes.NewReader(buildSOAP(reqEnv)))
	req.Header.Set("Content-Type", "application/soap+xml")
	wsdHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	body := rr.Body.Bytes()
	if !bytes.Contains(body, []byte("GetResponse")) && !bytes.Contains(body, []byte("Metadata")) {
		t.Fatalf("no metadata in response:\n%s", body)
	}
	// The response RelatesTo must echo the request MessageID.
	if !bytes.Contains(body, []byte("urn:uuid:req-1")) {
		t.Fatalf("RelatesTo not echoed:\n%s", body)
	}
}

func TestWSDHandlerUnknownActionFaults(t *testing.T) {
	cfg = defaultConfig()
	reqEnv := soapEnvelope{Action: "urn:bogus:action", MessageID: "urn:uuid:req-2", To: "urn:x"}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/wsd", bytes.NewReader(buildSOAP(reqEnv)))
	wsdHandler(rr, req)
	if !strings.Contains(rr.Body.String(), "ActionNotSupported") {
		t.Fatalf("expected ActionNotSupported fault:\n%s", rr.Body.String())
	}
}
