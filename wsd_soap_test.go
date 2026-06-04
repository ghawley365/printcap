package main

import (
	"bytes"
	"testing"
)

func TestSOAPRoundTrip(t *testing.T) {
	env := soapEnvelope{
		Action:    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
		MessageID: "urn:uuid:1111",
		To:        "urn:uuid:dev",
		RelatesTo: "",
		BodyXML:   []byte("<wprt:GetPrinterElements/>"),
	}
	raw := buildSOAP(env)
	got, ok := parseSOAP(raw)
	if !ok {
		t.Fatal("parseSOAP ok=false")
	}
	if got.Action != env.Action || got.MessageID != env.MessageID || got.To != env.To {
		t.Fatalf("addressing headers lost: %+v", got)
	}
}

func TestSOAPBodyPreserved(t *testing.T) {
	env := soapEnvelope{
		Action:    "urn:act",
		MessageID: "urn:uuid:2222",
		BodyXML:   []byte(`<wprt:CreatePrintJob><wprt:JobName>Report</wprt:JobName></wprt:CreatePrintJob>`),
	}
	got, ok := parseSOAP(buildSOAP(env))
	if !ok {
		t.Fatal("ok=false")
	}
	if !bytes.Contains(got.BodyXML, []byte("CreatePrintJob")) || !bytes.Contains(got.BodyXML, []byte("Report")) {
		t.Fatalf("body inner XML lost: %s", got.BodyXML)
	}
}

func TestParseSOAPRejectsGarbage(t *testing.T) {
	if _, ok := parseSOAP([]byte("not xml at all <<<<")); ok {
		t.Fatal("garbage must not parse ok")
	}
}

func TestRelatesToRoundTrip(t *testing.T) {
	env := soapEnvelope{Action: "urn:resp", MessageID: "urn:uuid:3", RelatesTo: "urn:uuid:req"}
	got, ok := parseSOAP(buildSOAP(env))
	if !ok || got.RelatesTo != "urn:uuid:req" {
		t.Fatalf("RelatesTo lost: ok=%v got=%q", ok, got.RelatesTo)
	}
}
