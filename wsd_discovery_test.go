package main

import (
	"bytes"
	"testing"
)

func TestProbeMatchesPrinter(t *testing.T) {
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	probe := []byte(`<d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><d:Types xmlns:wprt="http://schemas.microsoft.com/windows/2006/08/wdp/print">wprt:PrintDeviceType</d:Types></d:Probe>`)
	resp, matched := handleProbe(probe)
	if !matched {
		t.Fatal("printer probe should match")
	}
	if !bytes.Contains(resp, []byte("ProbeMatches")) {
		t.Fatalf("missing ProbeMatches: %s", resp)
	}
	if !bytes.Contains(resp, []byte(wsdEndpoint)) {
		t.Fatalf("missing XAddrs endpoint: %s", resp)
	}
	if !bytes.Contains(resp, []byte(deviceUUID(wsdHost()))) {
		t.Fatalf("missing device EPR: %s", resp)
	}
}

func TestProbeUnrelatedTypeNoMatch(t *testing.T) {
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	probe := []byte(`<d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"><d:Types>foo:SomethingElse</d:Types></d:Probe>`)
	if _, matched := handleProbe(probe); matched {
		t.Fatal("unrelated probe must not match")
	}
}

func TestEmptyProbeMatchesAll(t *testing.T) {
	// A Probe with no Types matches any device (WS-Discovery semantics).
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	probe := []byte(`<d:Probe xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"></d:Probe>`)
	if _, matched := handleProbe(probe); !matched {
		t.Fatal("empty-Types probe should match")
	}
}

func TestResolveMatches(t *testing.T) {
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	resp, ok := handleResolve([]byte(`<d:Resolve xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"/>`))
	if !ok || !bytes.Contains(resp, []byte("ResolveMatches")) || !bytes.Contains(resp, []byte(wsdEndpoint)) {
		t.Fatalf("resolve failed: ok=%v %s", ok, resp)
	}
}

func TestHelloByeContainEPR(t *testing.T) {
	cfg = defaultConfig()
	wsdEndpoint = "http://192.0.2.10:3911/wsd"
	if !bytes.Contains(helloMessage(), []byte("Hello")) || !bytes.Contains(helloMessage(), []byte(deviceUUID(wsdHost()))) {
		t.Fatal("hello missing")
	}
	if !bytes.Contains(byeMessage(), []byte("Bye")) {
		t.Fatal("bye missing")
	}
}
