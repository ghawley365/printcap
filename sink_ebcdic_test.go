package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEBCDICByQueue(t *testing.T) {
	cfg = defaultConfig()
	cfg.LPD.QueueDefaults = map[string]QueueDefault{
		"mvs*": {CodePage: "CP037", CarriageControl: "asa", EBCDIC: true},
	}
	j := &job{Queue: "mvs1"}
	page, cc, on := resolveEBCDIC(j, []byte{0x40})
	if !on || page != "CP037" || cc != "asa" {
		t.Fatalf("queue resolve: on=%v page=%q cc=%q", on, page, cc)
	}
}

func TestResolveEBCDICAutoDetect(t *testing.T) {
	cfg = defaultConfig()
	ebc := []byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6, 0x40, 0x40, 0x40, 0x40, 0x40}
	page, _, on := resolveEBCDIC(&job{Queue: "unmapped"}, ebc)
	if !on || page != "CP037" {
		t.Fatalf("auto resolve: on=%v page=%q", on, page)
	}
	if _, _, on := resolveEBCDIC(&job{}, []byte("plain ascii text here ok")); on {
		t.Fatal("ASCII should not resolve to EBCDIC")
	}
}

func TestSinkWritesDecodedSidecar(t *testing.T) {
	cfg = defaultConfig()
	cfg.OutDir = t.TempDir()
	cfg.LPD.QueueDefaults = map[string]QueueDefault{"mvs*": {CodePage: "CP037", CarriageControl: "none", EBCDIC: true}}
	sink = &captureSink{dir: cfg.OutDir}
	store = newJobStore(10)

	j := &job{Protocol: "LPR", Queue: "mvs1"}
	j.data = []byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6} // HELLO
	j.Bytes = len(j.data)
	_ = sink.save(j)

	if j.CodePage != "CP037" || j.DecodedAs == "" {
		t.Fatalf("metadata: codepage=%q decodedAs=%q", j.CodePage, j.DecodedAs)
	}
	b, err := os.ReadFile(filepath.Join(cfg.OutDir, j.DecodedAs))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "HELLO") {
		t.Fatalf("decoded sidecar content %q", b)
	}
}
