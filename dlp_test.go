package main

import (
	"testing"
)

func TestScanDLPKeyword(t *testing.T) {
	cfg = defaultConfig()
	cfg.DLP = DLPConf{Enabled: true, Rules: []DLPRule{{Name: "secret", Mode: "keyword", Pattern: "ConFiDenTial"}}}
	rebuildDLP()
	if got := scanDLP([]byte("This document is CONFIDENTIAL.\n"), ""); len(got) != 1 || got[0] != "secret" {
		t.Fatalf("keyword match failed: %v", got)
	}
	if got := scanDLP([]byte("nothing here"), ""); len(got) != 0 {
		t.Fatalf("unexpected match: %v", got)
	}
}

func TestScanDLPRegexAndDecoded(t *testing.T) {
	cfg = defaultConfig()
	cfg.DLP = DLPConf{Enabled: true, Rules: []DLPRule{{Name: "ssn", Mode: "regex", Pattern: `\b\d{3}-\d{2}-\d{4}\b`}}}
	rebuildDLP()
	if got := scanDLP([]byte("nope"), "employee 123-45-6789 record"); len(got) != 1 || got[0] != "ssn" {
		t.Fatalf("regex match on decoded text failed: %v", got)
	}
}

func TestScanDLPDisabledNoOp(t *testing.T) {
	cfg = defaultConfig()
	cfg.DLP = DLPConf{Enabled: false, Rules: []DLPRule{{Name: "x", Mode: "keyword", Pattern: "abc"}}}
	rebuildDLP()
	if got := scanDLP([]byte("abc"), ""); len(got) != 0 {
		t.Fatalf("disabled DLP must not match: %v", got)
	}
}

func TestSinkSaveTagsDLPMatch(t *testing.T) {
	cfg = defaultConfig()
	cfg.OutDir = t.TempDir()
	cfg.DLP = DLPConf{Enabled: true, Rules: []DLPRule{{Name: "cc", Mode: "regex", Pattern: `\b4\d{15}\b`}}}
	rebuildDLP()
	sink = &captureSink{dir: t.TempDir()}
	store = newJobStore(10)
	j := newJob("9100", "10.0.0.1:5000")
	j.data = []byte("pay with 4111111111111111 today")
	j.Bytes = len(j.data)
	if err := sink.save(j); err != nil {
		t.Fatal(err)
	}
	if len(j.DLPMatches) != 1 || j.DLPMatches[0] != "cc" {
		t.Fatalf("job not tagged with DLP match: %v", j.DLPMatches)
	}
}

func TestValidateDLPBadRegex(t *testing.T) {
	c := defaultConfig()
	c.DLP = DLPConf{Enabled: true, Rules: []DLPRule{{Name: "bad", Mode: "regex", Pattern: "("}}}
	if !hasErrors(validateConfig(c)) {
		t.Fatal("bad DLP regex should be a validation error")
	}
}
