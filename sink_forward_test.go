package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSinkSaveTeesAndCapturesBoth(t *testing.T) {
	cfg = defaultConfig()
	cfg.OutDir = t.TempDir()
	sink = &captureSink{dir: cfg.OutDir}
	store = newJobStore(10)

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	fwd, err := newForwarder(ForwardConf{
		Enabled: true, Capture: "both",
		Targets: []ForwardTarget{{
			Name: "lab", Transport: "raw", Address: ln.Addr().String(), Failure: "block",
			Transforms: []TransformStep{{Type: "replace", Mode: "literal", Match: "FOO", With: "BAR", All: true}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	forward = fwd
	defer func() { forward = nil }()

	j := &job{Protocol: "9100", Source: "127.0.0.1:1234"}
	j.data = []byte("FOO baz")
	j.Bytes = len(j.data)
	if err := sink.save(j); err != nil {
		t.Fatalf("save: %v", err)
	}

	entries, _ := os.ReadDir(cfg.OutDir)
	var sawOrig, sawSent bool
	for _, e := range entries {
		n := e.Name()
		if strings.Contains(n, "-sent-lab") {
			sawSent = true
			b, _ := os.ReadFile(filepath.Join(cfg.OutDir, n))
			if string(b) != "BAR baz" {
				t.Fatalf("sent file content %q", b)
			}
		} else if strings.HasSuffix(n, ".prn") || strings.HasSuffix(n, ".txt") {
			sawOrig = true
		}
	}
	if !sawOrig || !sawSent {
		t.Fatalf("orig=%v sent=%v entries=%v", sawOrig, sawSent, names(entries))
	}
	if len(j.Forwards) != 1 || j.Forwards[0].Status != "ok" {
		t.Fatalf("forwards=%+v", j.Forwards)
	}
	_ = time.Second
}

func names(es []os.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}
