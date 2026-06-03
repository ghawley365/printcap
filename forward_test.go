package main

import (
	"strings"
	"testing"
)

// fakeTransport records sends and can be made to fail.
type fakeTransport struct {
	sent    [][]byte
	failErr error
}

func (f *fakeTransport) send(t *target, data []byte, j *job) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.sent = append(f.sent, append([]byte{}, data...))
	return nil
}

func TestForwarderRoutesAndTransforms(t *testing.T) {
	cfg = defaultConfig()
	fw, err := newForwarder(ForwardConf{
		Enabled: true,
		Macros:  map[string]string{"reset": `\x1bE`},
		Targets: []ForwardTarget{{
			Name: "t1", Transport: "raw", Address: "x", Failure: "block",
			When: ForwardCond{Protocols: []string{"IPP"}},
			Transforms: []TransformStep{
				{Type: "inject_prefix", Data: "macro:reset"},
				{Type: "replace", Mode: "literal", Match: "A", With: "B", All: true},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTransport{}
	fw.targets[0].send = ft

	j := &job{Protocol: "IPP"}
	if err := fw.forward(j, []byte("AAA")); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if len(ft.sent) != 1 || string(ft.sent[0]) != "\x1bEBBB" {
		t.Fatalf("sent=%v", ft.sent)
	}
	if len(j.Forwards) != 1 || j.Forwards[0].Status != "ok" {
		t.Fatalf("forwards=%+v", j.Forwards)
	}

	j2 := &job{Protocol: "9100"}
	_ = fw.forward(j2, []byte("AAA"))
	if len(ft.sent) != 1 {
		t.Fatalf("non-matching job should not forward; sent=%v", ft.sent)
	}
}

func TestForwarderBlockPolicyReturnsError(t *testing.T) {
	cfg = defaultConfig()
	fw, err := newForwarder(ForwardConf{
		Enabled: true,
		Targets: []ForwardTarget{{Name: "t1", Transport: "raw", Address: "x", Failure: "block"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fw.targets[0].send = &fakeTransport{failErr: errForward}
	j := &job{Protocol: "IPP"}
	if err := fw.forward(j, []byte("X")); err == nil {
		t.Fatal("block policy must return the delivery error")
	}
	if len(j.Forwards) != 1 || j.Forwards[0].Status != "failed" {
		t.Fatalf("forwards=%+v", j.Forwards)
	}
}

func TestForwarderBestEffortSwallowsError(t *testing.T) {
	cfg = defaultConfig()
	fw, _ := newForwarder(ForwardConf{
		Enabled: true,
		Targets: []ForwardTarget{{Name: "t1", Transport: "raw", Address: "x", Failure: "best_effort"}},
	})
	fw.targets[0].send = &fakeTransport{failErr: errForward}
	j := &job{Protocol: "IPP"}
	if err := fw.forward(j, []byte("X")); err != nil {
		t.Fatalf("best_effort must not return an error, got %v", err)
	}
	if len(j.Forwards) != 1 || j.Forwards[0].Status != "failed" {
		t.Fatalf("best_effort should record a failed status; forwards=%+v", j.Forwards)
	}
}

var errForward = func() error { return errString("boom") }()

type errString string

func (e errString) Error() string { return string(e) }

func TestUnknownTransportDisablesTarget(t *testing.T) {
	cfg = defaultConfig()
	fw, err := newForwarder(ForwardConf{
		Enabled: true,
		Targets: []ForwardTarget{{Name: "bad", Transport: "smb", Address: "x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.targets) != 0 {
		t.Fatalf("unknown transport should be disabled; targets=%d", len(fw.targets))
	}
	_ = strings.TrimSpace
}
