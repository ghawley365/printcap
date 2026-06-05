package main

import (
	"strings"
	"sync"
	"testing"
	"time"
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

// countingTransport fails its first failFirst sends, then succeeds, closing
// succeeded on the first success. Safe for the concurrent spool_retry worker.
type countingTransport struct {
	mu        sync.Mutex
	calls     int
	failFirst int
	succeeded chan struct{}
	closeOnce sync.Once
}

func (c *countingTransport) send(t *target, data []byte, j *job) error {
	c.mu.Lock()
	c.calls++
	fail := c.calls <= c.failFirst
	c.mu.Unlock()
	if fail {
		return errForward
	}
	// Close once on first success. The channel field is never reassigned (it's set
	// at construction), so the test reading it in a select does not race this.
	if c.succeeded != nil {
		c.closeOnce.Do(func() { close(c.succeeded) })
	}
	return nil
}

func (c *countingTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// spool_retry records "queued" synchronously (never blocks the sender), then a
// background worker retries with backoff until it succeeds.
func TestForwarderSpoolRetryDeliversThenCloses(t *testing.T) {
	cfg = defaultConfig()
	fw, err := newForwarder(ForwardConf{
		Enabled: true,
		Targets: []ForwardTarget{{
			Name: "t1", Transport: "raw", Address: "x", Failure: "spool_retry",
			Retry: ForwardRetry{MaxAttempts: 5, BackoffMS: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ct := &countingTransport{failFirst: 2, succeeded: make(chan struct{})} // fail twice, succeed on the 3rd
	fw.targets[0].send = ct

	j := &job{Protocol: "IPP"}
	if err := fw.forward(j, []byte("X")); err != nil {
		t.Fatalf("spool_retry must not block/return: %v", err)
	}
	if len(j.Forwards) != 1 || j.Forwards[0].Status != "queued" {
		t.Fatalf("expected a synchronous 'queued' record; forwards=%+v", j.Forwards)
	}

	// Wait for the background worker to deliver (do NOT Close() first — Close
	// abandons in-flight retries by design).
	select {
	case <-ct.succeeded:
	case <-time.After(5 * time.Second):
		t.Fatal("spool_retry worker did not deliver within 5s")
	}
	if got := ct.count(); got != 3 {
		t.Fatalf("expected 3 attempts (2 fail + 1 ok), got %d", got)
	}
	fw.Close() // worker already done; Close returns promptly
}

// Close() must release a worker that is mid-backoff promptly via the done channel,
// rather than waiting out a long backoff.
func TestForwarderCloseReleasesRetryWorker(t *testing.T) {
	cfg = defaultConfig()
	fw, err := newForwarder(ForwardConf{
		Enabled: true,
		Targets: []ForwardTarget{{
			Name: "t1", Transport: "raw", Address: "x", Failure: "spool_retry",
			Retry: ForwardRetry{MaxAttempts: 100, BackoffMS: 60000}, // 60s backoff
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fw.targets[0].send = &fakeTransport{failErr: errForward} // always fails → enters backoff
	_ = fw.forward(&job{Protocol: "IPP"}, []byte("X"))

	done := make(chan struct{})
	go func() { fw.Close(); close(done) }()
	select {
	case <-done: // released despite the 60s backoff
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release the mid-backoff retry worker within 5s")
	}
}

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
