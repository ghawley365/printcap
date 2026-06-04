package main

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// flakyTransport fails its first failFirst sends, then succeeds, recording every
// delivered payload. Safe for the concurrent spool_retry worker.
type flakyTransport struct {
	mu        sync.Mutex
	failFirst int // fail this many times, then succeed
	calls     int
	delivered [][]byte
}

func (ft *flakyTransport) send(t *target, data []byte, j *job) error {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.calls++
	if ft.calls <= ft.failFirst {
		return fmt.Errorf("flaky: induced failure %d", ft.calls)
	}
	ft.delivered = append(ft.delivered, append([]byte{}, data...))
	return nil
}

// newTestForwarder builds a forwarder with a single target wired to ft and a
// fresh on-disk spool store under a temp SpoolDir.
func newTestForwarder(t *testing.T, ft transport, retry ForwardRetry, failure string) (*forwarder, *target) {
	cfg = defaultConfig()
	cfg.Storage.SpoolDir = t.TempDir()
	f := &forwarder{capture: "both", macros: map[string][]byte{}, done: make(chan struct{})}
	st, err := newSpoolStore(filepath.Join(spoolDir(), "forward-retry"))
	if err != nil {
		t.Fatal(err)
	}
	f.spool = st
	tg := &target{name: "lab", transport: "raw", address: "x", failure: failure, retry: retry, send: ft}
	f.targets = []*target{tg}
	return f, tg
}

func TestSpoolRetrySucceedsAfterFailures(t *testing.T) {
	ft := &flakyTransport{failFirst: 2}
	f, tg := newTestForwarder(t, ft, ForwardRetry{MaxAttempts: 5, BackoffMS: 5}, "spool_retry")
	m := &spoolMeta{Target: tg.name, NextAttempt: time.Now(), JobName: "doc"}
	if err := f.spool.put(m, []byte("PCLDATA")); err != nil {
		t.Fatal(err)
	}
	f.wg.Add(1)
	go func() { defer f.wg.Done(); f.retryLoopPersisted(tg, m) }()
	f.wg.Wait()
	if len(ft.delivered) != 1 || string(ft.delivered[0]) != "PCLDATA" {
		t.Fatalf("not delivered: %v", ft.delivered)
	}
	// On success the persisted files are removed.
	left, _ := f.spool.load()
	if len(left) != 0 {
		t.Fatalf("spool not cleaned after success: %d", len(left))
	}
}

func TestSpoolRetryPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg = defaultConfig()
	cfg.Storage.SpoolDir = dir
	// Forwarder #1: target always fails, shut down mid-retry -> item stays on disk.
	ftFail := &flakyTransport{failFirst: 1000}
	f1, tg1 := newTestForwarder(t, ftFail, ForwardRetry{MaxAttempts: 1000, BackoffMS: 20}, "spool_retry")
	_ = tg1
	// newTestForwarder reset cfg.Storage.SpoolDir to a NEW temp; point store + cfg back.
	cfg.Storage.SpoolDir = dir
	st1, _ := newSpoolStore(filepath.Join(dir, "forward-retry"))
	f1.spool = st1
	m := &spoolMeta{Target: "lab", NextAttempt: time.Now(), JobName: "persist"}
	f1.spool.put(m, []byte("KEEPME"))
	f1.wg.Add(1)
	go func() { defer f1.wg.Done(); f1.retryLoopPersisted(f1.targets[0], m) }()
	time.Sleep(30 * time.Millisecond)
	f1.Close() // abandons in-memory worker; file remains
	if items, _ := f1.spool.load(); len(items) == 0 {
		t.Fatal("item must persist across shutdown")
	}
	// Forwarder #2 over the SAME spool dir with a now-healthy target replays + delivers.
	ftOK := &flakyTransport{failFirst: 0}
	f2, _ := newTestForwarder(t, ftOK, ForwardRetry{MaxAttempts: 5, BackoffMS: 5}, "spool_retry")
	cfg.Storage.SpoolDir = dir
	st2, _ := newSpoolStore(filepath.Join(dir, "forward-retry"))
	f2.spool = st2
	// Manually drive replay (mirror what newForwarder does):
	items, _ := st2.load()
	for _, it := range items {
		it := it
		f2.wg.Add(1)
		go func() { defer f2.wg.Done(); f2.retryLoopPersisted(f2.targets[0], it) }()
	}
	f2.wg.Wait()
	if len(ftOK.delivered) != 1 || string(ftOK.delivered[0]) != "KEEPME" {
		t.Fatalf("replay did not deliver persisted job: %v", ftOK.delivered)
	}
	if left, _ := st2.load(); len(left) != 0 {
		t.Fatal("spool not cleaned after replayed delivery")
	}
}

func TestSpoolRetryDeadLettersOnGiveUp(t *testing.T) {
	ft := &flakyTransport{failFirst: 1000}
	f, tg := newTestForwarder(t, ft, ForwardRetry{MaxAttempts: 2, BackoffMS: 5}, "spool_retry")
	m := &spoolMeta{Target: tg.name, NextAttempt: time.Now()}
	f.spool.put(m, []byte("DEAD"))
	f.wg.Add(1)
	go func() { defer f.wg.Done(); f.retryLoopPersisted(tg, m) }()
	f.wg.Wait()
	// Active queue empty, dead-letter dir has the item.
	if left, _ := f.spool.load(); len(left) != 0 {
		t.Fatalf("active queue should be empty: %d", len(left))
	}
	deadEntries, _ := filepath.Glob(filepath.Join(f.spool.dir, "dead", "*.json"))
	if len(deadEntries) != 1 {
		t.Fatalf("expected 1 dead-letter, got %d", len(deadEntries))
	}
}

// load must tolerate a corrupt .json (skip with a warning, no panic) and a
// .json without its .data payload.
func TestSpoolLoadToleratesCorruptAndPartial(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "forward-retry")
	st, err := newSpoolStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A good item.
	good := &spoolMeta{Target: "lab", NextAttempt: time.Now()}
	if err := st.put(good, []byte("OK")); err != nil {
		t.Fatal(err)
	}
	// A corrupt .json.
	if err := writeFileAtomic(filepath.Join(dir, "corrupt.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A .json with no matching .data.
	if err := writeFileAtomic(filepath.Join(dir, "orphan.json"), []byte(`{"id":"orphan","target":"lab"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := st.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != good.ID {
		t.Fatalf("expected only the good item, got %d: %+v", len(items), items)
	}
}
