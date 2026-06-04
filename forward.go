package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// forward is the process-wide forwarder, built by the Engine at Start (nil when
// forwarding is disabled).
var forward *forwarder

type forwarder struct {
	capture string
	macros  map[string][]byte
	targets []*target
	spool   *spoolStore // durable on-disk spool_retry queue (nil if it couldn't be created)
	wg      sync.WaitGroup
	done    chan struct{} // closed by Close() to release in-flight retry workers
}

func transportFor(name string) (transport, bool) {
	switch name {
	case "raw":
		return rawTransport{}, true
	case "lpr":
		return lprTransport{}, true
	case "ipp", "ipps":
		return ippTransport{}, true
	}
	return nil, false
}

func newForwarder(c ForwardConf) (*forwarder, error) {
	f := &forwarder{capture: orElse(c.Capture, "both"), macros: map[string][]byte{}, done: make(chan struct{})}
	for name, raw := range c.Macros {
		f.macros[name] = decodeBytes(raw, nil)
	}
	for _, tc := range c.Targets {
		send, ok := transportFor(tc.Transport)
		if !ok {
			logWarn("fwd", "target %q: unknown transport %q, disabled", tc.Name, tc.Transport)
			continue
		}
		cond, err := compileCond(tc.When)
		if err != nil {
			logWarn("fwd", "target %q: %v, disabled", tc.Name, err)
			continue
		}
		steps, err := f.compileSteps(tc.Transforms)
		if err != nil {
			logWarn("fwd", "target %q: %v, disabled", tc.Name, err)
			continue
		}
		f.targets = append(f.targets, &target{
			name: tc.Name, transport: tc.Transport, address: tc.Address,
			timeout: time.Duration(tc.TimeoutMS) * time.Millisecond,
			queue:   tc.Queue, privPort: tc.PrivilegedSourcePort,
			tlsSkip: tc.TLSSkipVerify, docFormat: tc.DocumentFormat,
			when: cond, failure: orElse(tc.Failure, "best_effort"),
			retry: tc.Retry, steps: steps, send: send,
		})
	}

	// Create the durable spool_retry store. If it can't be created, forwarding
	// still works — just not durably (a restart could drop in-flight retries).
	if st, err := newSpoolStore(filepath.Join(spoolDir(), "forward-retry")); err != nil {
		logErr("fwd", "spool: durable retry queue disabled: %v", err)
	} else {
		f.spool = st
		f.replaySpool()
	}
	return f, nil
}

// replaySpool reloads any persisted spool_retry items from disk and resumes a
// durable retry loop for each. Items whose target no longer exists in config are
// left on disk (a future config may restore the target). NextAttempt is honored
// by retryLoopPersisted so we don't hammer immediately on restart.
func (f *forwarder) replaySpool() {
	items, err := f.spool.load()
	if err != nil {
		logErr("fwd", "spool: replay load failed: %v", err)
		return
	}
	for _, m := range items {
		t := f.targetByName(m.Target)
		if t == nil {
			logWarn("fwd", "spool: item %s targets unknown target %q, leaving on disk", m.ID, m.Target)
			continue
		}
		logInfo("fwd", "spool: replaying item %s for target %q (attempts=%d)", m.ID, m.Target, m.Attempts)
		mm := m
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.retryLoopPersisted(t, mm) }()
	}
}

func (f *forwarder) targetByName(name string) *target {
	for _, t := range f.targets {
		if t.name == name {
			return t
		}
	}
	return nil
}

func (f *forwarder) compileSteps(in []TransformStep) ([]compiledStep, error) {
	var out []compiledStep
	for _, s := range in {
		cs := compiledStep{kind: s.Type, mode: s.Mode, all: s.All}
		// ForwardCond contains slices and is not comparable, so always compile:
		// compileCond returns a non-nil *compiledCond whose matches() returns true
		// for an empty condition, so an always-apply step still works.
		cond, err := compileCond(s.When)
		if err != nil {
			return nil, fmt.Errorf("transform when: %w", err)
		}
		cs.when = cond
		switch s.Type {
		case "inject_prefix", "inject_suffix":
			cs.data = decodeBytes(s.Data, f.macros)
		case "replace":
			switch s.Mode {
			case "regex":
				re, err := compileRegex(s.Match)
				if err != nil {
					return nil, err
				}
				cs.re = re
				cs.withS = decodeRegexReplacement(s.With)
			case "hex":
				m, err := hex.DecodeString(s.Match)
				if err != nil {
					return nil, fmt.Errorf("bad hex match: %w", err)
				}
				w, err := hex.DecodeString(s.With)
				if err != nil {
					return nil, fmt.Errorf("bad hex with: %w", err)
				}
				cs.match, cs.with = m, w
			default: // literal
				cs.match = decodeBytes(s.Match, f.macros)
				cs.with = decodeBytes(s.With, f.macros)
			}
		default:
			return nil, fmt.Errorf("unknown transform type %q", s.Type)
		}
		out = append(out, cs)
	}
	return out, nil
}

// forward tees the job to every matching target. Returns the first error from a
// target whose failure policy is "block".
func (f *forwarder) forward(j *job, original []byte) error {
	var blockErr error
	for _, t := range f.targets {
		if t.when != nil && !t.when.matches(j, original) {
			logDebug("fwd", "target %q: condition not met, skipping", t.name)
			continue
		}
		out := applyTransforms(t.steps, original, j)
		captureTransformed(f.capture, j, t.name, out)
		if err := f.deliver(t, out, j); err != nil && t.failure == "block" && blockErr == nil {
			blockErr = err
		}
	}
	return blockErr
}

// deliver applies the target's failure policy.
//   - best_effort: deliver SYNCHRONOUSLY (bounded by the target timeout), record
//     the real outcome ("ok"/"failed"), but swallow the error (return nil).
//   - block: deliver synchronously, record the real status, and return the error.
//   - spool_retry: record "queued" synchronously, then hand off to a background
//     worker for retries. The worker MUST NOT touch j.Forwards after this returns.
func (f *forwarder) deliver(t *target, data []byte, j *job) error {
	record := func(status string, err error) {
		res := forwardResult{Target: t.name, Transport: t.transport, Address: t.address,
			Status: status, Bytes: len(data)}
		if err != nil {
			res.Error = err.Error()
		}
		j.Forwards = append(j.Forwards, res)
	}
	switch t.failure {
	case "block":
		if err := t.send.send(t, data, j); err != nil {
			logWarn("fwd", "target %q: forward failed (block): %v", t.name, err)
			record("failed", err)
			return err
		}
		logInfo("fwd", "forwarded %d bytes to %q", len(data), t.name)
		record("ok", nil)
		return nil
	case "spool_retry":
		record("queued", nil)
		payload := append([]byte{}, data...)
		now := time.Now()
		m := &spoolMeta{
			Target: t.name, Attempts: 0, FirstSeen: now, NextAttempt: now,
			Host: j.Host, User: j.User, JobName: j.JobName, Queue: j.Queue,
		}
		if t.retry.TTLMin > 0 {
			m.Deadline = now.Add(time.Duration(t.retry.TTLMin) * time.Minute)
		}
		if f.spool == nil {
			// No durable store: fall back to a best-effort in-memory retry so we
			// still attempt delivery (just not crash-safe).
			logWarn("fwd", "target %q: spool store unavailable, retrying in-memory (not durable)", t.name)
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.retryLoopMem(t, payload, m) }()
			return nil
		}
		if err := f.spool.put(m, payload); err != nil {
			logErr("fwd", "target %q: failed to persist spool item: %v", t.name, err)
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.retryLoopMem(t, payload, m) }()
			return nil
		}
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.retryLoopPersisted(t, m) }()
		return nil
	default: // best_effort
		if err := t.send.send(t, data, j); err != nil {
			logWarn("fwd", "target %q: forward failed (best_effort): %v", t.name, err)
			record("failed", err)
		} else {
			logInfo("fwd", "forwarded %d bytes to %q", len(data), t.name)
			record("ok", nil)
		}
		return nil
	}
}

// retryLimits returns the effective max attempts and backoff for a target,
// applying the historical defaults (3 attempts, 2s backoff).
func (t *target) retryLimits() (max int, backoff time.Duration) {
	max = t.retry.MaxAttempts
	if max <= 0 {
		max = 3
	}
	backoff = time.Duration(t.retry.BackoffMS) * time.Millisecond
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	return
}

func jobFromMeta(m *spoolMeta) *job {
	return &job{Host: m.Host, User: m.User, JobName: m.JobName, Queue: m.Queue}
}

// retryLoopPersisted is the durable spool_retry worker. It loads the payload
// from the store once, then retries with backoff up to max_attempts OR the TTL
// deadline. Successful delivery removes the persisted item; a give-up (max
// attempts or TTL) dead-letters it. On shutdown (f.done) it returns WITHOUT
// deleting the item — the item survives and is replayed by the next
// newForwarder. That is the durability guarantee.
func (f *forwarder) retryLoopPersisted(t *target, m *spoolMeta) {
	max, backoff := t.retryLimits()
	payload, err := f.spool.payload(m.ID)
	if err != nil {
		logErr("fwd", "target %q: spool item %s payload unreadable, dead-lettering: %v", t.name, m.ID, err)
		if derr := f.spool.deadLetter(m.ID); derr != nil {
			logErr("fwd", "target %q: dead-letter %s failed: %v", t.name, m.ID, derr)
		}
		return
	}
	j := jobFromMeta(m)

	// Honor a future NextAttempt across a restart: sleep until it's due,
	// releasing promptly on shutdown.
	if d := time.Until(m.NextAttempt); d > 0 {
		select {
		case <-f.done:
			return
		case <-time.After(d):
		}
	}

	for {
		if !m.Deadline.IsZero() && time.Now().After(m.Deadline) {
			logErr("fwd", "target %q: spool item %s TTL expired after %d attempt(s), dead-lettering", t.name, m.ID, m.Attempts)
			if derr := f.spool.deadLetter(m.ID); derr != nil {
				logErr("fwd", "target %q: dead-letter %s failed: %v", t.name, m.ID, derr)
			}
			return
		}
		if err := t.send.send(t, payload, j); err == nil {
			logInfo("fwd", "target %q: spooled job %s delivered on attempt %d", t.name, m.ID, m.Attempts+1)
			if rerr := f.spool.remove(m.ID); rerr != nil {
				logErr("fwd", "target %q: removing delivered spool item %s failed: %v", t.name, m.ID, rerr)
			}
			return
		} else {
			m.Attempts++
			m.NextAttempt = time.Now().Add(backoff)
			logWarn("fwd", "target %q: spool item %s attempt %d/%d failed: %v", t.name, m.ID, m.Attempts, max, err)
			if uerr := f.spool.update(m); uerr != nil {
				logErr("fwd", "target %q: updating spool item %s failed: %v", t.name, m.ID, uerr)
			}
			if m.Attempts >= max {
				logErr("fwd", "target %q: giving up on spool item %s after %d attempts, dead-lettering", t.name, m.ID, m.Attempts)
				if derr := f.spool.deadLetter(m.ID); derr != nil {
					logErr("fwd", "target %q: dead-letter %s failed: %v", t.name, m.ID, derr)
				}
				return
			}
		}
		select {
		case <-f.done:
			// Shutdown: leave the item persisted; it is replayed next start.
			return
		case <-time.After(backoff):
		}
	}
}

// retryLoopMem is the non-durable fallback used only when the spool store could
// not be created or a put failed. It retries in memory and is abandoned on
// shutdown (lost on restart) — same behavior as the pre-durability code.
func (f *forwarder) retryLoopMem(t *target, payload []byte, m *spoolMeta) {
	max, backoff := t.retryLimits()
	j := jobFromMeta(m)
	for attempt := 1; attempt <= max; attempt++ {
		if !m.Deadline.IsZero() && time.Now().After(m.Deadline) {
			logErr("fwd", "target %q: TTL expired after %d attempt(s)", t.name, attempt-1)
			return
		}
		if err := t.send.send(t, payload, j); err == nil {
			logInfo("fwd", "target %q: spooled job delivered on attempt %d (in-memory)", t.name, attempt)
			return
		} else {
			logWarn("fwd", "target %q: attempt %d/%d failed: %v", t.name, attempt, max, err)
		}
		select {
		case <-f.done:
			logWarn("fwd", "target %q: shutdown during retry, abandoning in-memory spooled job", t.name)
			return
		case <-time.After(backoff):
		}
	}
	logErr("fwd", "target %q: giving up after %d attempts (in-memory)", t.name, max)
}

// Close signals in-flight retry workers to stop and waits for them to exit.
func (f *forwarder) Close() error {
	if f.done != nil {
		close(f.done)
	}
	f.wg.Wait()
	return nil
}

func compileRegex(p string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("bad regex %q: %w", p, err)
	}
	return re, nil
}

// decodeRegexReplacement turns \xNN escapes in a regex replacement template into
// literal bytes while leaving $1-style backreferences intact.
func decodeRegexReplacement(s string) string {
	return string(decodeBytes(s, nil))
}

// captureTransformed writes the post-transform bytes when capture mode includes
// the sent copy. Filename mirrors the original's base with a -sent-<target> tag.
// (j.captureBase/captureExt are set by sink.save in Task 8; empty => skip.)
func captureTransformed(mode string, j *job, targetName string, data []byte) {
	if mode == "orig" {
		return
	}
	base := j.captureBase
	if base == "" {
		return
	}
	name := fmt.Sprintf("%s-sent-%s%s", base, unsafeName.ReplaceAllString(targetName, "_"), j.captureExt)
	if err := os.WriteFile(filepath.Join(sink.dir, name), data, 0o600); err != nil {
		logErr("fwd", "failed to write transformed capture: %v", err)
	}
}
