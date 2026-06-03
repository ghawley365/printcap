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
	return f, nil
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
		rj := &job{Host: j.Host, User: j.User, JobName: j.JobName, Queue: j.Queue}
		payload := append([]byte{}, data...)
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.retryLoop(t, payload, rj) }()
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

// retryLoop attempts delivery with backoff up to max_attempts OR the ttl_min
// wall-clock deadline. It carries a cloned job (preserving LPR H/P/J) and selects
// on f.done during backoff so Close() releases it promptly.
func (f *forwarder) retryLoop(t *target, data []byte, j *job) {
	max := t.retry.MaxAttempts
	if max <= 0 {
		max = 3
	}
	backoff := time.Duration(t.retry.BackoffMS) * time.Millisecond
	if backoff <= 0 {
		backoff = 2 * time.Second
	}
	var deadline time.Time
	if t.retry.TTLMin > 0 {
		deadline = time.Now().Add(time.Duration(t.retry.TTLMin) * time.Minute)
	}
	for attempt := 1; attempt <= max; attempt++ {
		if !deadline.IsZero() && time.Now().After(deadline) {
			logErr("fwd", "target %q: TTL (%d min) expired after %d attempt(s)", t.name, t.retry.TTLMin, attempt-1)
			return
		}
		if err := t.send.send(t, data, j); err == nil {
			logInfo("fwd", "target %q: spooled job delivered on attempt %d", t.name, attempt)
			return
		} else {
			logWarn("fwd", "target %q: attempt %d/%d failed: %v", t.name, attempt, max, err)
		}
		select {
		case <-f.done:
			logWarn("fwd", "target %q: shutdown during retry, abandoning spooled job", t.name)
			return
		case <-time.After(backoff):
		}
	}
	logErr("fwd", "target %q: giving up after %d attempts", t.name, max)
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
