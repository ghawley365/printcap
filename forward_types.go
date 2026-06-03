package main

import "time"

// transport delivers a (possibly transformed) job to one downstream target.
type transport interface {
	send(t *target, data []byte, j *job) error
}

// ForwardRetry bounds spool_retry delivery attempts (used by ForwardTarget config
// and the compiled target).
type ForwardRetry struct {
	MaxAttempts int `json:"max_attempts"`
	BackoffMS   int `json:"backoff_ms"`
	TTLMin      int `json:"ttl_min"`
}

// forwardResult is the per-target outcome recorded on a job (serialized in its
// .json sidecar and shown on the dashboard).
type forwardResult struct {
	Target    string `json:"target"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Status    string `json:"status"` // ok | failed | queued
	Bytes     int    `json:"bytes"`
	Error     string `json:"error,omitempty"`
}

// target is the compiled, runtime form of a ForwardTarget.
type target struct {
	name      string
	transport string
	address   string
	timeout   time.Duration
	queue     string
	privPort  bool
	tlsSkip   bool
	docFormat string
	when      *compiledCond
	failure   string
	retry     ForwardRetry
	steps     []compiledStep
	send      transport
}
