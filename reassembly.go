package main

import (
	"net/netip"
	"time"
)

// Lightweight, single-direction TCP reassembly for the pcap-carver. A print job
// is a bulk, mostly-in-order transfer from client to printer, so we do not need a
// full TCP stack — just enough to turn the client->printer half of a flow back
// into the contiguous byte stream the application sent. We track only flows whose
// destination port is a print port (that is the direction carrying the document).
//
// Handled: in-order segments, basic out-of-order buffering, retransmit/overlap
// de-duplication, sequence-number wraparound, FIN/RST teardown, and idle/stop
// flushing of streams that never close cleanly. Not handled: SACK gaps that never
// fill (the missing bytes are simply absent from the carved stream).

// flowKey identifies one unidirectional flow (client -> print port).
type flowKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// flowState accumulates the in-order payload of one flow.
type flowState struct {
	src, dst netip.AddrPort
	next     uint32            // next absolute sequence number expected in-order
	have     bool              // next has been initialized (SYN or first data seen)
	buf      []byte            // assembled, contiguous payload from the stream start
	pending  map[uint32][]byte // out-of-order segments: absolute seq -> payload copy
	last     time.Time         // timestamp of the most recent segment (for idle flush)
	overflow bool              // per-flow cap hit; buf was truncated
}

// streamReassembler routes segments to per-flow state and emits a flow's
// assembled bytes when it completes (FIN/RST), goes idle, or is flushed.
type streamReassembler struct {
	ports    map[uint16]bool
	maxFlow  int           // per-flow byte cap (0 = unlimited)
	idle     time.Duration // flush a flow this long after its last segment (0 = never)
	flows    map[flowKey]*flowState
	emit     func(*flowState)
	latestTS time.Time // newest timestamp seen, drives idle sweeps
}

func newStreamReassembler(ports map[uint16]bool, maxFlow int, idle time.Duration, emit func(*flowState)) *streamReassembler {
	return &streamReassembler{
		ports:   ports,
		maxFlow: maxFlow,
		idle:    idle,
		flows:   map[flowKey]*flowState{},
		emit:    emit,
	}
}

// maxPendingSegs caps the out-of-order segments buffered per flow. A lossy or
// hostile stream that never fills a gap would otherwise grow the pending map
// without bound; past this many waiting segments we stop buffering new ones (the
// flow is marked overflow and its carved file will be truncated/gappy).
const maxPendingSegs = 2048

// seqAfter reports whether a is after b in TCP sequence space (handles wrap).
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

// consume feeds one parsed segment, stamped ts, into the reassembler.
func (r *streamReassembler) consume(seg l4Segment, ts time.Time) {
	if !r.ports[seg.dst.Port()] {
		return // not a flow toward a print port; ignore (and ignore the return path)
	}
	if ts.After(r.latestTS) {
		r.latestTS = ts
	}

	key := flowKey{src: seg.src, dst: seg.dst}
	fs := r.flows[key]
	if fs == nil {
		fs = &flowState{src: seg.src, dst: seg.dst, pending: map[uint32][]byte{}}
		r.flows[key] = fs
	}
	fs.last = ts

	// A SYN names the byte before the first data byte; the first data segment of a
	// capture that missed the SYN seeds the baseline from its own sequence number.
	if seg.syn {
		fs.next = seg.seq + 1
		fs.have = true
	}
	if len(seg.payload) > 0 {
		if !fs.have {
			fs.next = seg.seq
			fs.have = true
		}
		r.integrate(fs, seg.seq, seg.payload)
	}
	if seg.fin || seg.rst {
		r.complete(key)
	}

	r.sweepIdle()
}

// integrate places one segment's payload into the flow, in order, dropping bytes
// already seen and buffering bytes that arrive early.
func (r *streamReassembler) integrate(fs *flowState, seq uint32, payload []byte) {
	switch {
	case seq == fs.next:
		r.appendInOrder(fs, payload)
		r.drainPending(fs)
	case seqAfter(seq, fs.next):
		// Future segment: buffer a copy until the gap fills, but bound the buffer
		// so a never-filled gap can't grow memory without limit.
		if _, exists := fs.pending[seq]; !exists && len(fs.pending) >= maxPendingSegs {
			fs.overflow = true
			return
		}
		cp := append([]byte(nil), payload...)
		fs.pending[seq] = cp
	default:
		// seq is at or before next: retransmit/overlap. Keep only the new tail.
		end := seq + uint32(len(payload))
		if seqAfter(end, fs.next) {
			skip := fs.next - seq
			if int(skip) < len(payload) {
				r.appendInOrder(fs, payload[skip:])
				r.drainPending(fs)
			}
		}
		// else: wholly duplicate, drop.
	}
}

// appendInOrder copies payload onto the assembled buffer, advances next, and
// enforces the per-flow cap.
func (r *streamReassembler) appendInOrder(fs *flowState, payload []byte) {
	if r.maxFlow > 0 && len(fs.buf) >= r.maxFlow {
		fs.overflow = true
		fs.next += uint32(len(payload)) // keep sequencing sane; just stop storing
		return
	}
	if r.maxFlow > 0 && len(fs.buf)+len(payload) > r.maxFlow {
		take := r.maxFlow - len(fs.buf)
		fs.buf = append(fs.buf, payload[:take]...)
		fs.overflow = true
	} else {
		fs.buf = append(fs.buf, payload...)
	}
	fs.next += uint32(len(payload))
}

// drainPending folds any buffered out-of-order segments that have become
// contiguous into the assembled stream.
func (r *streamReassembler) drainPending(fs *flowState) {
	for {
		cp, ok := fs.pending[fs.next]
		if !ok {
			return
		}
		delete(fs.pending, fs.next)
		r.appendInOrder(fs, cp)
	}
}

// complete emits a flow and removes it.
func (r *streamReassembler) complete(key flowKey) {
	fs := r.flows[key]
	if fs == nil {
		return
	}
	delete(r.flows, key)
	if r.emit != nil {
		r.emit(fs)
	}
}

// sweepIdle flushes flows whose last segment is older than the idle window,
// measured against the newest timestamp seen on the wire.
func (r *streamReassembler) sweepIdle() {
	if r.idle <= 0 {
		return
	}
	for key, fs := range r.flows {
		if r.latestTS.Sub(fs.last) >= r.idle {
			delete(r.flows, key)
			if r.emit != nil {
				r.emit(fs)
			}
		}
	}
}

// flush emits every remaining flow (used at capture teardown so a job still in
// flight when capture stops is not lost) and clears state.
func (r *streamReassembler) flush() {
	for key, fs := range r.flows {
		delete(r.flows, key)
		if r.emit != nil {
			r.emit(fs)
		}
	}
}
