package main

import (
	"sync"
	"time"
)

// liveTap is a bounded, in-memory ring of the most recently captured packets,
// fed by the interceptor pump. It powers the dashboard's live capture view
// without depending on the pcap file being flushed: the dashboard polls with a
// cursor and gets everything new since last time. Only the first liveSnapLen
// bytes of each frame are retained (enough to dissect L2/L3/L4 headers for the
// summary row) so the ring's memory is tightly bounded — full payloads still
// live in the pcap file for follow-stream reassembly.

// liveRec is one retained packet: a header-sized copy plus its true wire length
// and timestamp.
type liveRec struct {
	ts      time.Time
	data    []byte // truncated to liveSnapLen
	origLen int    // full captured length on the wire
}

type liveTap struct {
	mu   sync.Mutex
	buf  []liveRec
	link int
	seq  uint64 // total packets ever recorded (monotonic cursor space)
	max  int
}

const (
	liveMaxPackets = 8000 // ring capacity
	liveSnapLen    = 256  // bytes retained per frame (header-sized)
)

var captureLive = &liveTap{max: liveMaxPackets}

// reset clears the ring at the start of a capture run.
func (t *liveTap) reset(link int) {
	t.mu.Lock()
	t.buf = t.buf[:0]
	t.link = link
	t.seq = 0
	t.mu.Unlock()
}

// record stores a (truncated) copy of one captured frame.
func (t *liveTap) record(p capturedPacket) {
	n := len(p.data)
	keep := n
	if keep > liveSnapLen {
		keep = liveSnapLen
	}
	rec := liveRec{ts: p.ts, data: append([]byte(nil), p.data[:keep]...), origLen: n}
	t.mu.Lock()
	t.buf = append(t.buf, rec)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:] // drop oldest
	}
	t.seq++
	t.mu.Unlock()
}

// since returns up to limit records recorded after cursor, the link type, the new
// cursor, the absolute ordinal of the first returned record, and how many records
// were dropped from the ring before the caller could read them.
func (t *liveTap) since(cursor uint64, limit int) (recs []liveRec, link int, newCursor, firstNo, dropped uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	link = t.link
	newCursor = t.seq
	firstIdx := t.seq - uint64(len(t.buf)) // absolute index of buf[0]
	start := cursor
	if start < firstIdx {
		dropped = firstIdx - start
		start = firstIdx
	}
	if start >= t.seq {
		return nil, link, newCursor, t.seq, dropped
	}
	off := int(start - firstIdx)
	avail := t.buf[off:]
	if limit > 0 && len(avail) > limit {
		off += len(avail) - limit // keep the newest `limit`
		avail = t.buf[off:]
	}
	out := make([]liveRec, len(avail))
	copy(out, avail)
	return out, link, newCursor, firstIdx + uint64(off) + 1, dropped // 1-based ordinal
}

// at returns the retained frame at 1-based ordinal `no` (the same number shown in
// the live view), if it is still in the ring. The bytes are header-truncated
// (liveSnapLen), enough for the packet-detail view.
func (t *liveTap) at(no uint64) (liveRec, int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	firstIdx := t.seq - uint64(len(t.buf)) // absolute index of buf[0]
	if no < firstIdx+1 || no > t.seq {
		return liveRec{}, t.link, false
	}
	return t.buf[int(no-1-firstIdx)], t.link, true
}

// stats reports the current cursor and ring depth (for the UI header).
func (t *liveTap) stats() (seq uint64, depth int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.seq, len(t.buf)
}
