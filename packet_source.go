package main

import (
	"fmt"
	"sync"
	"time"
)

// capturedPacket is one frame handed up from a packetSource: the wire bytes plus
// the timestamp the source observed it. Keeping this platform-neutral lets the
// orchestrator, the pcap writer, and the tests share one type while the actual
// live capture (gopacket/Npcap) stays quarantined in a build-tagged file.
type capturedPacket struct {
	ts   time.Time
	data []byte
}

// packetSource is anything that yields frames: the live Npcap handle on Windows,
// or a replay/stub source for tests and unsupported platforms. Packets() returns
// a receive channel that is closed when the source is exhausted or Close'd.
type packetSource interface {
	Packets() <-chan capturedPacket
	// LinkType reports the libpcap link-layer type of the frames (linkTypeEthernet,
	// linkTypeRaw, …) so the pcap file header matches the bytes.
	LinkType() int
	Close() error
}

// newLiveSource opens a live capture on the named interface. It is implemented
// per-platform: capture_windows.go provides the real Npcap-backed source; every
// other platform gets the stub in capture_stub.go that returns an error. Keeping
// the constructor behind a build tag is what lets the whole orchestrator compile
// and unit-test on macOS/Linux without the cgo pcap dependency.
//
// (declared here for documentation; the real symbol lives in the per-OS files)

// sliceSource is an in-memory packetSource used by tests and as the replay
// backend (e.g. re-reading a prior pcap). It emits the supplied packets in order
// then closes the channel. Close is safe to call before or during draining.
type sliceSource struct {
	link   int
	mu     sync.Mutex
	ch     chan capturedPacket
	done   chan struct{}
	closed bool
}

func newSliceSource(linkType int, pkts []capturedPacket) *sliceSource {
	if linkType == 0 {
		linkType = linkTypeEthernet
	}
	s := &sliceSource{
		link: linkType,
		ch:   make(chan capturedPacket),
		done: make(chan struct{}),
	}
	go func() {
		defer close(s.ch)
		for _, p := range pkts {
			select {
			case s.ch <- p:
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *sliceSource) Packets() <-chan capturedPacket { return s.ch }
func (s *sliceSource) LinkType() int                  { return s.link }

func (s *sliceSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	return nil
}

// unsupportedLiveCapture is the error reported by the stub live source. Kept as a
// helper so both the stub and tests can reference the same wording.
func unsupportedLiveCapture(platform string) error {
	return fmt.Errorf("intercept: live packet capture is not built into this binary (%s build without the npcap tag); rebuild on a Windows host with the Npcap SDK using -tags=npcap", platform)
}
