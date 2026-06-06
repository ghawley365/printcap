//go:build darwin

package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// capture_darwin.go is the macOS live-capture backend. It uses the kernel BPF
// devices (/dev/bpfN) directly through golang.org/x/sys/unix — NO cgo and NO
// libpcap/Npcap dependency — so a plain `go build` produces a binary that
// captures (given root or membership in the access_bpf group). Capture is
// passive: forwarding is a no-op and active ARP positioning is not offered here
// (that stays Windows-only); macOS always operates as a read-only tap.

// bpfWordAlign rounds up to the BPF record alignment (4 bytes on macOS).
func bpfWordAlign(x int) int { return (x + 3) &^ 3 }

// parseBPFRecords walks the BPF-format buffer the kernel returns (one or more
// records, each a bpf_hdr followed by the captured bytes, padded to the BPF
// alignment) and calls emit for each packet. On macOS bpf_hdr is:
//
//	struct timeval32 bh_tstamp;  // [0:8]  sec(int32) usec(int32)
//	uint32           bh_caplen;  // [8:12]
//	uint32           bh_datalen; // [12:16]
//	uint16           bh_hdrlen;  // [16:18]
//
// Field offsets are fixed; bh_hdrlen gives the actual (aligned) header length, so
// we step by WORDALIGN(hdrlen+caplen). emit returns false to stop early. Returns
// false if emit asked to stop.
func parseBPFRecords(buf []byte, emit func(ts time.Time, data []byte) bool) bool {
	p := 0
	for p+18 <= len(buf) {
		secs := int64(binary.LittleEndian.Uint32(buf[p:]))
		usec := int64(binary.LittleEndian.Uint32(buf[p+4:]))
		caplen := int(binary.LittleEndian.Uint32(buf[p+8:]))
		hdrlen := int(binary.LittleEndian.Uint16(buf[p+16:]))
		if hdrlen < 18 || caplen < 0 {
			break // malformed header; stop rather than risk a bad slice
		}
		start := p + hdrlen
		end := start + caplen
		if start < p || end > len(buf) {
			break // truncated final record
		}
		data := make([]byte, caplen)
		copy(data, buf[start:end])
		if !emit(time.Unix(secs, usec*1000), data) {
			return false
		}
		adv := bpfWordAlign(hdrlen + caplen)
		if adv <= 0 {
			break // no forward progress: stop
		}
		p += adv
	}
	return true
}

// dltToLinkType maps a BPF data-link type to our pcap link-type constants.
func dltToLinkType(dlt int) int {
	switch dlt {
	case 0: // DLT_NULL — BSD loopback (4-byte address-family header)
		return linkTypeNull
	case 1: // DLT_EN10MB — Ethernet
		return linkTypeEthernet
	case 12, 14: // DLT_RAW variants — bare IP
		return linkTypeRaw
	default:
		return dlt
	}
}

// bpfSource is a live packetSource backed by a BPF device.
type bpfSource struct {
	fd     int
	link   int
	bufLen int
	ch     chan capturedPacket
	done   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

func (s *bpfSource) Packets() <-chan capturedPacket { return s.ch }
func (s *bpfSource) LinkType() int                  { return s.link }

func (s *bpfSource) Close() error {
	s.once.Do(func() {
		close(s.done)        // tell the read loop to stop
		_ = unix.Close(s.fd) // unblock any in-flight read
	})
	s.wg.Wait() // the loop has returned: no more sends
	close(s.ch) // signal end-of-stream to the consumer
	return nil
}

// loop reads BPF records and forwards each packet to the channel until Close.
func (s *bpfSource) loop() {
	defer s.wg.Done()
	buf := make([]byte, s.bufLen)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, err := unix.Read(s.fd, buf)
		if err != nil {
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN: // non-blocking, no data yet
				time.Sleep(20 * time.Millisecond)
				continue
			default:
				return // fd closed on Close, or a real error
			}
		}
		if n <= 0 {
			continue
		}
		cont := parseBPFRecords(buf[:n], func(ts time.Time, data []byte) bool {
			select {
			case s.ch <- capturedPacket{ts: ts, data: data}:
				return true
			case <-s.done:
				return false
			}
		})
		if !cont {
			return
		}
	}
}

// openLiveSource opens a BPF device, binds it to the capture interface, and
// starts the read loop. It is the macOS implementation of the platform hook.
func openLiveSource(c InterceptConf) (packetSource, error) {
	iface := c.Interface
	if iface == "" {
		d, err := defaultCaptureInterface()
		if err != nil {
			return nil, err
		}
		iface = d
	}
	if c.BPF != "" {
		logWarn("intercept", "intercept.bpf (%q) is ignored on macOS — capture-time BPF filtering is Windows/Npcap-only; use the viewer's display filter instead", c.BPF)
	}

	fd, err := openBPFDevice()
	if err != nil {
		return nil, err
	}

	// Buffer length must be set BEFORE binding the interface.
	bufLen := 1 << 18 // 256 KiB
	_ = unix.IoctlSetInt(fd, unix.BIOCSBLEN, bufLen)
	if actual, e := unix.IoctlGetInt(fd, unix.BIOCGBLEN); e == nil && actual > 0 {
		bufLen = actual
	}

	if err := bpfSetInterface(fd, iface); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("intercept: binding capture to %q failed: %w", iface, err)
	}
	_ = unix.IoctlSetInt(fd, unix.BIOCIMMEDIATE, 1) // deliver packets as they arrive
	if c.Promiscuous {
		_ = unix.IoctlSetInt(fd, unix.BIOCPROMISC, 1)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("intercept: set non-blocking: %w", err)
	}

	dlt, _ := unix.IoctlGetInt(fd, unix.BIOCGDLT)
	s := &bpfSource{
		fd:     fd,
		link:   dltToLinkType(dlt),
		bufLen: bufLen,
		ch:     make(chan capturedPacket, 256),
		done:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.loop()
	logInfo("intercept", "BPF capture started on %s (dlt=%d, link=%d, buf=%d bytes)", iface, dlt, s.link, bufLen)
	return s, nil
}

// openBPFDevice opens the first available /dev/bpfN cloning device.
func openBPFDevice() (int, error) {
	var lastErr error
	for i := 0; i < 256; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		lastErr = err
		if err == unix.EBUSY {
			continue // in use; try the next one
		}
		if err == unix.EACCES {
			break // permission denied — no point trying more
		}
	}
	return -1, fmt.Errorf("intercept: cannot open a /dev/bpf device (need root or access_bpf group membership): %w", lastErr)
}

// bpfSetInterface issues BIOCSETIF with a struct ifreq naming the interface.
func bpfSetInterface(fd int, name string) error {
	var ifr [unix.IFNAMSIZ + 16]byte // ifr_name + ifru union space
	if len(name) >= unix.IFNAMSIZ {
		return fmt.Errorf("interface name %q too long", name)
	}
	copy(ifr[:], name)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BIOCSETIF), uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// newForwardingControl: passive capture needs no kernel forwarding on macOS.
func newForwardingControl(c InterceptConf) forwardingControl {
	return noopForwarding{}
}

// newARPController: active ARP positioning is not offered on macOS; capture is
// strictly passive here. The interceptor logs this and continues capture-only.
func newARPController(c ARPConf, targets []netip.Addr, gw netip.Addr) (arpController, error) {
	return nil, fmt.Errorf("intercept: active ARP positioning is not available on macOS (passive capture only)")
}
