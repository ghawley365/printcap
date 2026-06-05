//go:build linux

package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// capture_linux.go is the Linux live-capture backend. It uses an AF_PACKET raw
// socket through golang.org/x/sys/unix — NO cgo and NO libpcap dependency — so a
// plain `go build` produces a binary that captures (given root or CAP_NET_RAW).
// Capture is passive: forwarding is a no-op and active ARP positioning is not
// offered here (that stays Windows-only).

const ethPAll = 0x0003 // ETH_P_ALL

// htons converts a uint16 to network byte order for the AF_PACKET protocol field.
func htons(x uint16) uint16 { return (x << 8) | (x >> 8) }

type afpacketSource struct {
	fd   int
	link int
	ch   chan capturedPacket
	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

func (s *afpacketSource) Packets() <-chan capturedPacket { return s.ch }
func (s *afpacketSource) LinkType() int                  { return s.link }

func (s *afpacketSource) Close() error {
	s.once.Do(func() {
		close(s.done)
		_ = unix.Close(s.fd)
	})
	s.wg.Wait()
	close(s.ch)
	return nil
}

func (s *afpacketSource) loop() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			switch err {
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				time.Sleep(20 * time.Millisecond)
				continue
			default:
				return
			}
		}
		if n <= 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case s.ch <- capturedPacket{ts: time.Now(), data: data}:
		case <-s.done:
			return
		}
	}
}

// openLiveSource opens an AF_PACKET socket bound to the capture interface and
// starts the read loop. It is the Linux implementation of the platform hook.
func openLiveSource(c InterceptConf) (packetSource, error) {
	iface := c.Interface
	if iface == "" {
		d, err := defaultCaptureInterface()
		if err != nil {
			return nil, err
		}
		iface = d
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("intercept: AF_PACKET socket (need root or CAP_NET_RAW): %w", err)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("intercept: interface %q: %w", iface, err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("intercept: bind capture to %q: %w", iface, err)
	}
	if c.Promiscuous {
		_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP,
			&unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_PROMISC})
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("intercept: set non-blocking: %w", err)
	}

	s := &afpacketSource{
		fd:   fd,
		link: linkTypeEthernet, // AF_PACKET SOCK_RAW delivers full Ethernet frames
		ch:   make(chan capturedPacket, 256),
		done: make(chan struct{}),
	}
	s.wg.Add(1)
	go s.loop()
	logInfo("intercept", "AF_PACKET capture started on %s (link=ethernet)", iface)
	return s, nil
}

// newForwardingControl: passive capture needs no kernel forwarding on Linux.
func newForwardingControl() forwardingControl { return noopForwarding{} }

// newARPController: active ARP positioning is not offered on Linux; capture is
// strictly passive here. The interceptor logs this and continues capture-only.
func newARPController(c ARPConf, targets []netip.Addr, gw netip.Addr) (arpController, error) {
	return nil, fmt.Errorf("intercept: active ARP positioning is not available on Linux (passive capture only)")
}
