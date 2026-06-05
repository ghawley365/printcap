package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// pcap (libpcap) save-file reader, the counterpart to pcapfile.go's writer. It is
// used by the dashboard's capture viewer to turn a captured .pcap back into
// per-packet records. It accepts any of the four classic libpcap byte-order /
// timestamp-resolution variants (so it reads files written by Wireshark/tshark/
// Npcap too, not just our own little-endian microsecond output), and is bounded:
// it stops after max records and rejects absurd per-record lengths so a corrupt
// or hostile file cannot exhaust memory.

// maxPcapFrame caps a single record's captured length while reading; real frames
// are well under this. A larger incl_len means a corrupt header, so we stop.
const maxPcapFrame = 1 << 20 // 1 MiB

// pcapData is the result of reading a capture file: the link-layer type and the
// records, plus whether reading stopped at the record cap.
type pcapData struct {
	linkType  int
	packets   []capturedPacket
	truncated bool // hit the max-record cap (more packets exist on disk)
}

// readPcap reads up to max records from the libpcap file at path (max <= 0 means
// no limit). It returns whatever it successfully parsed even on a mid-file error,
// so a partially-written capture (e.g. one still being appended) still displays.
func readPcap(path string, max int) (*pcapData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<16)

	var gh [24]byte
	if _, err := io.ReadFull(br, gh[:]); err != nil {
		return nil, fmt.Errorf("pcap: short global header: %w", err)
	}
	var bo binary.ByteOrder
	var nano bool
	switch {
	case gh[0] == 0xa1 && gh[1] == 0xb2 && gh[2] == 0xc3 && gh[3] == 0xd4:
		bo = binary.BigEndian
	case gh[0] == 0xd4 && gh[1] == 0xc3 && gh[2] == 0xb2 && gh[3] == 0xa1:
		bo = binary.LittleEndian
	case gh[0] == 0xa1 && gh[1] == 0xb2 && gh[2] == 0x3c && gh[3] == 0x4d:
		bo, nano = binary.BigEndian, true
	case gh[0] == 0x4d && gh[1] == 0x3c && gh[2] == 0xb2 && gh[3] == 0xa1:
		bo, nano = binary.LittleEndian, true
	default:
		return nil, fmt.Errorf("pcap: not a libpcap file (bad magic %02x%02x%02x%02x)", gh[0], gh[1], gh[2], gh[3])
	}

	res := &pcapData{linkType: int(bo.Uint32(gh[20:24]))}
	var rh [16]byte
	for {
		if max > 0 && len(res.packets) >= max {
			res.truncated = true
			break
		}
		if _, err := io.ReadFull(br, rh[:]); err != nil {
			break // EOF / partial trailing record: return what we have
		}
		tsSec := bo.Uint32(rh[0:4])
		tsFrac := bo.Uint32(rh[4:8])
		inclLen := bo.Uint32(rh[8:12])
		if inclLen == 0 || inclLen > maxPcapFrame {
			break // corrupt or out-of-range length: stop cleanly
		}
		data := make([]byte, inclLen)
		if _, err := io.ReadFull(br, data); err != nil {
			break // truncated final record
		}
		var ts time.Time
		if nano {
			ts = time.Unix(int64(tsSec), int64(tsFrac))
		} else {
			ts = time.Unix(int64(tsSec), int64(tsFrac)*1000)
		}
		res.packets = append(res.packets, capturedPacket{ts: ts, data: data})
	}
	return res, nil
}
