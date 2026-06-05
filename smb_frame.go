package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SMB2 command constants ([MS-SMB2] §2.2.1.2 Command field). Several are not
// yet referenced; later SMB2 stages consume them.
const (
	smb2Negotiate      uint16 = 0x0000
	smb2SessionSetup   uint16 = 0x0001
	smb2Logoff         uint16 = 0x0002
	smb2TreeConnect    uint16 = 0x0003
	smb2TreeDisconnect uint16 = 0x0004
	smb2Create         uint16 = 0x0005
	smb2Close          uint16 = 0x0006
	smb2Flush          uint16 = 0x0007
	smb2Write          uint16 = 0x0009
	smb2Read           uint16 = 0x0008
	smb2Ioctl          uint16 = 0x000B
)

// smb2FlagsServerToRedir marks a packet as a server-to-client response
// ([MS-SMB2] §2.2.1.2 SMB2_FLAGS_SERVER_TO_REDIR).
const smb2FlagsServerToRedir uint32 = 0x00000001

// NTStatus codes reused across the SMB2 stages ([MS-ERREF] §2.3.1).
const (
	statusSuccess                uint32 = 0x00000000
	statusMoreProcessingRequired uint32 = 0xC0000016
	statusAccessDenied           uint32 = 0xC0000022
	statusPending                uint32 = 0x00000103
	statusNotSupported           uint32 = 0xC00000BB
)

// smb2ProtocolID is the SMB2 ProtocolId magic: 0xFE 'S' 'M' 'B'.
var smb2ProtocolID = [4]byte{0xFE, 'S', 'M', 'B'}

// smb2HeaderSize is the fixed size of a sync SMB2 packet header.
const smb2HeaderSize = 64

// directTCPMaxLen is the maximum SMB2 message size expressible by the 24-bit
// Direct-TCP length field.
const directTCPMaxLen = 0x00FFFFFF

// smb2Header models the 64-byte synchronous SMB2 packet header
// ([MS-SMB2] §2.2.1.2). All multi-byte fields are little-endian on the wire.
type smb2Header struct {
	CreditCharge uint16
	Status       uint32
	Command      uint16
	CreditResp   uint16 // CreditRequest/CreditResponse field at offset 14.
	Flags        uint32
	NextCommand  uint32
	MessageId    uint64
	TreeId       uint32
	SessionId    uint64
	Signature    [16]byte
}

// encode serializes the header into a fresh 64-byte slice at the offsets
// defined by [MS-SMB2] §2.2.1.2. ProtocolId, StructureSize and the Reserved
// field at offset 32 are set automatically.
func (h smb2Header) encode() []byte {
	b := make([]byte, smb2HeaderSize)
	copy(b[0:4], smb2ProtocolID[:])
	binary.LittleEndian.PutUint16(b[4:6], smb2HeaderSize) // StructureSize = 64
	binary.LittleEndian.PutUint16(b[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(b[8:12], h.Status)
	binary.LittleEndian.PutUint16(b[12:14], h.Command)
	binary.LittleEndian.PutUint16(b[14:16], h.CreditResp)
	binary.LittleEndian.PutUint32(b[16:20], h.Flags)
	binary.LittleEndian.PutUint32(b[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(b[24:32], h.MessageId)
	// b[32:36] Reserved stays zero (sync header).
	binary.LittleEndian.PutUint32(b[36:40], h.TreeId)
	binary.LittleEndian.PutUint64(b[40:48], h.SessionId)
	copy(b[48:64], h.Signature[:])
	return b
}

// parseSMB2Header decodes a 64-byte sync SMB2 header from b. It returns
// ok=false if b is too short or the ProtocolId magic does not match.
func parseSMB2Header(b []byte) (smb2Header, bool) {
	if len(b) < smb2HeaderSize {
		return smb2Header{}, false
	}
	if b[0] != smb2ProtocolID[0] || b[1] != smb2ProtocolID[1] ||
		b[2] != smb2ProtocolID[2] || b[3] != smb2ProtocolID[3] {
		return smb2Header{}, false
	}
	var h smb2Header
	h.CreditCharge = binary.LittleEndian.Uint16(b[6:8])
	h.Status = binary.LittleEndian.Uint32(b[8:12])
	h.Command = binary.LittleEndian.Uint16(b[12:14])
	h.CreditResp = binary.LittleEndian.Uint16(b[14:16])
	h.Flags = binary.LittleEndian.Uint32(b[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(b[20:24])
	h.MessageId = binary.LittleEndian.Uint64(b[24:32])
	h.TreeId = binary.LittleEndian.Uint32(b[36:40])
	h.SessionId = binary.LittleEndian.Uint64(b[40:48])
	copy(h.Signature[:], b[48:64])
	return h, true
}

// errInvalidFrame is returned when a Direct-TCP prefix is malformed.
var errInvalidFrame = errors.New("invalid Direct-TCP frame")

// writeTCPFrame writes payload with its Direct-TCP transport prefix
// ([MS-SMB2] §2.1): byte 0 = 0x00, bytes 1-3 = 24-bit big-endian length.
func writeTCPFrame(w io.Writer, payload []byte) error {
	if len(payload) > directTCPMaxLen {
		return fmt.Errorf("smb: payload %d exceeds Direct-TCP max %d", len(payload), directTCPMaxLen)
	}
	n := uint32(len(payload))
	prefix := [4]byte{
		0x00,
		byte(n >> 16),
		byte(n >> 8),
		byte(n),
	}
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readTCPFrame reads one Direct-TCP framed SMB2 message from r. The 4-byte
// prefix must have a zero top byte; the 24-bit big-endian length bounds the
// message to at most 16 MiB.
func readTCPFrame(r io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	if prefix[0] != 0x00 {
		return nil, errInvalidFrame
	}
	n := int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3])
	if n > negMaxTransactSize {
		// Reject oversized frames before allocating: cap at the negotiated max
		// transact size (1 MiB) rather than the 16 MiB Direct-TCP maximum.
		return nil, errInvalidFrame
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
