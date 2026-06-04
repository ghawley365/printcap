package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
)

// SMB2 signing ([MS-SMB2] §3.1.4.1) and SMB3 encryption ([MS-SMB2] §2.2.41,
// §3.1.4.3). Signing uses AES-CMAC (see cmac.go); encryption uses AES-128-GCM.
// Only GCM is implemented: the server selects GCM in NEGOTIATE when offered, so
// AES-CCM is intentionally not implemented (GCM-preferred); when the negotiated
// cipher is CCM the caller disables encryption.

// smb2FlagsSigned marks an SMB2 message as signed ([MS-SMB2] §2.2.1.2,
// SMB2_FLAGS_SIGNED).
const smb2FlagsSigned uint32 = 0x00000008

// SMB2 header field offsets used by signing.
const (
	smb2FlagsOffset     = 16 // Flags (LE uint32)
	smb2SignatureOffset = 48 // Signature (16 bytes), ends at 64.
)

// smbSign returns a copy of msg (a full SMB2 message: header+body) with the
// SMB2_FLAGS_SIGNED flag set and the 16-byte Signature field filled with the
// AES-CMAC over the message with a zeroed signature field ([MS-SMB2]
// §3.1.4.1). The input slice is not modified.
func smbSign(signingKey, msg []byte) []byte {
	out := make([]byte, len(msg))
	copy(out, msg)
	if len(out) < smb2HeaderSize {
		return out
	}
	// Set SMB2_FLAGS_SIGNED.
	flags := binary.LittleEndian.Uint32(out[smb2FlagsOffset:smb2FlagsOffset+4]) | smb2FlagsSigned
	binary.LittleEndian.PutUint32(out[smb2FlagsOffset:smb2FlagsOffset+4], flags)
	// Zero the Signature field before computing the MAC.
	for i := smb2SignatureOffset; i < smb2SignatureOffset+16; i++ {
		out[i] = 0
	}
	sig := aesCMAC(signingKey, out)
	copy(out[smb2SignatureOffset:smb2SignatureOffset+16], sig[:16])
	return out
}

// smbVerifySign verifies an SMB2 signature ([MS-SMB2] §3.1.4.1): it saves the
// claimed Signature, recomputes the AES-CMAC over the message with the
// signature zeroed, and constant-time compares. Bounds-safe: returns false on
// short or malformed input.
func smbVerifySign(signingKey, msg []byte) bool {
	if len(msg) < smb2HeaderSize {
		return false
	}
	var claimed [16]byte
	copy(claimed[:], msg[smb2SignatureOffset:smb2SignatureOffset+16])

	work := make([]byte, len(msg))
	copy(work, msg)
	for i := smb2SignatureOffset; i < smb2SignatureOffset+16; i++ {
		work[i] = 0
	}
	want := aesCMAC(signingKey, work)
	return subtle.ConstantTimeCompare(claimed[:], want[:16]) == 1
}

// TRANSFORM_HEADER layout ([MS-SMB2] §2.2.41), 52 bytes total.
const (
	transformHeaderSize     = 52
	thProtocolIDOffset      = 0  // 4 bytes: 0xFD,'S','M','B'.
	thSignatureOffset       = 4  // 16 bytes: AEAD auth tag.
	thNonceOffset           = 20 // 16 bytes: nonce (GCM uses low 12 bytes).
	thOriginalMsgSizeOffset = 36 // 4 bytes: plaintext length.
	thFlagsOffset           = 42 // 2 bytes: 0x0001 (Encrypted).
	thSessionIDOffset       = 44 // 8 bytes.
	gcmNonceSize            = 12
)

// thProtocolID is the TRANSFORM_HEADER ProtocolId magic: 0xFD 'S' 'M' 'B'.
var thProtocolID = [4]byte{0xFD, 'S', 'M', 'B'}

// transformEncrypted is the Flags value indicating the message is encrypted
// ([MS-SMB2] §2.2.41).
const transformEncrypted uint16 = 0x0001

// smbEncrypt wraps plaintext (a full SMB2 message) in a TRANSFORM_HEADER using
// AES-128-GCM under key (16 bytes). The result is the 52-byte TRANSFORM_HEADER
// (with the GCM tag in Signature) followed by the ciphertext. The AEAD AAD is
// the header bytes from Nonce (offset 20) through SessionId (offset 51).
func smbEncrypt(key []byte, sessionID uint64, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return nil, err
	}

	hdr := make([]byte, transformHeaderSize)
	copy(hdr[thProtocolIDOffset:thProtocolIDOffset+4], thProtocolID[:])
	// Random 12-byte GCM nonce in the low bytes of the 16-byte Nonce field.
	nonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	copy(hdr[thNonceOffset:thNonceOffset+gcmNonceSize], nonce)
	binary.LittleEndian.PutUint32(hdr[thOriginalMsgSizeOffset:thOriginalMsgSizeOffset+4], uint32(len(plaintext)))
	binary.LittleEndian.PutUint16(hdr[thFlagsOffset:thFlagsOffset+2], transformEncrypted)
	binary.LittleEndian.PutUint64(hdr[thSessionIDOffset:thSessionIDOffset+8], sessionID)

	aad := hdr[thNonceOffset:transformHeaderSize] // bytes 20..51

	// Seal appends ciphertext||tag; split the trailing 16-byte tag into the
	// header Signature field and keep only the ciphertext after the header.
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	tagOff := len(sealed) - aead.Overhead()
	ct := sealed[:tagOff]
	tag := sealed[tagOff:]
	copy(hdr[thSignatureOffset:thSignatureOffset+16], tag)

	out := make([]byte, 0, transformHeaderSize+len(ct))
	out = append(out, hdr...)
	out = append(out, ct...)
	return out, nil
}

// smbDecrypt validates and decrypts a TRANSFORM_HEADER-wrapped message
// ([MS-SMB2] §3.1.4.3). It is bounds-safe against untrusted input and returns
// ok=false on any malformed, short, or tag-mismatched message.
func smbDecrypt(key []byte, wrapped []byte) (plaintext []byte, ok bool) {
	if len(wrapped) < transformHeaderSize {
		return nil, false
	}
	if subtle.ConstantTimeCompare(wrapped[thProtocolIDOffset:thProtocolIDOffset+4], thProtocolID[:]) != 1 {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	aead, err := cipher.NewGCMWithNonceSize(block, gcmNonceSize)
	if err != nil {
		return nil, false
	}

	hdr := wrapped[:transformHeaderSize]
	nonce := hdr[thNonceOffset : thNonceOffset+gcmNonceSize]
	tag := hdr[thSignatureOffset : thSignatureOffset+16]
	aad := hdr[thNonceOffset:transformHeaderSize]
	ct := wrapped[transformHeaderSize:]

	// Reassemble ciphertext||tag for Open.
	sealed := make([]byte, 0, len(ct)+len(tag))
	sealed = append(sealed, ct...)
	sealed = append(sealed, tag...)

	pt, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, false
	}
	return pt, true
}
