package main

import "testing"

// Regression for the SNMPv3 wrong-priv crash: a garbage BER length must be
// rejected, never panic. Before the fix, an 8-byte length overflowed int into a
// negative value that slipped past the bounds check and panicked b[p:p+l].
func TestReadTLVRejectsOverlongLength(t *testing.T) {
	b := []byte{0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}
	if _, _, _, ok := readTLV(b, 0); ok {
		t.Fatal("readTLV must reject an 8-byte (overlong) length field")
	}
}

func TestReadTLVRejectsTruncatedMultibyteLength(t *testing.T) {
	b := []byte{0x04, 0x82, 0x01} // declares 2 length bytes, only 1 present
	if _, _, _, ok := readTLV(b, 0); ok {
		t.Fatal("readTLV must reject a truncated multibyte length")
	}
}

// serveScopedPDU is the exact crash site: a SNMPv3 scoped PDU that decrypted to
// garbage (wrong priv key) must be rejected, not panic.
func TestServeScopedPDUGarbageNoPanic(t *testing.T) {
	cfg = defaultConfig()
	buildMIB()
	garbage := []byte{0xff, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, ok := serveScopedPDU(garbage); ok {
		t.Fatal("a garbage scoped PDU must not parse as valid")
	}
}
