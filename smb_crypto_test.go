package main

import (
	"bytes"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	msg := (smb2Header{Command: 0, MessageId: 7}).encode()
	body := make([]byte, 32)
	msg = append(msg, body...)
	signed := smbSign(key, msg)
	if !smbVerifySign(key, signed) {
		t.Fatal("valid signature must verify")
	}
	signed[70] ^= 0xFF // tamper a body byte
	if smbVerifySign(key, signed) {
		t.Fatal("tampered message must fail verification")
	}
	if smbVerifySign(key, []byte("short")) {
		t.Fatal("short msg must not panic and must fail")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(16 - i)
	}
	plain := append((smb2Header{Command: 9, MessageId: 3}).encode(), []byte("PCL DATA HERE")...)
	wrapped, err := smbEncrypt(key, 0xAABBCCDD, plain)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped[0] != 0xFD || wrapped[1] != 'S' {
		t.Fatalf("bad transform magic %x", wrapped[0:4])
	}
	got, ok := smbDecrypt(key, wrapped)
	if !ok || !bytes.Equal(got, plain) {
		t.Fatalf("decrypt mismatch ok=%v", ok)
	}
	wrapped[60] ^= 0xFF // tamper ciphertext
	if _, ok := smbDecrypt(key, wrapped); ok {
		t.Fatal("tampered ciphertext must fail")
	}
	if _, ok := smbDecrypt(key, []byte("short")); ok {
		t.Fatal("short must fail, not panic")
	}
}
