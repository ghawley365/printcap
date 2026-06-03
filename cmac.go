package main

import (
	"crypto/aes"
	"crypto/subtle"
)

// AES-CMAC ([RFC 4493] / NIST SP 800-38B). The Go standard library provides no
// CMAC, so the message-authentication code is implemented here on top of
// crypto/aes. Used by SMB2 signing ([MS-SMB2] §3.1.4.1).

// cmacRb is the constant used in subkey generation for a 128-bit block cipher
// (the representation of the GF(2^128) reduction polynomial), RFC 4493 §2.3.
const cmacRb = 0x87

// cmacSubkeys derives the K1/K2 subkeys from the AES block cipher (RFC 4493
// §2.3): L = AES_K(0^128); K1 = L<<1 (xor Rb if MSB(L)=1); K2 = K1<<1 (xor Rb
// if MSB(K1)=1).
func cmacSubkeys(block interface {
	Encrypt(dst, src []byte)
	BlockSize() int
}) (k1, k2 []byte) {
	l := make([]byte, block.BlockSize())
	block.Encrypt(l, l) // L = AES_K(0^128)
	k1 = cmacShiftXor(l)
	k2 = cmacShiftXor(k1)
	return k1, k2
}

// cmacShiftXor returns (in << 1), XORing the low byte with Rb when the high bit
// of the input was set. Operates on a 16-byte block.
func cmacShiftXor(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if in[0]&0x80 != 0 {
		out[len(out)-1] ^= cmacRb
	}
	return out
}

// aesCMAC computes the AES-CMAC (RFC 4493) of msg under key (16/24/32-byte AES
// key) and returns the 16-byte tag.
func aesCMAC(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		// AES key length is validated by callers; an invalid key is a
		// programming error. Return a zero tag rather than panicking.
		return make([]byte, 16)
	}
	bs := block.BlockSize()
	k1, k2 := cmacSubkeys(block)

	// Determine the number of blocks and whether the last block is complete.
	n := (len(msg) + bs - 1) / bs
	complete := false
	if n == 0 {
		n = 1
		complete = false
	} else {
		complete = len(msg)%bs == 0
	}

	// Build the last block: M_last = M_n XOR K1 (complete) or
	// (M_n || 10^j) XOR K2 (padded).
	last := make([]byte, bs)
	lastStart := (n - 1) * bs
	if complete {
		copy(last, msg[lastStart:])
		subtle.XORBytes(last, last, k1)
	} else {
		rem := msg[lastStart:]
		copy(last, rem)
		last[len(rem)] = 0x80 // padding: 10^j
		subtle.XORBytes(last, last, k2)
	}

	// CBC-MAC over the first n-1 blocks then the constructed last block.
	x := make([]byte, bs)
	y := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(y, x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	subtle.XORBytes(y, x, last)
	block.Encrypt(x, y)
	return x
}
