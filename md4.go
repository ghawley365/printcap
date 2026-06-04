package main

import (
	"encoding/binary"
	"math/bits"
)

// md4Sum returns the 16-byte RFC 1320 MD4 digest of data. MD4 is cryptographically
// broken and is used here ONLY where NTLMv2 mandates it (NTOWFv1 / the password
// hash inside NTOWFv2), never as a security primitive of our own choosing. Go
// removed MD4 from the standard library (it lived in golang.org/x/crypto/md4,
// which this package may not import), so the algorithm is reimplemented here.
func md4Sum(data []byte) []byte {
	// Initial register values (RFC 1320 §3.3).
	a := uint32(0x67452301)
	b := uint32(0xefcdab89)
	c := uint32(0x98badcfe)
	d := uint32(0x10325476)

	// Padding (RFC 1320 §3.1/§3.2): append 0x80, then 0x00 until the length is
	// 56 mod 64, then the original length in bits as a little-endian uint64.
	msgLenBits := uint64(len(data)) * 8
	padded := make([]byte, len(data))
	copy(padded, data)
	padded = append(padded, 0x80)
	for len(padded)%64 != 56 {
		padded = append(padded, 0x00)
	}
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], msgLenBits)
	padded = append(padded, lenBytes[:]...)

	// Round auxiliary functions (RFC 1320 §3.4).
	f := func(x, y, z uint32) uint32 { return (x & y) | (^x & z) }
	g := func(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }

	var X [16]uint32
	for off := 0; off < len(padded); off += 64 {
		block := padded[off : off+64]
		for i := 0; i < 16; i++ {
			X[i] = binary.LittleEndian.Uint32(block[i*4 : i*4+4])
		}

		aa, bb, cc, dd := a, b, c, d

		// Round 1: [abcd k s] = (a + F(b,c,d) + X[k]) <<< s.
		round1 := func(a, b, c, d *uint32, k, s int) {
			*a = bits.RotateLeft32(*a+f(*b, *c, *d)+X[k], s)
		}
		round1(&a, &b, &c, &d, 0, 3)
		round1(&d, &a, &b, &c, 1, 7)
		round1(&c, &d, &a, &b, 2, 11)
		round1(&b, &c, &d, &a, 3, 19)
		round1(&a, &b, &c, &d, 4, 3)
		round1(&d, &a, &b, &c, 5, 7)
		round1(&c, &d, &a, &b, 6, 11)
		round1(&b, &c, &d, &a, 7, 19)
		round1(&a, &b, &c, &d, 8, 3)
		round1(&d, &a, &b, &c, 9, 7)
		round1(&c, &d, &a, &b, 10, 11)
		round1(&b, &c, &d, &a, 11, 19)
		round1(&a, &b, &c, &d, 12, 3)
		round1(&d, &a, &b, &c, 13, 7)
		round1(&c, &d, &a, &b, 14, 11)
		round1(&b, &c, &d, &a, 15, 19)

		// Round 2: [abcd k s] = (a + G(b,c,d) + X[k] + 0x5A827999) <<< s.
		round2 := func(a, b, c, d *uint32, k, s int) {
			*a = bits.RotateLeft32(*a+g(*b, *c, *d)+X[k]+0x5A827999, s)
		}
		round2(&a, &b, &c, &d, 0, 3)
		round2(&d, &a, &b, &c, 4, 5)
		round2(&c, &d, &a, &b, 8, 9)
		round2(&b, &c, &d, &a, 12, 13)
		round2(&a, &b, &c, &d, 1, 3)
		round2(&d, &a, &b, &c, 5, 5)
		round2(&c, &d, &a, &b, 9, 9)
		round2(&b, &c, &d, &a, 13, 13)
		round2(&a, &b, &c, &d, 2, 3)
		round2(&d, &a, &b, &c, 6, 5)
		round2(&c, &d, &a, &b, 10, 9)
		round2(&b, &c, &d, &a, 14, 13)
		round2(&a, &b, &c, &d, 3, 3)
		round2(&d, &a, &b, &c, 7, 5)
		round2(&c, &d, &a, &b, 11, 9)
		round2(&b, &c, &d, &a, 15, 13)

		// Round 3: [abcd k s] = (a + H(b,c,d) + X[k] + 0x6ED9EBA1) <<< s.
		round3 := func(a, b, c, d *uint32, k, s int) {
			*a = bits.RotateLeft32(*a+h(*b, *c, *d)+X[k]+0x6ED9EBA1, s)
		}
		round3(&a, &b, &c, &d, 0, 3)
		round3(&d, &a, &b, &c, 8, 9)
		round3(&c, &d, &a, &b, 4, 11)
		round3(&b, &c, &d, &a, 12, 15)
		round3(&a, &b, &c, &d, 2, 3)
		round3(&d, &a, &b, &c, 10, 9)
		round3(&c, &d, &a, &b, 6, 11)
		round3(&b, &c, &d, &a, 14, 15)
		round3(&a, &b, &c, &d, 1, 3)
		round3(&d, &a, &b, &c, 9, 9)
		round3(&c, &d, &a, &b, 5, 11)
		round3(&b, &c, &d, &a, 13, 15)
		round3(&a, &b, &c, &d, 3, 3)
		round3(&d, &a, &b, &c, 11, 9)
		round3(&c, &d, &a, &b, 7, 11)
		round3(&b, &c, &d, &a, 15, 15)

		a += aa
		b += bb
		c += cc
		d += dd
	}

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint32(out[4:8], b)
	binary.LittleEndian.PutUint32(out[8:12], c)
	binary.LittleEndian.PutUint32(out[12:16], d)
	return out
}
