package main

import "hash"

// passwordToKey implements RFC 3414 §2.6 password-to-key plus key localization:
// expand the password to 1,048,576 bytes, hash to Ku, then Kul = H(Ku||engineID||Ku).
func passwordToKey(newHash func() hash.Hash, password string, engineID []byte) []byte {
	if password == "" {
		return nil
	}
	pw := []byte(password)
	h := newHash()
	buf := make([]byte, 64)
	var pwIndex, total int
	for total < 1048576 {
		for i := 0; i < 64; i++ {
			buf[i] = pw[pwIndex%len(pw)]
			pwIndex++
		}
		h.Write(buf)
		total += 64
	}
	ku := h.Sum(nil)

	h.Reset()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}
