package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

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

type authProto struct {
	newHash func() hash.Hash
	macLen  int
}

func (a authProto) localize(pass string, engineID []byte) []byte {
	return passwordToKey(a.newHash, pass, engineID)
}

// sign returns the truncated HMAC of msg under the localized key.
func (a authProto) sign(localizedKey, msg []byte) []byte {
	mac := hmac.New(a.newHash, localizedKey)
	mac.Write(msg)
	sum := mac.Sum(nil)
	if len(sum) > a.macLen {
		sum = sum[:a.macLen]
	}
	return sum
}

func authProtocol(name string) (authProto, bool) {
	switch name {
	case "MD5":
		return authProto{md5.New, 12}, true
	case "SHA-1", "SHA":
		return authProto{sha1.New, 12}, true
	case "SHA-256":
		return authProto{sha256.New, 24}, true
	case "SHA-512":
		return authProto{sha512.New, 48}, true
	}
	return authProto{}, false
}
