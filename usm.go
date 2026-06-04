package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
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

type privProto struct {
	kind   string // "des" | "aes"
	keyLen int    // localized-key bytes consumed for the cipher key
}

func privProtocol(name string) (privProto, bool) {
	switch name {
	case "DES":
		return privProto{"des", 16}, true // 8 key + 8 pre-IV
	case "AES-128":
		return privProto{"aes", 16}, true
	case "AES-192":
		return privProto{"aes", 24}, true
	case "AES-256":
		return privProto{"aes", 32}, true
	}
	return privProto{}, false
}

// extendKey lengthens a localized key to n bytes via repeated localization
// (Blumenthal) — only AES-192/256 need more than the base hash output.
func extendKey(key []byte, n int, newHash func() hash.Hash) []byte {
	out := append([]byte{}, key...)
	for len(out) < n {
		h := newHash()
		h.Write(out)
		out = append(out, h.Sum(nil)...)
	}
	return out[:n]
}

func (p privProto) encrypt(privKey []byte, boots, time uint32, plain []byte) (ct, salt []byte, err error) {
	// NOTE: RFC 3414 §8.1.1.1 specifies the DES salt as engineBoots||localCounter; we use a random 8-byte salt, a deliberate interoperable deviation — it is unique per message and travels in msgPrivacyParameters, so the receiver decrypts correctly. AES (RFC 3826) folds boots/time into the IV via aesIV.
	salt = make([]byte, 8)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, err
	}
	switch p.kind {
	case "des":
		key := privKey[:8]
		preIV := privKey[8:16]
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = preIV[i] ^ salt[i]
		}
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		padded := pad8(plain)
		ct = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		return ct, salt, nil
	default: // aes
		key := privKey[:p.keyLen]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, nil, err
		}
		iv := aesIV(boots, time, salt)
		ct = make([]byte, len(plain))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, plain)
		return ct, salt, nil
	}
}

func (p privProto) decrypt(privKey []byte, boots, time uint32, salt, ct []byte) ([]byte, error) {
	// The privacy parameters (msgPrivacyParameters / "salt") are a fixed 8 octets
	// for both DES (RFC 3414 §8.1.1.2) and AES (RFC 3826 §3.1.2.1). A request
	// whose salt is the wrong length is malformed; reject it as a decryption
	// error so the caller drops the request, rather than indexing past the slice.
	if len(salt) != 8 {
		return nil, fmt.Errorf("snmpv3: privacy parameters must be 8 octets, got %d", len(salt))
	}
	switch p.kind {
	case "des":
		// DES needs an 8-byte key + 8-byte pre-IV from the localized priv key.
		if len(privKey) < 16 {
			return nil, fmt.Errorf("snmpv3: DES privacy key too short (%d bytes)", len(privKey))
		}
		if len(ct) == 0 || len(ct)%8 != 0 {
			return nil, fmt.Errorf("snmpv3: DES ciphertext not block-aligned (%d bytes)", len(ct))
		}
		key := privKey[:8]
		preIV := privKey[8:16]
		iv := make([]byte, 8)
		for i := range iv {
			iv[i] = preIV[i] ^ salt[i]
		}
		block, err := des.NewCipher(key)
		if err != nil {
			return nil, err
		}
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
		return pt, nil
	default:
		if len(privKey) < p.keyLen {
			return nil, fmt.Errorf("snmpv3: AES privacy key too short (%d < %d)", len(privKey), p.keyLen)
		}
		key := privKey[:p.keyLen]
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		pt := make([]byte, len(ct))
		cipher.NewCFBDecrypter(block, aesIV(boots, time, salt)).XORKeyStream(pt, ct)
		return pt, nil
	}
}

// aesIV builds the RFC 3826 CFB IV: engineBoots(4) || engineTime(4) || salt(8).
func aesIV(boots, time uint32, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:], boots)
	binary.BigEndian.PutUint32(iv[4:], time)
	copy(iv[8:], salt)
	return iv
}

func pad8(b []byte) []byte {
	if len(b)%8 == 0 {
		return b
	}
	return append(b, make([]byte, 8-len(b)%8)...)
}
