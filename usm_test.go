package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

func TestPasswordToKey_RFC3414_MD5(t *testing.T) {
	engineID, _ := hex.DecodeString("000000000000000000000002")
	got := passwordToKey(md5.New, "maplesyrup", engineID)
	want := "526f5eed9fcce26f8964c2930787d82b"
	if hex.EncodeToString(got) != want {
		t.Fatalf("MD5 localized key\n got=%s\nwant=%s", hex.EncodeToString(got), want)
	}
}

func TestPasswordToKey_RFC3414_SHA1(t *testing.T) {
	engineID, _ := hex.DecodeString("000000000000000000000002")
	got := passwordToKey(sha1.New, "maplesyrup", engineID)
	want := "6695febc9288e36282235fc7151f128497b38f3f"
	if hex.EncodeToString(got) != want {
		t.Fatalf("SHA-1 localized key\n got=%s\nwant=%s", hex.EncodeToString(got), want)
	}
}

func TestAuthParamLengths(t *testing.T) {
	cases := map[string]int{"MD5": 12, "SHA-1": 12, "SHA-256": 24, "SHA-512": 48}
	engineID, _ := hex.DecodeString("000000000000000000000002")
	for proto, wantLen := range cases {
		a, ok := authProtocol(proto)
		if !ok {
			t.Fatalf("unknown proto %s", proto)
		}
		key := a.localize("maplesyrup", engineID)
		mac := a.sign(key, []byte("the whole message bytes"))
		if len(mac) != wantLen {
			t.Errorf("%s mac len=%d want %d", proto, len(mac), wantLen)
		}
	}
}

func TestAuthSignDeterministic(t *testing.T) {
	a, _ := authProtocol("SHA-1")
	engineID := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	key := a.localize("maplesyrup", engineID)
	m1 := a.sign(key, []byte("abc"))
	m2 := a.sign(key, []byte("abc"))
	if string(m1) != string(m2) {
		t.Fatal("sign must be deterministic")
	}
}

func TestPrivRoundTrip(t *testing.T) {
	engineID := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	auth, _ := authProtocol("SHA-1")
	// Extend the localized key to 32 bytes (Blumenthal) so AES-192/256 key slices
	// are valid — mirrors what the pipeline's privKeyFor does before encrypt/decrypt.
	privKey := extendKey(auth.localize("maplesyrupx", engineID), 32, sha1.New)

	for _, name := range []string{"DES", "AES-128", "AES-192", "AES-256"} {
		p, ok := privProtocol(name)
		if !ok {
			t.Fatalf("unknown priv %s", name)
		}
		plain := []byte("scoped-pdu-bytes-padded-to-something-reasonable!")
		ct, salt, err := p.encrypt(privKey, 1, 100, plain)
		if err != nil {
			t.Fatalf("%s encrypt: %v", name, err)
		}
		pt, err := p.decrypt(privKey, 1, 100, salt, ct)
		if err != nil {
			t.Fatalf("%s decrypt: %v", name, err)
		}
		// DES is block-padded; compare the prefix.
		if string(pt[:len(plain)]) != string(plain) {
			t.Fatalf("%s round-trip mismatch", name)
		}
	}
}

func TestDecryptRejectsShortPrivParamsNoPanic(t *testing.T) {
	// A privacy request whose msgPrivacyParameters ("salt") is shorter than the
	// mandatory 8 octets must be rejected as a decryption error, never panic
	// (regression: DES indexed salt[0..7] unchecked).
	des, _ := privProtocol("DES")
	aes, _ := privProtocol("AES-128")
	privKey := make([]byte, 32) // long enough for any algorithm
	ct := make([]byte, 16)
	for _, p := range []privProto{des, aes} {
		for _, badSalt := range [][]byte{nil, {}, {1, 2, 3}, make([]byte, 7)} {
			if _, err := p.decrypt(privKey, 1, 1, badSalt, ct); err == nil {
				t.Fatalf("%s: short salt (len %d) must error, not succeed", p.kind, len(badSalt))
			}
		}
	}
	// A correct 8-byte salt with aligned ciphertext must NOT error on length.
	if _, err := des.decrypt(privKey, 1, 1, make([]byte, 8), ct); err != nil {
		t.Fatalf("valid 8-byte salt rejected: %v", err)
	}
}
