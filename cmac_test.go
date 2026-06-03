package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestAESCMAC locks aesCMAC against the canonical RFC 4493 / NIST SP 800-38B
// AES-128 test vectors (key 2b7e1516...).
func TestAESCMAC(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	full := mustHex(t, "6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")

	cases := []struct {
		name string
		msg  []byte
		want string
	}{
		{"len0", nil, "bb1d6929e95937287fa37d129b756746"},
		{"len16", full[:16], "070a16b46b4d4144f79bdd9dd04a287c"},
		{"len40", full[:40], "dfa66747de9ae63030ca32611497c827"},
		{"len64", full[:64], "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := aesCMAC(key, tc.msg)
			want := mustHex(t, tc.want)
			if !bytes.Equal(got, want) {
				t.Fatalf("aesCMAC(%s) = %x, want %s", tc.name, got, tc.want)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
