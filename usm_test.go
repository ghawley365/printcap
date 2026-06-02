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
