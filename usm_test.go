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
