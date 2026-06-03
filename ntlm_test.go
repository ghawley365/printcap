package main

import (
	"encoding/hex"
	"testing"
)

// [MS-NLMP] §4.2.4: User="User", Domain="Domain", Password="Password".
func TestNTOWFv2Vector(t *testing.T) {
	got := ntowfv2("User", "Domain", "Password")
	want := "0c868a403bfd7a93a3001ef22ef02e3f"
	if hex.EncodeToString(got) != want {
		t.Fatalf("NTOWFv2\n got=%s\nwant=%s", hex.EncodeToString(got), want)
	}
}

// Domain is NOT uppercased; only the user is. A lowercase user must produce the
// same result as its uppercased form (the function uppercases internally).
func TestNTOWFv2UppercasesUserOnly(t *testing.T) {
	if hex.EncodeToString(ntowfv2("user", "Domain", "Password")) !=
		hex.EncodeToString(ntowfv2("USER", "Domain", "Password")) {
		t.Fatal("user must be uppercased before HMAC; domain case preserved")
	}
}
