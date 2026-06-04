package main

import (
	"bytes"
	"testing"
)

func TestAppendCapped(t *testing.T) {
	// Unlimited (cap<=0) appends everything.
	if got := appendCapped([]byte("ab"), []byte("cd"), 0); !bytes.Equal(got, []byte("abcd")) {
		t.Fatalf("uncapped got %q", got)
	}
	// Cap truncates the tail across calls and never exceeds the cap.
	buf := appendCapped(nil, []byte("hello"), 8)
	buf = appendCapped(buf, []byte("world"), 8) // would be 10; cap at 8
	if len(buf) != 8 || !bytes.Equal(buf, []byte("hellowor")) {
		t.Fatalf("capped got %q (len %d)", buf, len(buf))
	}
	// Once at the cap, further appends are no-ops.
	buf = appendCapped(buf, []byte("MORE"), 8)
	if len(buf) != 8 {
		t.Fatalf("over-cap append grew buffer to %d", len(buf))
	}
}
