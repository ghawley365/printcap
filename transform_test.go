package main

import "testing"

func TestDecodeBytesHexEscapes(t *testing.T) {
	got := decodeBytes(`\x1bE hello\x0a`, nil)
	want := []byte{0x1b, 'E', ' ', 'h', 'e', 'l', 'l', 'o', 0x0a}
	if string(got) != string(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDecodeBytesMacroExpansion(t *testing.T) {
	macros := map[string][]byte{"reset": {0x1b, 'E'}}
	got := decodeBytes("macro:reset", macros)
	if string(got) != "\x1bE" {
		t.Fatalf("got %v", got)
	}
}

func TestDecodeBytesUnknownMacroIsEmpty(t *testing.T) {
	if got := decodeBytes("macro:nope", map[string][]byte{}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
