package main

import "testing"

func TestDecodeEBCDIC_CP037Anchors(t *testing.T) {
	cases := []struct {
		b    byte
		want rune
	}{
		{0x40, ' '}, {0xC1, 'A'}, {0xC2, 'B'}, {0x81, 'a'}, {0xF0, '0'},
		{0x4B, '.'}, {0x5B, '$'}, {0x7D, '\''}, {0x6C, '%'}, {0x50, '&'},
	}
	for _, c := range cases {
		got := decodeEBCDIC([]byte{c.b}, "CP037")
		if got != string(c.want) {
			t.Errorf("CP037 0x%02x => %q want %q", c.b, got, string(c.want))
		}
	}
}

func TestDecodeEBCDIC_CP037Word(t *testing.T) {
	got := decodeEBCDIC([]byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6}, "CP037")
	if got != "HELLO" {
		t.Fatalf("got %q", got)
	}
}

func TestDecodeEBCDIC_CP500BracketDiffersFromCP037(t *testing.T) {
	if decodeEBCDIC([]byte{0x4A}, "CP500") == decodeEBCDIC([]byte{0x4A}, "CP037") {
		t.Fatal("CP500 and CP037 should differ at 0x4A")
	}
}

func TestDecodeEBCDIC_UnknownPageReturnsEmpty(t *testing.T) {
	if got := decodeEBCDIC([]byte{0xC1}, "CP999"); got != "" {
		t.Fatalf("unknown page should return empty, got %q", got)
	}
}
