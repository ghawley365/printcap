package main

import (
	"regexp"
	"testing"
)

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

func TestApplyInjectPrefixSuffix(t *testing.T) {
	steps := []compiledStep{
		{kind: "inject_prefix", data: []byte("<<")},
		{kind: "inject_suffix", data: []byte(">>")},
	}
	got := applyTransforms(steps, []byte("BODY"), &job{})
	if string(got) != "<<BODY>>" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyReplaceLiteralAllVsFirst(t *testing.T) {
	all := []compiledStep{{kind: "replace", mode: "literal", match: []byte("a"), with: []byte("X"), all: true}}
	if got := applyTransforms(all, []byte("banana"), &job{}); string(got) != "bXnXnX" {
		t.Fatalf("all got %q", got)
	}
	first := []compiledStep{{kind: "replace", mode: "literal", match: []byte("a"), with: []byte("X"), all: false}}
	if got := applyTransforms(first, []byte("banana"), &job{}); string(got) != "bXnana" {
		t.Fatalf("first got %q", got)
	}
}

func TestApplyReplaceRegexWithBackref(t *testing.T) {
	steps := []compiledStep{{kind: "replace", mode: "regex",
		re: mustCompileRE(t, `Draft (\d+)`), withS: "FINAL-$1"}}
	got := applyTransforms(steps, []byte("Draft 7 copy"), &job{})
	if string(got) != "FINAL-7 copy" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyReplaceHex(t *testing.T) {
	steps := []compiledStep{{kind: "replace", mode: "hex",
		match: []byte{0x1b, 0x45}, with: []byte{0x1b, 0x46}, all: true}}
	got := applyTransforms(steps, []byte{0x1b, 0x45, 0x01}, &job{})
	if string(got) != string([]byte{0x1b, 0x46, 0x01}) {
		t.Fatalf("got %v", got)
	}
}

func mustCompileRE(t *testing.T, p string) *regexp.Regexp {
	re, err := regexp.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return re
}
