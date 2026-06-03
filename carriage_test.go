package main

import "testing"

func TestASACarriageControl(t *testing.T) {
	in := " LINE1\n0LINE2\n1LINE3\n"
	got := applyCarriageControl(in, "asa")
	want := "LINE1\n\nLINE2\n\fLINE3\n"
	if got != want {
		t.Fatalf("asa got %q want %q", got, want)
	}
}

func TestNoneIsPassthrough(t *testing.T) {
	in := " LINE1\n0LINE2\n"
	if got := applyCarriageControl(in, "none"); got != in {
		t.Fatalf("none should pass through, got %q", got)
	}
}

func TestAutoDetectsASA(t *testing.T) {
	in := " A\n0B\n"
	if applyCarriageControl(in, "auto") != applyCarriageControl(in, "asa") {
		t.Fatal("auto should detect ASA here")
	}
	plain := "hello\nworld\n"
	if applyCarriageControl(plain, "auto") != plain {
		t.Fatal("auto should pass non-ASA text through")
	}
}

func TestMachineCarriageControlRaw(t *testing.T) {
	raw := []byte{0x09, 0xC1, 0x15, 0x8B, 0xC2, 0x15} // 0x09=print+space, 0x8B=skip-to-ch
	got := convertMachineRaw(raw)
	want := []byte{0xC1, 0x15, '\f', 0xC2, 0x15}
	if string(got) != string(want) {
		t.Fatalf("machine raw got %v want %v", got, want)
	}
}
