package main

import (
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	s := versionString()
	if !strings.Contains(s, "printcap") {
		t.Errorf("versionString() = %q, want it to contain %q", s, "printcap")
	}
	if !strings.Contains(s, version) {
		t.Errorf("versionString() = %q, want it to contain version %q", s, version)
	}
}
