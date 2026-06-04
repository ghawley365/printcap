package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveStorageDir(t *testing.T) {
	// Absolute passes through.
	if got := resolveStorageDir("/var/data/x", "def"); got != filepath.Clean("/var/data/x") {
		t.Fatalf("absolute: %q", got)
	}
	// Blank uses the default, made exe-relative.
	def := resolveStorageDir("", "captures")
	if !strings.HasSuffix(def, filepath.Join(exeDir(), "captures")) && def != filepath.Join(exeDir(), "captures") {
		t.Fatalf("default not exe-relative: %q", def)
	}
	if !filepath.IsAbs(def) && exeDir() != "." {
		t.Fatalf("expected absolute resolved path: %q", def)
	}
	// Relative becomes exe-relative.
	rel := resolveStorageDir("sub/dir", "def")
	if rel != filepath.Join(exeDir(), "sub", "dir") {
		t.Fatalf("relative: %q", rel)
	}
}

func TestCaptureAndSpoolDirsDistinct(t *testing.T) {
	cfg = defaultConfig()
	if captureDir() == spoolDir() {
		t.Fatal("capture and spool dirs must differ")
	}
}
