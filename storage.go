package main

import (
	"os"
	"path/filepath"
)

// exeDir returns the directory containing the running executable, falling back
// to "." if it can't be determined. All relative storage paths resolve against
// it so printcap is portable (run it from anywhere / a USB stick).
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// resolveStorageDir resolves a configured directory: blank uses def; a relative
// path is taken relative to the executable directory; an absolute path is used
// verbatim. The result is cleaned and absolute where possible.
func resolveStorageDir(p, def string) string {
	if p == "" {
		p = def
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(exeDir(), p))
}

// captureDir is the resolved directory where captured spool files are written.
func captureDir() string { return resolveStorageDir(cfg.OutDir, "captures") }

// spoolDir is the resolved directory for the forward retry queue and temp files.
func spoolDir() string { return resolveStorageDir(cfg.Storage.SpoolDir, "spool") }

// logDir is the resolved directory where log files are written by default: a
// "logs" subfolder of the capture directory, so all run artifacts live together.
func logDir() string { return filepath.Join(captureDir(), "logs") }

// ensureStorageDirs creates the capture, spool, and log directories (0o755). It
// never deletes anything. Returns the first creation error.
func ensureStorageDirs() error {
	for _, d := range []string{captureDir(), spoolDir(), logDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}
