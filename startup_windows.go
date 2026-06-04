//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Start-on-login for the tray GUI. We add/remove a value under the per-user Run
// key so the GUI launches when the current user signs in. This is a system-state
// toggle (not a cfg field) — the registry is the source of truth.

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "printcap"

// setRunAtLogin enables or disables launching printcap at user login. When on,
// the Run value is set to the quoted path of this executable; when off, the
// value is deleted (a missing value is not treated as an error).
func setRunAtLogin(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath,
		registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if on {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return k.SetStringValue(runValueName, `"`+exe+`"`)
	}

	if err := k.DeleteValue(runValueName); err != nil && err != registry.ErrNotExist {
		return err
	}
	return nil
}

// runAtLogin reports whether the Run value exists and points at this executable.
func runAtLogin() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	val, _, err := k.GetStringValue(runValueName)
	if err != nil {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	// The stored value is the (possibly quoted) exe path; compare case-insensitively
	// after trimming surrounding quotes, since Windows paths are case-insensitive.
	got := strings.Trim(val, `"`)
	return strings.EqualFold(got, exe)
}
