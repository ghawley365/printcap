//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// isElevated reports whether the current process has an elevated admin token.
func isElevated() bool {
	tok := windows.GetCurrentProcessToken()
	return tok.IsElevated()
}

// quoteArgs wraps each argument in double quotes if it contains whitespace so
// the relaunched command line round-trips arguments with spaces intact.
func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.ContainsAny(a, " \t") {
			out[i] = `"` + a + `"`
		} else {
			out[i] = a
		}
	}
	return out
}

// serviceCmdNeedsAdmin reports whether a -service subcommand requires an
// elevated admin token. status is a read-only query and does not.
func serviceCmdNeedsAdmin(cmd string) bool {
	switch cmd {
	case "install", "remove", "uninstall", "start", "stop":
		return true
	default:
		return false
	}
}

// firewallCmdNeedsAdmin reports whether a -firewall subcommand requires an
// elevated admin token.
func firewallCmdNeedsAdmin(cmd string) bool {
	switch cmd {
	case "add", "remove":
		return true
	default:
		return false
	}
}

// maybeElevate, for an admin-requiring command run from a non-elevated process,
// relaunches the same command line through a UAC prompt and exits this process.
// If relaunch fails it falls through so the caller still attempts the work and
// surfaces its own "run as Administrator?" error.
func maybeElevate(needsAdmin bool) {
	if !needsAdmin || isElevated() {
		return
	}
	if err := relaunchElevated(os.Args[1:]); err == nil {
		os.Exit(0)
	}
}

// relaunchElevated re-runs this exe with the given args via ShellExecute "runas"
// (triggers the UAC prompt). Returns nil if the elevated process was launched.
func relaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	argLine, err := windows.UTF16PtrFromString(strings.Join(quoteArgs(args), " "))
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, exePtr, argLine, nil, windows.SW_NORMAL)
}
