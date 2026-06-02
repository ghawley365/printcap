//go:build windows

package main

import (
	"log"
	"os"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

// dispatch chooses the front-end on Windows:
//   - launched by the Service Control Manager  -> run as a service
//   - -service <cmd>                            -> manage the service and exit
//   - -console                                  -> headless console
//   - otherwise (interactive double-click)      -> native settings GUI
func dispatch() {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		runService()
		return
	}
	if optServiceCmd != "" {
		serviceControl(optServiceCmd)
		return
	}
	if optFirewall != "" {
		firewallControl(optFirewall)
		return
	}
	if optConsole {
		attachConsole()
		runConsole()
		return
	}
	runGUI()
}

// attachConsole reattaches a windowsgui-subsystem binary to its launching
// console (cmd.exe) so -console output is visible. The binary is built with
// -H windowsgui (no console of its own) so the GUI launches without a flashing
// console window; this hook restores stdio for the headless path.
func attachConsole() {
	const attachParentProcess = ^uintptr(0) // (DWORD)-1 = ATTACH_PARENT_PROCESS
	k32 := syscall.NewLazyDLL("kernel32.dll")
	r, _, _ := k32.NewProc("AttachConsole").Call(attachParentProcess)
	if r == 0 {
		return // no parent console to attach to
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
		log.SetOutput(out)
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
}
