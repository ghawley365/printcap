package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// classifyListenErr turns a raw bind/listen error into an operator-actionable
// message: it names the likely cause (port already in use, privileged port /
// permission, unavailable bind address) and the concrete fix. Anything it does
// not recognize falls back to the raw error with a "-check" hint. name is the
// listener label ("9100", "IPP", …), proto is "tcp"/"udp", port is the port.
func classifyListenErr(name, proto string, port int, err error) string {
	if err == nil {
		return ""
	}
	switch sockErrClass(err) {
	case "inuse":
		return fmt.Sprintf("%s port %d/%s is already in use by another program. "+
			"Find what holds it:  netstat -ano | findstr :%d   then   tasklist /fi \"pid eq <PID>\". "+
			"(On Windows the SNMP Service commonly holds UDP 161, and the Print Spooler can hold 515/631.) "+
			"Stop that program/service, or change printcap's %s port, then restart.",
			name, port, proto, port, name)
	case "perm":
		if port > 0 && port < 1024 {
			return fmt.Sprintf("%s port %d/%s could not be opened: permission denied. "+
				"Port %d is privileged (<1024) — run printcap as Administrator (right-click → Run as administrator), "+
				"or move %s to a high port (e.g. LPR 1515, IPP 6310, raw 9100).",
				name, port, proto, port, name)
		}
		return fmt.Sprintf("%s port %d/%s could not be opened: permission denied. "+
			"Run printcap as Administrator, or allow it through Windows Defender Firewall.",
			name, port, proto)
	case "notavail":
		return fmt.Sprintf("%s could not bind address %q (port %d): that address is not available on this machine. "+
			"Use 0.0.0.0 (all interfaces), 127.0.0.1 (loopback only), or a local interface IP.",
			name, cfg.Bind, port)
	default:
		return fmt.Sprintf("%s port %d/%s failed to start: %v  (run 'printcap -check' to validate ports and paths)",
			name, port, proto, err)
	}
}

// sockErrClass classifies a socket error using the portable syscall constants,
// then defers to the platform hook for Windows Sockets (WSA) error numbers,
// which differ from the C errno values on Windows.
func sockErrClass(err error) string {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return "inuse"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM), os.IsPermission(err):
		return "perm"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "notavail"
	}
	return winSockErrClass(err)
}
