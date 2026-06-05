//go:build windows

package main

import (
	"errors"
	"syscall"
)

// Windows Sockets (WSA) error numbers, defined explicitly because the syscall
// package does not export all of them by name across Go versions. A failed bind
// surfaces as an *os.SyscallError wrapping a syscall.Errno with these values, so
// errors.Is matches them by value.
const (
	wsaeAddrInUse    = syscall.Errno(10048) // WSAEADDRINUSE  — port already in use
	wsaeAccess       = syscall.Errno(10013) // WSAEACCES      — permission denied / blocked
	wsaeAddrNotAvail = syscall.Errno(10049) // WSAEADDRNOTAVAIL — bad bind address
)

// winSockErrClass matches the WSA error numbers, which differ from the portable
// C errno values the cross-platform sockErrClass already checks.
func winSockErrClass(err error) string {
	switch {
	case errors.Is(err, wsaeAddrInUse):
		return "inuse"
	case errors.Is(err, wsaeAccess):
		return "perm"
	case errors.Is(err, wsaeAddrNotAvail):
		return "notavail"
	}
	return ""
}
