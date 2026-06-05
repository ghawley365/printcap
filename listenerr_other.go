//go:build !windows

package main

// winSockErrClass is a no-op on non-Windows platforms; the portable syscall
// constants in sockErrClass already cover Unix bind errors.
func winSockErrClass(err error) string { return "" }
