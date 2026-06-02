//go:build !windows

package main

// dispatch on non-Windows platforms always runs the console front-end. The GUI
// and Windows-service modes are Windows-only.
func dispatch() {
	runConsole()
}

// attachConsole is a no-op off Windows (the process already has a console).
func attachConsole() {}
