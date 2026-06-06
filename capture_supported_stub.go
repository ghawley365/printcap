//go:build !((windows && npcap) || darwin || linux)

package main

// captureBuilt is false: this build has no live-capture backend (e.g. a default
// Windows build without the npcap tag).
const captureBuilt = false
