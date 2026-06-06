//go:build (windows && npcap) || darwin || linux

package main

// captureBuilt reports that this binary was compiled WITH a live-capture backend
// (Npcap on Windows, BPF on macOS, AF_PACKET on Linux). The default Windows build
// (no npcap tag) sets this false so the GUI can tell the user to use the Npcap
// build rather than prompting them to install Npcap for a binary that can't use it.
const captureBuilt = true
