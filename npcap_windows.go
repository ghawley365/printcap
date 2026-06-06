//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/lxn/walk"
)

// Npcap presence detection and install prompting for the Windows GUI. gopacket
// loads wpcap.dll at runtime, so capture silently produces nothing if Npcap is
// absent; these helpers detect that and guide the user to install it (running a
// bundled installer if one ships next to the exe, else the download page).

// npcapInstalled reports whether the Npcap (or legacy WinPcap) runtime appears to
// be present, by looking for wpcap.dll in the usual locations.
func npcapInstalled() bool {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	for _, p := range []string{
		filepath.Join(root, "System32", "Npcap", "wpcap.dll"),
		filepath.Join(root, "System32", "wpcap.dll"),
		filepath.Join(root, "SysWOW64", "Npcap", "wpcap.dll"),
		filepath.Join(root, "SysWOW64", "wpcap.dll"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// ensureNpcap returns true when live capture can proceed. When it can't, it
// explains why and offers to open the Npcap download page, then returns false.
func ensureNpcap(parent walk.Form) bool {
	if !captureBuilt {
		walk.MsgBox(parent, "Live capture not in this build",
			"This printcap build does not include the live-capture driver.\n\nUse the Npcap build (printcap.exe from the -tags=npcap CI artifact) and install Npcap from npcap.com.",
			walk.MsgBoxIconWarning)
		return false
	}
	if npcapInstalled() {
		return true
	}
	if walk.MsgBox(parent, "Npcap required",
		"Live packet capture needs Npcap, which is not installed.\n\nOpen the Npcap download page now? Install it (tick \"Install Npcap in WinPcap API-compatible Mode\"), then click Start capture again.",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", "https://npcap.com/#download").Start()
	}
	return false
}
