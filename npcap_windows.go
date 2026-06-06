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

// bundledNpcapInstaller returns the path to an Npcap installer shipped next to
// printcap.exe (npcap-installer.exe, npcap.exe, or npcap-*.exe), or "".
func bundledNpcapInstaller() string {
	dir := exeDir()
	for _, name := range []string{"npcap-installer.exe", "npcap.exe"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "npcap-*.exe")); len(m) > 0 {
		return m[0]
	}
	return ""
}

// ensureNpcap returns true when live capture can proceed. When it can't, it
// explains why and offers a fix (use the Npcap build, run the bundled installer,
// or open the download page), then returns false.
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
	if inst := bundledNpcapInstaller(); inst != "" {
		if walk.MsgBox(parent, "Npcap required",
			"Live packet capture needs Npcap, which is not installed.\n\nRun the bundled Npcap installer now? A Windows UAC prompt will appear — in the installer, tick \"Install Npcap in WinPcap API-compatible Mode\". When it finishes, click Start capture again.",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			if err := exec.Command(inst).Start(); err != nil {
				walk.MsgBox(parent, "Npcap", "Could not launch the installer:\n"+err.Error()+"\n\nRun it manually:\n"+inst, walk.MsgBoxIconError)
			}
		}
		return false
	}
	if walk.MsgBox(parent, "Npcap required",
		"Live packet capture needs Npcap, which is not installed, and no bundled installer was found next to printcap.exe.\n\nOpen the Npcap download page now?",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", "https://npcap.com/#download").Start()
	}
	return false
}
