//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Windows Defender Firewall integration via netsh. We add program-scoped
// inbound allow rules (one for TCP, one for UDP) for this exe, so every port
// printcap listens on is permitted without enumerating them — and the rules
// keep working if you reconfigure ports later. Requires Administrator.

const (
	fwRuleTCP = "printcap (TCP in)"
	fwRuleUDP = "printcap (UDP in)"
)

// runHidden runs a console command without flashing a window (the GUI build has
// no console of its own).
func runHidden(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, string(out))
	}
	return nil
}

// addFirewallRules creates inbound allow rules for this executable. Idempotent:
// it removes any existing printcap rules first.
func addFirewallRules() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	_ = removeFirewallRules() // best-effort cleanup so we don't stack duplicates

	if err := runHidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+fwRuleTCP, "dir=in", "action=allow", "program="+exe,
		"protocol=TCP", "profile=any", "enable=yes"); err != nil {
		return err
	}
	if err := runHidden("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+fwRuleUDP, "dir=in", "action=allow", "program="+exe,
		"protocol=UDP", "profile=any", "enable=yes"); err != nil {
		return err
	}
	return nil
}

// removeFirewallRules deletes the printcap firewall rules (best-effort).
func removeFirewallRules() error {
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRuleTCP)
	_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+fwRuleUDP)
	return nil
}

// firewallControl handles the -firewall CLI flag.
func firewallControl(cmd string) {
	var err error
	switch cmd {
	case "add", "allow":
		if err = addFirewallRules(); err == nil {
			fmt.Println("firewall rules added for printcap")
		}
	case "remove", "delete":
		_ = removeFirewallRules()
		fmt.Println("firewall rules removed")
		return
	default:
		fmt.Fprintln(os.Stderr, "unknown -firewall command:", cmd, "(want add|remove)")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error (run as Administrator?):", err)
		os.Exit(1)
	}
}
