//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// Windows Defender Firewall integration via netsh. We add inbound allow rules
// that are BOTH program-scoped (this exe) AND port-scoped — one rule per port
// printcap actually listens on. Per-port least-privilege rules are what
// enterprise security teams expect over a blanket program rule. Requires
// Administrator.

const (
	// Legacy blanket rule names, removed on upgrade so old installs are cleaned up.
	fwLegacyTCP = "printcap (TCP in)"
	fwLegacyUDP = "printcap (UDP in)"
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

// firewallPorts returns the configured inbound ports grouped by protocol, based
// on the live cfg. Zero/disabled ports are skipped. Recomputed on every call so
// add/remove always reflect the current configuration.
func firewallPorts() (tcp, udp []int) {
	add := func(dst *[]int, p int) {
		if p > 0 {
			*dst = append(*dst, p)
		}
	}

	// TCP listeners.
	add(&tcp, cfg.Ports.Raw9100)
	for _, p := range cfg.Raw.ExtraPorts {
		add(&tcp, p)
	}
	add(&tcp, cfg.Ports.LPR)
	add(&tcp, cfg.Ports.IPP)
	add(&tcp, cfg.Ports.IPPS)
	add(&tcp, cfg.Ports.AutoTLS)
	add(&tcp, cfg.Ports.Dashboard)
	if cfg.SMB.Enabled {
		add(&tcp, cfg.SMB.Port)
	}
	if cfg.WSD.Enabled {
		add(&tcp, cfg.WSD.Port)
	}

	// UDP listeners.
	if cfg.SNMP.Enabled {
		add(&udp, cfg.Ports.SNMP)
	}
	if cfg.MDNS.Enabled {
		add(&udp, 5353) // mDNS / DNS-SD
	}
	if cfg.WSD.Enabled {
		add(&udp, 3702) // WS-Discovery multicast
	}
	return tcp, udp
}

// fwRuleName builds the per-port rule name, e.g. "printcap TCP 9100".
func fwRuleName(proto string, port int) string {
	return "printcap " + proto + " " + strconv.Itoa(port)
}

// addFirewallRules creates per-port inbound allow rules for this executable.
// Idempotent: it removes any existing printcap rules first. Returns the number
// of rules added.
func addFirewallRules() (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	_ = removeFirewallRules() // best-effort cleanup so we don't stack duplicates

	tcp, udp := firewallPorts()
	add := func(proto string, port int) error {
		return runHidden("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+fwRuleName(proto, port), "dir=in", "action=allow", "program="+exe,
			"protocol="+proto, "localport="+strconv.Itoa(port), "profile=any", "enable=yes")
	}

	n := 0
	for _, p := range tcp {
		if err := add("TCP", p); err != nil {
			return n, err
		}
		n++
	}
	for _, p := range udp {
		if err := add("UDP", p); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// removeFirewallRules deletes every per-port printcap rule for the CURRENTLY
// known port set, plus the legacy blanket rule names (so upgrades clean up old
// rules). Best-effort per name.
func removeFirewallRules() error {
	del := func(name string) {
		_ = runHidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	}

	tcp, udp := firewallPorts()
	for _, p := range tcp {
		del(fwRuleName("TCP", p))
	}
	for _, p := range udp {
		del(fwRuleName("UDP", p))
	}
	// Legacy blanket rules from older installs.
	del(fwLegacyTCP)
	del(fwLegacyUDP)
	return nil
}

// firewallControl handles the -firewall CLI flag.
func firewallControl(cmd string) {
	switch cmd {
	case "add", "allow":
		n, err := addFirewallRules()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error (run as Administrator?):", err)
			os.Exit(1)
		}
		fmt.Printf("firewall: added %d port rule(s) for printcap\n", n)
	case "remove", "delete":
		_ = removeFirewallRules()
		fmt.Println("firewall rules removed")
	default:
		fmt.Fprintln(os.Stderr, "unknown -firewall command:", cmd, "(want add|remove)")
		os.Exit(2)
	}
}
