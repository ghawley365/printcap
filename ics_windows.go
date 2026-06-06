//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Windows Internet Connection Sharing (ICS) automation. There is no netsh command
// for ICS; it is driven through the HNetCfg COM API, which PowerShell can call.
// enableICS shares the public (internet) connection with the private (printer)
// connection; disableICS turns sharing off everywhere for a clean teardown.
//
// Connection names are passed via environment variables (not interpolated into
// the script) so an odd adapter name can't inject PowerShell.
//
// NOTE: ICS forces the private adapter to 192.168.137.1/24 with its own DHCP+NAT
// — it suits the "this PC is the printer's router" topology, not a transparent
// ARP-MITM on an existing LAN (use RRAS NAT for that).

const psEnableICS = `
$ErrorActionPreference = 'Stop'
Set-Service -Name SharedAccess -StartupType Automatic
Start-Service -Name SharedAccess
$m = New-Object -ComObject HNetCfg.HNetShare
$pub = $null; $prv = $null
foreach ($c in $m.EnumEveryConnection) {
  $p = $m.NetConnectionProps.Invoke($c)
  if ($p.Name -eq $env:ICS_PUBLIC)  { $pub = $c }
  if ($p.Name -eq $env:ICS_PRIVATE) { $prv = $c }
}
if (-not $pub) { throw "internet connection '$($env:ICS_PUBLIC)' not found" }
if (-not $prv) { throw "printer connection '$($env:ICS_PRIVATE)' not found" }
$m.INetSharingConfigurationForINetConnection.Invoke($pub).EnableSharing(0)  # 0 = public
$m.INetSharingConfigurationForINetConnection.Invoke($prv).EnableSharing(1)  # 1 = private
Write-Host "ICS enabled: '$($env:ICS_PUBLIC)' -> '$($env:ICS_PRIVATE)'"
`

const psDisableICS = `
$ErrorActionPreference = 'Continue'
$m = New-Object -ComObject HNetCfg.HNetShare
foreach ($c in $m.EnumEveryConnection) {
  $cfg = $m.INetSharingConfigurationForINetConnection.Invoke($c)
  if ($cfg.SharingEnabled) { $cfg.DisableSharing() }
}
Write-Host "ICS disabled on all connections"
`

func runPowerShell(script string, env []string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

// enableICS turns on Internet Connection Sharing from the public (internet)
// connection to the private (printer) connection, by friendly connection name.
func enableICS(public, private string) error {
	if public == "" || private == "" {
		return fmt.Errorf("ICS needs both an internet and a printer connection name")
	}
	return runPowerShell(psEnableICS, []string{"ICS_PUBLIC=" + public, "ICS_PRIVATE=" + private})
}

// disableICS turns off Internet Connection Sharing on every connection (cleanup).
func disableICS() error {
	return runPowerShell(psDisableICS, nil)
}
