<#
.SYNOPSIS
  Enable Windows Internet Connection Sharing (ICS) so a printer on one adapter
  reaches the internet through another. printcap does this automatically when the
  Capture tab's ICS fields are set; this script is the same thing for manual use.

.DESCRIPTION
  Shares the -Public (internet) connection and marks -Private (printer side) as
  the shared/home network. Must run elevated (Administrator). Uses the HNetCfg
  COM API — there is no netsh equivalent for ICS.

  NOTE: ICS forces the private adapter to 192.168.137.1/24 with its own DHCP+NAT.
  It fits the "this PC is the printer's router" topology. For an ARP-MITM on an
  existing LAN where the printer keeps its real IP, use RRAS NAT instead.

.EXAMPLE
  .\ics-enable.ps1 -Public "Wi-Fi" -Private "Ethernet"
#>
param(
  [Parameter(Mandatory = $true)][string]$Public,
  [Parameter(Mandatory = $true)][string]$Private
)
$ErrorActionPreference = 'Stop'

Set-Service -Name SharedAccess -StartupType Automatic
Start-Service -Name SharedAccess

$m = New-Object -ComObject HNetCfg.HNetShare
$pub = $null; $prv = $null
foreach ($c in $m.EnumEveryConnection) {
  $p = $m.NetConnectionProps.Invoke($c)
  if ($p.Name -eq $Public)  { $pub = $c }
  if ($p.Name -eq $Private) { $prv = $c }
}
if (-not $pub) { throw "internet connection '$Public' not found" }
if (-not $prv) { throw "printer connection '$Private' not found" }

$m.INetSharingConfigurationForINetConnection.Invoke($pub).EnableSharing(0)  # 0 = public
$m.INetSharingConfigurationForINetConnection.Invoke($prv).EnableSharing(1)  # 1 = private
Write-Host "ICS enabled: '$Public' (internet) -> '$Private' (printer). Printer adapter is now 192.168.137.1 with NAT."
