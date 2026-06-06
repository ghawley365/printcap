<#
.SYNOPSIS
  Disable Windows Internet Connection Sharing (ICS) on every connection — the
  cleanup counterpart to ics-enable.ps1. printcap runs this automatically on stop
  when it enabled ICS; this is the same thing for manual use. Run elevated.

.EXAMPLE
  .\ics-disable.ps1
#>
$ErrorActionPreference = 'Continue'

$m = New-Object -ComObject HNetCfg.HNetShare
$n = 0
foreach ($c in $m.EnumEveryConnection) {
  $cfg = $m.INetSharingConfigurationForINetConnection.Invoke($c)
  if ($cfg.SharingEnabled) { $cfg.DisableSharing(); $n++ }
}
Write-Host "ICS disabled on $n connection(s)."
