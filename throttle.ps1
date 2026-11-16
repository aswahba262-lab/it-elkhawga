param(
  [int]$Kbps = 0,
  [string]$DataDir = "",
  [int]$EnableProxy = 0
)

# Applies or clears a Windows QoS outbound throttle policy, and optionally
# forces the system proxy through the local agent proxy so traffic can be
# logged and shaped.
$name = "IT ELKHAWGA Throttle"

try {
  Get-NetQosPolicy -Name $name -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
} catch {}

if ($Kbps -gt 0) {
  try {
    New-NetQosPolicy -Name $name -ThrottleRate "$($Kbps)Kbps" -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  } catch {
    Write-Host "QOSERR: $($_.Exception.Message)"
  }
}

$inet = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
if ($Kbps -gt 0 -or $EnableProxy -eq 1) {
  if (-not (Test-Path $inet)) { New-Item -Path $inet -Force | Out-Null }
  Set-ItemProperty -Path $inet -Name "ProxyEnable" -Value 1 -Type DWord
  Set-ItemProperty -Path $inet -Name "ProxyServer" -Value "127.0.0.1:8080" -Type String
  Set-ItemProperty -Path $inet -Name "ProxyOverride" -Value "<local>" -Type String
  Write-Host "OK: proxy forced for shaping"
} elseif ($EnableProxy -eq -1) {
  if (Test-Path $inet) {
    Set-ItemProperty -Path $inet -Name "ProxyEnable" -Value 0 -Type DWord
    Remove-ItemProperty -Path $inet -Name "ProxyServer" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $inet -Name "ProxyOverride" -ErrorAction SilentlyContinue
  }
  Write-Host "OK: proxy released"
}

Write-Host "OK: throttle $($Kbps)Kbps"
exit 0
