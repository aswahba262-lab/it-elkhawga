# Starts the IT ELKHAWGA relay on this PC and (optionally) a public HTTPS tunnel.
# Usage:
#   powershell -ExecutionPolicy Bypass -File relay\start-relay.ps1            # LAN only
#   powershell -ExecutionPolicy Bypass -File relay\start-relay.ps1 -Public    # LAN + HTTPS tunnel
param(
  [switch]$Public,
  [int]$Port = 8790
)
$ErrorActionPreference = "Stop"

$here = $PSScriptRoot
$dataDir = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# Stable admin key kept on disk across restarts.
$keyFile = Join-Path $dataDir "admin-key.txt"
if (-not (Test-Path $keyFile)) {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  (-join ($bytes | ForEach-Object { $_.ToString("x2") })) | Set-Content -LiteralPath $keyFile -Encoding ASCII
}
$adminKey = (Get-Content -LiteralPath $keyFile -Raw).Trim()

$env:ADMIN_KEY = $adminKey
$env:DATA_DIR  = $dataDir
$env:PORT      = "$Port"

Write-Host ""
Write-Host "=== IT ELKHAWGA Relay ===" -ForegroundColor Cyan
Write-Host "Local URL : http://localhost:$Port"
Write-Host "LAN URL   : http://$((Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress):$Port"
Write-Host "ADMIN_KEY : $adminKey"
Write-Host "DATA_DIR  : $dataDir"
Write-Host ""

# Start the relay in a separate process so the tunnel can run alongside.
$relay = Start-Process -FilePath "node" -ArgumentList "`"$here\server.js`"" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 1

if ($Public) {
  $cf = Join-Path $here "bin\cloudflared.exe"
  if (-not (Test-Path $cf)) {
    Write-Host "cloudflared not found - downloading..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path (Join-Path $here "bin") | Out-Null
    Invoke-WebRequest -Uri "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe" -OutFile $cf -UseBasicParsing
  }
  $log = Join-Path $dataDir "tunnel.log"
  $tunnel = Start-Process -FilePath $cf -ArgumentList "tunnel","--no-autoupdate","--url","http://localhost:$Port" -PassThru -WindowStyle Hidden -RedirectStandardError $log
  Write-Host "Opening public HTTPS tunnel..." -ForegroundColor Yellow
  $url = $null
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 750
    if (Test-Path $log) {
      $m = Select-String -Path $log -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -AllMatches |
           ForEach-Object { $_.Matches } | Select-Object -First 1
      if ($m) { $url = $m.Value; break }
    }
  }
  if ($url) {
    Write-Host ""
    Write-Host "PUBLIC URL : $url" -ForegroundColor Green
    Write-Host "Put this URL + ADMIN_KEY in the Admin app -> الربط السحابي" -ForegroundColor Green
    Write-Host ""
  } else {
    Write-Host "Tunnel started but URL not detected yet. Check $log" -ForegroundColor Yellow
  }
  Write-Host "Relay PID: $($relay.Id)   Tunnel PID: $($tunnel.Id)"
  Write-Host "Press Ctrl+C to stop the relay (tunnel keeps running; close its process if needed)." -ForegroundColor Yellow
} else {
  Write-Host "Relay PID: $($relay.Id)"
  Write-Host "Put the LAN URL + ADMIN_KEY in the Admin app -> الربط السحابي" -ForegroundColor Yellow
  Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
}

Wait-Process -Id $relay.Id
