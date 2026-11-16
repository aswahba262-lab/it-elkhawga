# Starts the IT ELKHAWGA relay locally on this PC (LAN testing).
# Usage:  powershell -ExecutionPolicy Bypass -File relay\start-local.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dataDir = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"

# Reuse the admin key across restarts so the admin app keeps working.
$keyFile = Join-Path $dataDir "admin-key.txt"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
if (Test-Path $keyFile) {
  $adminKey = (Get-Content -LiteralPath $keyFile -Raw).Trim()
} else {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $adminKey = -join ($bytes | ForEach-Object { $_.ToString("x2") })
  Set-Content -LiteralPath $keyFile -Value $adminKey -Encoding ASCII
}

$env:ADMIN_KEY = $adminKey
$env:DATA_DIR  = $dataDir
$env:PORT      = if ($env:PORT) { $env:PORT } else { "8787" }

Write-Host ""
Write-Host "=== IT ELKHAWGA Relay ===" -ForegroundColor Cyan
Write-Host "URL        : http://<this-pc-ip>:$($env:PORT)"
Write-Host "ADMIN_KEY  : $adminKey"
Write-Host "DATA_DIR   : $dataDir"
Write-Host "Health     : http://127.0.0.1:$($env:PORT)/healthz"
Write-Host ""
Write-Host "Put the URL + ADMIN_KEY into the Admin app -> 'الربط السحابي'." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host ""

node (Join-Path $PSScriptRoot "server.js")
