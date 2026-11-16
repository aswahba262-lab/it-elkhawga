# Starts the relay + the permanent Cloudflare tunnel (relay.itkhawaga-2027.com).
# Requires: relay\cloudflared.yml and the tunnel credentials in %USERPROFILE%\.cloudflared
param([int]$Port = 8790)
$ErrorActionPreference = "Stop"

$here = $PSScriptRoot
$dataDir = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

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
Write-Host "=== IT ELKHAWGA Relay (stable) ===" -ForegroundColor Cyan
Write-Host "Stable URL : https://relay.itkhawaga-2027.com"
Write-Host "Local URL  : http://localhost:$Port"
Write-Host "ADMIN_KEY  : $adminKey"
Write-Host ""

node (Join-Path $here "server.js") | Out-Null &
$relay = $LASTEXITCODE

$cf = Join-Path $here "bin\cloudflared.exe"
$cfg = Join-Path $here "cloudflared.yml"

Write-Host "Starting Cloudflare tunnel..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
& $cf tunnel --no-autoupdate --config $cfg run it-elkhawga
