# Run on the CURRENT machine (laptop) to package the relay state for migration.
# Usage: powershell -ExecutionPolicy Bypass -File relay\export-laptop.ps1
$ErrorActionPreference = "Stop"

$src = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"
$out = Join-Path $PSScriptRoot "migrate"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# Stop the running relay so the SQLite file is consistent.
try { schtasks /End /TN "IT ELKHAWGA Relay" | Out-Null } catch {}
Start-Sleep -Seconds 2

foreach ($f in @("relay.db", "relay.db-wal", "relay.db-shm", "admin-key.txt")) {
  $p = Join-Path $src $f
  if (Test-Path $p) {
    Copy-Item -LiteralPath $p -Destination (Join-Path $out $f) -Force
    Write-Host "copied $f"
  }
}

Write-Host ""
Write-Host "Migration bundle ready: $out" -ForegroundColor Green
Write-Host "Copy the whole 'relay' folder to the company PC, then run install-server.ps1 there (as Administrator)."
