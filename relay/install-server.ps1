# Installs the IT ELKHAWGA relay on this Windows PC as an always-on service-like task.
# Run as Administrator:
#   powershell -ExecutionPolicy Bypass -File install-server.ps1
#
# It expects the 'relay' folder (server.js, run-relay.cmd, optional migrate\* files)
# to be present next to this script.
param(
  [int]$Port = 8790,
  [switch]$SkipMigrate
)
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
  }
}

Assert-Admin

$here = $PSScriptRoot
$dataDir = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

# 1) Node.js
$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) {
  throw "Node.js is not installed. Install Node.js LTS (https://nodejs.org) and run again."
}
Write-Host ("Node: " + (& node --version)) -ForegroundColor Green

# 2) Migrate the existing database + admin key (keeps enrolled devices and the admin key)
$migrate = Join-Path $here "migrate"
if (-not $SkipMigrate -and (Test-Path $migrate)) {
  foreach ($f in @("relay.db", "relay.db-wal", "relay.db-shm", "admin-key.txt")) {
    $p = Join-Path $migrate $f
    if (Test-Path $p) {
      Copy-Item -LiteralPath $p -Destination (Join-Path $dataDir $f) -Force
      Write-Host "migrated $f"
    }
  }
}

# 3) Admin key must exist
$keyFile = Join-Path $dataDir "admin-key.txt"
if (-not (Test-Path $keyFile)) {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  (-join ($bytes | ForEach-Object { $_.ToString("x2") })) | Set-Content -LiteralPath $keyFile -Encoding ASCII
  Write-Host "generated a new admin key" -ForegroundColor Yellow
}

# 4) Firewall (LAN access to the relay port)
try {
  New-NetFirewallRule -DisplayName "IT ELKHAWGA Relay $Port" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private,Domain -ErrorAction SilentlyContinue | Out-Null
} catch {}

# 5) Scheduled task: start at boot as SYSTEM
$cmd = Join-Path $here "run-relay.cmd"
if (-not (Test-Path $cmd)) { throw "run-relay.cmd not found next to install-server.ps1" }
schtasks /Create /TN "IT ELKHAWGA Relay" /TR "\"$cmd\"" /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
schtasks /End /TN "IT ELKHAWGA Relay" 2>$null | Out-Null
Start-Sleep -Seconds 1
schtasks /Run /TN "IT ELKHAWGA Relay" | Out-Null
Start-Sleep -Seconds 4

# 5b) Watchdog: every 5 minutes, restart the relay if it stopped answering
$watchdog = Join-Path $here "watchdog.ps1"
if (Test-Path $watchdog) {
  $tr = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$watchdog`""
  schtasks /Create /TN "IT ELKHAWGA Relay Watchdog" /TR "$tr" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /F | Out-Null
  Write-Host "watchdog installed (every 5 minutes)"
}

# 6) Verify
try {
  $h = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -UseBasicParsing -TimeoutSec 8
  Write-Host ("Relay health: " + $h.Content) -ForegroundColor Green
} catch {
  Write-Host "Relay is not responding yet. Check the task 'IT ELKHAWGA Relay'." -ForegroundColor Red
}

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1).IPAddress
$key = (Get-Content -LiteralPath $keyFile -Raw).Trim()

Write-Host ""
Write-Host "=== IT ELKHAWGA Relay installed ===" -ForegroundColor Cyan
Write-Host "LAN URL   : http://$ip`:$Port"
Write-Host "ADMIN_KEY : $key"
Write-Host ""
Write-Host "Next: expose it over HTTPS (Tailscale Funnel or Cloudflare Tunnel + domain),"
Write-Host "then put that URL + ADMIN_KEY into the Admin app."
