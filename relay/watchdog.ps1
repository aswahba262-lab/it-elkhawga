# Watchdog: if the relay is not answering, (re)start its scheduled task.
# Registered to run every 5 minutes as SYSTEM. Safe to run manually.
$port = 8790
$taskName = "IT ELKHAWGA Relay"
$healthy = $false

try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/healthz" -UseBasicParsing -TimeoutSec 5
  $healthy = ($r.StatusCode -eq 200)
} catch { $healthy = $false }

if (-not $healthy) {
  try { schtasks /Run /TN $taskName | Out-Null } catch {}
  Start-Sleep -Seconds 4
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/healthz" -UseBasicParsing -TimeoutSec 5
    if ($r.StatusCode -eq 200) {
      Add-Content -Path (Join-Path $env:ProgramData "IT-ELKHAWGA-Relay\watchdog.log") -Value "$(Get-Date -Format s) restarted relay"
    }
  } catch {
    Add-Content -Path (Join-Path $env:ProgramData "IT-ELKHAWGA-Relay\watchdog.log") -Value "$(Get-Date -Format s) restart failed"
  }
}
