param([string]$InstallDir)
$ErrorActionPreference = "Continue"

$log = Join-Path $env:TEMP "it-elkhawga-install.log"
"[$(Get-Date -Format o)] install-tasks start dir=$InstallDir" | Out-File $log -Append
$exe = Join-Path $InstallDir "it-elkhawga.exe"
if (-not (Test-Path $exe)) { "exe not found: $exe" | Out-File $log -Append; exit 1 }
# Agent (SYSTEM, on start)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--agent"
  $t = New-ScheduledTaskTrigger -AtStartup
  $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
  "agent task OK" | Out-File $log -Append
  Start-ScheduledTask -TaskName "IT ELKHAWGA Agent" -ErrorAction SilentlyContinue
} catch { "agent task ERR: $($_.Exception.Message)" | Out-File $log -Append }
# Screen capture (interactive user, on logon)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--capture-agent"
  $t = New-ScheduledTaskTrigger -AtLogOn
  $p = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
  "screen task OK" | Out-File $log -Append
  Start-ScheduledTask -TaskName "IT ELKHAWGA Screen" -ErrorAction SilentlyContinue
} catch { "screen task ERR: $($_.Exception.Message)" | Out-File $log -Append }
# firewall
try { netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787 profile=private,domain 2>&1 | Out-Null } catch {}
# cleanup legacy
try { Unregister-ScheduledTask -TaskName "InternetBlockerAgent" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
"install-tasks done" | Out-File $log -Append
