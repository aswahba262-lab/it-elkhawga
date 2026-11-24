param([string]$InstallDir)
$ErrorActionPreference = "Continue"

$log = Join-Path $env:TEMP "it-elkhawga-install.log"
"[$(Get-Date -Format o)] install-tasks start dir=$InstallDir" | Out-File $log -Append
$exe = Join-Path $InstallDir "it-elkhawga.exe"
if (-not (Test-Path $exe)) { "exe not found: $exe" | Out-File $log -Append; exit 1 }

$isAdminInstall = $false
$modeFile = Join-Path $InstallDir "build-mode.json"
if (Test-Path $modeFile) {
  try {
    $m = Get-Content -LiteralPath $modeFile -Raw | ConvertFrom-Json
    if ($m.mode -eq "admin") { $isAdminInstall = $true }
  } catch {}
}

if ($isAdminInstall) {
  "admin mode detected: cleaning any client agent tasks on this admin machine" | Out-File $log -Append
  try { Unregister-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  try { Unregister-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  try { Unregister-ScheduledTask -TaskName "InternetBlockerAgent" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
  try { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "IT ELKHAWGA Agent" -ErrorAction SilentlyContinue } catch {}
  try { Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "IT ELKHAWGA Screen" -ErrorAction SilentlyContinue } catch {}
  try {
    Get-CimInstance Win32_Process -Filter "Name LIKE 'it-elkhawga%'" -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.ExecutablePath -eq $exe -and $_.CommandLine -match '--agent|--capture-agent') {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
      }
    }
  } catch {}
  try {
    netsh advfirewall firewall delete rule name="IT ELKHAWGA Relay" 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787-8796 profile=any 2>&1 | Out-Null
    netsh advfirewall firewall delete rule name="IT ELKHAWGA RustDesk OSS TCP" 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk OSS TCP" dir=in action=allow protocol=TCP localport=21115-21119 profile=any 2>&1 | Out-Null
    netsh advfirewall firewall delete rule name="IT ELKHAWGA RustDesk OSS UDP" 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk OSS UDP" dir=in action=allow protocol=UDP localport=21116 profile=any 2>&1 | Out-Null
  } catch {}
  "admin install-tasks done" | Out-File $log -Append
  exit 0
}
# Agent (SYSTEM, at boot AND on user logon so Fast Startup never skips it)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--agent"
  $t1 = New-ScheduledTaskTrigger -AtStartup
  $t2 = New-ScheduledTaskTrigger -AtLogOn
  $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Action $a -Trigger @($t1, $t2) -Principal $p -Settings $s -Force | Out-Null
  "agent task OK" | Out-File $log -Append
  Start-ScheduledTask -TaskName "IT ELKHAWGA Agent" -ErrorAction SilentlyContinue
} catch { "agent task ERR: $($_.Exception.Message)" | Out-File $log -Append }
# Screen capture (interactive user, on logon for ALL users, not just the UAC admin)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--capture-agent"
  $t = New-ScheduledTaskTrigger -AtLogOn
  $p = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
  "screen task OK" | Out-File $log -Append
  Start-ScheduledTask -TaskName "IT ELKHAWGA Screen" -ErrorAction SilentlyContinue
} catch { "screen task ERR: $($_.Exception.Message)" | Out-File $log -Append }
# Register HKLM Run ONLY for the interactive user-session screen helper (--capture-agent).
# Never put --agent in HKLM Run, otherwise a non-elevated user --agent could grab port 8788
# before the SYSTEM Scheduled Task starts!
try {
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "IT ELKHAWGA Agent" -ErrorAction SilentlyContinue
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "IT ELKHAWGA Screen" -Value "`"$exe`" --capture-agent" -Force
} catch {}
# firewall
try {
  netsh advfirewall firewall delete rule name="IT ELKHAWGA Relay" 2>&1 | Out-Null
  netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787-8796 profile=any 2>&1 | Out-Null
  netsh advfirewall firewall delete rule name="IT ELKHAWGA RustDesk Direct" 2>&1 | Out-Null
  netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk Direct" dir=in action=allow protocol=TCP localport=21118 profile=private,domain 2>&1 | Out-Null
  netsh advfirewall firewall delete rule name="IT ELKHAWGA RustDesk Discovery" 2>&1 | Out-Null
  netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk Discovery" dir=in action=allow protocol=UDP localport=21116 profile=private,domain 2>&1 | Out-Null
} catch {}
# cleanup legacy
try { Unregister-ScheduledTask -TaskName "InternetBlockerAgent" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
"install-tasks done" | Out-File $log -Append
