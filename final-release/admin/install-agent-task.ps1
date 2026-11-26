param([string]$InstallDir)
$ErrorActionPreference = "Continue"

$log = Join-Path $env:TEMP "it-elkhawga-install.log"
"[$(Get-Date -Format o)] install-tasks start dir=$InstallDir" | Out-File $log -Append
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  "not running as administrator - killing non-elevated processes so SYSTEM task takes over port 8788" | Out-File $log -Append
  & schtasks.exe /Run /TN "IT ELKHAWGA Agent" 2>&1 | Out-Null
  & taskkill.exe /F /IM it-elkhawga.exe /IM it-elkhawga.old.exe /IM it-elkhawga-client.exe /IM it-elkhawga-client.old.exe 2>&1 | Out-Null
  exit 0
}
$exe = Join-Path $InstallDir "it-elkhawga.exe"
$oldExe = Join-Path $InstallDir "it-elkhawga.old.exe"
if ((-not (Test-Path $exe)) -and (Test-Path $oldExe)) {
  Copy-Item -Path $oldExe -Destination $exe -Force -ErrorAction SilentlyContinue
  "self-healed missing it-elkhawga.exe from it-elkhawga.old.exe" | Out-File $log -Append
}
if (-not (Test-Path $exe)) { "exe not found: $exe" | Out-File $log -Append; exit 1 }

# Also sync to the alternate install folder (Program Files vs LocalAppData) if it exists from an older install
$altDirs = @(
  "$env:ProgramFiles\IT ELKHAWGA Client",
  "C:\Windows\System32\config\systemprofile\AppData\Local\IT ELKHAWGA Client"
)
foreach ($ad in $altDirs) {
  if ($ad -and ($ad -ne $InstallDir) -and (Test-Path $ad)) {
    try {
      Copy-Item -Path "$InstallDir\*" -Destination $ad -Recurse -Force -ErrorAction SilentlyContinue
      "synced updated files to alternate dir: $ad" | Out-File $log -Append
    } catch {}
  }
}

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
# Agent (SYSTEM, at boot, on user logon, AND every 5 minutes with auto-restart so it never stays offline)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--agent"
  $t1 = New-ScheduledTaskTrigger -AtStartup
  $t2 = New-ScheduledTaskTrigger -AtLogOn
  $t3 = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(-1)) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
  $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "IT ELKHAWGA Agent" -Action $a -Trigger @($t1, $t2, $t3) -Principal $p -Settings $s -Force | Out-Null
  "agent task OK" | Out-File $log -Append
  Start-ScheduledTask -TaskName "IT ELKHAWGA Agent" -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 900
  $agentRunning = Get-CimInstance Win32_Process -Filter "Name = 'it-elkhawga.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '--agent' }
  if (-not $agentRunning) {
    Start-Process -FilePath $exe -ArgumentList "--agent" -WindowStyle Hidden -ErrorAction SilentlyContinue
    "agent fallback direct start OK" | Out-File $log -Append
  }
} catch { "agent task ERR: $($_.Exception.Message)" | Out-File $log -Append }
# Screen capture (interactive user, on logon for ALL users, not just the UAC admin)
try {
  Unregister-ScheduledTask -TaskName "IT ELKHAWGA Screen" -Confirm:$false -ErrorAction SilentlyContinue
  $a = New-ScheduledTaskAction -Execute $exe -Argument "--capture-agent"
  $t = New-ScheduledTaskTrigger -AtLogOn
  $p = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
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
# Stop any pre-update renamed binaries (it-elkhawga.old.exe / running older process) AFTER new files & tasks are installed, then start the fresh SYSTEM task.
# IMPORTANT: Spawn an independent background cmd/powershell process to kill old processes & start the new task so that if this installer is inside the old task's Job Object, killing the old process doesn't abort task startup!
try {
  $relauncher = "ping 127.0.0.1 -n 2 >nul & taskkill /F /IM it-elkhawga.exe /IM it-elkhawga.old.exe /IM it-elkhawga-client.exe /IM it-elkhawga-client.old.exe >nul 2>&1 & ping 127.0.0.1 -n 2 >nul & schtasks /Run /TN `"IT ELKHAWGA Agent`" >nul 2>&1 & schtasks /Run /TN `"IT ELKHAWGA Screen`" >nul 2>&1 & start `"`" /B `"$exe`" --agent"
  & schtasks.exe /Create /TN "IT ELKHAWGA Restart" /TR "cmd.exe /c $relauncher" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
  & schtasks.exe /Run /TN "IT ELKHAWGA Restart" 2>&1 | Out-Null
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c $relauncher" -WindowStyle Hidden -ErrorAction SilentlyContinue
} catch {}
"install-tasks done" | Out-File $log -Append
