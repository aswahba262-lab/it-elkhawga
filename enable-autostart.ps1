#Requires -RunAsAdministrator

# ============================================
# Enable Autostart Script
# ============================================

$taskName = "Block-Internet-AutoStart"
$scriptPath = Join-Path $PSScriptRoot "block-internet.ps1"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   Enable Autostart with Windows" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Check if task exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($existingTask) {
    # Remove old task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "OK: Removed old task" -ForegroundColor Yellow
}

# Create new task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "OK: Autostart enabled successfully!" -ForegroundColor Green
Write-Host "`nThe script will run automatically when Windows starts" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

Start-Sleep -Seconds 2
