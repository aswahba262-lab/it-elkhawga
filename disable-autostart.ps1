#Requires -RunAsAdministrator

# ============================================
# Disable Autostart Script
# ============================================

$taskName = "Block-Internet-AutoStart"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   Disable Autostart" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "OK: Autostart disabled" -ForegroundColor Green
}
else {
    Write-Host "WARN: Autostart is not enabled" -ForegroundColor Yellow
}

Write-Host "`n========================================`n" -ForegroundColor Cyan

Start-Sleep -Seconds 2
