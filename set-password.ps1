#Requires -RunAsAdministrator

# ============================================
# Set Password Script
# ============================================

$dataDir = Join-Path $env:ProgramData "InternetBlocker"
if (-not (Test-Path $dataDir)) { New-Item -ItemType Directory -Path $dataDir -Force | Out-Null }
$configFile = Join-Path $dataDir "config.json"
if (-not (Test-Path $configFile) -and (Test-Path (Join-Path $PSScriptRoot "config.json"))) {
    Copy-Item (Join-Path $PSScriptRoot "config.json") $configFile
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   Set Protection Password" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Read current config
if (Test-Path $configFile) {
    $config = Get-Content $configFile | ConvertFrom-Json
} else {
    $config = @{
        mode = "whitelist"
        password_hash = ""
        log_file = "blocked-attempts.log"
        auto_start = $true
    }
}

# Request new password
$cred1 = Read-Host "Enter new password" -AsSecureString
$plainPass1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred1)
)

$cred2 = Read-Host "Confirm password" -AsSecureString
$plainPass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred2)
)

if ($plainPass1 -ne $plainPass2) {
    Write-Host "`nPasswords do not match!" -ForegroundColor Red
    Start-Sleep -Seconds 2
    exit 1
}

# Hash the password
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes($plainPass1)
) | ForEach-Object { $_.ToString("x2") }
$hashString = -join $hash

# Update config
$config.password_hash = $hashString
$config | ConvertTo-Json | Out-File $configFile -Encoding UTF8

Write-Host "`nOK: Password saved successfully!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Start-Sleep -Seconds 2
