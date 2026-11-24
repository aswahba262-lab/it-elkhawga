# ============================================
# Unblock Internet (machine-wide)
# ============================================
# -Force skips the password check. It is used by the client agent for unblock
# commands that the admin sent remotely (the admin is already authorized).
# Exit codes: 0 = ok, 2 = password missing, 3 = wrong password.

param(
    [string]$DataDir = (Join-Path $env:ProgramData "InternetBlocker"),
    [string]$Password,
    [string]$PasswordFile,
    [switch]$Force,
    [switch]$NoPrompt
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
foreach ($f in @("config.json", "allowed-sites.txt", "blocked-sites.txt")) {
    $target = Join-Path $DataDir $f
    if (-not (Test-Path $target)) {
        foreach ($src in @((Join-Path $PSScriptRoot $f), (Join-Path $PSScriptRoot "defaults\$f"))) {
            if (Test-Path $src) { Copy-Item $src $target; break }
        }
    }
}

$configFile = Join-Path $DataDir "config.json"
$config = $null
if (Test-Path $configFile) { $config = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json }

# Password passed through a one-time file so it never appears on a command line
if ($PasswordFile -and (Test-Path $PasswordFile)) {
    $Password = (Get-Content $PasswordFile -Raw -Encoding UTF8)
    if ($Password) { $Password = $Password.TrimEnd("`r", "`n") }
}

if (-not $Force -and $config -and $config.password_hash) {
    if (-not $Password) {
        if ($NoPrompt) { exit 2 }
        $cred = Read-Host "Enter password" -AsSecureString
        $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))
    }

    $bytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Password))
    $hashString = -join ($bytes | ForEach-Object { $_.ToString("x2") })

    if ($hashString -ne $config.password_hash) {
        Write-Host "Incorrect password!" -ForegroundColor Red
        exit 3
    }
}

Write-Host "UNBLOCKING INTERNET" -ForegroundColor Yellow

# 1. Windows proxy (machine-wide, plus the current user's old per-user value from v1)
$inetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
$inetPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"

if (Test-Path $inetKey) {
    try { Set-ItemProperty -Path $inetKey -Name "ProxyEnable" -Value 0 -Type DWord } catch { }
    Remove-ItemProperty -Path $inetKey -Name "ProxyServer" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $inetKey -Name "ProxyOverride" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $inetKey -Name "AutoConfigURL" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $inetKey -Name "AutoDetect" -ErrorAction SilentlyContinue
}
foreach ($n in @("ProxySettingsPerUser", "ProxyServer", "ProxyOverride", "AutoConfigURL")) {
    Remove-ItemProperty -Path $inetPolicyKey -Name $n -ErrorAction SilentlyContinue
}

$userInetKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
try {
    Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match "^S-1-5-21-\d+-\d+-\d+-\d+$"
    } | ForEach-Object {
        $uk = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $uk) { $userInetKeys += $uk }
    }
} catch { }
foreach ($uk in ($userInetKeys | Select-Object -Unique)) {
    if (Test-Path $uk) {
        Set-ItemProperty -Path $uk -Name "ProxyEnable" -Value 0 -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $uk -Name "ProxyServer" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $uk -Name "ProxyOverride" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $uk -Name "AutoConfigURL" -ErrorAction SilentlyContinue
    }
}
Write-Host "OK: proxy disabled" -ForegroundColor Green

# 2. Chrome / Edge policies set by block-internet.ps1
foreach ($key in @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    foreach ($n in @("DnsOverHttpsMode", "QuicAllowed", "ProxyMode", "ProxyServer", "ProxyBypassList")) {
        Remove-ItemProperty -Path $key -Name $n -ErrorAction SilentlyContinue
    }
}
Write-Host "OK: browser policies removed" -ForegroundColor Green

# 3. hosts file
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$startMarker = "# === BLOCKED SITES START ==="
$endMarker = "# === BLOCKED SITES END ==="

$newHosts = @()
$inBlock = $false
foreach ($line in (Get-Content $hostsFile)) {
    if ($line -eq $startMarker) { $inBlock = $true; continue }
    if ($line -eq $endMarker) { $inBlock = $false; continue }
    if (-not $inBlock) { $newHosts += $line }
}
$newHosts | Out-File $hostsFile -Encoding ASCII -Force
Write-Host "OK: hosts cleaned" -ForegroundColor Green

# 4. Flush DNS and tell WinINET to reload
ipconfig /flushdns | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class InternetRefresh {
    [DllImport("wininet.dll")]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    public static void Refresh() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
"@
[InternetRefresh]::Refresh()

Write-Host "INTERNET UNBLOCKED" -ForegroundColor Green
exit 0
