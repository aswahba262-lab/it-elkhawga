# ============================================
# Block Internet (machine-wide)
# ============================================
# Runs elevated, either by a logged-in admin (UAC) or as SYSTEM from the client agent.
# Settings are machine-wide (HKLM) so they also work when no user profile is loaded.

param(
    [string]$DataDir = (Join-Path $env:ProgramData "InternetBlocker")
)

$ErrorActionPreference = "Stop"

# Seed the data directory from the bundled defaults on first run
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
$allowedSitesFile = Join-Path $DataDir "allowed-sites.txt"
$blockedSitesFile = Join-Path $DataDir "blocked-sites.txt"

$config = $null
if (Test-Path $configFile) { $config = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json }
$mode = if ($config -and $config.mode) { $config.mode } else { "whitelist" }

function Read-List($path) {
    if (-not (Test-Path $path)) { return @() }
    return @(Get-Content $path -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") })
}

Write-Host "BLOCKING INTERNET (mode: $mode)" -ForegroundColor Yellow

$inetKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
$inetPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$overrideList = ""

# 1. Windows proxy (machine-wide + all loaded user hives so SYSTEM agent updates active sessions immediately)
$userInetKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
try {
    Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match "^S-1-5-21-\d+-\d+-\d+-\d+$"
    } | ForEach-Object {
        $uk = "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        if (Test-Path $uk) { $userInetKeys += $uk }
    }
} catch { }
$userInetKeys = $userInetKeys | Select-Object -Unique

# Always route traffic through our local proxy on 127.0.0.1:8080 when blocking is active
# (in both whitelist and blacklist modes) so blocked sites are enforced, logged, and trigger notifications.
$overrideList = "<local>;localhost;127.0.0.1"

if (-not (Test-Path $inetPolicyKey)) { New-Item -Path $inetPolicyKey -Force | Out-Null }
try { Set-ItemProperty -Path $inetPolicyKey -Name "ProxySettingsPerUser" -Value 0 -Type DWord } catch { }

foreach ($k in (@($inetKey) + $userInetKeys)) {
    if (Test-Path $k) {
        try { Set-ItemProperty -Path $k -Name "ProxyEnable" -Value 1 -Type DWord } catch { }
        try { Set-ItemProperty -Path $k -Name "ProxyServer" -Value "127.0.0.1:8080" -Type String } catch { }
        try { Set-ItemProperty -Path $k -Name "ProxyOverride" -Value $overrideList -Type String } catch { }
    }
}
Write-Host "OK: proxy set (mode: $mode)" -ForegroundColor Green

# 2. Chrome / Edge policies.
# Disable DNS-over-HTTPS and QUIC/UDP bypass while blocked and pin local proxy.
foreach ($key in @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    try {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name "DnsOverHttpsMode" -Value "off" -Type String
        Set-ItemProperty -Path $key -Name "QuicAllowed" -Value 0 -Type DWord

        $bypass = (($overrideList -split ";") | Where-Object { $_ }) -join ","
        Set-ItemProperty -Path $key -Name "ProxyMode" -Value "fixed_servers" -Type String
        Set-ItemProperty -Path $key -Name "ProxyServer" -Value "127.0.0.1:8080" -Type String
        Set-ItemProperty -Path $key -Name "ProxyBypassList" -Value $bypass -Type String
    } catch { }
}
Write-Host "OK: browser policies applied" -ForegroundColor Green

# 3. Clean any legacy hosts block markers so blocked domains go through 127.0.0.1:8080
# and can display/trigger the "blocked by IT ELKHAWGA" alert instead of silent 127.0.0.1 failure.
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
$startMarker = "# === BLOCKED SITES START ==="
$endMarker = "# === BLOCKED SITES END ==="

$newHosts = @()
$inBlock = $false
$hadBlock = $false
foreach ($line in (Get-Content $hostsFile -ErrorAction SilentlyContinue)) {
    if ($line -eq $startMarker) { $inBlock = $true; $hadBlock = $true; continue }
    if ($line -eq $endMarker) { $inBlock = $false; continue }
    if (-not $inBlock) { $newHosts += $line }
}
if ($hadBlock) {
    try {
        $newHosts | Out-File $hostsFile -Encoding ASCII -Force
        Write-Host "OK: legacy hosts block cleaned" -ForegroundColor Green
    } catch { Write-Host "WARN: hosts file not writable (need admin)" -ForegroundColor Yellow }
}

# 4. Ensure local LAN Direct RustDesk port (21118 TCP) is allowed on Private/Domain profiles for fast IT support
try {
    netsh advfirewall firewall delete rule name="IT ELKHAWGA RustDesk Direct" 2>&1 | Out-Null
    netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk Direct" dir=in action=allow protocol=TCP localport=21118 profile=private,domain 2>&1 | Out-Null
} catch { }

# 5. Flush DNS and tell WinINET to reload
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

Write-Host "INTERNET BLOCKED" -ForegroundColor Green
exit 0
