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

# 1. Windows proxy (machine-wide)
if ($mode -eq "whitelist") {
    $allowedSites = Read-List $allowedSitesFile

    $overrideList = ($allowedSites | ForEach-Object {
        $domain = $_ -replace "^https?://", "" -replace "^www\.", ""
        "*.$domain;www.$domain;$domain"
    }) -join ";"
    $overrideList = "<local>;$overrideList"

    if (-not (Test-Path $inetPolicyKey)) { New-Item -Path $inetPolicyKey -Force | Out-Null }
    try { Set-ItemProperty -Path $inetPolicyKey -Name "ProxySettingsPerUser" -Value 0 -Type DWord } catch { }

    try { Set-ItemProperty -Path $inetKey -Name "ProxyEnable" -Value 1 -Type DWord } catch { }
    try { Set-ItemProperty -Path $inetKey -Name "ProxyServer" -Value "127.0.0.1:8080" -Type String } catch { }
    try { Set-ItemProperty -Path $inetKey -Name "ProxyOverride" -Value $overrideList -Type String } catch { }
    Write-Host "OK: proxy set" -ForegroundColor Green
} else {
    if (Test-Path $inetKey) {
        try { Set-ItemProperty -Path $inetKey -Name "ProxyEnable" -Value 0 -Type DWord } catch { }
        Remove-ItemProperty -Path $inetKey -Name "ProxyServer" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $inetKey -Name "ProxyOverride" -ErrorAction SilentlyContinue
    }
    Remove-ItemProperty -Path $inetPolicyKey -Name "ProxySettingsPerUser" -ErrorAction SilentlyContinue
    Write-Host "OK: blacklist mode, proxy left off" -ForegroundColor Green
}

# 2. Chrome / Edge policies.
# Chrome/Edge upgrade to DNS-over-HTTPS by themselves, which skips the hosts file
# entirely. Turning DoH off makes the hosts block effective. In whitelist mode the
# proxy is also pinned by policy; a browser proxy policy ignores the Windows bypass
# list, so the allowed sites are repeated as ProxyBypassList.
foreach ($key in @("HKLM:\SOFTWARE\Policies\Google\Chrome", "HKLM:\SOFTWARE\Policies\Microsoft\Edge")) {
    try {
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        Set-ItemProperty -Path $key -Name "DnsOverHttpsMode" -Value "off" -Type String

        if ($mode -eq "whitelist") {
            $bypass = (($overrideList -split ";") | Where-Object { $_ }) -join ","
            Set-ItemProperty -Path $key -Name "ProxyMode" -Value "fixed_servers" -Type String
            Set-ItemProperty -Path $key -Name "ProxyServer" -Value "127.0.0.1:8080" -Type String
            Set-ItemProperty -Path $key -Name "ProxyBypassList" -Value $bypass -Type String
        } else {
            foreach ($n in @("ProxyMode", "ProxyServer", "ProxyBypassList")) {
                Remove-ItemProperty -Path $key -Name $n -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}
Write-Host "OK: browser policies applied" -ForegroundColor Green

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

$blockList = @()
# The built-in "distraction" list is only meaningful in blacklist mode. In whitelist
# mode the proxy already denies everything except the allowed list, so hardcoding
# these domains in hosts would also block sites the admin explicitly allowed.
if ($mode -eq "blacklist") {
    $blockList += @("youtube.com", "facebook.com", "m.facebook.com", "twitter.com", "x.com",
        "instagram.com", "tiktok.com", "reddit.com", "netflix.com", "twitch.tv",
        "snapchat.com", "pinterest.com", "linkedin.com")
}
$blockList += Read-List $blockedSitesFile

# In whitelist mode an allowed site must never end up in the hosts block, otherwise
# the 127.0.0.1 entry overrides the proxy bypass and the site cannot open.
$allowedNorm = @()
if ($mode -eq "whitelist") {
    $allowedNorm = (Read-List $allowedSitesFile | ForEach-Object {
        ($_ -replace "^https?://", "" -replace "^www.", "" -replace "/.*$", "").ToLower()
    })
}

# Names are validated by the app; keep only plain hostname characters here too.
$names = @()
foreach ($site in ($blockList | Select-Object -Unique)) {
    $d = ($site -replace "^https?://", "" -replace "/.*$", "").ToLower()
    $d = $d -replace "^www.", ""
    if ($d -notmatch "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$") { continue }
    if ($mode -eq "whitelist" -and ($allowedNorm -contains $d)) { continue }
    $names += $d
    if (-not $d.StartsWith("www.")) { $names += "www.$d" }
}
$names = $names | Select-Object -Unique

if ($names.Count -gt 0) {
    $newHosts += ""
    $newHosts += $startMarker
    $newHosts += "# Blocked on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    foreach ($n in $names) { $newHosts += "127.0.0.1    $n" }
    $newHosts += $endMarker
}
try {
    $newHosts | Out-File $hostsFile -Encoding ASCII -Force
    Write-Host "OK: hosts updated" -ForegroundColor Green
} catch { Write-Host "WARN: hosts file not writable (need admin)" -ForegroundColor Yellow }

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

Write-Host "INTERNET BLOCKED" -ForegroundColor Green
exit 0
