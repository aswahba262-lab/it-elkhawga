param(
    [ValidateSet("start", "restart", "dashboard", "silent")]
    [string]$Action = "start"
)

$ErrorActionPreference = "Continue"

function Test-PortListening {
    param([int]$Port)
    $conn = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return [bool]($conn | Select-Object -First 1)
}

function Start-DetachedProcess {
    param(
        [string]$CommandLine,
        [string]$WorkingDirectory,
        [bool]$Hidden = $false
    )
    try {
        $showVal = if ($Hidden) { [uint16]0 } else { [uint16]1 }
        $startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ ShowWindow = $showVal }
        $res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine = $CommandLine
            CurrentDirectory = $WorkingDirectory
            ProcessStartupInformation = $startup
        }
        return ($res.ReturnValue -eq 0)
    } catch {
        return $false
    }
}

function Get-LanIPv4 {
    $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' }
    $preferred = $ips | Where-Object {
        $_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' -or $_.IPAddress -match '^172\.(1[6-9]|2[0-9]|3[01])\.'
    } | Select-Object -First 1
    if ($preferred) { return $preferred.IPAddress }
    $fallback = $ips | Where-Object { $_.IPAddress -notlike '100.*' } | Select-Object -First 1
    if ($fallback) { return $fallback.IPAddress }
    $any = $ips | Select-Object -First 1
    if ($any) { return $any.IPAddress }
    return "127.0.0.1"
}

$installedAdmin = "C:\Program Files\IT ELKHAWGA Admin\it-elkhawga.exe"
$portableAdmin  = "C:\Users\IT APP\Desktop\blockwebsite\final-release\admin\it-elkhawga-admin.exe"
$candidates = @($installedAdmin, $portableAdmin) | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-Item -LiteralPath $_ }
$adminExe = ($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

if (-not (Test-Path -LiteralPath $adminExe)) {
    Write-Host "ERROR: Admin executable not found at '$installedAdmin' or '$portableAdmin'." -ForegroundColor Red
    exit 1
}

$relayScript = "C:\Users\IT APP\Desktop\blockwebsite\relay\server.js"
$relayData   = Join-Path $env:ProgramData "IT-ELKHAWGA-Relay"
New-Item -ItemType Directory -Force -Path $relayData | Out-Null

# Lock down NTFS ACLs on sensitive DLP Archive & Relay database directories
$archiveRoot = "C:\IT-ELKHAWGA-Archive"
New-Item -ItemType Directory -Force -Path $archiveRoot | Out-Null
$svcAcct = if ($env:USERDOMAIN) { "$($env:USERDOMAIN)\$($env:USERNAME):(OI)(CI)F" } else { "$($env:USERNAME):(OI)(CI)F" }
foreach ($secDir in @($archiveRoot, $relayData)) {
    if (Test-Path -LiteralPath $secDir) {
        & icacls $secDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" $svcAcct | Out-Null
    }
}

$keyFile = Join-Path $relayData "admin-key.txt"
$defaultKey = "2a0fa2811eb5acdba9847da8ece72ac29e59352a051e093664ba5fd413da2f8e"
if (-not (Test-Path -LiteralPath $keyFile)) {
    Set-Content -LiteralPath $keyFile -Value $defaultKey -Encoding ASCII -NoNewline
}
$adminKey = (Get-Content -LiteralPath $keyFile -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($adminKey)) { $adminKey = $defaultKey }

$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
$nodeExe = if ($nodeCmd) { $nodeCmd.Source } elseif (Test-Path "C:\Program Files\nodejs\node.exe") { "C:\Program Files\nodejs\node.exe" } else { $null }

if ($Action -eq "restart") {
    Write-Host "Stopping running Admin and Relay processes..." -ForegroundColor Yellow
    Get-CimInstance Win32_Process -Filter "Name LIKE 'it-elkhawga%'" -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not [string]::IsNullOrWhiteSpace($_.CommandLine) -and $_.CommandLine -notmatch '--agent|--capture-agent') {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    Get-CimInstance Win32_Process -Filter "Name LIKE 'node%'" -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.CommandLine -match 'server\.js') {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }
    Get-Process -Name "hbbs","hbbr" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

$adminDir = Split-Path -Parent $adminExe

if (-not (Test-PortListening -Port 8788)) {
    Write-Host "Starting local agent (port 8788)..." -ForegroundColor Cyan
    if (-not (Start-DetachedProcess -CommandLine "`"$adminExe`" --agent" -WorkingDirectory $adminDir -Hidden $true)) {
        Start-Process -FilePath $adminExe -ArgumentList "--agent" -WorkingDirectory $adminDir -WindowStyle Hidden
    }
}

$hasCapture = Get-CimInstance Win32_Process -Filter "Name LIKE 'it-elkhawga%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match '--capture-agent' } | Select-Object -First 1
if (-not $hasCapture) {
    Write-Host "Starting screen capture helper..." -ForegroundColor Cyan
    if (-not (Start-DetachedProcess -CommandLine "`"$adminExe`" --capture-agent" -WorkingDirectory $adminDir -Hidden $true)) {
        Start-Process -FilePath $adminExe -ArgumentList "--capture-agent" -WorkingDirectory $adminDir -WindowStyle Hidden
    }
}

if (-not (Test-PortListening -Port 8790)) {
    if ($nodeExe -and (Test-Path -LiteralPath $relayScript)) {
        Write-Host "Starting Cloud Relay server (port 8790)..." -ForegroundColor Cyan
        $relayDir = Split-Path -Parent $relayScript
        $relayCmd = "cmd.exe /c set `"PORT=8790`"&&set `"DATA_DIR=$relayData`"&&set `"ADMIN_KEY=$adminKey`"&&`"$nodeExe`" `"$relayScript`""
        if (-not (Start-DetachedProcess -CommandLine $relayCmd -WorkingDirectory $relayDir -Hidden $true)) {
            $env:PORT = "8790"
            $env:DATA_DIR = $relayData
            $env:ADMIN_KEY = $adminKey
            Start-Process -FilePath $nodeExe -ArgumentList "`"$relayScript`"" -WorkingDirectory $relayDir -WindowStyle Hidden
        }
    } else {
        Write-Host "WARNING: Node.js or relay server.js not found; Relay server skipped." -ForegroundColor Yellow
    }
}

$tailscaleExe = "C:\Program Files\Tailscale\tailscale.exe"
if (Test-Path -LiteralPath $tailscaleExe) {
    if (-not (Start-DetachedProcess -CommandLine "`"$tailscaleExe`" funnel --bg 8790" -WorkingDirectory (Split-Path -Parent $tailscaleExe) -Hidden $true)) {
        Start-Process -FilePath $tailscaleExe -ArgumentList "funnel", "--bg", "8790" -WindowStyle Hidden
    }
}

$rdServerDir = Join-Path $env:ProgramData "IT-ELKHAWGA-RustDeskServer"
$hbbsExe = Join-Path $rdServerDir "hbbs.exe"
$hbbrExe = Join-Path $rdServerDir "hbbr.exe"
$lanIpForRd = Get-LanIPv4
if ((Test-Path -LiteralPath $hbbsExe) -and (Test-Path -LiteralPath $hbbrExe)) {
    if (-not (Test-PortListening -Port 21117)) {
        Write-Host "Starting RustDesk Server OSS Relay (hbbr :21117)..." -ForegroundColor Cyan
        if (-not (Start-DetachedProcess -CommandLine "`"$hbbrExe`"" -WorkingDirectory $rdServerDir -Hidden $true)) {
            Start-Process -FilePath $hbbrExe -WorkingDirectory $rdServerDir -WindowStyle Hidden
        }
    }
    if (-not (Test-PortListening -Port 21116)) {
        Write-Host "Starting RustDesk Server OSS ID Server (hbbs :21116)..." -ForegroundColor Cyan
        $hbbsCmd = "`"$hbbsExe`" -r ${lanIpForRd}:21117"
        if (-not (Start-DetachedProcess -CommandLine $hbbsCmd -WorkingDirectory $rdServerDir -Hidden $true)) {
            Start-Process -FilePath $hbbsExe -ArgumentList "-r", "${lanIpForRd}:21117" -WorkingDirectory $rdServerDir -WindowStyle Hidden
        }
    }
}

if (-not (Test-PortListening -Port 8787)) {
    Write-Host "Starting Admin Server & Web Dashboard (port 8787)..." -ForegroundColor Cyan
    if (-not (Start-DetachedProcess -CommandLine "`"$adminExe`" --server" -WorkingDirectory $adminDir -Hidden $true)) {
        Start-Process -FilePath $adminExe -ArgumentList "--server" -WorkingDirectory $adminDir -WindowStyle Hidden
    }
}

$ready = $false
for ($i = 0; $i -lt 16; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8787/healthz" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($resp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {}
    Start-Sleep -Milliseconds 500
}

$ip = Get-LanIPv4
$dashUrl = "http://${ip}:8787"
$relayUrl = "http://${ip}:8790"
$publicRelayUrl = "https://desktop-04jeumk.tail0632e0.ts.net"

$cfgPath = Join-Path $env:ProgramData "InternetBlocker\config.json"
if (Test-Path -LiteralPath $cfgPath) {
    try {
        $rawCfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8
        $cfg = $rawCfg | ConvertFrom-Json
        if ([string]::IsNullOrWhiteSpace($cfg.relay_url) -or $cfg.relay_url -match 'wahba\.taild9bb1e\.ts\.net') {
            $cfg.relay_url = $publicRelayUrl
            $jsonOut = $cfg | ConvertTo-Json -Depth 10
            [System.IO.File]::WriteAllText($cfgPath, $jsonOut, [System.Text.UTF8Encoding]::new($false))
        }
    } catch {}
}

$relayReady = $false
for ($j = 0; $j -lt 10; $j++) {
    try {
        $rResp = Invoke-WebRequest -Uri "http://127.0.0.1:8790/healthz" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($rResp.StatusCode -eq 200) {
            $relayReady = $true
            break
        }
    } catch {}
    Start-Sleep -Milliseconds 300
}

$rdPubKeyPath = Join-Path $rdServerDir "id_ed25519.pub"
$rdPubKey = if (Test-Path -LiteralPath $rdPubKeyPath) { (Get-Content -LiteralPath $rdPubKeyPath -Raw).Trim() } else { "" }
$rdOssRunning = (Test-PortListening 21116) -and (Test-PortListening 21117)

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  IT ELKHAWGA Server Status" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ("  Admin + Web Dashboard (8787): " + $(if ($ready -or (Test-PortListening 8787)) { "RUNNING" } else { "NOT READY" })) -ForegroundColor $(if ($ready -or (Test-PortListening 8787)) { "Green" } else { "Red" })
Write-Host ("  Cloud Relay Server    (8790): " + $(if ($relayReady -or (Test-PortListening 8790)) { "RUNNING" } else { "STOPPED" })) -ForegroundColor $(if ($relayReady -or (Test-PortListening 8790)) { "Green" } else { "Yellow" })
Write-Host ("  Local Agent           (8788): " + $(if (Test-PortListening 8788) { "RUNNING" } else { "STOPPED" })) -ForegroundColor $(if (Test-PortListening 8788) { "Green" } else { "Yellow" })
Write-Host ("  RustDesk Server OSS  (21116): " + $(if ($rdOssRunning) { "RUNNING" } else { "STOPPED" })) -ForegroundColor $(if ($rdOssRunning) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "  Web Dashboard URL : $dashUrl" -ForegroundColor Green
Write-Host "  Cloud Relay URL   : $publicRelayUrl" -ForegroundColor Green
Write-Host "  Relay LAN URL     : $relayUrl" -ForegroundColor Gray
if ($rdOssRunning) {
    Write-Host "  RustDesk OSS LAN  : ${ip}:21116" -ForegroundColor Green
    if ($rdPubKey) { Write-Host "  RustDesk OSS Key  : $rdPubKey" -ForegroundColor Gray }
}
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

if ($Action -eq "start" -or $Action -eq "dashboard") {
    Start-Process $dashUrl
}
