@echo off
title IT ELKHAWGA - Quick Recovery and Update v1.2.3
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [1/4] Clearing dead proxy locks in Windows Registry, Chrome, and Edge...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxySettingsPerUser /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ProxyMode /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ProxyServer /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Google\Chrome" /v ProxyBypassList /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ProxyMode /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ProxyServer /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ProxyBypassList /f >nul 2>&1
netsh winhttp reset proxy >nul 2>&1

echo [2/4] Restoring agent binary if interrupted during previous update...
if not exist "C:\Program Files\IT ELKHAWGA Client\it-elkhawga.exe" (
    if exist "C:\Program Files\IT ELKHAWGA Client\it-elkhawga.old.exe" (
        copy /Y "C:\Program Files\IT ELKHAWGA Client\it-elkhawga.old.exe" "C:\Program Files\IT ELKHAWGA Client\it-elkhawga.exe" >nul 2>&1
    )
)
for /D %%U in ("C:\Users\*") do (
    if not exist "%%~fU\AppData\Local\IT ELKHAWGA Client\it-elkhawga.exe" (
        if exist "%%~fU\AppData\Local\IT ELKHAWGA Client\it-elkhawga.old.exe" (
            copy /Y "%%~fU\AppData\Local\IT ELKHAWGA Client\it-elkhawga.old.exe" "%%~fU\AppData\Local\IT ELKHAWGA Client\it-elkhawga.exe" >nul 2>&1
        )
    )
)

echo [3/4] Downloading latest stable Client (v1.2.3) directly (bypassing proxy)...
del /F /Q "%TEMP%\itk-setup.exe" >nul 2>&1
curl.exe -k -L --noproxy "*" "https://desktop-04jeumk.tail0632e0.ts.net/api/v1/client-setup.exe" -o "%TEMP%\itk-setup.exe"

if exist "%TEMP%\itk-setup.exe" (
    for %%A in ("%TEMP%\itk-setup.exe") do (
        if %%~zA GTR 500000 (
            echo Installing IT ELKHAWGA Client v1.2.3 silently...
            "%TEMP%\itk-setup.exe" /S
            timeout /t 6 >nul
        )
    )
)

if exist "C:\Program Files\IT ELKHAWGA Client\install-agent-task.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\IT ELKHAWGA Client\install-agent-task.ps1" -InstallDir "C:\Program Files\IT ELKHAWGA Client"
)

echo [4/4] Done! Internet proxy lock cleared and Client v1.2.3 installed.
timeout /t 5
