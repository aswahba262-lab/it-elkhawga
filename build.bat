@echo off
setlocal
echo ========================================
echo  Building Internet Blocker Pro (Tauri)
echo ========================================

rem Rust and a 64-bit MinGW toolchain must be installed (see README). Add them to PATH if present.
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
for /d %%D in ("%LOCALAPPDATA%\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*") do set "PATH=%%D\mingw64\bin;%PATH%"

where cargo >nul 2>nul
if errorlevel 1 (
    echo Rust is not installed. Install it from https://rustup.rs and run this file again.
    pause
    exit /b 1
)

where windres >nul 2>nul
if errorlevel 1 (
    echo MinGW windres not found on PATH. Install WinLibs or MSYS2 MinGW and run this file again.
    pause
    exit /b 1
)

call npm install
if errorlevel 1 ( echo npm install failed & pause & exit /b 1 )

call npm run build
if errorlevel 1 ( echo Build failed & pause & exit /b 1 )

echo.
echo Done. Installers are in:
echo   src-tauri\target\release\bundle\nsis\Internet Blocker Admin_1.0.0_x64-setup.exe
echo   src-tauri\target-client\release\bundle\nsis\Internet Blocker Client_1.0.0_x64-setup.exe
pause
