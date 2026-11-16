@echo off
:: تشغيل سكربت فتح الإنترنت كـ Administrator
cd /d "%~dp0"
powershell -Command "& {Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0allow-internet.ps1\"' -Verb RunAs}"
