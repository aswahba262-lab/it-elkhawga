@echo off
:: تشغيل سكربت قفل الإنترنت كـ Administrator
cd /d "%~dp0"
powershell -Command "& {Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0block-internet.ps1\"' -Verb RunAs}"
