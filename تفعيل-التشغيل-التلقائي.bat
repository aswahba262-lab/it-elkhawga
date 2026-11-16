@echo off
:: تشغيل سكربت تفعيل التشغيل التلقائي
cd /d "%~dp0"
powershell -Command "& {Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0enable-autostart.ps1\"' -Verb RunAs}"
