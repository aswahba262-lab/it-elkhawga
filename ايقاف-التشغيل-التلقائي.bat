@echo off
:: تشغيل سكربت إيقاف التشغيل التلقائي
cd /d "%~dp0"
powershell -Command "& {Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0disable-autostart.ps1\"' -Verb RunAs}"
