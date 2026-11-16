@echo off
:: تشغيل سكربت تعيين كلمة السر
cd /d "%~dp0"
powershell -Command "& {Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -NoExit -File \"%~dp0set-password.ps1\"' -Verb RunAs}"
