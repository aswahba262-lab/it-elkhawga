@echo off
REM IT ELKHAWGA Relay - startup wrapper (used by the scheduled task).
setlocal
set "DATA_DIR=%ProgramData%\IT-ELKHAWGA-Relay"
set "PORT=8790"

if exist "%DATA_DIR%\admin-key.txt" (
  set /p ADMIN_KEY=<"%DATA_DIR%\admin-key.txt"
)

"C:\Program Files\nodejs\node.exe" "%~dp0server.js"
