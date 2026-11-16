!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'schtasks /Delete /TN "InternetBlockerAgent" /F'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\install-agent-task.ps1" -InstallDir "$INSTDIR"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787 profile=private,domain'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'schtasks /Delete /TN "IT ELKHAWGA Screen" /F'
  nsExec::ExecToLog 'schtasks /Delete /TN "IT ELKHAWGA Agent" /F'
  nsExec::ExecToLog 'schtasks /Delete /TN "InternetBlockerAgent" /F'
  nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\allow-internet.ps1" -Force'
!macroend
