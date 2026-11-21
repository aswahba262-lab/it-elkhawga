!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToLog 'schtasks /Delete /TN "InternetBlockerAgent" /F'
  nsExec::ExecToLog 'taskkill /F /IM it-elkhawga-client.exe'
  nsExec::ExecToLog 'taskkill /F /IM it-elkhawga.exe'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\install-agent-task.ps1" -InstallDir "$INSTDIR"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="IT ELKHAWGA Relay"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787-8796 profile=any'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "IT ELKHAWGA Agent" /f'
  nsExec::ExecToLog 'reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "IT ELKHAWGA Screen" /f'
  nsExec::ExecToLog 'schtasks /Delete /TN "IT ELKHAWGA Screen" /F'
  nsExec::ExecToLog 'schtasks /Delete /TN "IT ELKHAWGA Agent" /F'
  nsExec::ExecToLog 'schtasks /Delete /TN "InternetBlockerAgent" /F'
  nsExec::ExecToLog 'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\allow-internet.ps1" -Force'
!macroend
