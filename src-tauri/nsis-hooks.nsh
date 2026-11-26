!macro NSIS_HOOK_PREINSTALL
  SetShellVarContext all
  StrCpy $INSTDIR "$PROGRAMFILES64\IT ELKHAWGA Client"
  nsExec::ExecToLog 'powershell -NoProfile -WindowStyle Hidden -Command "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { schtasks /Run /TN \"IT ELKHAWGA Agent\" 2>&1 | Out-Null; taskkill /F /IM it-elkhawga.exe /IM it-elkhawga.old.exe /IM it-elkhawga-client.exe /IM it-elkhawga-client.old.exe 2>&1 | Out-Null; exit 42 }"'
  Pop $0
  IntCmp $0 42 0 +2 +2
  Quit
  SetOutPath "$INSTDIR"
  nsExec::ExecToLog 'taskkill /F /IM it-elkhawga.exe /IM it-elkhawga.old.exe /IM it-elkhawga-client.exe /IM it-elkhawga-client.old.exe'
  Delete "$INSTDIR\it-elkhawga.old.exe"
  Rename "$INSTDIR\it-elkhawga.exe" "$INSTDIR\it-elkhawga.old.exe"
  Delete "$INSTDIR\it-elkhawga-client.old.exe"
  Rename "$INSTDIR\it-elkhawga-client.exe" "$INSTDIR\it-elkhawga-client.old.exe"
  Delete "$LOCALAPPDATA\IT ELKHAWGA Client\it-elkhawga.old.exe"
  Rename "$LOCALAPPDATA\IT ELKHAWGA Client\it-elkhawga.exe" "$LOCALAPPDATA\IT ELKHAWGA Client\it-elkhawga.old.exe"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToLog 'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\install-agent-task.ps1" -InstallDir "$INSTDIR"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="Node.js JavaScript Runtime"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="it-elkhawga.exe"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="hbbs"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="hbbr"'
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
