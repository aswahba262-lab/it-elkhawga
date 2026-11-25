# Removes accidental Windows Firewall "Block" rules on Node.js, it-elkhawga.exe, hbbs, and hbbr
# and allows inbound TCP 8787-8796 + RustDesk 21115-21119 across all profiles.
foreach ($rName in @("Node.js JavaScript Runtime", "it-elkhawga.exe", "hbbs", "hbbr", "IT ELKHAWGA Relay", "IT ELKHAWGA Relay 8790")) {
    netsh advfirewall firewall delete rule name="$rName" | Out-Null
}
netsh advfirewall firewall add rule name="IT ELKHAWGA Relay" dir=in action=allow protocol=TCP localport=8787-8796 profile=any | Out-Null
netsh advfirewall firewall add rule name="IT ELKHAWGA Node Runtime" dir=in action=allow program="C:\Program Files\nodejs\node.exe" profile=any | Out-Null
netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk TCP" dir=in action=allow protocol=TCP localport=21115-21119 profile=any | Out-Null
netsh advfirewall firewall add rule name="IT ELKHAWGA RustDesk UDP" dir=in action=allow protocol=UDP localport=21116 profile=any | Out-Null
Write-Host "OK: Windows Firewall rules updated successfully!" -ForegroundColor Green
