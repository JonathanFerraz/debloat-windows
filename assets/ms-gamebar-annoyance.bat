$id = 'ms-gamebar-annoyance'
$cl = 'apply'  # Define a ação como 'apply' diretamente

#:: Under limited user
$toggle = (1,0)[$cl -eq 'apply']
sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" $toggle -type dword -force -ea 0
sp "HKCU:\System\GameConfigStore" "GameDVR_Enabled" $toggle -type dword -force -ea 0

#:: Under admin user
$ps = {
  $f0 = $args[0]; $cl = $args[1]; $id = $args[2]; [Console]::Title = "$id $cl"
  $toggle = (1,0)[$cl -eq 'apply']
  sp "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" $toggle -type dword -force -ea 0
  sp "HKCU:\System\GameConfigStore" "GameDVR_Enabled" $toggle -type dword -force -ea 0
  "ms-gamebar","ms-gamebarservices","ms-gamingoverlay" |foreach {
    if (!(test-path "Registry::HKCR\$_\shell")) {ni "Registry::HKCR\$_\shell" -force >''}
    if (!(test-path "Registry::HKCR\$_\shell\open")) {ni "Registry::HKCR\$_\shell\open" -force >''}
    if (!(test-path "Registry::HKCR\$_\shell\open\command")) {ni "Registry::HKCR\$_\shell\open\command" -force >''}
    sp "Registry::HKCR\$_" "(Default)" "URL:$_" -force
    sp "Registry::HKCR\$_" "URL Protocol" "" -force
    if ($toggle -eq 0) {
      sp "Registry::HKCR\$_" "NoOpenWith" "" -force
      sp "Registry::HKCR\$_\shell\open\command" "(Default)" "`"$env:SystemRoot\System32\systray.exe`"" -force
    } else {
      rp "Registry::HKCR\$_" "NoOpenWith" -force -ea 0
      ri "Registry::HKCR\$_\shell" -rec -force -ea 0
    }
  }
  start ms-gamebar://annoyance # AveYo: test if working
}

#:: Elevate
if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.Value -notcontains 'S-1-5-32-544') {
  write-host " '$id' $cl : Requesting ADMIN rights.. " -fore Black -back Yellow; sleep 2; pushd ~
  sp HKCU:\Volatile*\* $id ".{$ps} '$($f0-replace"'","''")' '$($cl-replace"'","''")' '$id'" -force -ea 0
  start powershell -args "-nop -c iex(gp Registry::HKU\S-1-5-21*\Volatile*\* '$id' -ea 0).'$id'" -verb runas; popd
} else {. $ps $f0 $cl $id}

$Press_Enter_if_pasted_in_powershell
