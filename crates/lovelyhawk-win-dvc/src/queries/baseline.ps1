$ErrorActionPreference = 'Stop'
function Reg-Value($path, $name) {
  try { Get-ItemPropertyValue -LiteralPath $path -Name $name -ErrorAction Stop } catch { $null }
}
function Query-Value([scriptblock]$query) { try { & $query } catch { $null } }
$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$mp = Query-Value { Get-MpComputerStatus }
$smb = Query-Value { Get-SmbServerConfiguration }
$smbClient = Query-Value { Get-SmbClientConfiguration }
$fw = @(Query-Value { Get-NetFirewallProfile -PolicyStore ActiveStore })
$os = Query-Value { Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8 }
$guest = Query-Value { Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1 }
[ordered]@{
  rdpNla = Reg-Value $rdp 'UserAuthentication'; rdpEnc = Reg-Value $rdp 'MinEncryptionLevel'
  uacLua = Reg-Value $policy 'EnableLUA'; uacPrompt = Reg-Value $policy 'ConsentPromptBehaviorAdmin'
  secureDesktop = Reg-Value $policy 'PromptOnSecureDesktop'; uacFilterAdmin = Reg-Value $policy 'FilterAdministratorToken'
  wdigest = Reg-Value 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
  lsassPplValue2Supported = if ($os) { $os.ProductType -eq 1 -and [uint32]$os.BuildNumber -ge 22621 } else { $null }
  lsassPpl = Reg-Value $lsa 'RunAsPPL'; limitBlankPasswords = Reg-Value $lsa 'LimitBlankPasswordUse'
  restrictAnonymous = Reg-Value $lsa 'RestrictAnonymous'; restrictAnonymousSam = Reg-Value $lsa 'RestrictAnonymousSAM'
  lmCompatibility = Reg-Value $lsa 'LmCompatibilityLevel'; noLmHash = Reg-Value $lsa 'NoLMHash'
  autoLogon = Reg-Value 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
  smb1 = if ($smb -and $null -ne $smb.EnableSMB1Protocol) { [int]$smb.EnableSMB1Protocol } else { $null }
  smbSigning = if ($smb -and $null -ne $smb.RequireSecuritySignature) { [int]$smb.RequireSecuritySignature } else { $null }
  smbClientSigning = if ($smbClient -and $null -ne $smbClient.RequireSecuritySignature) { [int]$smbClient.RequireSecuritySignature } else { $null }
  smbGuest = if ($smbClient -and $null -ne $smbClient.EnableInsecureGuestLogons) { [int]$smbClient.EnableInsecureGuestLogons } else { $null }
  guestEnabled = if ($guest) { [bool]$guest.Enabled } else { $null }
  defenderRealtime = if ($mp -and $null -ne $mp.RealTimeProtectionEnabled) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
  defenderTamper = if ($mp -and $null -ne $mp.IsTamperProtected) { [int]$mp.IsTamperProtected } else { $null }
  fwDisabledCount = if ($fw.Count -eq 3) { @($fw | Where-Object { -not $_.Enabled }).Count } else { $null }
  psScriptBlock = Reg-Value "$ps\ScriptBlockLogging" 'EnableScriptBlockLogging'
  psModuleLogging = Reg-Value "$ps\ModuleLogging" 'EnableModuleLogging'
  psTranscription = Reg-Value "$ps\Transcription" 'EnableTranscripting'
  winrmBasic = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic'
  winrmUnencrypted = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic'
  remoteRegistry = Query-Value { [string](Get-Service RemoteRegistry).StartType }
  rdpSecurityLayer = Reg-Value $rdp 'SecurityLayer'
  alwaysInstallMachine = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
  alwaysInstallUser = Reg-Value 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
  autoRun = Reg-Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
} | ConvertTo-Json -Compress
