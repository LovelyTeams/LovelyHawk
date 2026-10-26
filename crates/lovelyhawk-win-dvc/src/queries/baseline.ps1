$ErrorActionPreference = 'Stop'
$baselineErrors = @{}
function Read-Failure($record) {
  if ($record.CategoryInfo.Category -eq 'PermissionDenied' -or $record.Exception -is [UnauthorizedAccessException] -or $record.Exception.InnerException -is [UnauthorizedAccessException]) { 'permission-denied' }
  elseif ($record.Exception -is [System.Management.Automation.CommandNotFoundException]) { 'unavailable' }
  else { 'query-failed' }
}
function Reg-Value($path, $name, $field = '') {
  try { Get-ItemPropertyValue -LiteralPath $path -Name $name -ErrorAction Stop }
  catch { if ($field) { $baselineErrors[$field] = if ($_.CategoryInfo.Category -eq 'ObjectNotFound' -or $_.CategoryInfo.Category -eq 'InvalidArgument') { 'not-configured' } else { Read-Failure $_ } }; $null }
}
function Query-Value([scriptblock]$query, $field = '') {
  try { & $query } catch { if ($field) { $baselineErrors[$field] = Read-Failure $_ }; $null }
}
function Property-Value($item, $name) { if ($null -ne $item) { $item.$name } else { $null } }
$rdp = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$mp = Query-Value { Get-MpComputerStatus } 'defender'
$smb = Query-Value { Get-SmbServerConfiguration }
$smbClient = Query-Value { Get-SmbClientConfiguration }
$fw = @(Query-Value { Get-NetFirewallProfile -PolicyStore ActiveStore } 'firewall')
$os = Query-Value { Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8 } 'os'
$guest = Query-Value { Get-LocalUser | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1 }
$dg = Query-Value { Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -OperationTimeoutSec 8 } 'deviceGuard'
$logs = @{}
foreach ($channel in @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational')) {
  $logs[$channel] = Query-Value { Get-WinEvent -ListLog $channel -ErrorAction Stop } $channel
}
$profiles = @($fw | ForEach-Object {
  [ordered]@{
    name = [string]$_.Name; enabled = [string]$_.Enabled
    inbound = [string]$_.DefaultInboundAction; logBlocked = [string]$_.LogBlocked
    logSizeKb = Property-Value $_ 'LogMaxSizeKilobytes'
  }
})
$completeProfiles = $profiles.Count -eq 3 -and (@($profiles.name | Sort-Object -Unique) -join ',') -eq 'Domain,Private,Public'
$result = [ordered]@{
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
  fwDisabledCount = if ($completeProfiles -and @($profiles | Where-Object { $_.enabled -notin @('True', 'False') }).Count -eq 0) { @($profiles | Where-Object { $_.enabled -eq 'False' }).Count } else { $null }
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
  productType = Property-Value $os 'ProductType'
  defenderMode = Property-Value $mp 'AMRunningMode'
  defenderAntivirus = Property-Value $mp 'AntivirusEnabled'
  defenderBehavior = Property-Value $mp 'BehaviorMonitorEnabled'
  defenderOnAccess = Property-Value $mp 'OnAccessProtectionEnabled'
  defenderSignatureAge = Property-Value $mp 'AntivirusSignatureAge'
  vbsStatus = Property-Value $dg 'VirtualizationBasedSecurityStatus'
  securityServicesRunning = if ($null -ne $dg.SecurityServicesRunning) { @($dg.SecurityServicesRunning) } else { $null }
  firewallProfiles = $profiles
  securityLogEnabled = Property-Value $logs.Security 'IsEnabled'
  securityLogMaxBytes = Property-Value $logs.Security 'MaximumSizeInBytes'
  systemLogEnabled = Property-Value $logs.System 'IsEnabled'
  systemLogMaxBytes = Property-Value $logs.System 'MaximumSizeInBytes'
  applicationLogEnabled = Property-Value $logs.Application 'IsEnabled'
  powershellLogEnabled = Property-Value $logs['Microsoft-Windows-PowerShell/Operational'] 'IsEnabled'
  processCommandLine = Reg-Value "$policy\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 'processCommandLine'
  uacStandardPrompt = Reg-Value $policy 'ConsentPromptBehaviorUser' 'uacStandardPrompt'
  remoteTokenFilter = Reg-Value $policy 'LocalAccountTokenFilterPolicy' 'remoteTokenFilter'
  everyoneAnonymous = Reg-Value $lsa 'EveryoneIncludesAnonymous' 'everyoneAnonymous'
  winrmClientBasic = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 'winrmClientBasic'
  winrmClientUnencrypted = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic' 'winrmClientUnencrypted'
  llmnr = Reg-Value 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'llmnr'
}
foreach ($key in $baselineNative.Keys) { $result[$key] = $baselineNative[$key] }
$result.readErrors = $baselineErrors
$result | ConvertTo-Json -Depth 5 -Compress
