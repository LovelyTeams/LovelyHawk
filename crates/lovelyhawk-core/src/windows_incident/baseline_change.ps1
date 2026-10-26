$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Identity {
  $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8
  $system = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 8
  $token = [Security.Principal.WindowsIdentity]::GetCurrent()
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
  try { $key = $base.OpenSubKey('SOFTWARE\Microsoft\Cryptography'); try { $machine = [string]$key.GetValue('MachineGuid') } finally { if ($key) { $key.Dispose() } } } finally { $base.Dispose() }
  if (-not $machine -or -not $os -or -not $system) { throw 'identity unavailable' }
  return [ordered]@{ machine=$machine; account=$token.User.Value; hostName=[string]$system.Name; version=[string]$os.Version; boot=$os.LastBootUpTime.ToUniversalTime().ToString('o'); elevated=([Security.Principal.WindowsPrincipal]$token).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); domain=[bool]$system.PartOfDomain; productType=[int]$os.ProductType }
}
function OpenBase($rule) {
  $hive = if ($rule.hive -eq 'HKCU') { [Microsoft.Win32.RegistryHive]::CurrentUser } else { [Microsoft.Win32.RegistryHive]::LocalMachine }
  return [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Registry64)
}
function ReadValue($rule) {
  $base = OpenBase $rule
  try {
    $key = $base.OpenSubKey($rule.path)
    if (-not $key) { return [ordered]@{ id=$rule.id; keyExists=$false; value=$null; security='' } }
    try {
      $security = $key.GetAccessControl([Security.AccessControl.AccessControlSections]'Access,Owner,Group').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group')
      $value = $null
      if ($key.GetValueNames() -contains $rule.name) {
        if ($key.GetValueKind($rule.name) -ne [Microsoft.Win32.RegistryValueKind]::DWord) { throw 'unexpected registry type' }
        $signed = [int]$key.GetValue($rule.name)
        $value = [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
      }
      return [ordered]@{ id=$rule.id; keyExists=$true; value=$value; security=$security }
    } finally { $key.Dispose() }
  } finally { $base.Dispose() }
}
function SameValue($a, $b) { return ($a.keyExists -eq $b.keyExists -and $a.value -eq $b.value -and $a.security -ceq $b.security) }
$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json
if ($payload.mode -eq 'read') {
  $identity = Identity
  $values = @($payload.rules | ForEach-Object { ReadValue $_ })
  [ordered]@{ identity=$identity; values=$values } | ConvertTo-Json -Compress -Depth 8
} else {
  $started = $false
  try {
    $identity = Identity
    foreach ($field in @('machine','account','hostName','version','boot','elevated','domain','productType')) {
      if ($identity[$field] -cne $payload.identity.$field) { throw 'identity changed' }
    }
    if (-not $identity.elevated -or $identity.domain -or $identity.productType -eq 2) { throw 'unsupported target' }
    $rule = $payload.rule
    if (-not (SameValue (ReadValue $rule) $payload.before)) { throw 'registry changed' }
    $base = OpenBase $rule
    try {
      # No ACL/owner changes. New empty policy keys may remain after value restoration.
      $key = $base.OpenSubKey($rule.path, $true)
      if ($key -and -not $payload.before.keyExists) { $key.Dispose(); throw 'key appeared during write' }
      if (-not $key) {
        if ($null -eq $payload.desired) { throw 'missing key' }
        $started = $true
        $key = $base.CreateSubKey($rule.path)
      }
      try {
        # Recheck on the opened key immediately before the write; this is not an atomic registry transaction.
        if ($payload.before.keyExists -and -not (SameValue (ReadValue $rule) $payload.before)) { throw 'registry changed' }
        if (-not $payload.before.keyExists -and $key.GetValueNames() -contains $rule.name) { throw 'value appeared during write' }
        $started = $true
        if ($null -eq $payload.desired) { $key.DeleteValue($rule.name, $false) }
        else { $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$payload.desired), 0); $key.SetValue($rule.name, $signed, [Microsoft.Win32.RegistryValueKind]::DWord) }
        $key.Flush()
      } finally { if ($key) { $key.Dispose() } }
    } finally { $base.Dispose() }
    '{"outcome":"written"}'
  } catch {
    if ($started) { '{"outcome":"uncertain"}' } else { '{"outcome":"refused"}' }
  }
}
