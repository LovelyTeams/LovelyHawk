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
function EnsureNative {
  if (-not ('LovelyHawkPolicyOp' -as [type])) {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LovelyHawkPolicyOp {
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetUserModalsGet(string s,uint l,out IntPtr b);
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetUserModalsSet(string s,uint l,ref P0 b,out uint e);
  [DllImport("netapi32.dll",CharSet=CharSet.Unicode)] static extern uint NetUserModalsSet(string s,uint l,ref P3 b,out uint e);
  [DllImport("netapi32.dll")] static extern uint NetApiBufferFree(IntPtr b);
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(ref Guid g,uint c,out IntPtr b);
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.U1)] static extern bool AuditSetSystemPolicy(ref AP b,uint c);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr b);
  [StructLayout(LayoutKind.Sequential)] public struct P0 { public uint MinLen,MaxAge,MinAge,ForceOff,HistLen; }
  [StructLayout(LayoutKind.Sequential)] public struct P3 { public uint Duration,ObsWin,Threshold; }
  [StructLayout(LayoutKind.Sequential)] public struct AP { public Guid Sub,Cat; public uint Flags; }
  public static uint GetSam(string f) {
    IntPtr b=IntPtr.Zero; uint l=f.StartsWith("M")||f.StartsWith("H")?0u:3u;
    if (NetUserModalsGet(null,l,out b)!=0||b==IntPtr.Zero) throw new Exception("sam");
    try {
      if (l==0) { var p=(P0)Marshal.PtrToStructure(b,typeof(P0)); return f=="MinimumLength"?p.MinLen:f=="HistoryLength"?p.HistLen:p.MinAge; }
      var q=(P3)Marshal.PtrToStructure(b,typeof(P3)); return f=="Threshold"?q.Threshold:f=="Duration"?q.Duration:q.ObsWin;
    } finally { NetApiBufferFree(b); }
  }
  public static void SetSam(string f,uint v) {
    IntPtr b=IntPtr.Zero; uint e=0,l=f.StartsWith("M")||f.StartsWith("H")?0u:3u;
    if (NetUserModalsGet(null,l,out b)!=0||b==IntPtr.Zero) throw new Exception("sam");
    try {
      if (l==0) {
        var p=(P0)Marshal.PtrToStructure(b,typeof(P0));
        if (f=="MinimumLength") p.MinLen=v; else if (f=="HistoryLength") p.HistLen=v; else p.MinAge=v;
        if (NetUserModalsSet(null,0,ref p,out e)!=0) throw new Exception("sam");
      } else {
        var q=(P3)Marshal.PtrToStructure(b,typeof(P3));
        if (f=="Threshold") { q.Threshold=v; if (v>0&&q.Duration<900) q.Duration=900; if (v>0&&(q.ObsWin<900||q.ObsWin>q.Duration)) q.ObsWin=900; }
        else if (f=="Duration") { q.Duration=v; if (q.ObsWin>v) q.ObsWin=v; }
        else { q.ObsWin=v; if (q.Duration<v) q.Duration=v; }
        if (NetUserModalsSet(null,3,ref q,out e)!=0) throw new Exception("sam");
      }
    } finally { NetApiBufferFree(b); }
  }
  public static uint GetAudit(string s) {
    var g=new Guid("0cce"+s+"-69ae-11d9-bed3-505054503030"); IntPtr b=IntPtr.Zero;
    if (!AuditQuerySystemPolicy(ref g,1,out b)||b==IntPtr.Zero) throw new Exception("audit");
    try { return (uint)Marshal.ReadInt32(b,16); } finally { AuditFree(b); }
  }
  public static void SetAudit(string s,uint f) {
    var g=new Guid("0cce"+s+"-69ae-11d9-bed3-505054503030"); IntPtr b=IntPtr.Zero;
    if (!AuditQuerySystemPolicy(ref g,1,out b)||b==IntPtr.Zero) throw new Exception("audit");
    Guid c; try { byte[] cb=new byte[16]; Marshal.Copy(IntPtr.Add(b,20),cb,0,16); c=new Guid(cb); } finally { AuditFree(b); }
    var a=new AP{Sub=g,Flags=f,Cat=c}; if (!AuditSetSystemPolicy(ref a,1)) throw new Exception("audit");
  }
}
'@
  }
}
function ReadSpecial($rule) {
  $p=$rule.path; $n=$rule.name
  $val = switch -Wildcard ($p) {
    '@SAM\Guest' { [uint32][bool](Get-LocalUser|Where-Object{$_.SID.Value -match '-501$'}|Select-Object -First 1).Enabled }
    '@SAM\*' { EnsureNative; [LovelyHawkPolicyOp]::GetSam($n) }
    '@AUDIT\*' { EnsureNative; [LovelyHawkPolicyOp]::GetAudit($n) }
    '@EVENTLOG\*' { $log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($p.Substring(10)); try{if($n -eq 'IsEnabled'){[uint32][bool]$log.IsEnabled}else{[uint32]$log.MaximumSizeInBytes}}finally{$log.Dispose()} }
    '@FIREWALL\*' {
      $fw=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
      if($n -eq 'Enabled'){if(@($fw|Where-Object{[string]$_.Enabled -eq 'True'}).Count -eq 3){1u}else{0u}}
      elseif($n -eq 'DefaultInboundAction'){if(@($fw|Where-Object{[string]$_.DefaultInboundAction -eq 'Block'}).Count -eq 3){1u}else{0u}}
      elseif($n -eq 'LogBlocked'){if(@($fw|Where-Object{[string]$_.LogBlocked -eq 'True'}).Count -eq 3){1u}else{0u}}
      else{[uint32]($fw|Measure-Object -Property LogMaxSizeKilobytes -Minimum).Minimum}
    }
    '@SMB\Server' { [uint32][bool](Get-SmbServerConfiguration -ErrorAction Stop).$n }
    '@SMB\Client' { [uint32][bool](Get-SmbClientConfiguration -ErrorAction Stop).$n }
    '@DEFENDER\Preference' { [uint32][bool](Get-MpPreference -ErrorAction Stop).$n }
    '@DEFENDER\Signature' { [uint32](Get-MpComputerStatus -ErrorAction Stop).AntivirusSignatureAge }
    '@SERVICE\*' { [uint32](Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -Name 'Start' -ErrorAction Stop) }
    default { throw 'unsupported' }
  }
  return [ordered]@{id=$rule.id;keyExists=$true;value=[uint32]$val;security='SYSTEM-POLICY'}
}
function WriteSpecial($rule,[uint32]$desired) {
  $p=$rule.path; $n=$rule.name; $b=($desired -ne 0)
  switch -Wildcard ($p) {
    '@SAM\Guest' { $g=Get-LocalUser|Where-Object{$_.SID.Value -match '-501$'}|Select-Object -First 1; if($b){Enable-LocalUser -SID $g.SID -ErrorAction Stop}else{Disable-LocalUser -SID $g.SID -ErrorAction Stop} }
    '@SAM\*' { EnsureNative; [LovelyHawkPolicyOp]::SetSam($n,$desired) }
    '@AUDIT\*' { EnsureNative; [LovelyHawkPolicyOp]::SetAudit($n,$desired) }
    '@EVENTLOG\*' { $log=[Diagnostics.Eventing.Reader.EventLogConfiguration]::new($p.Substring(10)); try{if($n -eq 'IsEnabled'){$log.IsEnabled=$b}else{$log.MaximumSizeInBytes=[int64]$desired};$log.SaveChanges()}finally{$log.Dispose()} }
    '@FIREWALL\*' {
      if($n -eq 'Enabled'){Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled $(if($b){'True'}else{'False'}) -ErrorAction Stop}
      elseif($n -eq 'DefaultInboundAction'){Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction $(if($b){'Block'}else{'Allow'}) -ErrorAction Stop}
      elseif($n -eq 'LogBlocked'){Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked $(if($b){'True'}else{'False'}) -ErrorAction Stop}
      else{Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes $desired -ErrorAction Stop}
    }
    '@SMB\Server' { $m=@{Force=$true;ErrorAction='Stop'}; $m[$n]=$b; Set-SmbServerConfiguration @m }
    '@SMB\Client' { $m=@{Force=$true;ErrorAction='Stop'}; $m[$n]=$b; Set-SmbClientConfiguration @m }
    '@DEFENDER\Preference' { $m=@{ErrorAction='Stop'}; $m[$n]=$b; Set-MpPreference @m }
    '@DEFENDER\Signature' { Update-MpSignature -ErrorAction Stop }
    '@SERVICE\*' { if($desired -eq 4){Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue}; Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry' -Name 'Start' -Value ([int]$desired) -Type DWord -ErrorAction Stop }
    default { throw 'unsupported' }
  }
}
function ReadValue($rule) {
  if ($rule.path.StartsWith('@')) { return ReadSpecial $rule }
  $base = OpenBase $rule
  try {
    $key = $base.OpenSubKey($rule.path)
    if (-not $key) { return [ordered]@{ id=$rule.id; keyExists=$false; value=$null; security='' } }
    try {
      $security = $key.GetAccessControl([Security.AccessControl.AccessControlSections]'Access,Owner,Group').GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]'Access,Owner,Group')
      $value = $null
      if ($key.GetValueNames() -contains $rule.name) {
        $kind = $key.GetValueKind($rule.name)
        if ($kind -eq [Microsoft.Win32.RegistryValueKind]::String -and $rule.name -eq 'AutoAdminLogon') {
          $value = [uint32][int][string]$key.GetValue($rule.name)
        } elseif ($kind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
          throw 'unexpected registry type'
        } else {
          $signed = [int]$key.GetValue($rule.name)
          $value = [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
        }
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
    if ($rule.path.StartsWith('@')) {
      if ($null -eq $payload.desired) { throw 'missing desired value' }
      $started = $true
      WriteSpecial $rule ([uint32]$payload.desired)
    } else {
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
          elseif ($rule.name -eq 'AutoAdminLogon') { $key.SetValue($rule.name, [string]$payload.desired, [Microsoft.Win32.RegistryValueKind]::String) }
          else { $signed = [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]$payload.desired), 0); $key.SetValue($rule.name, $signed, [Microsoft.Win32.RegistryValueKind]::DWord) }
          $key.Flush()
        } finally { if ($key) { $key.Dispose() } }
      } finally { $base.Dispose() }
    }
    '{"outcome":"written"}'
  } catch {
    if ($started) { '{"outcome":"uncertain"}' } else { '{"outcome":"refused"}' }
  }
}
