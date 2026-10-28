//! Bounded, read-only queries shared by the native agent and PowerShell fallback.
//! Localized display names and profile directories are not account identities.

pub const ACCOUNTS: &str = r#"
$ErrorActionPreference = 'Stop'
$adminSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.SID.Value })
$users = @(Get-LocalUser -ErrorAction Stop)
if ($users.Count -gt 4096) { throw '本地账户超过本次采集上限 4096，未返回不完整账户清单。' }
$out = foreach ($u in $users) {
  $sid = [string]$u.SID.Value
  [ordered]@{
    name = [string]$u.Name
    fullName = [string]$u.FullName
    enabled = [bool]$u.Enabled
    isAdmin = [bool]($sid -in $adminSids)
    sid = $sid
    rid = [uint32](($sid -split '-')[-1])
    lastLogon = if ($null -ne $u.LastLogon) { $u.LastLogon.ToString('o') } else { '' }
    passwordRequired = [bool]$u.PasswordRequired
    passwordExpires = ($null -ne $u.PasswordExpires)
  }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
"#;

pub fn logs(category: &str) -> Option<String> {
    let filters = match category {
        "logon" => "@{LogName='Security'; Id=@(4624,4625,4634,4648,4672)}",
        "account" => "@{LogName='Security'; Id=@(4720,4722,4724,4726,4728,4732,4756)}",
        "service" => "@{LogName='System'; Id=@(7045,7036,104)}",
        "powershell" => "@{LogName='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104)}",
        "failed-logon" => "@{LogName='Security'; Id=@(4625,4740,4771,4776)}",
        "rdp" => {
            "@{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=@(21,22,23,24,25)},@{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=@(1149)}"
        }
        "defender" => {
            "@{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117,5001,5007)}"
        }
        "tasks" => {
            "@{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=@(106,140,141,200,201)}"
        }
        "sysmon" => {
            "@{LogName='Microsoft-Windows-Sysmon/Operational'; Id=@(1,3,7,8,10,11,12,13,22)}"
        }
        "clear-log" => "@{LogName='Security'; Id=@(1102)},@{LogName='System'; Id=@(104)}",
        "process" => "@{LogName='Security'; Id=@(4688,4689)}",
        "security" => "@{LogName='Security'}",
        "system" => "@{LogName='System'}",
        "application" => "@{LogName='Application'}",
        "wmi" => {
            "@{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=@(5857,5858,5859,5860,5861)}"
        }
        "all" => {
            "@{LogName='Security'; Id=@(4624,4625,4720,4726,4732,4688,1102)},\
                  @{LogName='System'; Id=@(7045,7036,104)},\
                  @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=@(4103,4104)},\
                  @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=@(21,24,25)},\
                  @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1116,1117,5001,5007)},\
                  @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=@(106,140,141)}"
        }
        _ => return None,
    };
    let limit = 200;
    Some(format!(
        r#"
$ErrorActionPreference = 'Stop'
$warnings = New-Object System.Collections.Generic.List[string]
$records = New-Object System.Collections.Generic.List[object]
$recordBytes = 0
$budgetReached = $false
foreach ($filter in @({filters})) {{
  try {{
    $filter.StartTime = (Get-Date).AddDays(-7)
    $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents {limit} -ErrorAction Stop)
    if ($events.Count -eq {limit}) {{ $warnings.Add("$($filter.LogName)：已达到本次 {limit} 条上限，仅展示最近匹配事件。") }}
    foreach ($e in $events) {{
      $full = [string]$e.Message
      $partial = $full.Length -gt 2048
      $summary = ($full -split "`r?`n")[0]
      if ($summary.Length -gt 256) {{ $summary = $summary.Substring(0, 256) }}
      if ($partial) {{ $full = $full.Substring(0, 2048) }}
      $record = [ordered]@{{
        recordId = [uint64]$e.RecordId
        timeCreated = $e.TimeCreated.ToString('o')
        channel = [string]$e.LogName
        eventId = [uint32]$e.Id
        level = [string]$e.LevelDisplayName
        summary = $summary
        detail = $full
        detailTruncated = $partial
      }}
      $recordBytes += [Text.Encoding]::UTF8.GetByteCount(($record | ConvertTo-Json -Compress)) + 1
      if ($recordBytes -gt 1400000) {{ $budgetReached = $true; break }}
      $records.Add($record)
    }}
    if ($budgetReached) {{ $warnings.Add("日志已达到本次总字节上限，后续通道与事件未读取；请按单个类别重查。"); break }}
  }} catch {{
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{
      $warnings.Add("$($filter.LogName)：未能读取，请检查日志是否存在以及当前账户的读取权限。")
    }}
  }}
}}
[ordered]@{{ entries = @($records.ToArray()); warnings = @($warnings.ToArray()) }} | ConvertTo-Json -Depth 5 -Compress
"#
    ))
}

pub fn registry(key_path: &str) -> Option<String> {
    if key_path.is_empty() || key_path.len() > 1024 || key_path.contains(['\0', '\r', '\n']) {
        return None;
    }
    let upper = key_path.to_ascii_uppercase();
    let (alias, hive, suffix) = [
        ("HKLM", "HKEY_LOCAL_MACHINE"),
        ("HKCU", "HKEY_CURRENT_USER"),
        ("HKU", "HKEY_USERS"),
        ("HKCR", "HKEY_CLASSES_ROOT"),
        ("HKCC", "HKEY_CURRENT_CONFIG"),
    ]
    .into_iter()
    .find_map(|(alias, hive)| {
        [
            format!("{alias}:\\"),
            format!("{alias}\\"),
            format!("{hive}\\"),
        ]
        .iter()
        .find(|prefix| upper.starts_with(prefix.as_str()))
        .map(|prefix| (alias, hive, &key_path[prefix.len()..]))
    })?;
    let canonical = format!("{alias}:\\{suffix}").replace('\'', "''");
    let provider = format!("Registry::{hive}\\{suffix}").replace('\'', "''");
    Some(format!(
        r#"
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath '{provider}' -ErrorAction Stop
$warnings = New-Object System.Collections.Generic.List[string]
$keys = @($item.GetSubKeyNames() | Select-Object -First 501)
if ($keys.Count -gt 500) {{ $warnings.Add('子键超过本次 500 项上限，仅返回前 500 项。') }}
$names = @($item.GetValueNames() | Select-Object -First 257)
if ($names.Count -gt 256) {{ $warnings.Add('键值超过本次 256 项上限，仅返回前 256 项。') }}
$values = foreach ($name in ($names | Select-Object -First 256)) {{
  $kind = [string]$item.GetValueKind($name)
  $raw = $item.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $partial = $false
  if ($raw -is [byte[]]) {{
    $partial = $raw.Length -gt 1024
    $val = if ($raw.Length -eq 0) {{ '' }} else {{ [BitConverter]::ToString([byte[]]@($raw | Select-Object -First 1024)).Replace('-', ' ') }}
  }} elseif ($raw -is [string[]]) {{ $val = $raw -join "`n" }}
  else {{ $val = [string]$raw }}
  if ($val.Length -gt 4096) {{ $val = $val.Substring(0, 4096); $partial = $true }}
  [ordered]@{{ name = [string]$name; kind = $kind; data = $val; truncated = $partial }}
}}
[ordered]@{{
  keyPath = '{canonical}'
  subkeys = @($keys | Select-Object -First 500)
  values = @($values)
  warnings = @($warnings.ToArray())
}} | ConvertTo-Json -Depth 4 -Compress
"#
    ))
}

pub const OVERVIEW: &str = include_str!("queries/overview.ps1");
pub const BASELINE: &str = concat!(
    include_str!("queries/baseline-native.ps1"),
    "\n",
    include_str!("queries/baseline.ps1")
);
pub const NETWORK: &str = include_str!("queries/network.ps1");
pub const PROCESSES: &str = include_str!("queries/processes.ps1");

pub fn process_inspection(pid: u32, start_time: &str) -> Option<String> {
    if pid == 0
        || start_time.len() > 64
        || chrono::DateTime::parse_from_rfc3339(start_time).is_err()
    {
        return None;
    }
    Some(format!(
        "$targetPid = {pid}; $expectedStart = '{}'\n{}",
        start_time.replace('\'', "''"),
        include_str!("queries/process-inspection.ps1")
    ))
}

pub const DEFENDER_ANALYSIS: &str = r#"# LovelyHawk-IR-Query
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$warnings = New-Object System.Collections.Generic.List[string]
$exclusions = New-Object System.Collections.Generic.List[object]
$detections = New-Object System.Collections.Generic.List[object]
$configChanges = New-Object System.Collections.Generic.List[object]
$seenExcl = @{}

function Add-Excl($kind, $val, $source) {
  $v = ([string]$val).Trim()
  if (-not $v) { return }
  if ($v.Length -gt 1024) { $v = $v.Substring(0, 1024) }
  $k = "$kind|$($v.ToLowerInvariant())"
  if ($seenExcl.ContainsKey($k)) { return }
  $seenExcl[$k] = $true
  if ($exclusions.Count -lt 512) {
    $exclusions.Add([ordered]@{ kind = $kind; value = $v; source = $source })
  }
}

$mp = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $warnings.Add('Get-MpComputerStatus 未能读取，可能未启用 Windows Defender 或权限受限。') }

try {
  $pref = Get-MpPreference -ErrorAction Stop
  foreach ($p in @($pref.ExclusionPath)) { Add-Excl 'path' $p 'Get-MpPreference' }
  foreach ($p in @($pref.ExclusionProcess)) { Add-Excl 'process' $p 'Get-MpPreference' }
  foreach ($p in @($pref.ExclusionExtension)) { Add-Excl 'extension' $p 'Get-MpPreference' }
  foreach ($p in @($pref.ExclusionIpAddress)) { Add-Excl 'ip' $p 'Get-MpPreference' }
} catch {
  $warnings.Add('Get-MpPreference 排除项读取受限，已尝试结合注册表与事件日志核查。')
}

foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions')) {
  foreach ($pair in @(@('Paths','path'), @('Processes','process'), @('Extensions','extension'), @('IpAddresses','ip'))) {
    $sub = "$base\$($pair[0])"
    try {
      if (Test-Path -LiteralPath $sub) {
        $item = Get-Item -LiteralPath $sub -ErrorAction Stop
        foreach ($name in @($item.GetValueNames() | Select-Object -First 256)) {
          Add-Excl $pair[1] $name '注册表策略'
        }
      }
    } catch {}
  }
}

try {
  $events = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = @(1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5001, 5004, 5007, 5010, 5012, 5013)
    StartTime = (Get-Date).AddDays(-30)
  } -MaxEvents 300 -ErrorAction Stop)
  foreach ($e in $events) {
    $map = @{}
    try {
      $xml = [xml]$e.ToXml()
      foreach ($d in @($xml.Event.EventData.Data)) {
        if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' }
      }
    } catch {}
    $msg = [string]$e.Message
    if ($msg.Length -gt 2048) { $msg = $msg.Substring(0, 2048) }
    $id = [uint32]$e.Id
    if ($id -in @(1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119)) {
      if ($detections.Count -ge 256) { continue }
      $rawPath = [string]($map['Path'] + '')
      $cleanPath = $rawPath
      if ($cleanPath -match '(?:file|containerfile|regkey|startup):_?([^;]+)') { $cleanPath = $Matches[1].Trim() }
      $threat = [string]($map['Threat Name'] + '')
      if (-not $threat -and $msg -match '(?:名称|Name)\s*[:：]\s*([^\r\n]+)') { $threat = $Matches[1].Trim() }
      if (-not $threat) { $threat = "Defender 事件 $id" }
      $sev = [string]($map['Severity Name'] + '')
      if (-not $sev) { $sev = [string]$e.LevelDisplayName }
      $cat = [string]($map['Category Name'] + '')
      $proc = [string]($map['Process Name'] + '')
      $usr = [string]($map['Detection User'] + $map['Origin Name'])
      $act = [string]($map['Action Name'] + '')
      if (-not $act) {
        $act = switch ($id) {
          1116 { '检出威胁' }
          1117 { '已执行保护动作' }
          1118 { '处置失败（高危）' }
          1119 { '严重处置失败（高危）' }
          default { "事件 $id" }
        }
      }
      $detections.Add([ordered]@{
        recordId = [uint64]$e.RecordId
        timeCreated = $e.TimeCreated.ToString('o')
        eventId = $id
        threatName = if ($threat.Length -gt 256) { $threat.Substring(0, 256) } else { $threat }
        severity = if ($sev.Length -gt 64) { $sev.Substring(0, 64) } else { $sev }
        category = if ($cat.Length -gt 128) { $cat.Substring(0, 128) } else { $cat }
        filePath = if ($cleanPath.Length -gt 1024) { $cleanPath.Substring(0, 1024) } else { $cleanPath }
        processName = if ($proc.Length -gt 512) { $proc.Substring(0, 512) } else { $proc }
        user = if ($usr.Length -gt 256) { $usr.Substring(0, 256) } else { $usr }
        action = if ($act.Length -gt 128) { $act.Substring(0, 128) } else { $act }
        detail = $msg
      })
    } else {
      if ($configChanges.Count -ge 256) { continue }
      $oldVal = [string]($map['Old Value'] + '')
      $newVal = [string]($map['New Value'] + '')
      $changeType = switch ($id) {
        5001 { '实时保护被关闭 (5001)' }
        5004 { '实时保护配置变更 (5004)' }
        5007 { 'Defender 配置变更 (5007)' }
        5010 { '恶意软件扫描被禁用 (5010)' }
        5012 { '病毒扫描被禁用 (5012)' }
        5013 { '防篡改保护拦截变更 (5013)' }
        default { "配置事件 ($id)" }
      }
      $configChanges.Add([ordered]@{
        recordId = [uint64]$e.RecordId
        timeCreated = $e.TimeCreated.ToString('o')
        eventId = $id
        changeType = $changeType
        oldValue = if ($oldVal.Length -gt 1024) { $oldVal.Substring(0, 1024) } else { $oldVal }
        newValue = if ($newVal.Length -gt 1024) { $newVal.Substring(0, 1024) } else { $newVal }
        detail = $msg
      })
    }
  }
} catch {
  if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
    $warnings.Add('未能完整读取 Microsoft-Windows-Windows Defender/Operational 日志通道。')
  }
}

[ordered]@{
  observedAt = [DateTime]::UtcNow.ToString('o')
  runningMode = if ($mp -and $mp.AMRunningMode) { [string]$mp.AMRunningMode } else { '' }
  antivirusEnabled = if ($mp -and $null -ne $mp.AntivirusEnabled) { [bool]$mp.AntivirusEnabled } else { $null }
  realtimeProtection = if ($mp -and $null -ne $mp.RealTimeProtectionEnabled) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
  behaviorMonitor = if ($mp -and $null -ne $mp.BehaviorMonitorEnabled) { [bool]$mp.BehaviorMonitorEnabled } else { $null }
  ioavProtection = if ($mp -and $null -ne $mp.IoavProtectionEnabled) { [bool]$mp.IoavProtectionEnabled } else { $null }
  onAccessProtection = if ($mp -and $null -ne $mp.OnAccessProtectionEnabled) { [bool]$mp.OnAccessProtectionEnabled } else { $null }
  tamperProtected = if ($mp -and $null -ne $mp.IsTamperProtected) { [bool]$mp.IsTamperProtected } else { $null }
  engineVersion = if ($mp -and $mp.AMEngineVersion) { [string]$mp.AMEngineVersion } else { '' }
  signatureVersion = if ($mp -and $mp.AntivirusSignatureVersion) { [string]$mp.AntivirusSignatureVersion } else { '' }
  signatureLastUpdated = if ($mp -and $mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { '' }
  signatureAgeDays = if ($mp -and $null -ne $mp.AntivirusSignatureAge -and [uint32]$mp.AntivirusSignatureAge -lt 65535) { [uint32]$mp.AntivirusSignatureAge } else { $null }
  exclusions = @($exclusions.ToArray())
  detections = @($detections.ToArray())
  configChanges = @($configChanges.ToArray())
  warnings = @($warnings.ToArray())
} | ConvertTo-Json -Depth 6 -Compress
"#;

pub const COMMAND_MONITOR: &str = r#"# LovelyHawk-IR-Query
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$warnings = New-Object System.Collections.Generic.List[string]
$entries = New-Object System.Collections.Generic.List[object]

$cmdLineAudit = $false
try {
  $v = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction Stop
  $cmdLineAudit = ([int]$v -eq 1)
} catch {}

$scriptBlockAudit = $false
try {
  $v = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction Stop
  $scriptBlockAudit = ([int]$v -eq 1)
} catch {}

$sysmonInstalled = $false
try {
  $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
  $sysmonInstalled = $true
} catch {}

$procAudit = $false
try {
  $procs = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate -OperationTimeoutSec 10 -ErrorAction Stop | Select-Object -First 1024)
  foreach ($p in $procs) {
    if ([uint32]$p.ProcessId -eq $PID) { continue }
    $cmd = ([string]$p.CommandLine).Trim()
    if (-not $cmd) { continue }
    if ($entries.Count -ge 600) { break }
    $entries.Add([ordered]@{
      id = "proc:$($p.ProcessId):$(if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { '' })"
      timeCreated = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { [DateTime]::UtcNow.ToString('o') }
      source = 'active-process'
      pid = [uint32]$p.ProcessId
      ppid = [uint32]$p.ParentProcessId
      processName = ([string]$p.Name).Substring(0, [Math]::Min(([string]$p.Name).Length, 256))
      executablePath = ([string]$p.ExecutablePath).Substring(0, [Math]::Min(([string]$p.ExecutablePath).Length, 1024))
      parentName = ''
      user = ''
      commandLine = if ($cmd.Length -gt 4096) { $cmd.Substring(0, 4096) } else { $cmd }
    })
  }
} catch {
  $warnings.Add('活动进程命令行读取未完全成功，请核对 WMI/CIM 状态。')
}

try {
  $ev4688 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 150 -ErrorAction Stop)
  $procAudit = $true
  foreach ($e in $ev4688) {
    if ($entries.Count -ge 600) { break }
    $map = @{}
    try {
      $xml = [xml]$e.ToXml()
      foreach ($d in @($xml.Event.EventData.Data)) { if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' } }
    } catch {}
    $newProc = [string]($map['NewProcessName'] + '')
    $cmd = [string]($map['CommandLine'] + '')
    if (-not $cmd) { $cmd = $newProc }
    $leaf = if ($newProc) { [IO.Path]::GetFileName($newProc) } else { '4688' }
    $pidVal = try { [uint32]$map['NewProcessId'] } catch { 0 }
    $ppidVal = try { [uint32]$map['ProcessId'] } catch { 0 }
    $usr = [string]($map['SubjectDomainName'] + '\' + $map['SubjectUserName']).Trim('\')
    $parent = [string]($map['ParentProcessName'] + '')
    $entries.Add([ordered]@{
      id = "4688:$($e.RecordId)"
      timeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
      source = 'security-4688'
      pid = $pidVal
      ppid = $ppidVal
      processName = if ($leaf.Length -gt 256) { $leaf.Substring(0, 256) } else { $leaf }
      executablePath = if ($newProc.Length -gt 1024) { $newProc.Substring(0, 1024) } else { $newProc }
      parentName = if ($parent.Length -gt 512) { $parent.Substring(0, 512) } else { $parent }
      user = if ($usr.Length -gt 256) { $usr.Substring(0, 256) } else { $usr }
      commandLine = if ($cmd.Length -gt 4096) { $cmd.Substring(0, 4096) } else { $cmd }
    })
  }
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $procAudit = $true }
}

if ($sysmonInstalled) {
  try {
    $evSys = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 150 -ErrorAction Stop)
    foreach ($e in $evSys) {
      if ($entries.Count -ge 600) { break }
      $map = @{}
      try {
        $xml = [xml]$e.ToXml()
        foreach ($d in @($xml.Event.EventData.Data)) { if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' } }
      } catch {}
      $img = [string]($map['Image'] + '')
      $cmd = [string]($map['CommandLine'] + '')
      $leaf = if ($img) { [IO.Path]::GetFileName($img) } else { 'sysmon-1' }
      $pidVal = try { [uint32]$map['ProcessId'] } catch { 0 }
      $ppidVal = try { [uint32]$map['ParentProcessId'] } catch { 0 }
      $parent = [string]($map['ParentImage'] + '')
      $usr = [string]($map['User'] + '')
      $entries.Add([ordered]@{
        id = "sysmon:$($e.RecordId)"
        timeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
        source = 'sysmon-1'
        pid = $pidVal
        ppid = $ppidVal
        processName = if ($leaf.Length -gt 256) { $leaf.Substring(0, 256) } else { $leaf }
        executablePath = if ($img.Length -gt 1024) { $img.Substring(0, 1024) } else { $img }
        parentName = if ($parent.Length -gt 512) { $parent.Substring(0, 512) } else { $parent }
        user = if ($usr.Length -gt 256) { $usr.Substring(0, 256) } else { $usr }
        commandLine = if ($cmd.Length -gt 4096) { $cmd.Substring(0, 4096) } else { $cmd }
      })
    }
  } catch {}
}

try {
  $evPs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = @(4103, 4104); StartTime = (Get-Date).AddDays(-7) } -MaxEvents 120 -ErrorAction Stop)
  foreach ($e in $evPs) {
    if ($entries.Count -ge 600) { break }
    $msg = [string]$e.Message
    if ($msg -match 'LovelyHawkDvcNative|LovelyHawkBaselineV3|LovelyHawkProcessOwner|# LovelyHawk|__LH_END_') { continue }
    $map = @{}
    try {
      $xml = [xml]$e.ToXml()
      foreach ($d in @($xml.Event.EventData.Data)) { if ($d.Name) { $map[[string]$d.Name] = [string]$d.'#text' } }
    } catch {}
    $scriptText = [string]($map['ScriptBlockText'] + '')
    if (-not $scriptText) { $scriptText = $msg }
    $scriptText = $scriptText.Trim()
    if ($scriptText -match 'LovelyHawkDvcNative|LovelyHawkBaselineV3|LovelyHawkProcessOwner|# LovelyHawk|__LH_END_') { continue }
    $pathVal = [string]($map['Path'] + '')
    $entries.Add([ordered]@{
      id = "ps:$($e.RecordId)"
      timeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
      source = 'powershell-4104'
      pid = [uint32]$e.ProcessId
      ppid = 0
      processName = 'powershell.exe'
      executablePath = if ($pathVal.Length -gt 1024) { $pathVal.Substring(0, 1024) } else { $pathVal }
      parentName = ''
      user = ''
      commandLine = if ($scriptText.Length -gt 4096) { $scriptText.Substring(0, 4096) } else { $scriptText }
    })
  }
} catch {}

try {
  $usersDir = Join-Path $env:SystemDrive 'Users'
  if (Test-Path -LiteralPath $usersDir) {
    foreach ($uDir in @(Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 32)) {
      $histFile = Join-Path $uDir.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
      if (Test-Path -LiteralPath $histFile -PathType Leaf) {
        $info = Get-Item -LiteralPath $histFile -Force -ErrorAction SilentlyContinue
        $mtime = if ($info) { $info.LastWriteTime.ToUniversalTime().ToString('o') } else { [DateTime]::UtcNow.ToString('o') }
        $lines = @(Get-Content -LiteralPath $histFile -Tail 60 -ErrorAction SilentlyContinue)
        $idx = 0
        foreach ($line in $lines) {
          $idx++
          $trimmed = ([string]$line).Trim()
          if (-not $trimmed -or $trimmed -match 'LovelyHawkDvcNative|# LovelyHawk') { continue }
          if ($entries.Count -ge 600) { break }
          $entries.Add([ordered]@{
            id = "hist:$($uDir.Name):$idx"
            timeCreated = $mtime
            source = 'psreadline-history'
            pid = 0
            ppid = 0
            processName = 'powershell.exe (PSReadLine)'
            executablePath = $histFile
            parentName = ''
            user = [string]$uDir.Name
            commandLine = if ($trimmed.Length -gt 4096) { $trimmed.Substring(0, 4096) } else { $trimmed }
          })
        }
      }
    }
  }
} catch {}

[ordered]@{
  observedAt = [DateTime]::UtcNow.ToString('o')
  processCreationEventsEnabled = [bool]$procAudit
  commandLineAuditEnabled = [bool]$cmdLineAudit
  scriptBlockLoggingEnabled = [bool]$scriptBlockAudit
  sysmonInstalled = [bool]$sysmonInstalled
  warnings = @($warnings.ToArray())
  entries = @($entries.ToArray())
} | ConvertTo-Json -Depth 6 -Compress
"#;

pub fn webshell_scan(target_path: &str) -> Option<String> {
    let trimmed = target_path.trim();
    if trimmed.len() > 1024 || trimmed.contains(['\0', '\r', '\n']) {
        return None;
    }
    let escaped = trimmed.replace('\'', "''");
    Some(format!(
        r#"# LovelyHawk-IR-Query
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sw = [Diagnostics.Stopwatch]::StartNew()
$rawTarget = '{escaped}'
$warnings = New-Object System.Collections.Generic.List[string]
$roots = New-Object System.Collections.Generic.List[string]
if (-not $rawTarget -or $rawTarget -ieq 'auto') {{
  foreach ($cand in @('C:\inetpub\wwwroot', 'C:\wwwroot', 'D:\wwwroot', 'C:\phpstudy_pro\WWW', 'D:\phpstudy_pro\WWW', 'C:\xampp\htdocs', 'C:\wamp64\www', 'C:\Users\Public')) {{
    if (Test-Path -LiteralPath $cand -PathType Container) {{ [void]$roots.Add($cand) }}
  }}
  if ($roots.Count -eq 0) {{ [void]$roots.Add('C:\Users\Public') }}
}} else {{
  $expanded = [Environment]::ExpandEnvironmentVariables($rawTarget)
  if (-not (Test-Path -LiteralPath $expanded -PathType Container)) {{
    throw "扫描目录不存在或不可访问: $expanded"
  }}
  [void]$roots.Add((Get-Item -LiteralPath $expanded -Force).FullName)
}}
$exts = @('.php','.phtml','.inc','.php3','.php4','.php5','.php7','.phar','.asp','.asa','.cer','.cdx','.aspx','.ashx','.asmx','.ascx','.cshtml','.config','.jsp','.jspx','.jspf','.py','.ps1','.vbs','.hta','.cgi','.js')
$candidateFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$scannedDirs = 0
$truncated = $false
$dirQueue = New-Object System.Collections.Generic.Queue[string]
foreach ($r in $roots) {{ $dirQueue.Enqueue($r) }}
while ($dirQueue.Count -gt 0) {{
  if ($scannedDirs -ge 1500 -or $candidateFiles.Count -ge 6000) {{ $truncated = $true; break }}
  $curr = $dirQueue.Dequeue()
  $scannedDirs++
  try {{
    $di = [System.IO.DirectoryInfo]::new($curr)
    foreach ($sub in $di.EnumerateDirectories()) {{
      if (($sub.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ continue }}
      if ($sub.Name -in @('node_modules', '.git', 'WinSxS', 'Installer')) {{ continue }}
      $dirQueue.Enqueue($sub.FullName)
    }}
    foreach ($fi in $di.EnumerateFiles()) {{
      if ($fi.Length -le 0 -or $fi.Length -gt 2097152) {{ continue }}
      if ($exts -contains $fi.Extension.ToLowerInvariant()) {{
        $candidateFiles.Add($fi)
        if ($candidateFiles.Count -ge 6000) {{ $truncated = $true; break }}
      }}
    }}
  }} catch {{}}
}}
$threads = [Math]::Min([Math]::Max([Environment]::ProcessorCount, 2), 8)
$entries = New-Object System.Collections.Generic.List[object]
foreach ($fi in $candidateFiles) {{
  if ($entries.Count -ge 500) {{ $truncated = $true; break }}
  try {{
    $text = [System.IO.File]::ReadAllText($fi.FullName)
    $lower = $text.ToLowerInvariant()
    $rules = New-Object System.Collections.Generic.List[string]
    $level = 0
    $threat = ''
    if ($lower -match 'openssl_decrypt|rijndaelmanaged|aesmanaged|defineclass.*cipher|frombase64string.*aes') {{
      $rules.Add('冰蝎/哥斯拉加密通信与字节码加载特征 (Behinder/Godzilla)')
      $level = 5; $threat = '加密 Webshell 木马 (冰蝎/哥斯拉特征)'
    }}
    if ($lower -match '(?:eval|assert|create_function)\s*\([^)]*(?:\$_(?:post|get|request|cookie|server)|base64_decode|gzinflate|str_rot13|php://input)') {{
      $rules.Add('PHP 动态代码执行一句话后门 (eval/assert + 外部输入或解码)')
      $level = 5; if (-not $threat) {{ $threat = 'PHP 一句话代码执行后门' }}
    }}
    if ($lower -match '(?:call_user_func|array_map|array_filter|register_shutdown_function)\s*\([^)]*\$_(?:post|get|request|cookie)') {{
      $rules.Add('PHP 回调函数动态后门 (Callback Webshell)')
      if ($level -lt 4) {{ $level = 4 }}; if (-not $threat) {{ $threat = 'PHP 回调混淆后门' }}
    }}
    if ($lower -match '(?:execute|executeglobal|eval)\s*\(\s*request|wscript\.shell|shell\.application|assembly\.load\s*\(|compileassemblyfromsource') {{
      $rules.Add('ASP / ASP.NET 脚本执行或反射内存加载特征')
      $level = 5; if (-not $threat) {{ $threat = 'ASP/ASP.NET 命令执行或内存加载后门' }}
    }}
    if ($lower -match 'runtime\.getruntime\(\)\.exec|processbuilder|\$\$bcel\$\$|defineclass\s*\(') {{
      $rules.Add('JSP / Java 字节码加载或系统命令执行特征')
      $level = 5; if (-not $threat) {{ $threat = 'JSP 命令执行或内存马后门' }}
    }}
    if ($lower -match '(?:system|shell_exec|passthru|proc_open|popen)\s*\([^)]*\$_(?:post|get|request|cookie)') {{
      $rules.Add('Web 脚本直接调用系统命令函数并接收外部参数')
      if ($level -lt 4) {{ $level = 4 }}; if (-not $threat) {{ $threat = 'Web 命令执行后门' }}
    }}
    if ($rules.Count -gt 0) {{
      $hash = (Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
      $snippet = ($text -split "`r?`n" | Where-Object {{ $_.Trim().Length -gt 0 }} | Select-Object -First 1)
      if ($snippet.Length -gt 220) {{ $snippet = $snippet.Substring(0, 220) + '…' }}
      $entries.Add([ordered]@{{
        fullPath = [string]$fi.FullName
        name = [string]$fi.Name
        extension = [string]$fi.Extension.ToLowerInvariant()
        sizeBytes = [uint64]$fi.Length
        lastWriteTime = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        sha256 = if ($hash) {{ [string]$hash.ToLowerInvariant() }} else {{ '' }}
        riskLevel = if ($level -ge 5) {{ 'high' }} elseif ($level -ge 3) {{ 'medium' }} else {{ 'low' }}
        confidenceLevel = [uint32]$level
        threatType = $threat
        matchedRules = @($rules.ToArray())
        lineSnippet = [string]$snippet
      }})
    }}
  }} catch {{}}
}}
$sw.Stop()
[ordered]@{{
  scannedPaths = @($roots.ToArray())
  observedAt = [DateTime]::UtcNow.ToString('o')
  scannedFiles = [uint32]$candidateFiles.Count
  scannedDirs = [uint32]$scannedDirs
  elapsedMs = [uint64]$sw.ElapsedMilliseconds
  workerThreads = [uint32]$threads
  truncated = [bool]$truncated
  warnings = @($warnings.ToArray())
  entries = @($entries.ToArray())
}} | ConvertTo-Json -Depth 6 -Compress
"#
    ))
}
