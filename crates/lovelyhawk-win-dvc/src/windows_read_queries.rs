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
pub const BASELINE: &str = include_str!("queries/baseline.ps1");
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
