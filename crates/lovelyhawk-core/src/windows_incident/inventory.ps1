$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$kind = '__KIND__'
$warnings = New-Object 'Collections.Generic.List[string]'
$items = New-Object 'Collections.Generic.List[object]'
$truncated = $false
$total = 0
function Text($value, $limit) {
  $text = [string]$value
  if ($text.Length -gt $limit) { $script:truncated=$true; return $text.Substring(0,$limit) + '…[截断]' }
  return $text
}
try {
  if ($kind -eq 'tasks') {
    $all = @(Get-ScheduledTask -ErrorAction Stop | Select-Object -First 2001)
    $total = $all.Count
    foreach ($t in ($all | Select-Object -First 2000)) {
      $details = New-Object 'Collections.Generic.List[string]'
      $actions = @($t.Actions)
      foreach ($a in ($actions | Select-Object -First 10)) {
        $details.Add((Text ("操作：" + $a.CimClass.CimClassName + ' · ' + $a.Execute + ' ' + $a.Arguments + ' · 工作目录：' + $a.WorkingDirectory + ' · 类标识：' + $a.ClassId) 900))
      }
      foreach ($trigger in ($t.Triggers | Select-Object -First 10)) {
        $details.Add((Text ("触发器：" + $trigger.CimClass.CimClassName + ' · 开始：' + $trigger.StartBoundary + ' · 启用：' + $trigger.Enabled) 900))
      }
      if ($actions.Count -gt 10 -or @($t.Triggers).Count -gt 10) { $details.Add('操作或触发器仅展示前 10 项。'); $truncated=$true }
      $details.Add((Text ("权限：" + $t.Principal.RunLevel + ' · 登录类型：' + $t.Principal.LogonType) 900))
      $items.Add(@{name=(Text $t.TaskName 250);displayName=(Text $t.Description 250);location=(Text $t.TaskPath 500);command=(Text (($actions | Select-Object -First 10 | ForEach-Object { ([string]$_.Execute + ' ' + $_.Arguments).Trim() }) -join ' ; ') 2000);account=(Text $t.Principal.UserId 250);state=[string]$t.State;startMode='';pid=0;details=$details.ToArray();riskLevel='normal';riskReason=''})
    }
  } else {
    $class = if ($kind -eq 'drivers') { 'Win32_SystemDriver' } else { 'Win32_Service' }
    $all = @(Get-CimInstance -ClassName $class -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -First 2001)
    $total = $all.Count
    foreach ($s in ($all | Select-Object -First 2000)) {
      $details = @((Text ("说明：" + $s.Description) 900),(Text ("服务类型：" + $s.ServiceType + ' · 错误控制：' + $s.ErrorControl + ' · 接受停止：' + $s.AcceptStop) 900))
      $processId = if ($kind -eq 'services') { [uint32]$s.ProcessId } else { 0 }
      $items.Add(@{name=(Text $s.Name 250);displayName=(Text $s.DisplayName 250);location=(Text ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $s.Name) 500);command=(Text $s.PathName 2000);account=(Text $s.StartName 250);state=[string]$s.State;startMode=[string]$s.StartMode;pid=$processId;details=$details;riskLevel='normal';riskReason=''})
    }
  }
} catch {
  $warnings.Add('清单读取未完成：请核对当前账户读取权限、CIM 服务及计划任务工具是否可用；已取得的条目不代表完整清单。')
}
if ($total -gt 2000) { $truncated=$true }
$result = @{kind=$kind;observedAt=[DateTime]::UtcNow.ToString('o');totalCount=$total;truncated=$truncated;warnings=$warnings.ToArray();entries=$items.ToArray()}
$json = $result | ConvertTo-Json -Depth 8 -Compress
while ([Text.Encoding]::UTF8.GetByteCount($json) -gt 1900000 -and $items.Count -gt 0) {
  $items.RemoveAt($items.Count-1); $result.entries=$items.ToArray(); $result.truncated=$true
  $json = $result | ConvertTo-Json -Depth 8 -Compress
}
$json
