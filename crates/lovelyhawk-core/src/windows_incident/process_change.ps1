$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Discovery is bounded; unknown creation times in a subtree fail closed.
function Read-Tree($rootId, $rootStart, $withChildren) {
  $all = @(Get-CimInstance Win32_Process -OperationTimeoutSec 8 | Select-Object -First 32769)
  if ($all.Count -gt 32768) { throw 'Process table limit' }
  $byId = @{}; foreach ($p in $all) { $byId[[uint32]$p.ProcessId] = $p }
  $root = $byId[[uint32]$rootId]
  if (-not $root -or -not $root.CreationDate -or $root.CreationDate.ToUniversalTime().ToString('o') -cne $rootStart) { throw 'Identity changed' }
  $own = @{}; $ancestor = [uint32]$PID
  while ($byId.ContainsKey($ancestor) -and -not $own.ContainsKey($ancestor)) {
    $own[$ancestor] = $true; $ancestor = [uint32]$byId[$ancestor].ParentProcessId
  }
  $protected = @('system','idle','registry','smss.exe','csrss.exe','wininit.exe','services.exe','lsass.exe','winlogon.exe','fontdrvhost.exe','dwm.exe')
  $queue = New-Object 'Collections.Generic.List[object]'; $queue.Add($root)
  $seen = @{}
  for ($i=0; $i -lt $queue.Count; $i++) {
    $p = $queue[$i]; $key = [uint32]$p.ProcessId
    if ($key -le 4 -or $own.ContainsKey($key) -or $seen.ContainsKey($key) -or $protected -contains ([string]$p.Name).ToLowerInvariant()) { throw 'Protected process' }
    $seen[$key] = $true
    if ($withChildren) {
      foreach ($child in $all) {
        if ([uint32]$child.ParentProcessId -ne $key) { continue }
        if (-not $child.CreationDate) { throw 'Unknown child identity' }
        if ($child.CreationDate -lt $p.CreationDate) { continue } # reused parent PID
        if ($child.CreationDate -eq $p.CreationDate) { throw 'Ambiguous parent identity' }
        $queue.Add($child)
        if ($queue.Count -gt 64) { throw 'Tree limit' }
      }
    }
  }
  return @($queue | ForEach-Object { [pscustomobject]@{pid=[uint32]$_.ProcessId;ppid=[uint32]$_.ParentProcessId;name=[string]$_.Name;startTime=$_.CreationDate.ToUniversalTime().ToString('o')} })
}
if ($request.mode -eq 'plan') {
  @{target=[Environment]::MachineName;items=@(Read-Tree $request.pid $request.startTime $request.tree)} | ConvertTo-Json -Depth 6 -Compress
  return
}
$plan = $request.plan
$plan.items = @($plan.items | ForEach-Object { [pscustomobject]@{pid=[uint32]$_[0];ppid=[uint32]$_[1];startTime=[DateTime]::FromFileTimeUtc([long]$_[2]).ToString("o")} })
$results = @($plan.items | ForEach-Object { [pscustomobject]@{pid=$_.pid;state='skipped'} })
$message = '未执行：进程范围、身份或权限发生变化，请重新预览。'
$handles = New-Object 'Collections.Generic.List[IntPtr]'
try {
  # Handles pin the exact process objects. Never reopen by PID after approval checks.
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LovelyHawkProcessPlan {
 [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetProcessTimes(IntPtr p, out long c, out long e, out long k, out long u);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool IsProcessCritical(IntPtr p, out bool critical);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr p, uint code);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr p, uint ms);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr p);
}
'@
  $root = $plan.items[0]
  $current = @(Read-Tree $root.pid $root.startTime $plan.tree)
  if ($current.Count -ne $plan.items.Count) { throw 'Scope changed' }
  foreach ($item in $plan.items) {
    $match = @($current | Where-Object { $_.pid -eq $item.pid -and $_.ppid -eq $item.ppid -and $_.startTime -ceq $item.startTime })
    if ($match.Count -ne 1) { throw 'Scope changed' }
    $handle = [LovelyHawkProcessPlan]::OpenProcess(0x101001,$false,[uint32]$item.pid)
    if ($handle -eq [IntPtr]::Zero) { throw 'Cannot open process' }
    $handles.Add($handle)
    [long]$created=0; [long]$ended=0; [long]$kernel=0; [long]$user=0; [bool]$critical=$false
    if (-not [LovelyHawkProcessPlan]::GetProcessTimes($handle,[ref]$created,[ref]$ended,[ref]$kernel,[ref]$user)) { throw 'Cannot read identity' }
    # CIM CreationDate has microsecond precision; kernel FILETIME has 100 ns precision.
    $expected = [DateTime]::Parse($item.startTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToFileTimeUtc()
    if ([Math]::Floor($created / [decimal]10) -ne [Math]::Floor($expected / [decimal]10)) { throw 'PID reused' }
    if (-not [LovelyHawkProcessPlan]::IsProcessCritical($handle,[ref]$critical) -or $critical) { throw 'Critical process' }
    if ([LovelyHawkProcessPlan]::WaitForSingleObject($handle,0) -ne 258) { throw 'Process exited' }
  }
  # Repeat the entire membership check after all handles are pinned, before effects.
  $last = @(Read-Tree $root.pid $root.startTime $plan.tree)
  if ($last.Count -ne $current.Count -or (@($last | ForEach-Object { "$($_.pid):$($_.startTime)" } | Sort-Object) -join '|') -cne (@($current | ForEach-Object { "$($_.pid):$($_.startTime)" } | Sort-Object) -join '|')) { throw 'Scope changed' }
  $deadline = [Diagnostics.Stopwatch]::StartNew()
  $message = '已核实计划内进程结束。进程树是预览时的范围，不能排除执行期间新建、逃逸或自动拉起的进程；请刷新并复查持久化。终止不可恢复。'
  for ($i=$handles.Count-1; $i -ge 0; $i--) {
    if ($deadline.Elapsed.TotalSeconds -ge 25) { $message='处置超时，后续进程未处理，请核对逐项结果。'; break }
    $results[$i].state='uncertain'
    if ([LovelyHawkProcessPlan]::WaitForSingleObject($handles[$i],0) -eq 0) { $results[$i].state='verified'; continue }
    if (-not [LovelyHawkProcessPlan]::TerminateProcess($handles[$i],1)) { $results[$i].state='failed'; $message='部分进程未能结束，已停止后续操作。请核对权限、保护状态及逐项结果。'; break }
    if ([LovelyHawkProcessPlan]::WaitForSingleObject($handles[$i],500) -ne 0) { $message='已发出终止请求，但未核实退出，已停止后续操作。请重新采集核对。'; break }
    $results[$i].state='verified'
  }
} catch {
  if (@($results | Where-Object { $_.state -ne 'skipped' }).Count -eq 0) {
    foreach ($r in $results) { $r.state='refused' }
  } else { $message='处置中断，请核对逐项结果并重新采集；不能确认整个进程树已经结束。' }
} finally {
  foreach ($handle in $handles) { [void][LovelyHawkProcessPlan]::CloseHandle($handle) }
}
@{id=$plan.id;items=$results;message=$message} | ConvertTo-Json -Depth 6 -Compress
