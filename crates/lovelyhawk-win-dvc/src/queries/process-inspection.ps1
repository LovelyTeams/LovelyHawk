$ErrorActionPreference = 'Stop'
$warnings = New-Object System.Collections.Generic.List[string]
function Identity {
  $p = Get-CimInstance Win32_Process -Filter "ProcessId=$targetPid" -OperationTimeoutSec 8
  if (-not $p -or -not $p.CreationDate -or $p.CreationDate.ToUniversalTime().ToString('o') -ne $expectedStart) { throw '进程已退出或 PID 已复用，请刷新进程列表。' }
  $p
}
$before = Identity
$owner = ''
try { $o = Invoke-CimMethod -InputObject $before -MethodName GetOwner -OperationTimeoutSec 5; if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" } else { $warnings.Add('无法取得进程账户。') } } catch { $warnings.Add('无法取得进程账户。') }
$services = @()
try {
  $all = @(Get-CimInstance Win32_Service -Filter "ProcessId=$targetPid" -OperationTimeoutSec 8 | Select-Object -First 257)
  if ($all.Count -gt 256) { $warnings.Add('服务超过 256 项，仅显示前 256 项。') }
  $services = @(foreach ($s in ($all | Select-Object -First 256)) { @{ name = [string]$s.Name; displayName = [string]$s.DisplayName; state = [string]$s.State; startMode = [string]$s.StartMode; path = [string]$s.PathName; account = [string]$s.StartName } })
} catch { $warnings.Add('服务对应未完成，请检查 CIM 组件和读取权限。') }
$modules = @()
try {
  $live = Get-Process -Id $targetPid -ErrorAction Stop
  $all = @($live.Modules | Select-Object -First 513)
  if ($all.Count -gt 512) { $warnings.Add('模块超过 512 项，仅显示前 512 项。') }
  $modules = @(foreach ($m in ($all | Select-Object -First 512)) { @{ name = [string]$m.ModuleName; path = [string]$m.FileName; sizeBytes = [uint64]$m.ModuleMemorySize } })
} catch { $warnings.Add('DLL/模块未完成读取：进程可能受保护、已退出或与采集端位数不同；没有模块不能证明没有注入。') }
$network = New-Object System.Collections.Generic.List[object]
try {
  $all = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object OwningProcess -eq $targetPid | Select-Object -First 1025)
  if ($all.Count -gt 1024) { $warnings.Add('TCP 端点超过 1024 项，仅显示前 1024 项。') }
  foreach ($n in ($all | Select-Object -First 1024)) { $network.Add(@{ protocol = 'TCP'; localAddress = [string]$n.LocalAddress; localPort = [uint16]$n.LocalPort; remoteAddress = [string]$n.RemoteAddress; remotePort = [uint16]$n.RemotePort; state = [string]$n.State; pid = $targetPid; processName = [string]$before.Name; processPath = [string]$before.ExecutablePath }) }
} catch { $warnings.Add('TCP 连接未完成读取。') }
try {
  $all = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object OwningProcess -eq $targetPid | Select-Object -First 1025)
  if ($all.Count -gt 1024) { $warnings.Add('UDP 端点超过 1024 项，仅显示前 1024 项。') }
  foreach ($n in ($all | Select-Object -First 1024)) { $network.Add(@{ protocol = 'UDP'; localAddress = [string]$n.LocalAddress; localPort = [uint16]$n.LocalPort; remoteAddress = ''; remotePort = 0; state = ''; pid = $targetPid; processName = [string]$before.Name; processPath = [string]$before.ExecutablePath }) }
} catch { $warnings.Add('UDP 端点未完成读取。') }
$after = Identity
if ($before.ExecutablePath -ne $after.ExecutablePath) { throw '进程路径在读取时变化，请刷新后重试。' }
[ordered]@{ pid = $targetPid; startTime = $expectedStart; observedAt = [DateTimeOffset]::Now.ToString('o'); user = $owner; services = @($services); modules = @($modules); network = @($network.ToArray()); warnings = @($warnings.ToArray()) } | ConvertTo-Json -Depth 5 -Compress
