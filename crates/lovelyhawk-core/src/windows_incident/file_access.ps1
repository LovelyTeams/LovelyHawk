$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$path = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PATH__'))
$warnings = [Collections.Generic.List[string]]::new()
$owner = ''; $attributes = ''; $rules = @(); $processes = @(); $services = @()
function Canonical([string]$value) {
  if (-not $value) { return '' }
  $value = [Environment]::ExpandEnvironmentVariables($value)
  if ($value.StartsWith('\??\')) { $value = $value.Substring(4) }
  if ($value.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) { $value = $env:SystemRoot + $value.Substring(11) }
  if ($value.StartsWith('System32\', [StringComparison]::OrdinalIgnoreCase)) { $value = Join-Path $env:SystemRoot $value }
  return $value.Trim().TrimEnd('\').ToLowerInvariant()
}
function Executable([string]$command) {
  if ($command -match '^\s*"([^"]+)"') { return Canonical $matches[1] }
  if ($command -match '^\s*(.+?\.(?:exe|sys))(?:\s|$)') { return Canonical $matches[1] }
  return Canonical $command
}
try {
  $item = Get-Item -LiteralPath ([Environment]::ExpandEnvironmentVariables($path)) -Force -ErrorAction Stop
  if ($item.PSIsContainer) { throw 'directory' }
  $path = $item.FullName; $attributes = $item.Attributes.ToString()
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $warnings.Add('这是重解析点；请核实实际指向，不应按普通文件直接处置。') }
} catch { $warnings.Add('未能读取文件属性：可能已移动、无权限或不是普通文件。') }
try {
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop; $owner = [string]$acl.Owner
  $allRules = @($acl.Access)
  $rules = @($allRules | Select-Object -First 64 | ForEach-Object { [ordered]@{ identity=[string]$_.IdentityReference; rights=[string]$_.FileSystemRights; access=[string]$_.AccessControlType; inherited=[bool]$_.IsInherited } })
  if ($allRules.Count -gt 64) { $warnings.Add('访问规则仅显示前 64 条。') }
} catch { $warnings.Add('无法读取文件访问规则；不会取得所有权或修改权限。') }
$canonical = Canonical $path
try {
  $allProcesses = @(Get-CimInstance Win32_Process -OperationTimeoutSec 8 | Select-Object -First 4097)
  if ($allProcesses.Count -gt 4096) { $warnings.Add('进程路径查询仅检查前 4096 项。') }
  $matchesByPath = @($allProcesses | Select-Object -First 4096 | Where-Object { $_.ExecutablePath -and (Canonical $_.ExecutablePath) -eq $canonical })
  $processes = @($matchesByPath | Select-Object -First 256 | ForEach-Object { [ordered]@{ pid=[uint32]$_.ProcessId; name=[string]$_.Name } })
  if ($matchesByPath.Count -gt 256) { $warnings.Add('关联进程仅显示前 256 项。') }
} catch { $warnings.Add('进程路径查询失败或权限不足，不能排除仍有程序占用文件。') }
foreach ($class in @('Win32_Service','Win32_SystemDriver')) {
  try {
    $allServices = @(Get-CimInstance -ClassName $class -OperationTimeoutSec 8 | Select-Object -First 4097)
    if ($allServices.Count -gt 4096) { $warnings.Add($class + ' 仅检查前 4096 项。') }
    $matchesByPath = @($allServices | Select-Object -First 4096 | Where-Object { $_.PathName -and (Executable $_.PathName) -eq $canonical })
    $services += @($matchesByPath | Select-Object -First 128 | ForEach-Object { [ordered]@{ name=[string]$_.Name; displayName=[string]$_.DisplayName; state=[string]$_.State; startMode=[string]$_.StartMode; path=[string]$_.PathName; kind=$(if ($class -eq 'Win32_SystemDriver') {'driver'} else {'service'}) } })
    if ($matchesByPath.Count -gt 128) { $warnings.Add($class + ' 关联结果仅显示前 128 项。') }
  } catch { $warnings.Add($class + ' 查询失败或权限不足，无法核实关联服务。') }
}
$warnings.Add('ACL 是访问规则观察，不是有效删除权限判断；路径相同不证明文件占用，也未枚举所有已打开文件。')
$warnings.Add('不停止服务、不卸载驱动、不修改 ACL。删除已加载驱动文件不能替代驱动卸载，启动驱动需在维护窗口另行处置。')
[ordered]@{ path=$path; observedAt=[DateTime]::UtcNow.ToString('o'); attributes=$attributes; owner=$owner; accessRules=@($rules); processes=@($processes); services=@($services); warnings=@($warnings.ToArray()) } | ConvertTo-Json -Compress -Depth 6
