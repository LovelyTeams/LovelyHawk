$ErrorActionPreference = 'Stop'
$warnings = New-Object System.Collections.Generic.List[string]
$facts = New-Object System.Collections.Generic.List[object]
function Fact($group, $label, $value) {
  $text = [string]$value
  if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096); $warnings.Add("${label}：内容已截断。") }
  $facts.Add(@{ group = $group; label = $label; value = $text })
}
function Read-Part($label, [scriptblock]$query) {
  try { & $query } catch { $warnings.Add("${label}：未能读取，请检查组件与当前账户权限。") }
}
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 8
$cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 8
$cpu = Get-CimInstance Win32_Processor -OperationTimeoutSec 8 | Select-Object -First 1
$drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -OperationTimeoutSec 8
$mp = Read-Part 'Defender 运行状态' { Get-MpComputerStatus }
$fw = @(Read-Part '防火墙生效配置' { Get-NetFirewallProfile -PolicyStore ActiveStore })
$fwMap = @{}
foreach ($p in $fw) { $fwMap[$p.Name] = [bool]$p.Enabled }
Fact '系统' '制造商 / 型号' "$($cs.Manufacturer) / $($cs.Model)"
Fact '系统' '安装时间' ($os.InstallDate.ToString('o'))
Fact '系统' '系统目录' $os.WindowsDirectory
Fact '系统' '系统类型' $cs.SystemType
Fact '系统' '物理 / 逻辑处理器' "$($cs.NumberOfProcessors) / $($cs.NumberOfLogicalProcessors)"
Fact '系统' '当前时区' ([TimeZoneInfo]::Local.DisplayName)
Fact '系统' '采集时钟' ([DateTimeOffset]::Now.ToString('o'))
Read-Part 'BIOS' {
  $bios = Get-CimInstance Win32_BIOS -OperationTimeoutSec 8 | Select-Object -First 1
  Fact '硬件' 'BIOS 厂商 / 版本' "$($bios.Manufacturer) / $($bios.SMBIOSBIOSVersion)"
  Fact '硬件' 'BIOS 日期' $bios.ReleaseDate
} | Out-Null
Read-Part '磁盘' {
  $disks = @(Get-CimInstance Win32_LogicalDisk -OperationTimeoutSec 8 | Select-Object -First 33)
  if ($disks.Count -gt 32) { $warnings.Add('磁盘超过 32 项，仅显示前 32 项。') }
  foreach ($d in ($disks | Select-Object -First 32)) { Fact '磁盘' "$($d.DeviceID) $($d.VolumeName)" "$($d.FileSystem) · 类型 $($d.DriveType) · 可用 $([math]::Round($d.FreeSpace / 1GB, 2)) / $([math]::Round($d.Size / 1GB, 2)) GiB" }
} | Out-Null
Read-Part '网络适配器' {
  $adapters = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -OperationTimeoutSec 8 | Select-Object -First 33)
  if ($adapters.Count -gt 32) { $warnings.Add('网络适配器超过 32 项，仅显示前 32 项。') }
  foreach ($a in ($adapters | Select-Object -First 32)) {
    Fact '网络' $a.Description "IP: $($a.IPAddress -join ', ')`n子网: $($a.IPSubnet -join ', ')`n网关: $($a.DefaultIPGateway -join ', ')`nDNS: $($a.DNSServerSearchOrder -join ', ')`nMAC: $($a.MACAddress) · DHCP: $($a.DHCPEnabled)"
  }
} | Out-Null
Read-Part '系统更新' {
  $patches = @(Get-CimInstance Win32_QuickFixEngineering -OperationTimeoutSec 8 | Sort-Object InstalledOn -Descending | Select-Object -First 51)
  if ($patches.Count -gt 50) { $warnings.Add('更新记录仅显示最近 50 项；此来源不包含全部更新类型。') }
  foreach ($p in ($patches | Select-Object -First 50)) { Fact '更新记录' $p.HotFixID "$($p.Description) · $($p.InstalledOn)" }
} | Out-Null
if ($mp) {
  Fact '防护' 'Defender 引擎 / 签名版本' "$($mp.AMEngineVersion) / $($mp.AntivirusSignatureVersion)"
  Fact '防护' '签名更新时间' $mp.AntivirusSignatureLastUpdated
  Fact '防护' '防篡改状态（报告值）' $mp.IsTamperProtected
}
$total = [uint64][math]::Round($os.TotalVisibleMemorySize / 1024)
$used = $total - [uint64][math]::Round($os.FreePhysicalMemory / 1024)
[ordered]@{
  hostname = [string]$env:COMPUTERNAME; osCaption = [string]$os.Caption
  osVersion = "$($os.Version) (Build $($os.BuildNumber))"; architecture = [string]$os.OSArchitecture
  domainOrWorkgroup = [string]$cs.Domain; partOfDomain = [bool]$cs.PartOfDomain
  currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  sessionName = [string]$env:SESSIONNAME; bootTime = $os.LastBootUpTime.ToString('o')
  uptimeHours = [uint64][math]::Max(0, ((Get-Date) - $os.LastBootUpTime).TotalHours)
  cpuName = [string]$cpu.Name; cpuCores = [uint32]$cs.NumberOfLogicalProcessors; cpuLoadPercent = [uint32]$cpu.LoadPercentage
  memoryTotalMb = $total; memoryUsedMb = $used; memoryUsagePercent = if ($total) { [uint32][math]::Round($used * 100 / $total) } else { 0 }
  systemDriveFreeGb = [uint64][math]::Round($drive.FreeSpace / 1GB); systemDriveTotalGb = [uint64][math]::Round($drive.Size / 1GB)
  defenderEnabled = if ($mp -and $null -ne $mp.AntivirusEnabled) { [bool]$mp.AntivirusEnabled } else { $null }
  realtimeProtection = if ($mp -and $null -ne $mp.RealTimeProtectionEnabled) { [bool]$mp.RealTimeProtectionEnabled } else { $null }
  firewallDomainEnabled = $fwMap['Domain']; firewallPrivateEnabled = $fwMap['Private']; firewallPublicEnabled = $fwMap['Public']
  facts = @($facts.ToArray()); warnings = @($warnings.ToArray())
} | ConvertTo-Json -Depth 5 -Compress
