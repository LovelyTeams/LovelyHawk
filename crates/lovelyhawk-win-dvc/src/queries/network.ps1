$ErrorActionPreference = 'Stop'
$procMap = @{}
Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object { $procMap[[uint32]$_.ProcessId] = @{ name = [string]$_.Name; path = [string]$_.ExecutablePath } }
$out = New-Object System.Collections.Generic.List[object]
foreach ($kind in @('TCP','UDP')) {
  $rows = if ($kind -eq 'TCP') { @(Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 8193) } else { @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -First 8193) }
  if ($rows.Count -gt 8192) { throw "$kind 超过本次 8192 条上限，未返回不完整连接清单。" }
  foreach ($row in $rows) {
    $owner = [uint32]$row.OwningProcess
    $p = $procMap[$owner]
    $out.Add([ordered]@{
      protocol = $kind; localAddress = [string]$row.LocalAddress; localPort = [uint16]$row.LocalPort
      remoteAddress = if ($kind -eq 'TCP') { [string]$row.RemoteAddress } else { '' }
      remotePort = if ($kind -eq 'TCP') { [uint16]$row.RemotePort } else { 0 }
      state = if ($kind -eq 'TCP') { [string]$row.State } else { 'STATELESS' }
      pid = $owner
      processName = if ($p) { $p.name } else { '' }
      processPath = if ($p) { $p.path } else { '' }
    })
  }
}
ConvertTo-Json -InputObject @($out.ToArray()) -Depth 4 -Compress
