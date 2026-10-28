param([string]$OutputDirectory = (Join-Path $PSScriptRoot "../target/process-tree-lab-$([guid]::NewGuid())"))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($OutputDirectory)
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $root.StartsWith((Join-Path $workspace 'target') + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Evidence root must be in workspace target' }
[void][IO.Directory]::CreateDirectory($root)
$ps = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
$script = [IO.File]::ReadAllText((Join-Path $workspace 'crates/lovelyhawk-core/src/windows_incident/process_change.ps1'))
$owned = New-Object 'Collections.Generic.List[System.Diagnostics.Process]'
$checks = New-Object 'Collections.Generic.List[object]'
function Enc([string]$text) { [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($text)) }
function Start-Owned([string]$code) {
  $start = New-Object Diagnostics.ProcessStartInfo
  $start.FileName = $ps; $start.Arguments = '-NoProfile -NonInteractive -EncodedCommand ' + (Enc $code)
  $start.UseShellExecute=$false; $start.CreateNoWindow=$true
  $process=[Diagnostics.Process]::Start($start)
  $owned.Add($process)
  return $process
}
function Invoke-Query($payload) {
  $json = $payload | ConvertTo-Json -Depth 10 -Compress
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
  $code = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;`n" + '$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(' + "'$b64'" + ')) | ConvertFrom-Json' + "`n" + $script
  $encoded=Enc $code
  if ($encoded.Length -gt 29900) { throw 'Command too long' }
  $result = & $ps -NoProfile -NonInteractive -EncodedCommand $encoded 2> (Join-Path $root 'stderr.txt')
  if ($LASTEXITCODE -ne 0) { throw "PowerShell query failed: $(Get-Content -LiteralPath (Join-Path $root 'stderr.txt') -Raw)" }
  return ($result -join "`n" | ConvertFrom-Json -DateKind String)
}
function Assert-Check($name,$ok) {
  $checks.Add(@{name=$name;passed=[bool]$ok})
  if (-not $ok) { throw "Check failed: $name" }
}
function Compact-Plan($plan) {
  $identities = @($plan.items | ForEach-Object { ,@([uint32]$_.pid,[uint32]$_.ppid,[DateTime]::Parse($_.startTime).ToFileTimeUtc()) })
  return @{mode='apply';plan=@{id=[guid]::NewGuid().ToString();tree=$true;items=$identities}}
}
try {
  # A controlled parent starts exactly one sleeping child. No unrelated PID is targeted.
  $marker=Join-Path $root 'child.txt'; $quotedMarker=$marker.Replace("'","''")
  $leaf=Enc 'Start-Sleep -Seconds 180'
  $parentCode = '$s=New-Object Diagnostics.ProcessStartInfo; $s.FileName=' + "'$ps';" + '$s.Arguments=' + "'-NoProfile -NonInteractive -EncodedCommand $leaf';" + '$s.UseShellExecute=$false;$s.CreateNoWindow=$true;$child=[Diagnostics.Process]::Start($s);[IO.File]::WriteAllText(' + "'$quotedMarker'," + '[string]$child.Id);Start-Sleep -Seconds 180'
  $parent = Start-Owned $parentCode
  $limit=[DateTime]::UtcNow.AddSeconds(15)
  while (-not (Test-Path -LiteralPath $marker)) { if ([DateTime]::UtcNow -gt $limit) { throw 'Child startup timed out' }; Start-Sleep -Milliseconds 100 }
  $childId=[int][IO.File]::ReadAllText($marker)
  $child=[Diagnostics.Process]::GetProcessById($childId); [void]$child.Handle; $owned.Add($child)
  $row=Get-CimInstance Win32_Process -Filter "ProcessId=$($parent.Id)"
  $plan=Invoke-Query @{mode='plan';pid=$parent.Id;startTime=$row.CreationDate.ToUniversalTime().ToString('o');tree=$true}
  $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'preview.json') -Encoding utf8
  Assert-Check 'preview contains owned parent, child and their console hosts only' ($plan.items[0].pid -eq $parent.Id -and @($plan.items | Where-Object pid -eq $childId).Count -eq 1 -and @($plan.items | Where-Object { $_.pid -ne $parent.Id -and $_.pid -ne $childId -and ($_.name -ne 'conhost.exe' -or $_.ppid -notin @($parent.Id,$childId)) }).Count -eq 0)
  Assert-Check 'preview has no termination effect' (-not $parent.HasExited -and -not $child.HasExited)
  $changed=Compact-Plan $plan; $changed.plan.items[1][2] += 10000000
  $refused=Invoke-Query $changed
  Assert-Check 'changed child identity refuses the whole plan before effects' (@($refused.items | Where-Object state -eq 'refused').Count -eq $plan.items.Count -and -not $parent.HasExited -and -not $child.HasExited)
  $missing=Compact-Plan $plan; $missing.plan.items=@($missing.plan.items[0])
  # Explicit nested array preserves a single compact identity through JSON.
  $missing.plan.items=,@($parent.Id,[uint32]$row.ParentProcessId,$row.CreationDate.ToUniversalTime().ToFileTimeUtc())
  $scopeRefused=Invoke-Query $missing
  Assert-Check 'unapproved live descendant prevents mutation' ($scopeRefused.items[0].state -eq 'refused' -and -not $parent.HasExited -and -not $child.HasExited)
  $result=Invoke-Query (Compact-Plan $plan)
  $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'result.json') -Encoding utf8
  Assert-Check 'both exact process objects verified terminated' (@($result.items | Where-Object state -eq 'verified').Count -eq $plan.items.Count -and $parent.WaitForExit(2000) -and $child.WaitForExit(2000))
  $checks | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'checks.json') -Encoding utf8
  Write-Output "PASS: $($checks.Count) checks; evidence $root"
} finally {
  # Retained process objects, never a new lookup by a potentially recycled PID.
  foreach ($process in $owned) { try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(2000) } } finally { $process.Dispose() } }
}
