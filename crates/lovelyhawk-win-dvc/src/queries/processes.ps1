$ErrorActionPreference = 'Stop'
$rows = @(Get-CimInstance Win32_Process -OperationTimeoutSec 15)
if ($rows.Count -gt 32768) { throw '进程数量超过 32768，未返回不完整清单。' }
# An owner is only kept for the same PID and start time; owners that cannot be read stay empty.
$owners = @{}
try {
  foreach ($g in @(Get-Process -IncludeUserName -ErrorAction Stop)) { if ($g.UserName) { $owners[[uint32]$g.Id] = @{ name = [string]$g.UserName; start = $(try { $g.StartTime.ToUniversalTime() } catch { $null }) } } }
} catch {
  # Without elevation: read each process token directly; WMI GetOwner is far too slow for a full list.
  try {
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class LovelyHawkProcessOwner {
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  public static string Get(uint pid, long created) {
    IntPtr process = OpenProcess(0x1000, false, pid);
    if (process == IntPtr.Zero) return "";
    try {
      long c, e, k, u;
      if (created != 0 && (!GetProcessTimes(process, out c, out e, out k, out u) || Math.Abs(c - created) > 20000000)) return "";
      IntPtr token;
      if (!OpenProcessToken(process, 0x0008, out token)) return "";
      try {
        using (WindowsIdentity identity = new WindowsIdentity(token)) {
          try { return identity.Name ?? ""; } catch { return identity.User == null ? "" : identity.User.Value; }
        }
      } catch { return ""; } finally { CloseHandle(token); }
    } finally { CloseHandle(process); }
  }
}
'@
    foreach ($p in $rows) {
      $name = [LovelyHawkProcessOwner]::Get([uint32]$p.ProcessId, $(if ($p.CreationDate) { $p.CreationDate.ToFileTimeUtc() } else { 0 }))
      if ($name) { $owners[[uint32]$p.ProcessId] = @{ name = $name; start = $null } }
    }
  } catch { }
}
$out = foreach ($p in $rows) {
  $id = [uint32]$p.ProcessId
  $owner = ''
  if ($owners.ContainsKey($id)) {
    $o = $owners[$id]
    if ($null -eq $o.start -or -not $p.CreationDate -or [math]::Abs(($o.start - $p.CreationDate.ToUniversalTime()).TotalSeconds) -lt 2) { $owner = $o.name }
  }
  [ordered]@{
    pid = $id; ppid = [uint32]$p.ParentProcessId; name = [string]$p.Name
    executablePath = [string]$p.ExecutablePath; commandLine = [string]$p.CommandLine; user = $owner
    sessionId = [uint32]$p.SessionId; workingSetMb = [uint64][math]::Round($p.WorkingSetSize / 1MB)
    startTime = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { '' }
  }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
