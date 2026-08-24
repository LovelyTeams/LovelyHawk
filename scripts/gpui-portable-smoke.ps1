[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$Version = '1.0.0',
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 30,
    [string]$ScratchDirectory = ([System.IO.Path]::GetTempPath())
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$checksumPath = "$archive.sha256"
if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
    throw "Missing archive checksum '$checksumPath'."
}
$checksumLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($checksumLine -notmatch '^(?<digest>[a-fA-F0-9]{64})\s{2}(?<name>.+)$') {
    throw "Invalid SHA-256 checksum format in '$checksumPath'."
}
if ($Matches.name -ne [System.IO.Path]::GetFileName($archive)) {
    throw "Checksum names '$($Matches.name)', expected '$([System.IO.Path]::GetFileName($archive))'."
}
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if ($archiveHash -ne $Matches.digest) {
    throw "SHA-256 mismatch for '$archive'."
}
$scratchRoot = (Resolve-Path -LiteralPath $ScratchDirectory).Path
$runRoot = Join-Path $scratchRoot "LovelyRes 空格 测试\中文解压-$([guid]::NewGuid().ToString('N'))"
$extractRoot = Join-Path $runRoot '解压 目录'
$controlRoot = Join-Path $runRoot 'smoke-control'
$profileRoot = Join-Path $runRoot 'isolated-profile'
[System.IO.Directory]::CreateDirectory($extractRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($controlRoot) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $profileRoot 'Roaming')) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $profileRoot 'Local')) | Out-Null

Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot
$packageRoot = Join-Path $extractRoot "LovelyRes-$Version-windows-x64"
$executable = Join-Path $packageRoot 'LovelyRes.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Archive does not contain the expected executable '$executable'."
}

function Get-TreeSnapshot {
    param([string]$Root)

    $snapshot = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path -LiteralPath $Root)) {
        return $snapshot
    }
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        $relative = [System.IO.Path]::GetRelativePath($Root, $entry.FullName)
        if ($entry.PSIsContainer) {
            $snapshot[$relative] = 'directory'
        } else {
            $hash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $snapshot[$relative] = "file:$($entry.Length):$hash"
        }
    }
    return $snapshot
}

function Assert-NoChangesOutsideData {
    param(
        [System.Collections.Generic.Dictionary[string, string]]$Before,
        [System.Collections.Generic.Dictionary[string, string]]$After
    )

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $After.GetEnumerator()) {
        $relative = $entry.Key
        $inData = $relative -eq 'data' -or $relative.StartsWith("data$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase)
        if ($inData) { continue }
        if (-not $Before.ContainsKey($relative)) {
            $violations.Add("created:$relative")
        } elseif ($Before[$relative] -ne $entry.Value) {
            $violations.Add("modified:$relative")
        }
    }
    foreach ($entry in $Before.GetEnumerator()) {
        $relative = $entry.Key
        $inData = $relative -eq 'data' -or $relative.StartsWith("data$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $inData -and -not $After.ContainsKey($relative)) {
            $violations.Add("deleted:$relative")
        }
    }
    if ($violations.Count -gt 0) {
        throw "Portable smoke wrote outside data/: $($violations -join ', ')"
    }
}

$packageBefore = Get-TreeSnapshot -Root $packageRoot
$previousAppData = [Environment]::GetEnvironmentVariable('APPDATA', 'Process')
$previousLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
$externalRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
[void]$externalRoots.Add((Join-Path $profileRoot 'Roaming'))
[void]$externalRoots.Add((Join-Path $profileRoot 'Local'))
foreach ($base in @($previousAppData, $previousLocalAppData)) {
    if ([string]::IsNullOrWhiteSpace($base)) { continue }
    foreach ($name in @('LovelyRes', 'lovelyres', 'com.lovelyres.app')) {
        [void]$externalRoots.Add((Join-Path $base $name))
    }
}
$externalBefore = @{}
foreach ($root in $externalRoots) {
    $externalBefore[$root] = Get-TreeSnapshot -Root $root
}

$readyPath = Join-Path $controlRoot 'ready.json'
$stdoutPath = Join-Path $controlRoot 'stdout.log'
$stderrPath = Join-Path $controlRoot 'stderr.log'
$process = $null
try {
    [Environment]::SetEnvironmentVariable('APPDATA', (Join-Path $profileRoot 'Roaming'), 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $profileRoot 'Local'), 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', $readyPath, 'Process')

    $process = Start-Process -FilePath $executable -WorkingDirectory $packageRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) {
            throw "LovelyRes exited before signaling ready (exit code $($process.ExitCode)). Logs: '$controlRoot'."
        }
        if (Test-Path -LiteralPath $readyPath -PathType Leaf) { break }
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf)) {
        throw "Timed out waiting for '$readyPath'. Logs: '$controlRoot'."
    }

    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    if ($ready.schema -ne 'lovelyres-smoke-ready/v1' -or $ready.status -ne 'ready') {
        throw "Invalid smoke-ready marker in '$readyPath'."
    }
}
finally {
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) {
            [void]$process.CloseMainWindow()
            if (-not $process.WaitForExit(3000)) {
                Stop-Process -Id $process.Id -Force
                $process.WaitForExit()
            }
        }
        $process.Dispose()
    }
    [Environment]::SetEnvironmentVariable('APPDATA', $previousAppData, 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $previousLocalAppData, 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', $null, 'Process')
}

$packageAfter = Get-TreeSnapshot -Root $packageRoot
Assert-NoChangesOutsideData -Before $packageBefore -After $packageAfter
foreach ($root in $externalRoots) {
    $after = Get-TreeSnapshot -Root $root
    $before = $externalBefore[$root]
    if ($after.Count -ne $before.Count) {
        throw "Portable smoke created persistent state outside data/: '$root'."
    }
    foreach ($entry in $after.GetEnumerator()) {
        if (-not $before.ContainsKey($entry.Key) -or $before[$entry.Key] -ne $entry.Value) {
            throw "Portable smoke changed persistent state outside data/: '$root\$($entry.Key)'."
        }
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'data') -PathType Container)) {
    throw 'Portable data/ directory is missing after startup.'
}

Write-Host "Portable smoke passed in the Unicode/space path '$packageRoot'."
Write-Host "Ready marker schema: $($ready.schema); persistent writes were confined to data/."
