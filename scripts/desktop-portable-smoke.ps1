[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ArchivePath,
    [int]$StartupTimeoutSeconds = 60,
    [int]$ShutdownTimeoutSeconds = 30
)

# Runs a portable package the way an operator would: extracted into a fresh
# folder whose path has spaces and Chinese characters, started with no
# arguments, closed through its window. Passes only if the page reported it
# rendered, the app exited cleanly, everything it wrote is under data\ beside
# the executable, and nothing appeared in the (redirected) user profile.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
& (Join-Path $PSScriptRoot 'desktop-validate-package.ps1') -ArchivePath $archive

$runNonce = [guid]::NewGuid().ToString('N')
$scratchRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$runRoot = Join-Path $scratchRoot "LovelyHawk 便携 空格 测试-$runNonce"
$extractRoot = Join-Path $runRoot '解压 目录'
$profileRoot = Join-Path $runRoot 'profile'
# The host writes its readiness marker only into a directory with this exact
# name directly under the system temporary directory.
$controlRoot = Join-Path $scratchRoot "lovelyhawk-smoke-$runNonce"
$readyPath = Join-Path $controlRoot "ready-$runNonce.json"

function Get-TreeSnapshot {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Recurse -Force | ForEach-Object {
        [System.IO.Path]::GetRelativePath($Root, $_.FullName).Replace('\', '/')
    } | Sort-Object)
}

function Get-DescendantProcessIds {
    param([int]$ParentId)
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $ParentId" -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        [int]$child.ProcessId
        Get-DescendantProcessIds -ParentId ([int]$child.ProcessId)
    }
}

$previousAppData = [Environment]::GetEnvironmentVariable('APPDATA', 'Process')
$previousLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
$process = $null
$result = $null
try {
    foreach ($directory in @($extractRoot, (Join-Path $profileRoot 'Roaming'), (Join-Path $profileRoot 'Local'), $controlRoot)) {
        [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractRoot)
    $packageRoot = @(Get-ChildItem -LiteralPath $extractRoot -Directory)[0].FullName
    $executable = Join-Path $packageRoot 'LovelyHawk.exe'
    $before = Get-TreeSnapshot -Root $packageRoot

    [Environment]::SetEnvironmentVariable('APPDATA', (Join-Path $profileRoot 'Roaming'), 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $profileRoot 'Local'), 'Process')
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($executable)
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = $packageRoot
    $startInfo.Environment['LOVELYHAWK_SMOKE_READY_ROOT'] = $controlRoot
    $startInfo.Environment['LOVELYHAWK_SMOKE_READY_NONCE'] = $runNonce
    $process = [System.Diagnostics.Process]::Start($startInfo)

    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    while (-not (Test-Path -LiteralPath $readyPath)) {
        if ($process.HasExited) { throw "LovelyHawk exited with code $($process.ExitCode) before the page reported ready." }
        if ([DateTime]::UtcNow -gt $deadline) { throw "Timed out waiting for the readiness marker in '$controlRoot'." }
        Start-Sleep -Milliseconds 250
    }
    $marker = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    if ($marker.schema -cne 'lovelyhawk-smoke-ready/v1' -or $marker.status -cne 'ready') {
        throw "Invalid readiness marker in '$readyPath'."
    }
    $helpers = @(Get-DescendantProcessIds -ParentId $process.Id)

    # The window's close goes through the page's close handshake.
    $process.Refresh()
    if (-not $process.CloseMainWindow()) { throw 'LovelyHawk has no main window to close.' }
    if (-not $process.WaitForExit($ShutdownTimeoutSeconds * 1000)) {
        throw 'LovelyHawk did not exit after its window was closed.'
    }
    if ($process.ExitCode -ne 0) { throw "LovelyHawk exited with code $($process.ExitCode)." }
    Start-Sleep -Seconds 2
    $survivors = @($helpers | Where-Object { $null -ne (Get-Process -Id $_ -ErrorAction SilentlyContinue) })
    if ($survivors.Count -gt 0) { throw "Helper processes survived shutdown: $($survivors -join ', ')." }

    $after = Get-TreeSnapshot -Root $packageRoot
    $added = @($after | Where-Object { $before -notcontains $_ })
    $outsideData = @($added | Where-Object { $_ -ne 'data' -and -not $_.StartsWith('data/', [System.StringComparison]::Ordinal) })
    if ($outsideData.Count -gt 0) { throw "The app wrote outside data\: $($outsideData -join ', ')" }
    if (@($added | Where-Object { $_ -like 'data/webview2*' }).Count -eq 0) { throw 'WebView2 state was not kept under data\webview2.' }
    $removed = @($before | Where-Object { $after -notcontains $_ })
    if ($removed.Count -gt 0) { throw "The app removed shipped files: $($removed -join ', ')" }
    $profileWrites = @(Get-TreeSnapshot -Root $profileRoot | Where-Object { $_ -notin @('Roaming', 'Local') })
    if ($profileWrites.Count -gt 0) { throw "The app wrote into the user profile: $($profileWrites -join ', ')" }

    $result = [ordered]@{
        schema = 'lovelyhawk-portable-smoke/v1'
        archive = [System.IO.Path]::GetFileName($archive)
        marker = $marker.schema
        exitCode = $process.ExitCode
        helperProcesses = $helpers.Count
        dataEntries = @($added).Count
        profileWrites = 0
        extractedPathHasSpacesAndCjk = $true
        completedAt = [DateTime]::UtcNow.ToString('o')
    }
} finally {
    [Environment]::SetEnvironmentVariable('APPDATA', $previousAppData, 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $previousLocalAppData, 'Process')
    if ($null -ne $process -and -not $process.HasExited) { $process.Kill($true) }
    foreach ($directory in @($controlRoot, $runRoot)) {
        $full = [System.IO.Path]::GetFullPath($directory)
        if ($full.StartsWith($scratchRoot, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $full)) {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$result | ConvertTo-Json -Depth 4
Write-Host 'Portable smoke passed.'
