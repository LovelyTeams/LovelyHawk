[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$Version = '1.0.0',
    [ValidateRange(10, 120)]
    [int]$TimeoutSeconds = 60,
    [string]$ScratchDirectory = ([System.IO.Path]::GetTempPath())
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
if (-not (Test-Path -LiteralPath $ScratchDirectory -PathType Container)) {
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath($ScratchDirectory)) | Out-Null
}
$scratchRoot = (Resolve-Path -LiteralPath $ScratchDirectory).Path
& (Join-Path $PSScriptRoot 'electron-validate-package.ps1') -ArchivePath $archive -Version $Version

$runNonce = [guid]::NewGuid().ToString('N')
$runRoot = Join-Path $scratchRoot "LovelyRes Electron 空格 测试\中文解压-$runNonce"
$extractRoot = Join-Path $runRoot '解压 目录'
$controlRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyres-electron-smoke-$runNonce"
$profileRoot = Join-Path $runRoot 'isolated-profile'
[System.IO.Directory]::CreateDirectory($extractRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($controlRoot) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $profileRoot 'Roaming')) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $profileRoot 'Local')) | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractRoot)
$packageRoot = Join-Path $extractRoot "LovelyRes-$Version-windows-x64"
$executable = Join-Path $packageRoot 'LovelyRes.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Archive does not contain '$executable'."
}

function Get-TreeSnapshot {
    param([string]$Root)

    $snapshot = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path -LiteralPath $Root)) { return $snapshot }
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
        throw "Portable smoke changed files outside data/: $($violations -join ', ')"
    }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

function Send-CdpCommand {
    param(
        [System.Net.WebSockets.ClientWebSocket]$Socket,
        [int]$Id,
        [string]$Method,
        [DateTime]$Deadline,
        [hashtable]$Parameters = @{}
    )

    $remainingMilliseconds = [int][Math]::Floor(($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if ($remainingMilliseconds -le 0) { throw "CDP deadline expired before '$Method'." }
    $cancellation = [Threading.CancellationTokenSource]::new()
    $cancellation.CancelAfter($remainingMilliseconds)
    $request = @{ id = $Id; method = $Method; params = $Parameters } | ConvertTo-Json -Compress -Depth 8
    $requestBytes = [System.Text.Encoding]::UTF8.GetBytes($request)
    $requestSegment = [System.ArraySegment[byte]]::new($requestBytes)
    try {
        [void]$Socket.SendAsync($requestSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cancellation.Token).GetAwaiter().GetResult()
        for (;;) {
            $stream = [System.IO.MemoryStream]::new()
            try {
                do {
                    $buffer = [byte[]]::new(65536)
                    $segment = [System.ArraySegment[byte]]::new($buffer)
                    $result = $Socket.ReceiveAsync($segment, $cancellation.Token).GetAwaiter().GetResult()
                    if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                        throw 'CDP WebSocket closed before returning a command result.'
                    }
                    $stream.Write($buffer, 0, $result.Count)
                    if ($stream.Length -gt 1MB) { throw "CDP response for '$Method' exceeded 1 MiB." }
                } while (-not $result.EndOfMessage)
                $response = [System.Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
                $idProperty = $response.PSObject.Properties['id']
                if ($null -ne $idProperty -and [int]$idProperty.Value -eq $Id) {
                    $errorProperty = $response.PSObject.Properties['error']
                    if ($null -ne $errorProperty) { throw "CDP command '$Method' failed: $($errorProperty.Value | ConvertTo-Json -Compress)" }
                    return $response.result
                }
            }
            finally {
                $stream.Dispose()
            }
        }
    } finally {
        $cancellation.Dispose()
    }
}

function Get-DescendantProcessIds {
    param([int]$RootProcessId)

    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId)
    $pending = [System.Collections.Generic.Queue[uint32]]::new()
    $found = [System.Collections.Generic.HashSet[int]]::new()
    $pending.Enqueue([uint32]$RootProcessId)
    while ($pending.Count -gt 0) {
        $parent = $pending.Dequeue()
        foreach ($child in @($processes | Where-Object { [uint32]$_.ParentProcessId -eq $parent })) {
            $childId = [int]$child.ProcessId
            if ($found.Add($childId)) { $pending.Enqueue([uint32]$childId) }
        }
    }
    return @($found)
}

function Test-ProcessAlive {
    param([int]$ProcessId)
    return $null -ne (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Remove-SmokeFirewallRules {
    param([string[]]$RuleNames)

    foreach ($ruleName in $RuleNames) {
        $matches = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Name -eq $ruleName })
        if ($matches.Count -gt 0) {
            Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
        }
    }
    $remainingRules = @(Get-NetFirewallRule -ErrorAction Stop)
    foreach ($ruleName in $RuleNames) {
        if ($remainingRules | Where-Object { $_.Name -eq $ruleName }) {
            throw "Temporary firewall rule '$ruleName' remains after cleanup."
        }
    }
}

$packageBefore = Get-TreeSnapshot -Root $packageRoot
$profileBefore = Get-TreeSnapshot -Root $profileRoot
$readyPath = Join-Path $controlRoot "ready-$runNonce.json"
$stdoutPath = Join-Path $controlRoot 'stdout.log'
$stderrPath = Join-Path $controlRoot 'stderr.log'
$port = Get-FreeTcpPort
$previousAppData = [Environment]::GetEnvironmentVariable('APPDATA', 'Process')
$previousLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
$previousSmokeRoot = [Environment]::GetEnvironmentVariable('LOVELYRES_SMOKE_READY_ROOT', 'Process')
$previousSmokeNonce = [Environment]::GetEnvironmentVariable('LOVELYRES_SMOKE_READY_NONCE', 'Process')
$process = $null
$socket = $null
$debugTarget = $null
$evaluation = $null
$sidecarProcesses = @()
$observedProcessIds = [System.Collections.Generic.HashSet[int]]::new()
$forcedShutdown = $false
$firewallRuleNames = @(
    "LovelyResSmoke-$runNonce-App",
    "LovelyResSmoke-$runNonce-Backend"
)
try {
    [Environment]::SetEnvironmentVariable('APPDATA', (Join-Path $profileRoot 'Roaming'), 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $profileRoot 'Local'), 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_ROOT', $controlRoot, 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_NONCE', $runNonce, 'Process')

    try {
        New-NetFirewallRule -Name $firewallRuleNames[0] -DisplayName $firewallRuleNames[0] -Direction Outbound -Action Block -Program $executable -Profile Any -ErrorAction Stop | Out-Null
        New-NetFirewallRule -Name $firewallRuleNames[1] -DisplayName $firewallRuleNames[1] -Direction Outbound -Action Block -Program (Join-Path $packageRoot 'resources\bin\lovelyres-backend.exe') -Profile Any -ErrorAction Stop | Out-Null
    } catch {
        try { Remove-SmokeFirewallRules -RuleNames $firewallRuleNames } catch { }
        $notRun = [ordered]@{
            schema = 'lovelyres-electron-portable-smoke/v1'
            status = 'NOT_RUN'
            reason = 'Unable to install mandatory temporary outbound firewall rules.'
        }
        [System.IO.File]::WriteAllText((Join-Path $controlRoot 'report.json'), "$($notRun | ConvertTo-Json -Depth 4)`n", [System.Text.UTF8Encoding]::new($false))
        throw "Electron offline portable smoke NOT_RUN: mandatory firewall isolation could not be installed. $($_.Exception.Message)"
    }

    $arguments = @(
        "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=$port",
        '--remote-allow-origins=http://127.0.0.1'
    )
    $process = Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $packageRoot -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    [void]$observedProcessIds.Add($process.Id)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        foreach ($processId in @(Get-DescendantProcessIds -RootProcessId $process.Id)) { [void]$observedProcessIds.Add($processId) }
        if ($process.HasExited) {
            throw "LovelyRes exited before portable readiness (exit $($process.ExitCode)); logs: '$controlRoot'."
        }
        if (Test-Path -LiteralPath $readyPath -PathType Leaf) {
            try {
                $targets = @(Invoke-RestMethod -Uri "http://127.0.0.1:$port/json/list" -TimeoutSec 1)
                $debugTarget = $targets | Where-Object { $_.type -eq 'page' -and $_.url -eq 'lovelyres://app/' } | Select-Object -First 1
                if ($null -ne $debugTarget) { break }
            } catch {
                # The marker and CDP endpoint become available on independent event loops.
            }
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $readyPath -PathType Leaf) -or $null -eq $debugTarget) {
        throw "Timed out waiting for the native marker and Electron CDP target; logs: '$controlRoot'."
    }

    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    if ($ready.schema -ne 'lovelyres-smoke-ready/v1' -or $ready.status -ne 'ready') {
        throw "Invalid smoke-ready marker in '$readyPath'."
    }

    $socket = [System.Net.WebSockets.ClientWebSocket]::new()
    $connectMilliseconds = [int][Math]::Floor(($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if ($connectMilliseconds -le 0) { throw 'CDP deadline expired before WebSocket connect.' }
    $connectCancellation = [Threading.CancellationTokenSource]::new()
    $connectCancellation.CancelAfter($connectMilliseconds)
    try {
        [void]$socket.ConnectAsync([Uri]$debugTarget.webSocketDebuggerUrl, $connectCancellation.Token).GetAwaiter().GetResult()
    } finally {
        $connectCancellation.Dispose()
    }
    [void](Send-CdpCommand -Socket $socket -Id 1 -Method 'Runtime.enable' -Deadline $deadline)
    $expression = @'
(() => ({
  href: location.href,
  title: document.title,
  backendConnected: document.body.textContent.includes('Rust 后端已连接'),
  processType: typeof window.process,
  requireType: typeof window.require,
  resources: performance.getEntriesByType('resource').map(entry => entry.name),
  navItems: document.querySelectorAll('.nav-item').length
}))()
'@
    $runtimeResult = Send-CdpCommand -Socket $socket -Id 2 -Method 'Runtime.evaluate' -Deadline $deadline -Parameters @{
        expression = $expression
        returnByValue = $true
    }
    $evaluation = $runtimeResult.result.value
    if ($evaluation.href -ne 'lovelyres://app/' -or $evaluation.title -ne 'LovelyRes' -or
        $evaluation.backendConnected -ne $true -or $evaluation.processType -ne 'undefined' -or
        $evaluation.requireType -ne 'undefined' -or [int]$evaluation.navItems -ne 20) {
        throw "Packaged renderer CDP contract failed: $($evaluation | ConvertTo-Json -Compress -Depth 5)"
    }
    foreach ($resource in @($evaluation.resources)) {
        if (-not ([string]$resource).StartsWith('lovelyres://app/', [System.StringComparison]::Ordinal)) {
            throw "Packaged renderer loaded a non-local resource '$resource'."
        }
    }

    $sidecarProcesses = @(
        Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)" |
            Where-Object { $_.Name -eq 'lovelyres-backend.exe' }
    )
    if ($sidecarProcesses.Count -ne 1) {
        throw "Expected one live packaged sidecar child process, found $($sidecarProcesses.Count)."
    }
    foreach ($sidecarProcess in $sidecarProcesses) { [void]$observedProcessIds.Add([int]$sidecarProcess.ProcessId) }
    foreach ($ruleName in $firewallRuleNames) {
        if (-not (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)) {
            throw "Mandatory offline firewall rule '$ruleName' disappeared during smoke."
        }
    }
}
finally {
    try {
      if ($null -ne $socket) {
        if ($socket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $closeCancellation = [Threading.CancellationTokenSource]::new()
            $closeCancellation.CancelAfter(2000)
            try {
                [void]$socket.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'portable smoke complete', $closeCancellation.Token).GetAwaiter().GetResult()
            } catch {
                $socket.Abort()
            } finally {
                $closeCancellation.Dispose()
            }
        }
        $socket.Dispose()
    }
      if ($null -ne $process) {
        $process.Refresh()
        if ($process.HasExited) { $forcedShutdown = $true }
        try {
            foreach ($processId in @(Get-DescendantProcessIds -RootProcessId $process.Id)) { [void]$observedProcessIds.Add($processId) }
        } catch {
            $forcedShutdown = $true
        }
        if (-not $process.HasExited) {
            [void]$process.CloseMainWindow()
            $gracefulDeadline = [DateTime]::UtcNow.AddSeconds(20)
            if ($deadline -lt $gracefulDeadline) { $gracefulDeadline = $deadline }
            do {
                try {
                    foreach ($processId in @(Get-DescendantProcessIds -RootProcessId $process.Id)) { [void]$observedProcessIds.Add($processId) }
                } catch {
                    $forcedShutdown = $true
                }
                $process.Refresh()
                if ($process.HasExited) { break }
                Start-Sleep -Milliseconds 100
            } while ([DateTime]::UtcNow -lt $gracefulDeadline)
            if (-not $process.HasExited) { $forcedShutdown = $true }
        }
        try {
            foreach ($processId in @(Get-DescendantProcessIds -RootProcessId $process.Id)) { [void]$observedProcessIds.Add($processId) }
        } catch {
            $forcedShutdown = $true
        }
        $liveTree = @($observedProcessIds | Where-Object { Test-ProcessAlive -ProcessId $_ })
        if ($liveTree.Count -gt 0) {
            $forcedShutdown = $true
            foreach ($processId in @($liveTree | Where-Object { $_ -ne $process.Id })) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        $treeDeadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            $remainingTree = @($observedProcessIds | Where-Object { Test-ProcessAlive -ProcessId $_ })
            if ($remainingTree.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $treeDeadline)
        if ($remainingTree.Count -gt 0) {
            throw "Portable smoke could not terminate the complete process tree: $($remainingTree -join ', ')."
        }
        $process.Dispose()
      }
    } finally {
        try {
            Remove-SmokeFirewallRules -RuleNames $firewallRuleNames
        } finally {
            [Environment]::SetEnvironmentVariable('APPDATA', $previousAppData, 'Process')
            [Environment]::SetEnvironmentVariable('LOCALAPPDATA', $previousLocalAppData, 'Process')
            [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_ROOT', $previousSmokeRoot, 'Process')
            [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_NONCE', $previousSmokeNonce, 'Process')
        }
    }
}

if ($forcedShutdown) {
    throw "Electron portable smoke failed: graceful shutdown did not terminate the complete process tree; force was used only for cleanup. Evidence: '$controlRoot'."
}

$packageAfter = Get-TreeSnapshot -Root $packageRoot
Assert-NoChangesOutsideData -Before $packageBefore -After $packageAfter
$profileAfter = Get-TreeSnapshot -Root $profileRoot
if ($profileAfter.Count -ne $profileBefore.Count) {
    throw 'Portable smoke created persistent state in APPDATA or LOCALAPPDATA.'
}
foreach ($entry in $profileAfter.GetEnumerator()) {
    if (-not $profileBefore.ContainsKey($entry.Key) -or $profileBefore[$entry.Key] -ne $entry.Value) {
        throw "Portable smoke changed isolated profile state '$($entry.Key)'."
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot 'data') -PathType Container)) {
    throw 'Portable data/ directory is missing after startup.'
}
if (Test-Path -LiteralPath (Join-Path $packageRoot 'data\data')) {
    throw 'Portable startup created forbidden nested data/data.'
}

$report = [ordered]@{
    schema = 'lovelyres-electron-portable-smoke/v1'
    status = 'PASS'
    packageRoot = $packageRoot
    marker = 'lovelyres-smoke-ready/v1'
    cdpUrl = $evaluation.href
    navItems = $evaluation.navItems
    sidecarProcessCount = $sidecarProcesses.Count
    processTreeExit = 'graceful'
    outboundNetworkIsolation = 'windows-firewall-block'
    persistentWrites = 'data-only'
}
$reportPath = Join-Path $controlRoot 'report.json'
[System.IO.File]::WriteAllText($reportPath, "$($report | ConvertTo-Json -Depth 4)`n", [System.Text.UTF8Encoding]::new($false))

Write-Host "Electron portable smoke passed in '$packageRoot'."
Write-Host "Marker, CDP renderer isolation/local resources, process topology, and data-only writes passed."
Write-Host "Evidence: '$reportPath'."
