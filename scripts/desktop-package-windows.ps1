[CmdletBinding()]
param(
    [string]$Version = '0.0.1-dev',
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [string]$ExecutablePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\x86_64-pc-windows-msvc\release\lovelyhawk.exe'),
    [string]$AgentPath,
    [string]$LicensePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'LICENSE'),
    [string]$NoticesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'ui\THIRD_PARTY_NOTICES.md'),
    [switch]$Build
)

# Portable Windows package: the desktop with its UI embedded, the remote
# Windows session agent, licenses,
# and a manifest. Runtime state is created beside the executable under data\
# on first launch; the package itself ships none. WebView2 Runtime comes from
# the system (present on Windows 11 and current Windows 10).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Invalid release version '$Version'."
}

$workspaceRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'desktop-source-gate.ps1') -RepositoryRoot $workspaceRoot -SelfTest
& (Join-Path $PSScriptRoot 'desktop-source-gate.ps1') -RepositoryRoot $workspaceRoot
if ($Build) {
    & (Join-Path $PSScriptRoot 'desktop-build-windows.ps1') -RepositoryRoot $workspaceRoot
}

$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
if ([string]::IsNullOrWhiteSpace($AgentPath)) { $AgentPath = Join-Path (Split-Path -Parent $executable) 'lovelyhawk-win-agent.exe' }
$agent = (Resolve-Path -LiteralPath $AgentPath).Path
$license = (Resolve-Path -LiteralPath $LicensePath).Path
$notices = (Resolve-Path -LiteralPath $NoticesPath).Path
& (Join-Path $PSScriptRoot 'desktop-verify-windows-binary.ps1') -BinaryPath $executable -Target 'x86_64-pc-windows-msvc' -AllowSystemUcrt
& (Join-Path $PSScriptRoot 'desktop-verify-windows-binary.ps1') -BinaryPath $agent -Target 'x86_64-pc-windows-msvc' -AllowSystemUcrt

$noticesText = Get-Content -LiteralPath $notices -Raw
foreach ($requiredNotice in @('React 19.2.8', 'React DOM 19.2.8', 'Scheduler 0.27.0', 'MIT License', 'Inter 4.1', 'Cascadia Mono 2407.24', 'Tauri 2.12.1', '@tauri-apps/api 2.12.1', 'xterm.js 6.0.0')) {
    if (-not $noticesText.Contains($requiredNotice, [System.StringComparison]::Ordinal)) {
        throw "Third-party notices are missing '$requiredNotice'."
    }
}

$tauriConfig = Get-Content -LiteralPath (Join-Path $workspaceRoot 'crates\lovelyhawk-desktop\tauri.conf.json') -Raw | ConvertFrom-Json
if ([string]$tauriConfig.version -cne $Version) {
    throw "Package version '$Version' does not match tauri.conf.json version '$($tauriConfig.version)'."
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $outputRoot).Path

function Assert-ChildPath {
    param([string]$Root, [string]$Candidate)

    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    if (-not $candidateFull.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing an operation outside '$Root': '$candidateFull'."
    }
}

$packageName = "LovelyHawk-$Version-windows-x64"
$stageRoot = Join-Path $outputRoot ".desktop-stage-$([guid]::NewGuid().ToString('N'))"
$packageRoot = Join-Path $stageRoot $packageName
$archivePath = Join-Path $outputRoot "$packageName.zip"
$checksumPath = "$archivePath.sha256"
foreach ($candidate in @($stageRoot, $archivePath, $checksumPath)) { Assert-ChildPath -Root $outputRoot -Candidate $candidate }
foreach ($existing in @($archivePath, $checksumPath)) {
    if (Test-Path -LiteralPath $existing) { throw "Refusing to overwrite existing release artifact '$existing'." }
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
try {
    [System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null
    Copy-Item -LiteralPath $executable -Destination (Join-Path $packageRoot 'LovelyHawk.exe')
    Copy-Item -LiteralPath $agent -Destination (Join-Path $packageRoot 'lovelyhawk-win-agent.exe')
    Copy-Item -LiteralPath $license -Destination (Join-Path $packageRoot 'LICENSE')
    Copy-Item -LiteralPath $notices -Destination (Join-Path $packageRoot 'THIRD_PARTY_NOTICES.md')
    # The Rust crates' own license texts and a bill of materials for everything inside.
    & node (Join-Path $PSScriptRoot 'desktop-third-party.mjs') --target 'x86_64-pc-windows-msvc' --out $packageRoot --version $Version
    if ($LASTEXITCODE -ne 0) { throw "Third-party inventory failed with exit code $LASTEXITCODE." }
    $readme = @(
        'LovelyHawk 便携版',
        '',
        '直接运行 LovelyHawk.exe，无需安装。',
        '首次启动会在本程序旁边创建 data 文件夹，连接库、历史、案件与证据都保存在其中；',
        '复制整个文件夹即可迁移。不会写入用户配置目录。',
        '',
        '运行需要系统自带的 Microsoft Edge WebView2 Runtime（Windows 11 与已更新的 Windows 10 默认具备）。',
        '同一个 data 文件夹同时只允许运行一份程序。',
        '',
        'Windows 应急响应：在主界面按三步接入向导操作。',
        'lovelyhawk-win-agent.exe 是远程会话采集端；也可使用向导中的免落地 PowerShell 方式。',
        '采集端应由操作员复制到已授权的远程桌面会话中启动，不会随主程序自动运行。'
    ) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $packageRoot 'README.txt'), "$readme`r`n", $utf8NoBom)

    $files = @(
        Get-ChildItem -LiteralPath $packageRoot -File -Force -Recurse |
            ForEach-Object {
                [ordered]@{
                    path = [System.IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace('\', '/')
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            } |
            Sort-Object { $_['path'] }
    )
    $manifest = [ordered]@{
        schema = 'lovelyhawk-portable-package/v1'
        product = 'LovelyHawk'
        version = $Version
        platform = 'windows'
        arch = 'x64'
        shell = 'tauri-2.12.1'
        webview = 'system WebView2 Runtime'
        files = $files
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $packageRoot 'PACKAGE_MANIFEST.json'),
        "$($manifest | ConvertTo-Json -Depth 6)`n",
        $utf8NoBom
    )

    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText($checksumPath, "$hash  $packageName.zip`n", $utf8NoBom)
} finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Assert-ChildPath -Root $outputRoot -Candidate $stageRoot
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}

& (Join-Path $PSScriptRoot 'desktop-validate-package.ps1') -ArchivePath $archivePath
Write-Host "Portable package written to '$archivePath'."
