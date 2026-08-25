[CmdletBinding()]
param(
    [string]$Version = '1.0.0',
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [string]$RuntimeDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'electron\node_modules\electron\dist'),
    [string]$MainBuildDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'electron\dist-electron'),
    [string]$RendererBuildDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'electron\dist-renderer'),
    [string]$SidecarPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target\x86_64-pc-windows-msvc\release\lovelyres-backend.exe'),
    [string]$LicensePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'LICENSE'),
    [string]$NoticesPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'electron\THIRD_PARTY_NOTICES.md')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Invalid release version '$Version'."
}

$workspaceRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'electron-source-gate.ps1') -RepositoryRoot $workspaceRoot -SelfTest
& (Join-Path $PSScriptRoot 'electron-source-gate.ps1') -RepositoryRoot $workspaceRoot
$runtime = (Resolve-Path -LiteralPath $RuntimeDirectory).Path
$mainBuild = (Resolve-Path -LiteralPath $MainBuildDirectory).Path
$rendererBuild = (Resolve-Path -LiteralPath $RendererBuildDirectory).Path
$sidecar = (Resolve-Path -LiteralPath $SidecarPath).Path
$license = (Resolve-Path -LiteralPath $LicensePath).Path
$notices = (Resolve-Path -LiteralPath $NoticesPath).Path
$noticesText = Get-Content -LiteralPath $notices -Raw
foreach ($requiredNotice in @('React 19.2.8', 'React DOM 19.2.8', 'Scheduler 0.27.0', 'MIT License', 'Inter 4.1', 'Cascadia Mono 2407.24')) {
    if (-not $noticesText.Contains($requiredNotice, [System.StringComparison]::Ordinal)) {
        throw "Third-party notices are missing '$requiredNotice'."
    }
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

function Assert-SafeGeneratedDirectory {
    param([string]$Parent, [string]$Candidate, [string]$LeafPattern)

    Assert-ChildPath -Root $Parent -Candidate $Candidate
    $item = Get-Item -LiteralPath $Candidate -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove reparse-point staging path '$Candidate'."
    }
    $resolvedParent = (Resolve-Path -LiteralPath $Parent).Path
    $resolvedCandidate = (Resolve-Path -LiteralPath $Candidate).Path
    Assert-ChildPath -Root $resolvedParent -Candidate $resolvedCandidate
    if ([System.IO.Path]::GetFileName($resolvedCandidate) -notlike $LeafPattern) {
        throw "Refusing to remove unexpected staging path '$resolvedCandidate'."
    }
}

function Convert-RuntimeRelativePath {
    param([string]$RelativePath)

    switch ($RelativePath.Replace('/', '\')) {
        'electron.exe' { return 'LovelyRes.exe' }
        'LICENSE' { return 'licenses\ELECTRON_LICENSE' }
        'LICENSES.chromium.html' { return 'licenses\LICENSES.chromium.html' }
        default { return $RelativePath.Replace('/', '\') }
    }
}

function Copy-ProductionTree {
    param([string]$Source, [string]$Destination)

    foreach ($file in Get-ChildItem -LiteralPath $Source -File -Force -Recurse) {
        $relative = [System.IO.Path]::GetRelativePath($Source, $file.FullName)
        $segments = $relative -split '[\\/]'
        if ($segments -contains 'node_modules' -or $segments -contains 'src' -or $file.Name -match '(?i)\.map$|\.tsx?$|\.(?:test|spec)\.[^.]+$') {
            continue
        }
        $target = Join-Path $Destination $relative
        [System.IO.Directory]::CreateDirectory((Split-Path -Parent $target)) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target
    }
}

$electronPackage = Get-Content -LiteralPath (Join-Path $workspaceRoot 'electron\package.json') -Raw | ConvertFrom-Json
$lockedElectronVersion = [string]$electronPackage.devDependencies.electron
$installedVersion = (Get-Content -LiteralPath (Join-Path $runtime 'version') -Raw).Trim()
if ($lockedElectronVersion -ne $installedVersion) {
    throw "Installed Electron runtime '$installedVersion' does not match the exact package version '$lockedElectronVersion'."
}
if (-not (Test-Path -LiteralPath (Join-Path $runtime 'electron.exe') -PathType Leaf)) {
    throw "Electron runtime is incomplete: '$runtime\electron.exe' is missing."
}
& (Join-Path $PSScriptRoot 'electron-verify-windows-sidecar.ps1') -BinaryPath $sidecar -Target 'x86_64-pc-windows-msvc'

$packageName = "LovelyRes-$Version-windows-x64"
$stageRoot = Join-Path $outputRoot ".electron-stage-$([guid]::NewGuid().ToString('N'))"
$packageRoot = Join-Path $stageRoot $packageName
$archivePath = Join-Path $outputRoot "$packageName.zip"
$checksumPath = "$archivePath.sha256"
Assert-ChildPath -Root $outputRoot -Candidate $stageRoot
Assert-ChildPath -Root $outputRoot -Candidate $archivePath
Assert-ChildPath -Root $outputRoot -Candidate $checksumPath

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
try {
    [System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $runtime -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $packageRoot -Recurse
    }

    Move-Item -LiteralPath (Join-Path $packageRoot 'electron.exe') -Destination (Join-Path $packageRoot 'LovelyRes.exe')
    [System.IO.Directory]::CreateDirectory((Join-Path $packageRoot 'licenses')) | Out-Null
    Move-Item -LiteralPath (Join-Path $packageRoot 'LICENSE') -Destination (Join-Path $packageRoot 'licenses\ELECTRON_LICENSE')
    Move-Item -LiteralPath (Join-Path $packageRoot 'LICENSES.chromium.html') -Destination (Join-Path $packageRoot 'licenses\LICENSES.chromium.html')
    Copy-Item -LiteralPath $license -Destination (Join-Path $packageRoot 'LICENSE')
    Copy-Item -LiteralPath $notices -Destination (Join-Path $packageRoot 'THIRD_PARTY_NOTICES.md')

    $runtimeFiles = @(
        Get-ChildItem -LiteralPath $runtime -File -Force -Recurse |
            ForEach-Object {
                $sourceRelative = [System.IO.Path]::GetRelativePath($runtime, $_.FullName)
                $packageRelative = Convert-RuntimeRelativePath -RelativePath $sourceRelative
                [ordered]@{
                    path = $packageRelative.Replace('\', '/')
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            } |
            Sort-Object { $_['path'] }
    )
    $runtimeInventory = [ordered]@{
        schema = 'lovelyres-electron-runtime/v1'
        electronVersion = $installedVersion
        platform = 'windows'
        arch = 'x64'
        files = $runtimeFiles
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $packageRoot 'RUNTIME_MANIFEST.json'),
        "$($runtimeInventory | ConvertTo-Json -Depth 6)`n",
        $utf8NoBom
    )

    $appRoot = Join-Path $packageRoot 'resources\app'
    [System.IO.Directory]::CreateDirectory($appRoot) | Out-Null
    Copy-ProductionTree -Source $mainBuild -Destination (Join-Path $appRoot 'dist-electron')
    Copy-ProductionTree -Source $rendererBuild -Destination (Join-Path $appRoot 'dist-renderer')
    $appPackage = [ordered]@{
        name = 'lovelyres'
        version = $Version
        private = $true
        main = 'dist-electron/main/index.js'
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $appRoot 'package.json'),
        "$($appPackage | ConvertTo-Json -Depth 4)`n",
        $utf8NoBom
    )

    [System.IO.Directory]::CreateDirectory((Join-Path $packageRoot 'resources\bin')) | Out-Null
    Copy-Item -LiteralPath $sidecar -Destination (Join-Path $packageRoot 'resources\bin\lovelyres-backend.exe')
    $packagedSidecar = Join-Path $packageRoot 'resources\bin\lovelyres-backend.exe'
    if ((Get-FileHash -LiteralPath $packagedSidecar -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $sidecar -Algorithm SHA256).Hash) {
        throw 'Packaged sidecar hash differs from the verified release sidecar.'
    }
    & (Join-Path $PSScriptRoot 'electron-verify-windows-sidecar.ps1') -BinaryPath $packagedSidecar -Target 'x86_64-pc-windows-msvc'
    [System.IO.Directory]::CreateDirectory((Join-Path $packageRoot 'data')) | Out-Null
    $dataReadme = @'
LovelyRes portable runtime data belongs in this directory.
Keep data/ beside LovelyRes.exe when moving or backing up the application.
Do not create a nested data/data directory.
'@
    [System.IO.File]::WriteAllText((Join-Path $packageRoot 'data\README.txt'), $dataReadme, $utf8NoBom)

    $manifestFiles = @(
        Get-ChildItem -LiteralPath $packageRoot -File -Force -Recurse |
            Where-Object { [System.IO.Path]::GetRelativePath($packageRoot, $_.FullName) -cne 'PACKAGE_MANIFEST.json' } |
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
        schema = 'lovelyres-electron-package/v1'
        product = 'LovelyRes'
        version = $Version
        platform = 'windows'
        arch = 'x64'
        electronVersion = $installedVersion
        hashAlgorithm = 'SHA-256'
        manifestExcludes = @('PACKAGE_MANIFEST.json')
        sidecarSha256 = (Get-FileHash -LiteralPath $packagedSidecar -Algorithm SHA256).Hash.ToLowerInvariant()
        sidecarStaticCrtVerified = $true
        files = $manifestFiles
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $packageRoot 'PACKAGE_MANIFEST.json'),
        "$($manifest | ConvertTo-Json -Depth 6)`n",
        $utf8NoBom
    )

    foreach ($target in @($archivePath, $checksumPath)) {
        if (Test-Path -LiteralPath $target) {
            Assert-ChildPath -Root $outputRoot -Candidate $target
            Remove-Item -LiteralPath $target -Force
        }
    }
    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $checksumPath,
        "$archiveHash  $([System.IO.Path]::GetFileName($archivePath))$([Environment]::NewLine)",
        $utf8NoBom
    )

    & (Join-Path $PSScriptRoot 'electron-validate-package.ps1') -ArchivePath $archivePath -Version $Version -WorkspaceRoot $workspaceRoot
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Assert-SafeGeneratedDirectory -Parent $outputRoot -Candidate $stageRoot -LeafPattern '.electron-stage-*'
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}

Write-Host "Created '$archivePath'."
Write-Host "Created '$checksumPath'."
