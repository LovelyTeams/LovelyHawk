[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$Version = '1.0.0',
    [string]$WorkspaceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$workspace = if ([string]::IsNullOrWhiteSpace($WorkspaceRoot)) { $null } else { (Resolve-Path -LiteralPath $WorkspaceRoot).Path }
$maximumEntries = 4096
$maximumEntryBytes = 320MB
$maximumExpandedBytes = 768MB
$maximumCompressionRatio = 200
$maximumEntryNameLength = 512

function Assert-X64Pe {
    param([string]$Path, [string]$Label)

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 512) { throw "$Label is not a PE executable." }
        $reader = [System.IO.BinaryReader]::new($stream, [System.Text.Encoding]::UTF8, $true)
        try {
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw "$Label is not a PE executable." }
            $stream.Position = 0x3c
            $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 0 -or $peOffset + 6 -gt $stream.Length) { throw "$Label has an invalid PE header offset." }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
                throw "$Label is not an x86-64 PE/COFF executable."
            }
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
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
$checksumPath = "$archive.sha256"
if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
    throw "Missing archive checksum '$checksumPath'."
}
$checksumLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($checksumLine -notmatch '^(?<digest>[a-fA-F0-9]{64})\s{2}(?<name>[^\\/]+)$') {
    throw "Invalid SHA-256 checksum format in '$checksumPath'."
}
if ($Matches.name -ne [System.IO.Path]::GetFileName($archive)) {
    throw "Checksum names '$($Matches.name)', expected '$([System.IO.Path]::GetFileName($archive))'."
}
$archiveHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($archiveHash -ne $Matches.digest.ToLowerInvariant()) {
    throw "SHA-256 mismatch for '$archive'."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
$entryNames = [System.Collections.Generic.Dictionary[string, bool]]::new([System.StringComparer]::OrdinalIgnoreCase)
$expandedBytes = [long]0
$compressionRatioViolation = $null
try {
    if ($zip.Entries.Count -gt $maximumEntries) {
        throw "Archive entry count $($zip.Entries.Count) exceeds limit $maximumEntries."
    }
    foreach ($entry in $zip.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'Archive contains an empty entry name.' }
        if ($name.Length -gt $maximumEntryNameLength -or $name.IndexOf([char]0) -ge 0) {
            throw "Archive entry name exceeds the safe length or contains NUL: '$name'."
        }
        if ($name.StartsWith('/') -or $name -match '^[A-Za-z]:' -or $name.StartsWith('//')) {
            throw "Archive contains an unsafe path '$name'."
        }
        $isDirectory = $name.EndsWith('/')
        $trimmedName = $name.TrimEnd('/')
        $segments = @($trimmedName -split '/')
        $unsafeSegments = @($segments | Where-Object {
                $_.Length -eq 0 -or $_ -in @('.', '..') -or $_.Length -gt 255 -or
                $_.Contains(':') -or $_ -match '[\x00-\x1f<>"|?*]' -or $_ -match '[\. ]$' -or
                (($_ -split '\.', 2)[0] -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$')
            })
        if ($segments.Count -eq 0 -or $unsafeSegments.Count -gt 0) {
            throw "Archive contains a Windows-unsafe path '$name'."
        }
        $normalizedName = ($segments -join '/').Normalize([Text.NormalizationForm]::FormC)
        if ($entryNames.ContainsKey($normalizedName)) { throw "Archive contains a normalized duplicate path '$name'." }
        $entryNames.Add($normalizedName, $isDirectory)

        if (-not $isDirectory) {
            if ($entry.Length -lt 0 -or $entry.Length -gt $maximumEntryBytes) {
                throw "Archive entry '$name' exceeds the per-file expansion limit."
            }
            $expandedBytes += [long]$entry.Length
            if ($expandedBytes -gt $maximumExpandedBytes) {
                throw "Archive expanded size exceeds limit $maximumExpandedBytes."
            }
            if ($entry.Length -gt 0 -and $entry.CompressedLength -eq 0) {
                throw "Archive entry '$name' has an invalid zero compressed length."
            }
            if ($entry.CompressedLength -gt 0 -and ([double]$entry.Length / [double]$entry.CompressedLength) -gt $maximumCompressionRatio) {
                if ($null -eq $compressionRatioViolation) { $compressionRatioViolation = $name }
            }
        }
    }
    if ($null -ne $compressionRatioViolation) {
        throw "Archive entry '$compressionRatioViolation' exceeds compression ratio limit $maximumCompressionRatio."
    }
    foreach ($name in @($entryNames.Keys)) {
        $parts = @($name -split '/')
        for ($index = 1; $index -lt $parts.Count; $index++) {
            $parent = ($parts[0..($index - 1)] -join '/')
            if ($entryNames.ContainsKey($parent) -and -not $entryNames[$parent]) {
                throw "Archive path '$name' descends through file '$parent'."
            }
        }
    }
}
finally {
    $zip.Dispose()
}

$validationRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyres-electron-validate-$([guid]::NewGuid().ToString('N'))"
[System.IO.Directory]::CreateDirectory($validationRoot) | Out-Null
try {
    $validationPrefix = [System.IO.Path]::GetFullPath($validationRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    foreach ($name in @($entryNames.Keys)) {
        $destination = [System.IO.Path]::GetFullPath((Join-Path $validationRoot $name.Replace('/', '\')))
        if (-not $destination.StartsWith($validationPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Archive path resolves outside the validation root: '$name'."
        }
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $validationRoot)
    $roots = @(Get-ChildItem -LiteralPath $validationRoot -Force)
    $expectedRootName = "LovelyRes-$Version-windows-x64"
    if ($roots.Count -ne 1 -or -not $roots[0].PSIsContainer -or $roots[0].Name -ne $expectedRootName) {
        throw "Archive must contain exactly one '$expectedRootName' directory."
    }
    $packageRoot = $roots[0].FullName

    $requiredFiles = @(
        'LovelyRes.exe',
        'chrome_100_percent.pak',
        'chrome_200_percent.pak',
        'd3dcompiler_47.dll',
        'ffmpeg.dll',
        'icudtl.dat',
        'resources.pak',
        'snapshot_blob.bin',
        'v8_context_snapshot.bin',
        'version',
        'locales\en-US.pak',
        'resources\default_app.asar',
        'resources\app\package.json',
        'resources\app\dist-electron\main\index.js',
        'resources\app\dist-electron\preload\index.js',
        'resources\app\dist-electron\shared\contract.js',
        'resources\app\dist-renderer\index.html',
        'resources\bin\lovelyres-backend.exe',
        'licenses\ELECTRON_LICENSE',
        'licenses\LICENSES.chromium.html',
        'LICENSE',
        'THIRD_PARTY_NOTICES.md',
        'data\README.txt',
        'RUNTIME_MANIFEST.json',
        'PACKAGE_MANIFEST.json'
    )
    foreach ($relative in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $relative) -PathType Leaf)) {
            throw "Package is missing required file '$relative'."
        }
    }
    if (Test-Path -LiteralPath (Join-Path $packageRoot 'data\data')) {
        throw 'Package contains forbidden nested data/data.'
    }

    $appRoot = Join-Path $packageRoot 'resources\app'
    $forbiddenAppEntries = @(
        Get-ChildItem -LiteralPath $appRoot -Force -Recurse |
            Where-Object {
                $_.Name -in @('node_modules', 'src') -or
                $_.Name -match '(?i)\.map$|\.tsx?$|\.(?:test|spec)\.[^.]+$'
            }
    )
    if ($forbiddenAppEntries.Count -gt 0) {
        throw "Production resources/app contains source, test, source-map, or node_modules content: $($forbiddenAppEntries[0].FullName)"
    }
    $gpuiNamedEntry = Get-ChildItem -LiteralPath $packageRoot -Force -Recurse |
        Where-Object { $_.Name -match '(?i)gpui' } |
        Select-Object -First 1
    if ($null -ne $gpuiNamedEntry) {
        throw "Package contains a GPUI-named entry '$($gpuiNamedEntry.FullName)'."
    }

    $appPackage = Get-Content -LiteralPath (Join-Path $appRoot 'package.json') -Raw | ConvertFrom-Json
    if ($appPackage.main -ne 'dist-electron/main/index.js' -or $appPackage.version -ne $Version) {
        throw 'Production resources/app/package.json has an unexpected main entry or version.'
    }
    $electronVersion = (Get-Content -LiteralPath (Join-Path $packageRoot 'version') -Raw).Trim()
    $runtimeManifest = Get-Content -LiteralPath (Join-Path $packageRoot 'RUNTIME_MANIFEST.json') -Raw | ConvertFrom-Json
    if ($runtimeManifest.schema -ne 'lovelyres-electron-runtime/v1' -or
        $runtimeManifest.electronVersion -ne $electronVersion -or
        $runtimeManifest.platform -ne 'windows' -or $runtimeManifest.arch -ne 'x64') {
        throw 'RUNTIME_MANIFEST.json metadata is invalid.'
    }
    $declaredRuntime = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $packagePrefix = [System.IO.Path]::GetFullPath($packageRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    foreach ($entry in @($runtimeManifest.files)) {
        $relative = ([string]$entry.path).Replace('\', '/')
        $runtimeFile = [System.IO.Path]::GetFullPath((Join-Path $packageRoot $relative.Replace('/', '\')))
        if ([string]::IsNullOrWhiteSpace($relative) -or $relative.StartsWith('/') -or
            ($relative -split '/') -contains '..' -or $relative.Contains(':') -or
            -not $runtimeFile.StartsWith($packagePrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not $declaredRuntime.TryAdd($relative.Normalize([Text.NormalizationForm]::FormC), $entry)) {
            throw "Runtime manifest contains an empty or duplicate path '$relative'."
        }
        if (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf) -or
            (Get-Item -LiteralPath $runtimeFile).Length -ne [long]$entry.size -or
            (Get-FileHash -LiteralPath $runtimeFile -Algorithm SHA256).Hash.ToLowerInvariant() -cne ([string]$entry.sha256).ToLowerInvariant()) {
            throw "Packaged Electron runtime file '$relative' differs from RUNTIME_MANIFEST.json."
        }
    }
    foreach ($runtimeRequired in @('LovelyRes.exe', 'licenses/ELECTRON_LICENSE', 'licenses/LICENSES.chromium.html', 'resources/default_app.asar')) {
        if (-not $declaredRuntime.ContainsKey($runtimeRequired)) { throw "Runtime manifest omits '$runtimeRequired'." }
    }
    $packageFilesForRuntimeSet = @(Get-ChildItem -LiteralPath $packageRoot -File -Force -Recurse)
    foreach ($file in $packageFilesForRuntimeSet) {
        $relative = [System.IO.Path]::GetRelativePath($packageRoot, $file.FullName).Replace('\', '/')
        if ($declaredRuntime.ContainsKey($relative) -or $relative -in @(
                'LICENSE', 'THIRD_PARTY_NOTICES.md', 'RUNTIME_MANIFEST.json', 'PACKAGE_MANIFEST.json',
                'data/README.txt', 'resources/bin/lovelyres-backend.exe'
            ) -or $relative.StartsWith('resources/app/', [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }
        throw "Package contains an undeclared Electron runtime file '$relative'."
    }
    if ($null -ne $workspace) {
        $projectPackage = Get-Content -LiteralPath (Join-Path $workspace 'electron\package.json') -Raw | ConvertFrom-Json
        if ($electronVersion -ne [string]$projectPackage.devDependencies.electron) {
            throw "Packaged Electron '$electronVersion' does not match the exact project version '$($projectPackage.devDependencies.electron)'."
        }
        $installedRuntime = (Resolve-Path -LiteralPath (Join-Path $workspace 'electron\node_modules\electron\dist')).Path
        $installedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($runtimeFile in Get-ChildItem -LiteralPath $installedRuntime -File -Force -Recurse) {
            $runtimeRelative = [System.IO.Path]::GetRelativePath($installedRuntime, $runtimeFile.FullName)
            $packageRelative = (Convert-RuntimeRelativePath -RelativePath $runtimeRelative).Replace('\', '/')
            [void]$installedPaths.Add($packageRelative)
            if (-not $declaredRuntime.ContainsKey($packageRelative)) {
                throw "Runtime manifest omits installed Electron file '$runtimeRelative'."
            }
            $declared = $declaredRuntime[$packageRelative]
            if ($runtimeFile.Length -ne [long]$declared.size -or
                (Get-FileHash -LiteralPath $runtimeFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne ([string]$declared.sha256).ToLowerInvariant()) {
                throw "Runtime manifest file '$packageRelative' differs from the locked installed runtime."
            }
        }
        if ($installedPaths.Count -ne $declaredRuntime.Count) {
            throw 'Runtime manifest contains files absent from the locked installed runtime.'
        }
    }

    Assert-X64Pe -Path (Join-Path $packageRoot 'LovelyRes.exe') -Label 'Packaged Electron runtime'
    $sidecarPath = Join-Path $packageRoot 'resources\bin\lovelyres-backend.exe'
    Assert-X64Pe -Path $sidecarPath -Label 'Packaged sidecar'

    $manifestPath = Join-Path $packageRoot 'PACKAGE_MANIFEST.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -ne 'lovelyres-electron-package/v1' -or
        $manifest.version -ne $Version -or $manifest.platform -ne 'windows' -or
        $manifest.arch -ne 'x64' -or $manifest.electronVersion -ne $electronVersion -or
        $manifest.hashAlgorithm -ne 'SHA-256' -or $manifest.sidecarStaticCrtVerified -ne $true -or
        ([string]$manifest.sidecarSha256).ToLowerInvariant() -cne
        (Get-FileHash -LiteralPath $sidecarPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'PACKAGE_MANIFEST.json metadata is invalid.'
    }
    if (@($manifest.manifestExcludes).Count -ne 1 -or $manifest.manifestExcludes[0] -ne 'PACKAGE_MANIFEST.json') {
        throw 'PACKAGE_MANIFEST.json must explicitly exclude only itself.'
    }

    $actualFiles = @(
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
    $declaredFiles = @($manifest.files | Sort-Object path)
    if ($declaredFiles.Count -ne $actualFiles.Count) {
        throw "Manifest file count $($declaredFiles.Count) does not match package file count $($actualFiles.Count)."
    }
    for ($index = 0; $index -lt $actualFiles.Count; $index++) {
        $actual = $actualFiles[$index]
        $declared = $declaredFiles[$index]
        $actualPath = [string]$actual['path']
        $actualSize = [long]$actual['size']
        $actualHash = [string]$actual['sha256']
        if ([string]$declared.path -cne $actualPath -or [long]$declared.size -ne $actualSize -or
            ([string]$declared.sha256).ToLowerInvariant() -cne $actualHash) {
            throw "Manifest mismatch at index $index (declared '$($declared.path)', actual '$actualPath')."
        }
    }

    $scannableFiles = @(
        Get-ChildItem -LiteralPath $appRoot -File -Recurse |
            Where-Object { $_.Extension -match '(?i)^\.(js|json|html|css)$' }
    ) + @(
        Get-Item -LiteralPath (Join-Path $packageRoot 'LICENSE'), (Join-Path $packageRoot 'THIRD_PARTY_NOTICES.md'), (Join-Path $packageRoot 'data\README.txt')
    )
    $workspaceForms = if ($null -eq $workspace) { @() } else { @($workspace, $workspace.Replace('\', '/')) }
    foreach ($file in $scannableFiles) {
        $text = Get-Content -LiteralPath $file.FullName -Raw
        if ($text -match '(?i)gpui') {
            throw "Package contains a GPUI reference in '$($file.FullName)'."
        }
        foreach ($workspaceForm in $workspaceForms) {
            if ($text.IndexOf($workspaceForm, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw "Package leaks workspace path '$workspaceForm' in '$($file.FullName)'."
            }
        }
    }

    $noticesText = Get-Content -LiteralPath (Join-Path $packageRoot 'THIRD_PARTY_NOTICES.md') -Raw
    foreach ($requiredNotice in @('React 19.2.8', 'React DOM 19.2.8', 'Scheduler 0.27.0', 'MIT License', 'Inter 4.1', 'Cascadia Mono 2407.24')) {
        if (-not $noticesText.Contains($requiredNotice, [System.StringComparison]::Ordinal)) {
            throw "Third-party notices are missing '$requiredNotice'."
        }
    }

    $indexHtml = Get-Content -LiteralPath (Join-Path $appRoot 'dist-renderer\index.html') -Raw
    if ($indexHtml -match '(?is)(?:src|href)\s*=\s*["'']\s*(?:https?:)?//' -or
        $indexHtml -notmatch "default-src\s+'none'") {
        throw 'Renderer HTML contains a remote resource or lacks the strict default-src CSP.'
    }
    foreach ($file in Get-ChildItem -LiteralPath (Join-Path $appRoot 'dist-renderer') -File -Recurse) {
        if ($file.Extension -notmatch '(?i)^\.(js|css|html)$') { continue }
        $text = Get-Content -LiteralPath $file.FullName -Raw
        if ($text -match '(?is)url\(\s*["'']?(?:https?:)?//' -or
            $text -match '(?is)@import\s+(?:url\()?\s*["'']?(?:https?:)?//' -or
            $text -match '(?is)(?:fetch|import)\s*\(\s*["'']https?://' -or
            $text -match '(?is)new\s+(?:WebSocket|EventSource)\s*\(\s*["''](?:https?|wss?)://' -or
            $text -match '(?is)\.open\s*\(\s*["''](?:GET|POST|PUT|DELETE|PATCH)["'']\s*,\s*["'']https?://') {
            throw "Renderer contains a remote resource load in '$($file.FullName)'."
        }
    }
}
finally {
    if (Test-Path -LiteralPath $validationRoot) {
        $item = Get-Item -LiteralPath $validationRoot -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to remove reparse-point validation path '$validationRoot'."
        }
        $tempRoot = (Resolve-Path -LiteralPath ([System.IO.Path]::GetTempPath())).Path.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $resolvedValidationRoot = (Resolve-Path -LiteralPath $validationRoot).Path
        if (-not $resolvedValidationRoot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            [System.IO.Path]::GetFileName($resolvedValidationRoot) -notlike 'lovelyres-electron-validate-*') {
            throw "Refusing to remove unexpected validation path '$resolvedValidationRoot'."
        }
        Remove-Item -LiteralPath $resolvedValidationRoot -Recurse -Force
    }
}

Write-Host "Electron package validation passed for '$archive'."
