[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArchivePath,
    [string]$Version = '1.0.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyres-electron-validator-selftest-$([guid]::NewGuid().ToString('N'))"
$extractRoot = Join-Path $testRoot 'extracted'
$mutatedArchive = Join-Path $testRoot "LovelyRes-$Version-windows-x64.zip"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.Directory]::CreateDirectory($extractRoot) | Out-Null

function Update-PackageManifest {
    param([string]$PackageRoot)

    $manifestPath = Join-Path $PackageRoot 'PACKAGE_MANIFEST.json'
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $files = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Force -Recurse |
            Where-Object { [System.IO.Path]::GetRelativePath($PackageRoot, $_.FullName) -cne 'PACKAGE_MANIFEST.json' } |
            ForEach-Object {
                [ordered]@{
                    path = [System.IO.Path]::GetRelativePath($PackageRoot, $_.FullName).Replace('\', '/')
                    size = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            } |
            Sort-Object { $_['path'] }
    )
    $manifest.files = $files
    [System.IO.File]::WriteAllText($manifestPath, "$($manifest | ConvertTo-Json -Depth 6)`n", $utf8NoBom)
}

function Write-MutatedArchive {
    param([string]$PackageRoot)

    Update-PackageManifest -PackageRoot $PackageRoot
    if (Test-Path -LiteralPath $mutatedArchive) { Remove-Item -LiteralPath $mutatedArchive -Force }
    if (Test-Path -LiteralPath "$mutatedArchive.sha256") { Remove-Item -LiteralPath "$mutatedArchive.sha256" -Force }
    Compress-Archive -LiteralPath $PackageRoot -DestinationPath $mutatedArchive -CompressionLevel Optimal
    $digest = (Get-FileHash -LiteralPath $mutatedArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        "$mutatedArchive.sha256",
        "$digest  $([System.IO.Path]::GetFileName($mutatedArchive))$([Environment]::NewLine)",
        $utf8NoBom
    )
}

function Write-ArchiveChecksum {
    $digest = (Get-FileHash -LiteralPath $mutatedArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        "$mutatedArchive.sha256",
        "$digest  $([System.IO.Path]::GetFileName($mutatedArchive))$([Environment]::NewLine)",
        $utf8NoBom
    )
}

function Write-BoundedZipFixture {
    param([object[]]$Entries)

    if (Test-Path -LiteralPath $mutatedArchive) { Remove-Item -LiteralPath $mutatedArchive -Force }
    $fixtureZip = [System.IO.Compression.ZipFile]::Open($mutatedArchive, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $buffer = [byte[]]::new(1MB)
        foreach ($specification in $Entries) {
            $entry = $fixtureZip.CreateEntry([string]$specification.Name, $specification.Level)
            $stream = $entry.Open()
            try {
                $remaining = [long]$specification.Length
                while ($remaining -gt 0) {
                    $count = [int][Math]::Min($buffer.Length, $remaining)
                    $stream.Write($buffer, 0, $count)
                    $remaining -= $count
                }
            } finally { $stream.Dispose() }
        }
    } finally { $fixtureZip.Dispose() }
    Write-ArchiveChecksum
}

function Assert-ValidatorRejects {
    param([string]$ExpectedMessage)

    $rejected = $false
    try {
        & (Join-Path $PSScriptRoot 'electron-validate-package.ps1') -ArchivePath $mutatedArchive -Version $Version -WorkspaceRoot (Split-Path -Parent $PSScriptRoot) 6>$null
    }
    catch {
        if ($_.Exception.Message -notmatch $ExpectedMessage) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "Validator accepted mutation expected to match '$ExpectedMessage'." }
    Write-Host "Rejected mutation: $ExpectedMessage"
}

function Remove-SafeSelfTestDirectory {
    param([string]$Parent, [string]$Candidate)

    $item = Get-Item -LiteralPath $Candidate -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove reparse-point self-test child '$Candidate'."
    }
    $parentPrefix = (Resolve-Path -LiteralPath $Parent).Path.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $resolvedCandidate = (Resolve-Path -LiteralPath $Candidate).Path
    if (-not $resolvedCandidate.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove self-test child outside '$Parent': '$resolvedCandidate'."
    }
    Remove-Item -LiteralPath $resolvedCandidate -Recurse -Force
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
try {
    & (Join-Path $PSScriptRoot 'electron-validate-package.ps1') -ArchivePath $archive -Version $Version 6>$null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractRoot)
    $packageRoot = Join-Path $extractRoot "LovelyRes-$Version-windows-x64"
    $mainBundle = Join-Path $packageRoot 'resources\app\dist-electron\main\index.js'
    $indexHtml = Join-Path $packageRoot 'resources\app\dist-renderer\index.html'

    $requiredFile = Join-Path $packageRoot 'resources\app\dist-electron\preload\index.js'
    $savedRequiredFile = Join-Path $testRoot 'saved-preload.js'
    Move-Item -LiteralPath $requiredFile -Destination $savedRequiredFile
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'missing required file'
    [System.IO.Directory]::CreateDirectory((Split-Path -Parent $requiredFile)) | Out-Null
    Move-Item -LiteralPath $savedRequiredFile -Destination $requiredFile

    $originalBundle = [System.IO.File]::ReadAllBytes($mainBundle)
    [System.IO.File]::AppendAllText($mainBundle, "`n/* GPUI forbidden residue */`n", $utf8NoBom)
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'GPUI reference'
    [System.IO.File]::WriteAllBytes($mainBundle, $originalBundle)

    [System.IO.File]::AppendAllText($mainBundle, "`n/* $((Split-Path -Parent $PSScriptRoot).Replace('\', '/')) */`n", $utf8NoBom)
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'leaks workspace path'
    [System.IO.File]::WriteAllBytes($mainBundle, $originalBundle)

    $originalHtml = [System.IO.File]::ReadAllText($indexHtml)
    [System.IO.File]::WriteAllText(
        $indexHtml,
        $originalHtml.Replace('</body>', '<script src="https://invalid.example/remote.js"></script></body>'),
        $utf8NoBom
    )
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'remote resource'
    [System.IO.File]::WriteAllText($indexHtml, $originalHtml, $utf8NoBom)

    [System.IO.Directory]::CreateDirectory((Join-Path $packageRoot 'data\data')) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $packageRoot 'data\data\forbidden.txt'), 'forbidden', $utf8NoBom)
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'nested data/data'

    Remove-SafeSelfTestDirectory -Parent (Join-Path $packageRoot 'data') -Candidate (Join-Path $packageRoot 'data\data')
    $noticesPath = Join-Path $packageRoot 'THIRD_PARTY_NOTICES.md'
    $originalNotices = [System.IO.File]::ReadAllText($noticesPath)
    [System.IO.File]::WriteAllText($noticesPath, $originalNotices.Replace('React 19.2.8', 'React notice removed'), $utf8NoBom)
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'Third-party notices are missing'
    [System.IO.File]::WriteAllText($noticesPath, $originalNotices, $utf8NoBom)

    $extraRuntime = Join-Path $packageRoot 'locales\undeclared-test.pak'
    [System.IO.File]::WriteAllText($extraRuntime, 'undeclared runtime file', $utf8NoBom)
    Write-MutatedArchive -PackageRoot $packageRoot
    Assert-ValidatorRejects -ExpectedMessage 'undeclared Electron runtime file'
    Remove-Item -LiteralPath $extraRuntime -Force

    foreach ($unsafeName in @(
            '../escape.txt',
            "LovelyRes-$Version-windows-x64/ads.txt:stream",
            "LovelyRes-$Version-windows-x64/trailing-dot.",
            "LovelyRes-$Version-windows-x64/CON.extra.txt"
        )) {
        Copy-Item -LiteralPath $archive -Destination $mutatedArchive -Force
        $unsafeZip = [System.IO.Compression.ZipFile]::Open($mutatedArchive, [System.IO.Compression.ZipArchiveMode]::Update)
        try {
            $unsafeEntry = $unsafeZip.CreateEntry($unsafeName)
            $writer = [System.IO.StreamWriter]::new($unsafeEntry.Open(), $utf8NoBom)
            try { $writer.Write('unsafe') } finally { $writer.Dispose() }
        } finally { $unsafeZip.Dispose() }
        Write-ArchiveChecksum
        Assert-ValidatorRejects -ExpectedMessage 'unsafe path|Windows-unsafe path'
    }

    if (Test-Path -LiteralPath $mutatedArchive) { Remove-Item -LiteralPath $mutatedArchive -Force }
    $entryCountZip = [System.IO.Compression.ZipFile]::Open($mutatedArchive, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        for ($index = 0; $index -lt 4097; $index++) { [void]$entryCountZip.CreateEntry("entry-$index") }
    } finally { $entryCountZip.Dispose() }
    Write-ArchiveChecksum
    Assert-ValidatorRejects -ExpectedMessage 'entry count'

    Write-BoundedZipFixture -Entries @(
        [pscustomobject]@{ Name = ('a' * 513); Length = 0; Level = [System.IO.Compression.CompressionLevel]::NoCompression }
    )
    Assert-ValidatorRejects -ExpectedMessage 'safe length'

    Write-BoundedZipFixture -Entries @(
        [pscustomobject]@{ Name = 'oversized.bin'; Length = 321MB; Level = [System.IO.Compression.CompressionLevel]::Fastest }
    )
    Assert-ValidatorRejects -ExpectedMessage 'per-file expansion limit'

    Write-BoundedZipFixture -Entries @(
        [pscustomobject]@{ Name = 'expanded-1.bin'; Length = 200MB; Level = [System.IO.Compression.CompressionLevel]::Fastest },
        [pscustomobject]@{ Name = 'expanded-2.bin'; Length = 200MB; Level = [System.IO.Compression.CompressionLevel]::Fastest },
        [pscustomobject]@{ Name = 'expanded-3.bin'; Length = 200MB; Level = [System.IO.Compression.CompressionLevel]::Fastest },
        [pscustomobject]@{ Name = 'expanded-4.bin'; Length = 200MB; Level = [System.IO.Compression.CompressionLevel]::Fastest }
    )
    Assert-ValidatorRejects -ExpectedMessage 'expanded size exceeds'

    Write-BoundedZipFixture -Entries @(
        [pscustomobject]@{ Name = 'ratio.bin'; Length = 2MB; Level = [System.IO.Compression.CompressionLevel]::Optimal }
    )
    Assert-ValidatorRejects -ExpectedMessage 'compression ratio limit'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        $item = Get-Item -LiteralPath $testRoot -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to remove reparse-point self-test path '$testRoot'."
        }
        $tempPrefix = (Resolve-Path -LiteralPath ([System.IO.Path]::GetTempPath())).Path.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $resolvedTestRoot = (Resolve-Path -LiteralPath $testRoot).Path
        if (-not $resolvedTestRoot.StartsWith($tempPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
            [System.IO.Path]::GetFileName($resolvedTestRoot) -notlike 'lovelyres-electron-validator-selftest-*') {
            throw "Refusing to remove unexpected self-test path '$resolvedTestRoot'."
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

Write-Host 'Electron package validator rejection self-test passed (16/16).'
