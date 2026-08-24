[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$NoticesPath,
    [Parameter(Mandatory = $true)]
    [string]$SbomPath,
    [string]$LicensePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'LICENSE'),
    [string]$Version = '1.0.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Invalid release version '$Version'."
}

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$license = (Resolve-Path -LiteralPath $LicensePath).Path
$notices = (Resolve-Path -LiteralPath $NoticesPath).Path
$sbom = (Resolve-Path -LiteralPath $SbomPath).Path
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

$packageName = "LovelyRes-$Version-windows-x64"
$stageRoot = Join-Path $outputRoot ".gpui-stage-$([guid]::NewGuid().ToString('N'))"
$packageRoot = Join-Path $stageRoot $packageName
$archivePath = Join-Path $outputRoot "$packageName.zip"
$checksumPath = "$archivePath.sha256"
Assert-ChildPath -Root $outputRoot -Candidate $stageRoot
Assert-ChildPath -Root $outputRoot -Candidate $archivePath
Assert-ChildPath -Root $outputRoot -Candidate $checksumPath

try {
    [System.IO.Directory]::CreateDirectory($packageRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory((Join-Path $packageRoot 'data')) | Out-Null

    Copy-Item -LiteralPath $binary -Destination (Join-Path $packageRoot 'LovelyRes.exe')
    Copy-Item -LiteralPath $license -Destination (Join-Path $packageRoot 'LICENSE')
    Copy-Item -LiteralPath $notices -Destination (Join-Path $packageRoot 'THIRD_PARTY_NOTICES.txt')
    Copy-Item -LiteralPath $sbom -Destination (Join-Path $packageRoot 'SBOM.cdx.json')

    $dataReadme = @'
LovelyRes portable runtime data belongs in this directory.
Keep this directory with the executable when moving or backing up the application.
'@
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $packageRoot 'data\README.txt'), $dataReadme, $utf8NoBom)

    Compress-Archive -LiteralPath $packageRoot -DestinationPath $archivePath -CompressionLevel Optimal -Force
    if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        throw "Portable archive was not created at '$archivePath'."
    }

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $checksumPath,
        "$hash  $([System.IO.Path]::GetFileName($archivePath))$([Environment]::NewLine)",
        $utf8NoBom
    )
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        Assert-ChildPath -Root $outputRoot -Candidate $stageRoot
        if ([System.IO.Path]::GetFileName($stageRoot) -notlike '.gpui-stage-*') {
            throw "Refusing to remove an unexpected staging path '$stageRoot'."
        }
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
}

Write-Host "Created '$archivePath'."
Write-Host "Created '$checksumPath'."
