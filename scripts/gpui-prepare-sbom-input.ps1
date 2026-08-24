[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml'),
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$workspaceRoot = Split-Path -Parent $manifest
$lockfile = (Resolve-Path -LiteralPath (Join-Path $workspaceRoot 'Cargo.lock')).Path
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
if ($outputRoot -eq [System.IO.Path]::GetFullPath($workspaceRoot)) {
    throw 'SBOM input must not be the workspace root.'
}
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null

Copy-Item -LiteralPath $manifest -Destination (Join-Path $outputRoot 'Cargo.toml') -Force
Copy-Item -LiteralPath $lockfile -Destination (Join-Path $outputRoot 'Cargo.lock') -Force

$cratesRoot = Join-Path $workspaceRoot 'crates'
foreach ($crateManifest in Get-ChildItem -LiteralPath $cratesRoot -Filter Cargo.toml -File -Recurse) {
    $relative = [System.IO.Path]::GetRelativePath($workspaceRoot, $crateManifest.FullName)
    $destination = Join-Path $outputRoot $relative
    [System.IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
    Copy-Item -LiteralPath $crateManifest.FullName -Destination $destination -Force
}

Write-Host "Prepared a GPUI-only Cargo SBOM input at '$outputRoot'."

