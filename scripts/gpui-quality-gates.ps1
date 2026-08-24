[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml'),
    [string]$ExpectedVersion = '1.0.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$dependencyGate = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'gpui-dependency-gate.ps1')).Path
$testLedgerGate = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'gpui-test-migration-ledger.ps1')).Path
$sourceGate = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'gpui-source-gate.ps1')).Path

$rustVersion = (& rustc --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "rustc is unavailable: $rustVersion"
}
if ($rustVersion -notmatch '^rustc 1\.93\.1(?:\s|$)') {
    throw "LovelyRes GPUI releases require rustc 1.93.1; found '$rustVersion'."
}

$metadataText = (& cargo metadata --locked --no-deps --format-version 1 --manifest-path $manifest | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata version gate failed.' }
$metadata = $metadataText | ConvertFrom-Json
$gpuiPackage = @($metadata.packages | Where-Object { $_.name -eq 'lovelyres-gpui' })
if ($gpuiPackage.Count -ne 1 -or [string]$gpuiPackage[0].version -ne $ExpectedVersion) {
    $found = ($gpuiPackage | ForEach-Object { $_.version }) -join ', '
    throw "Expected lovelyres-gpui version '$ExpectedVersion'; found '$found'."
}

$env:CARGO_INCREMENTAL = '0'

Write-Host '==> frozen pre-native test baseline gate'
& $testLedgerGate

Write-Host '==> GPUI source/resource architecture gate'
& $sourceGate -ManifestPath $manifest

Write-Host '==> cargo fmt --all --check'
& cargo fmt --all --check --manifest-path $manifest
if ($LASTEXITCODE -ne 0) { throw 'cargo fmt gate failed.' }

Write-Host '==> cargo clippy --workspace --all-targets --locked -- -D warnings'
& cargo clippy --workspace --all-targets --locked --manifest-path $manifest -- -D warnings
if ($LASTEXITCODE -ne 0) { throw 'cargo clippy gate failed.' }

Write-Host '==> cargo test --workspace --all-targets --locked'
& cargo test --workspace --all-targets --locked --manifest-path $manifest
if ($LASTEXITCODE -ne 0) { throw 'cargo test gate failed.' }

Write-Host '==> cargo tree dependency gate'
& $dependencyGate -ManifestPath $manifest

Write-Host 'All GPUI quality gates passed.'
