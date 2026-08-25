[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml'),
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$LlvmObjdumpPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$workspaceRoot = Split-Path -Parent $manifest
$previousRustFlags = [Environment]::GetEnvironmentVariable('RUSTFLAGS', 'Process')
try {
    [Environment]::SetEnvironmentVariable('RUSTFLAGS', '-C target-feature=+crt-static', 'Process')
    & cargo build --release --locked --manifest-path $manifest --package lovelyres-electron-backend --bin lovelyres-backend --target $Target
    if ($LASTEXITCODE -ne 0) { throw "Release sidecar build failed with exit code $LASTEXITCODE." }
}
finally {
    [Environment]::SetEnvironmentVariable('RUSTFLAGS', $previousRustFlags, 'Process')
}

$binary = Join-Path $workspaceRoot "target\$Target\release\lovelyres-backend.exe"
$verifyArguments = @{
    BinaryPath = $binary
    Target = $Target
}
if (-not [string]::IsNullOrWhiteSpace($LlvmObjdumpPath)) {
    $verifyArguments.LlvmObjdumpPath = $LlvmObjdumpPath
}
& (Join-Path $PSScriptRoot 'electron-verify-windows-sidecar.ps1') @verifyArguments

Write-Host "Release sidecar is ready at '$binary'."
