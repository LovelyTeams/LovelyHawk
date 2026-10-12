[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$LlvmObjdumpPath
)

# Builds the release desktop executable: the UI bundle first (it is embedded at
# compile time), then the Tauri host with a static CRT so the portable folder
# needs no Visual C++ redistributable.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
Push-Location $root
try {
    & pnpm --filter '@lovelyhawk/ui' build
    if ($LASTEXITCODE -ne 0) { throw "UI build failed with exit code $LASTEXITCODE." }
    # The bundle just built is what the executable embeds: it must load nothing remote.
    & (Join-Path $PSScriptRoot 'desktop-source-gate.ps1') -RepositoryRoot $root -BundleOnly

    $previousRustFlags = [Environment]::GetEnvironmentVariable('RUSTFLAGS', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('RUSTFLAGS', '-C target-feature=+crt-static', 'Process')
        & cargo build --release --locked --package lovelyhawk-desktop --bin lovelyhawk --target $Target
        if ($LASTEXITCODE -ne 0) { throw "Release desktop build failed with exit code $LASTEXITCODE." }
    } finally {
        [Environment]::SetEnvironmentVariable('RUSTFLAGS', $previousRustFlags, 'Process')
    }
} finally {
    Pop-Location
}

$binary = Join-Path $root "target\$Target\release\lovelyhawk.exe"
$verifyArguments = @{ BinaryPath = $binary; Target = $Target; AllowSystemUcrt = $true }
if (-not [string]::IsNullOrWhiteSpace($LlvmObjdumpPath)) { $verifyArguments.LlvmObjdumpPath = $LlvmObjdumpPath }
& (Join-Path $PSScriptRoot 'desktop-verify-windows-binary.ps1') @verifyArguments

Write-Host "Release desktop executable is ready at '$binary'."
