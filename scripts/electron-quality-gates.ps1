[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$RequireComplete,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CheckedStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    Write-Host "[$Name]"
    $global:LASTEXITCODE = 0
    & $Action
    if (-not $?) {
        throw "Electron quality gate step '$Name' failed."
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Electron quality gate step '$Name' failed with exit code $LASTEXITCODE."
    }
}

function Assert-SelfTest {
    Invoke-CheckedStep -Name 'passing fixture' -Action { $true | Out-Null }
    $failed = $false
    try {
        Invoke-CheckedStep -Name 'failing fixture' -Action { & pwsh -NoProfile -Command 'exit 7' }
    } catch {
        $failed = $_.Exception.Message -match "failing fixture.*exit code 7"
    }
    if (-not $failed) {
        throw 'Electron quality gate self-test did not propagate a failing child command.'
    }
    Write-Host 'Electron quality gate failure-propagation self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
Push-Location $root
try {
    Invoke-CheckedStep -Name 'Rust format (Electron-owned crates)' -Action {
        & cargo fmt `
            --package lovelyres-core `
            --package lovelyres-electron-backend `
            --package lovelyres-terminal `
            -- `
            --check
    }
    Invoke-CheckedStep -Name 'lovelyres-core clippy' -Action {
        & cargo clippy --locked --package lovelyres-core --all-targets -- -D warnings
    }
    Invoke-CheckedStep -Name 'Electron sidecar clippy' -Action {
        & cargo clippy --locked --package lovelyres-electron-backend --all-targets -- -D warnings
    }
    Invoke-CheckedStep -Name 'Headless terminal clippy' -Action {
        & cargo clippy --locked --package lovelyres-terminal --no-default-features --all-targets -- -D warnings
    }
    Invoke-CheckedStep -Name 'lovelyres-core tests' -Action {
        & cargo test --locked --package lovelyres-core --all-targets
    }
    Invoke-CheckedStep -Name 'Electron sidecar tests' -Action {
        & cargo test --locked --package lovelyres-electron-backend --all-targets
    }
    Invoke-CheckedStep -Name 'Headless terminal tests' -Action {
        & cargo test --locked --package lovelyres-terminal --no-default-features --all-targets
    }
    Invoke-CheckedStep -Name 'Electron TypeScript, tests, and builds' -Action {
        & pnpm --filter '@lovelyres/electron' check
    }
    Invoke-CheckedStep -Name 'Electron source and security gate' -Action {
        & pwsh -NoProfile -File ./scripts/electron-source-gate.ps1
    }
    Invoke-CheckedStep -Name 'Electron dependency gate' -Action {
        & pwsh -NoProfile -File ./scripts/electron-dependency-gate.ps1 -RequireGpuiRetired:$RequireComplete
    }
    Invoke-CheckedStep -Name 'Electron UI migration ledger gate' -Action {
        & pwsh -NoProfile -File ./scripts/electron-ui-ledger-gate.ps1 -RequireComplete:$RequireComplete
    }

    if ($RequireComplete) {
        Invoke-CheckedStep -Name 'Final workspace format' -Action {
            & cargo fmt --all -- --check
        }
        Invoke-CheckedStep -Name 'Final workspace clippy' -Action {
            & cargo clippy --workspace --all-targets --locked -- -D warnings
        }
        Invoke-CheckedStep -Name 'Final workspace tests' -Action {
            & cargo test --workspace --all-targets --locked
        }
    }
} finally {
    Pop-Location
}

Write-Host "Electron quality gates passed (final completion required: $([bool]$RequireComplete))."
