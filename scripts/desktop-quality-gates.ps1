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
        throw "Desktop quality gate step '$Name' failed."
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Desktop quality gate step '$Name' failed with exit code $LASTEXITCODE."
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
        throw 'Desktop quality gate self-test did not propagate a failing child command.'
    }
    Write-Host 'Desktop quality gate failure-propagation self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
Push-Location $root
try {
    Invoke-CheckedStep -Name 'Rust format' -Action {
        & cargo fmt `
            --package lovelyhawk-core `
            --package lovelyhawk-backend `
            --package lovelyhawk-terminal `
            --package lovelyhawk-desktop `
            --package lovelyhawk-win-dvc `
            -- `
            --check
    }
    Invoke-CheckedStep -Name 'lovelyhawk-core clippy' -Action {
        & cargo clippy --locked --package lovelyhawk-core --all-targets -- -D warnings
    }
    Invoke-CheckedStep -Name 'lovelyhawk-win-dvc clippy' -Action {
        & cargo clippy --locked --package lovelyhawk-win-dvc --all-targets --no-deps -- -D warnings
    }
    Invoke-CheckedStep -Name 'Backend clippy' -Action {
        & cargo clippy --locked --package lovelyhawk-backend --all-targets --no-deps -- -D warnings
    }
    Invoke-CheckedStep -Name 'Headless terminal clippy' -Action {
        & cargo clippy --locked --package lovelyhawk-terminal --no-default-features --all-targets -- -D warnings
    }
    Invoke-CheckedStep -Name 'lovelyhawk-core tests' -Action {
        & cargo test --locked --package lovelyhawk-core --all-targets
    }
    Invoke-CheckedStep -Name 'lovelyhawk-win-dvc tests' -Action {
        & cargo test --locked --package lovelyhawk-win-dvc --all-targets
    }
    Invoke-CheckedStep -Name 'Backend tests' -Action {
        & cargo test --locked --package lovelyhawk-backend --all-targets
    }
    Invoke-CheckedStep -Name 'Headless terminal tests' -Action {
        & cargo test --locked --package lovelyhawk-terminal --no-default-features --all-targets
    }
    # The desktop crate embeds ui/dist, so the UI is built (and checked) first.
    Invoke-CheckedStep -Name 'UI TypeScript, tests, and build' -Action {
        & pnpm --filter '@lovelyhawk/ui' check
    }
    Invoke-CheckedStep -Name 'Desktop host clippy' -Action {
        & cargo clippy --locked --package lovelyhawk-desktop --all-targets --no-deps -- -D warnings
    }
    Invoke-CheckedStep -Name 'Desktop host tests' -Action {
        & cargo test --locked --package lovelyhawk-desktop --all-targets
    }
    Invoke-CheckedStep -Name 'Desktop source and security gate' -Action {
        & pwsh -NoProfile -File ./scripts/desktop-source-gate.ps1
    }
    Invoke-CheckedStep -Name 'Desktop dependency gate' -Action {
        & pwsh -NoProfile -File ./scripts/desktop-dependency-gate.ps1
    }
    Invoke-CheckedStep -Name 'Desktop UI ledger gate' -Action {
        & pwsh -NoProfile -File ./scripts/desktop-ui-ledger-gate.ps1 -RequireComplete:$RequireComplete
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

Write-Host "Desktop quality gates passed (final completion required: $([bool]$RequireComplete))."
