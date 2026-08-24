[CmdletBinding()]
param(
    [string]$LedgerPath = '',
    [switch]$InventoryOnly,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$defaultLedgerPath = Join-Path $repoRoot 'docs\GPUI_TEST_MIGRATION_LEDGER.json'
if ([string]::IsNullOrWhiteSpace($LedgerPath)) {
    $LedgerPath = $defaultLedgerPath
}

# These constants bind the validator to the one frozen migration oracle. Rewriting the
# ledger IDs and their in-file digests together must not be enough to move the baseline.
$expectedCounts = [ordered]@{
    TypeScript = 214
    RustActive = 59
    RustIgnoredVm = 4
    Total = 277
}
$expectedInventorySha256 = [ordered]@{
    TypeScript = '5ff9a612b28c6424b8978fe11d89de0ce623bb138a11442dfd9784e6a0f86caa'
    RustActive = '16faeddbbfa0937fae90a0bcc7278e6b5dcc4151870ba74d4b348acc46295433'
    RustIgnoredVm = '2644e0447067687cfab71a0451e8fb32f3a67baf053a62d40a9058a0312358cf'
}
$expectedBaselineCommit = '11afc9af444cb14a6acfd46a0892c23849c594e4'
$expectedBaselineTag = 'migration-tauri-baseline-2026-08-11'

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Command 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) {
        throw "$Description failed:`n$($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { "$_" })
}

function Get-IdDigest {
    param([Parameter(Mandatory = $true)][string[]]$Ids)

    $ordered = [string[]]@($Ids)
    [System.Array]::Sort($ordered, [System.StringComparer]::Ordinal)
    $normalized = ($ordered -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function New-OrdinalSet {
    param([string[]]$Values = @())

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($value in @($Values)) {
        [void]$set.Add($value)
    }
    return ,$set
}

function Assert-ExactSet {
    param(
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string[]]$Actual,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $expectedSet = New-OrdinalSet -Values $Expected
    $actualSet = New-OrdinalSet -Values $Actual
    $missing = @($expectedSet | Where-Object { -not $actualSet.Contains($_) } | Sort-Object -CaseSensitive)
    $extra = @($actualSet | Where-Object { -not $expectedSet.Contains($_) } | Sort-Object -CaseSensitive)
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        throw "$Label differs from the frozen ledger. Missing=[$($missing -join '; ')] Extra=[$($extra -join '; ')]."
    }
}

function Get-FrozenInventory {
    param([Parameter(Mandatory = $true)]$Ledger)

    $typescript = [System.Collections.Generic.List[string]]::new()
    $rustActive = [System.Collections.Generic.List[string]]::new()
    $rustIgnored = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in @($Ledger.tests)) {
        $id = [string]$entry.id
        $suite = [string]$entry.suite
        $classification = [string]$entry.legacyClassification
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw 'Migration ledger contains an empty legacy test ID.'
        }

        switch ("$suite|$classification") {
            'TypeScript|Active' {
                if ($id -notmatch '^TS:[^#]+#.+$') {
                    throw "TypeScript legacy test has an invalid ID: '$id'."
                }
                $typescript.Add($id)
            }
            'Rust|Active' {
                if ($id -notmatch '^RS:[A-Za-z0-9_:]+#[A-Za-z0-9_]+$') {
                    throw "Active Rust legacy test has an invalid ID: '$id'."
                }
                $rustActive.Add($id)
            }
            'Rust|IgnoredVm' {
                if ($id -notmatch '^RS:[A-Za-z0-9_:]+#[A-Za-z0-9_]+$') {
                    throw "Ignored Rust legacy test has an invalid ID: '$id'."
                }
                $rustIgnored.Add($id)
            }
            default {
                throw "Legacy test '$id' has unsupported suite/classification '$suite/$classification'."
            }
        }
    }

    return [pscustomobject]@{
        TypeScript = [string[]]@($typescript | Sort-Object -CaseSensitive)
        RustActive = [string[]]@($rustActive | Sort-Object -CaseSensitive)
        RustIgnoredVm = [string[]]@($rustIgnored | Sort-Object -CaseSensitive)
    }
}

function Assert-FrozenInventory {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)]$Inventory
    )

    if ([int]$Ledger.schemaVersion -ne 1) {
        throw "Unsupported migration ledger schemaVersion '$($Ledger.schemaVersion)'."
    }

    $entries = @($Ledger.tests)
    $entryIds = [string[]]@($entries | ForEach-Object { [string]$_.id })
    if ((New-OrdinalSet -Values $entryIds).Count -ne $entryIds.Count) {
        throw 'Migration ledger contains duplicate legacy IDs.'
    }

    $allInventoryIds = [string[]]@($Inventory.TypeScript) +
        [string[]]@($Inventory.RustActive) +
        [string[]]@($Inventory.RustIgnoredVm)
    Assert-ExactSet -Expected $entryIds -Actual $allInventoryIds -Label 'ledger inventory partition'

    if ($Inventory.TypeScript.Count -ne $expectedCounts.TypeScript -or
        $Inventory.RustActive.Count -ne $expectedCounts.RustActive -or
        $Inventory.RustIgnoredVm.Count -ne $expectedCounts.RustIgnoredVm -or
        $entries.Count -ne $expectedCounts.Total) {
        throw "Frozen count mismatch: TS=$($Inventory.TypeScript.Count), Rust active=$($Inventory.RustActive.Count), Rust ignored=$($Inventory.RustIgnoredVm.Count), total=$($entries.Count)."
    }

    $metadataCounts = $Ledger.baseline.expectedCounts
    if ([int]$metadataCounts.typeScript -ne $expectedCounts.TypeScript -or
        [int]$metadataCounts.rustActive -ne $expectedCounts.RustActive -or
        [int]$metadataCounts.rustIgnoredVm -ne $expectedCounts.RustIgnoredVm -or
        [int]$metadataCounts.total -ne $expectedCounts.Total) {
        throw 'Ledger baseline expectedCounts do not match the frozen 214/59/4/277 contract.'
    }

    $calculatedDigests = [ordered]@{
        TypeScript = Get-IdDigest -Ids $Inventory.TypeScript
        RustActive = Get-IdDigest -Ids $Inventory.RustActive
        RustIgnoredVm = Get-IdDigest -Ids $Inventory.RustIgnoredVm
    }
    $metadataDigests = $Ledger.baseline.inventorySha256
    foreach ($name in @('TypeScript', 'RustActive', 'RustIgnoredVm')) {
        $metadataName = switch ($name) {
            'TypeScript' { 'typeScript' }
            'RustActive' { 'rustActive' }
            'RustIgnoredVm' { 'rustIgnoredVm' }
        }
        $metadataDigest = [string]$metadataDigests.$metadataName
        if ($calculatedDigests[$name] -ne $metadataDigest -or
            $calculatedDigests[$name] -ne $expectedInventorySha256[$name]) {
            throw "Frozen $name inventory SHA-256 mismatch: calculated=$($calculatedDigests[$name]), ledger=$metadataDigest, expected=$($expectedInventorySha256[$name])."
        }
    }

    if ([string]$Ledger.baseline.gitCommit -ne $expectedBaselineCommit -or
        [string]$Ledger.baseline.gitTag -ne $expectedBaselineTag) {
        throw "Ledger baseline moved from '$expectedBaselineTag' / '$expectedBaselineCommit'."
    }

    Assert-ExactSet -Expected @('Pending', 'Ported', 'Removed', 'Replaced') -Actual @($Ledger.policy.allowedDispositions | ForEach-Object { [string]$_ }) -Label 'allowed dispositions policy'
    Assert-ExactSet -Expected @('CaseWorkspace', 'WebTerminal') -Actual @($Ledger.policy.removedFeatureAllowlist | ForEach-Object { [string]$_ }) -Label 'removed feature allowlist'
    Assert-ExactSet -Expected @('evidence', 'replacementTestIds') -Actual @($Ledger.policy.completedMappingRequires | ForEach-Object { [string]$_ }) -Label 'completed mapping requirements'
    if ($Ledger.policy.pendingMayNotClaimEvidence -ne $true) {
        throw 'Ledger policy must forbid Pending entries from claiming evidence.'
    }
}

function Get-ReplacementInventory {
    param([Parameter(Mandatory = $true)]$Ledger)

    $ids = @(
        $Ledger.tests |
            ForEach-Object { @($_.replacementTestIds) } |
            ForEach-Object { [string]$_ } |
            Sort-Object -CaseSensitive -Unique
    )
    foreach ($id in $ids) {
        if ($id -notmatch '^NEW:(lovelyres-(?:core|terminal|gpui))#([A-Za-z_][A-Za-z0-9_]*)(?:::[A-Za-z_][A-Za-z0-9_]*)*::([A-Za-z_][A-Za-z0-9_]*)$') {
            throw "Replacement test ID has an invalid shape: '$id'."
        }
        $package = $Matches[1]
        $module = $Matches[2]
        $testName = $Matches[3]
        $sourcePath = Join-Path $repoRoot "crates\$package\src\$module.rs"
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Replacement test '$id' has no module source '$sourcePath'."
        }
        $source = Get-Content -Raw -Encoding UTF8 -LiteralPath $sourcePath
        $escapedName = [regex]::Escape($testName)
        $attributePattern = '(?ms)#\[(?:test|tokio::test(?:\([^\]]*\))?|gpui::test(?:\([^\]]*\))?)\](?:\s*#\[[^\]]+\])*\s*(?:async\s+)?fn\s+' + $escapedName + '\s*\('
        if ($source -notmatch $attributePattern) {
            throw "Replacement test '$id' is not declared with a test attribute in '$sourcePath'."
        }
    }
    return $ids
}

function Assert-LedgerMappings {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][string[]]$ReplacementIds
    )

    $entries = @($Ledger.tests)
    $replacementSet = New-OrdinalSet -Values $ReplacementIds
    $allowedDispositions = New-OrdinalSet -Values @($Ledger.policy.allowedDispositions | ForEach-Object { [string]$_ })
    $removedFeatures = New-OrdinalSet -Values @($Ledger.policy.removedFeatureAllowlist | ForEach-Object { [string]$_ })

    foreach ($entry in $entries) {
        $id = [string]$entry.id
        $disposition = [string]$entry.disposition
        $replacements = [string[]]@($entry.replacementTestIds | ForEach-Object { [string]$_ })
        $evidence = [string[]]@($entry.evidence | ForEach-Object { [string]$_ })
        $notes = [string]$entry.notes

        if (-not $allowedDispositions.Contains($disposition)) {
            throw "Legacy test '$id' has invalid disposition '$disposition'."
        }
        if ((New-OrdinalSet -Values $replacements).Count -ne $replacements.Count) {
            throw "Legacy test '$id' contains duplicate replacement test IDs."
        }

        if ($disposition -eq 'Pending') {
            if ($replacements.Count -ne 0 -or $evidence.Count -ne 0) {
                throw "Pending test '$id' must not claim replacement evidence."
            }
            if ([string]::IsNullOrWhiteSpace($notes)) {
                throw "Pending test '$id' must explain the unresolved behavior."
            }
            continue
        }

        if ($disposition -eq 'Removed') {
            if (-not $removedFeatures.Contains([string]$entry.featureArea)) {
                throw "Only allowlisted features may use Removed; '$id' is '$($entry.featureArea)'."
            }
            if ($replacements.Count -ne 0 -or $evidence.Count -ne 0 -or [string]::IsNullOrWhiteSpace($notes)) {
                throw "Removed test '$id' must have a reason and no replacement evidence."
            }
            continue
        }

        if ($replacements.Count -eq 0 -or $evidence.Count -eq 0) {
            throw "$disposition test '$id' requires replacementTestIds and evidence."
        }
        foreach ($replacement in $replacements) {
            if (-not $replacementSet.Contains($replacement)) {
                throw "Legacy test '$id' references missing replacement test '$replacement'."
            }
        }
        foreach ($path in $evidence) {
            $normalized = $path.Replace('\', '/')
            if ([System.IO.Path]::IsPathRooted($path) -or $normalized.Split('/').Contains('..')) {
                throw "Legacy test '$id' has unsafe evidence path '$path'."
            }
            if (-not ($normalized.StartsWith('crates/', [System.StringComparison]::Ordinal) -or
                $normalized.StartsWith('scripts/gpui-', [System.StringComparison]::Ordinal))) {
                throw "Legacy test '$id' evidence must be GPUI-owned and legacy-independent: '$path'."
            }
            if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $path) -PathType Leaf)) {
                throw "Legacy test '$id' references missing evidence '$path'."
            }
        }
    }
}

function Assert-LedgerModel {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)]$Inventory,
        [Parameter(Mandatory = $true)][string[]]$ReplacementIds
    )

    Assert-FrozenInventory -Ledger $Ledger -Inventory $Inventory
    Assert-LedgerMappings -Ledger $Ledger -Inventory $Inventory -ReplacementIds $ReplacementIds
}

function Assert-BaselineTag {
    param([Parameter(Mandatory = $true)]$Ledger)

    $tag = [string]$Ledger.baseline.gitTag
    $tagCommit = (Invoke-CapturedCommand -Description 'baseline tag lookup' -Command {
        & git -C $repoRoot rev-list -n 1 "refs/tags/$tag"
    } | Select-Object -First 1).Trim()
    if ($tagCommit -ne [string]$Ledger.baseline.gitCommit) {
        throw "Baseline tag '$tag' resolves to '$tagCommit', expected '$($Ledger.baseline.gitCommit)'."
    }
}

function Assert-SelfTestFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Command,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        & $Command
    }
    catch {
        return
    }
    throw "Ledger validator self-test '$Label' did not reject the invalid fixture."
}

$resolvedLedger = (Resolve-Path -LiteralPath $LedgerPath).Path
$ledger = Get-Content -Raw -Encoding UTF8 -LiteralPath $resolvedLedger | ConvertFrom-Json
$inventory = Get-FrozenInventory -Ledger $ledger
Assert-FrozenInventory -Ledger $ledger -Inventory $inventory

if ($InventoryOnly) {
    [ordered]@{
        typeScript = $inventory.TypeScript
        rustActive = $inventory.RustActive
        rustIgnoredVm = $inventory.RustIgnoredVm
        inventorySha256 = [ordered]@{
            typeScript = Get-IdDigest -Ids $inventory.TypeScript
            rustActive = Get-IdDigest -Ids $inventory.RustActive
            rustIgnoredVm = Get-IdDigest -Ids $inventory.RustIgnoredVm
        }
    } | ConvertTo-Json -Depth 6
    exit 0
}

$replacementIds = Get-ReplacementInventory -Ledger $ledger
Assert-LedgerMappings -Ledger $ledger -Inventory $inventory -ReplacementIds $replacementIds
Assert-BaselineTag -Ledger $ledger

if ($SelfTest) {
    $cloneJson = $ledger | ConvertTo-Json -Depth 20

    $duplicate = $cloneJson | ConvertFrom-Json
    $duplicate.tests[1].id = $duplicate.tests[0].id
    Assert-SelfTestFailure -Label 'duplicate ID' -Command {
        Assert-LedgerModel -Ledger $duplicate -Inventory $inventory -ReplacementIds $replacementIds
    }

    $wrongDigest = $cloneJson | ConvertFrom-Json
    $wrongDigest.baseline.inventorySha256.typeScript = '0000000000000000000000000000000000000000000000000000000000000000'
    Assert-SelfTestFailure -Label 'moved inventory digest' -Command {
        Assert-LedgerModel -Ledger $wrongDigest -Inventory $inventory -ReplacementIds $replacementIds
    }

    $movedTag = $cloneJson | ConvertFrom-Json
    $movedTag.baseline.gitTag = 'migration-tauri-baseline-moved'
    Assert-SelfTestFailure -Label 'moved baseline tag' -Command {
        Assert-LedgerModel -Ledger $movedTag -Inventory $inventory -ReplacementIds $replacementIds
    }

    $unexplainedRemoval = $cloneJson | ConvertFrom-Json
    $unexplainedRemoval.tests[0].disposition = 'Removed'
    $unexplainedRemoval.tests[0].featureArea = 'CoreSafety'
    $unexplainedRemoval.tests[0].replacementTestIds = @()
    $unexplainedRemoval.tests[0].evidence = @()
    Assert-SelfTestFailure -Label 'non-WebTerminal removal' -Command {
        Assert-LedgerModel -Ledger $unexplainedRemoval -Inventory $inventory -ReplacementIds $replacementIds
    }

    $ported = @($ledger.tests | Where-Object { $_.disposition -in @('Ported', 'Replaced') }) | Select-Object -First 1
    if ($null -eq $ported) {
        throw 'Ledger validator self-test requires at least one completed mapping.'
    }
    $missingReplacement = $cloneJson | ConvertFrom-Json
    $target = @($missingReplacement.tests | Where-Object { $_.id -eq $ported.id })[0]
    $target.replacementTestIds = @()
    Assert-SelfTestFailure -Label 'missing replacement evidence' -Command {
        Assert-LedgerModel -Ledger $missingReplacement -Inventory $inventory -ReplacementIds $replacementIds
    }

    Write-Host 'Migration ledger validator self-tests passed.'
}

$summary = $ledger.tests | Group-Object disposition | Sort-Object Name
$summaryText = ($summary | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
Write-Host "Migration ledger valid from frozen JSON: TS=$($inventory.TypeScript.Count), RustActive=$($inventory.RustActive.Count), RustIgnoredVm=$($inventory.RustIgnoredVm.Count); $summaryText."
