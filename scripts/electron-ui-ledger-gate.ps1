[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$LedgerPath,
    [switch]$RequireComplete,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredEntryFields = @(
    'id',
    'owner',
    'source',
    'replacement',
    'status',
    'acceptance',
    'tests'
)
$allowedStatuses = @('Completed', 'Pending')
$allowedReplacementStates = @('implemented', 'planned', 'mixed')
$defaultSectionCounts = [ordered]@{
    foundations = 2
    protectedWorktree = 1
    pages = 15
    connections = 6
    windows = 4
    overlays = 6
    assets = 4
    gates = 9
    finalAcceptance = 6
}

function Test-HasProperty {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Name
    )

    return $null -ne $Value.PSObject.Properties[$Name]
}

function Test-NonEmptyStringArray {
    param($Value)

    $items = @($Value)
    return $items.Count -gt 0 -and @($items | Where-Object {
        $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)
    }).Count -eq 0
}

function Get-LedgerViolations {
    param(
        [Parameter(Mandatory = $true)]$Ledger,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedSectionCounts,
        [switch]$StrictCompletion
    )

    $violations = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-HasProperty -Value $Ledger -Name 'schemaVersion') -or $Ledger.schemaVersion -ne 1) {
        $violations.Add('schemaVersion must be exactly 1')
    }
    foreach ($name in @('snapshot', 'entryContract', 'verificationRuns')) {
        if (-not (Test-HasProperty -Value $Ledger -Name $name)) {
            $violations.Add("missing top-level '$name'")
        }
    }

    $runsById = @{}
    if (Test-HasProperty -Value $Ledger -Name 'verificationRuns') {
        foreach ($run in @($Ledger.verificationRuns)) {
            if (-not (Test-HasProperty -Value $run -Name 'id') -or
                $run.id -isnot [string] -or
                [string]::IsNullOrWhiteSpace($run.id)) {
                $violations.Add('verification run has no non-empty id')
                continue
            }
            if ($runsById.ContainsKey($run.id)) {
                $violations.Add("duplicate verification run id '$($run.id)'")
                continue
            }
            if (-not (Test-HasProperty -Value $run -Name 'command') -or
                $run.command -isnot [string] -or
                [string]::IsNullOrWhiteSpace($run.command)) {
                $violations.Add("verification run '$($run.id)' has no command")
            }
            if (-not (Test-HasProperty -Value $run -Name 'result') -or
                $run.result -isnot [string] -or
                [string]::IsNullOrWhiteSpace($run.result)) {
                $violations.Add("verification run '$($run.id)' has no result")
            }
            $runsById[$run.id] = $run
        }
    }

    $entryIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($section in $ExpectedSectionCounts.GetEnumerator()) {
        if (-not (Test-HasProperty -Value $Ledger -Name $section.Key)) {
            $violations.Add("missing ledger section '$($section.Key)'")
            continue
        }
        $entries = @($Ledger.($section.Key))
        if ($entries.Count -ne [int]$section.Value) {
            $violations.Add("section '$($section.Key)' must contain exactly $($section.Value) entries; found $($entries.Count)")
        }

        for ($index = 0; $index -lt $entries.Count; $index++) {
            $entry = $entries[$index]
            $location = "$($section.Key)[$index]"
            foreach ($field in $requiredEntryFields) {
                if (-not (Test-HasProperty -Value $entry -Name $field)) {
                    $violations.Add("$location is missing '$field'")
                }
            }
            if (-not (Test-HasProperty -Value $entry -Name 'id') -or
                $entry.id -isnot [string] -or
                [string]::IsNullOrWhiteSpace($entry.id)) {
                $violations.Add("$location has no non-empty id")
                continue
            }
            $location = "$($section.Key)/$($entry.id)"
            if (-not $entryIds.Add($entry.id)) {
                $violations.Add("duplicate ledger entry id '$($entry.id)'")
            }
            if (-not (Test-HasProperty -Value $entry -Name 'status') -or
                $entry.status -notin $allowedStatuses) {
                $violations.Add("$location has unsupported status '$($entry.status)'")
            }
            if ($StrictCompletion -and $entry.status -ne 'Completed') {
                $violations.Add("$location remains $($entry.status)")
            }
            foreach ($field in @('owner', 'source', 'acceptance')) {
                if (-not (Test-HasProperty -Value $entry -Name $field) -or
                    -not (Test-NonEmptyStringArray -Value $entry.$field)) {
                    $violations.Add("$location must have a non-empty string array '$field'")
                }
            }

            if (-not (Test-HasProperty -Value $entry -Name 'replacement') -or
                $null -eq $entry.replacement) {
                $violations.Add("$location has no replacement contract")
            } else {
                if (-not (Test-HasProperty -Value $entry.replacement -Name 'state') -or
                    $entry.replacement.state -notin $allowedReplacementStates) {
                    $violations.Add("$location has unsupported replacement state '$($entry.replacement.state)'")
                }
                if (-not (Test-HasProperty -Value $entry.replacement -Name 'targets') -or
                    -not (Test-NonEmptyStringArray -Value $entry.replacement.targets)) {
                    $violations.Add("$location must list replacement targets")
                }
                if ($entry.status -eq 'Completed' -and $entry.replacement.state -ne 'implemented') {
                    $violations.Add("$location is Completed but replacement.state is '$($entry.replacement.state)'")
                }
            }

            if (-not (Test-HasProperty -Value $entry -Name 'tests') -or $null -eq $entry.tests) {
                $violations.Add("$location has no tests contract")
                continue
            }
            if (-not (Test-HasProperty -Value $entry.tests -Name 'required') -or
                -not (Test-NonEmptyStringArray -Value $entry.tests.required)) {
                $violations.Add("$location must list required tests")
            }
            if (-not (Test-HasProperty -Value $entry.tests -Name 'evidence')) {
                $violations.Add("$location is missing tests.evidence")
                continue
            }
            $evidence = @($entry.tests.evidence)
            if (@($evidence | Where-Object {
                $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_)
            }).Count -ne 0) {
                $violations.Add("$location has an empty or non-string evidence id")
            }
            if ($entry.status -eq 'Completed' -and $evidence.Count -eq 0) {
                $violations.Add("$location is Completed without passing evidence")
            }
            foreach ($evidenceId in $evidence) {
                if ($evidenceId -isnot [string]) { continue }
                if (-not $runsById.ContainsKey($evidenceId)) {
                    $violations.Add("$location references unknown evidence '$evidenceId'")
                    continue
                }
                if ($entry.status -eq 'Completed' -and $runsById[$evidenceId].result -cne 'Passed') {
                    $violations.Add("$location cites non-passing evidence '$evidenceId' ($($runsById[$evidenceId].result))")
                }
            }
        }
    }

    return $violations
}

function New-SelfTestFixture {
    param(
        [string]$Status = 'Completed',
        [string]$ReplacementState = 'implemented',
        [string]$RunResult = 'Passed'
    )

    return [pscustomobject]@{
        schemaVersion = 1
        snapshot = [pscustomobject]@{ truthRule = 'fixture' }
        entryContract = [pscustomobject]@{ statusValues = @('Completed', 'Pending') }
        verificationRuns = @([pscustomobject]@{
            id = 'fixture-run'
            command = 'fixture command'
            result = $RunResult
        })
        pages = @([pscustomobject]@{
            id = 'fixture-page'
            owner = @('qa')
            source = @('legacy')
            replacement = [pscustomobject]@{
                state = $ReplacementState
                targets = @('electron')
            }
            status = $Status
            acceptance = @('fixture acceptance')
            tests = [pscustomobject]@{
                required = @('fixture command')
                evidence = @('fixture-run')
            }
        })
    }
}

function Assert-SelfTest {
    $counts = [ordered]@{ pages = 1 }
    $good = New-SelfTestFixture
    if (@(Get-LedgerViolations -Ledger $good -ExpectedSectionCounts $counts -StrictCompletion).Count -ne 0) {
        throw 'Electron UI ledger gate self-test rejected a complete passing fixture.'
    }
    $failedEvidence = New-SelfTestFixture -RunResult 'Failed'
    if (@(Get-LedgerViolations -Ledger $failedEvidence -ExpectedSectionCounts $counts).Count -eq 0) {
        throw 'Electron UI ledger gate self-test accepted failed evidence for a Completed entry.'
    }
    $pending = New-SelfTestFixture -Status 'Pending' -ReplacementState 'mixed'
    if (@(Get-LedgerViolations -Ledger $pending -ExpectedSectionCounts $counts).Count -ne 0) {
        throw 'Electron UI ledger gate self-test rejected an honest Pending fixture.'
    }
    if (@(Get-LedgerViolations -Ledger $pending -ExpectedSectionCounts $counts -StrictCompletion).Count -eq 0) {
        throw 'Electron UI ledger gate self-test accepted Pending in strict completion mode.'
    }
    Write-Host 'Electron UI ledger gate fixture self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if ([string]::IsNullOrWhiteSpace($LedgerPath)) {
    $LedgerPath = Join-Path $root 'docs/ELECTRON_UI_LEDGER.json'
}
$resolvedLedger = (Resolve-Path -LiteralPath $LedgerPath).Path
$ledger = Get-Content -LiteralPath $resolvedLedger -Raw | ConvertFrom-Json -Depth 100
$violations = @(Get-LedgerViolations `
    -Ledger $ledger `
    -ExpectedSectionCounts $defaultSectionCounts `
    -StrictCompletion:$RequireComplete)
if ($violations.Count -gt 0) {
    throw "Electron UI ledger gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}

$entryCount = 0
$completedCount = 0
foreach ($section in $defaultSectionCounts.Keys) {
    $entries = @($ledger.$section)
    $entryCount += $entries.Count
    $completedCount += @($entries | Where-Object { $_.status -eq 'Completed' }).Count
}
Write-Host "Electron UI ledger gate passed ($completedCount/$entryCount Completed; strict completion: $([bool]$RequireComplete))."
