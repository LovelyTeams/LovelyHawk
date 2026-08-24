#requires -Version 7.2

[CmdletBinding()]
param(
    [string]$ScratchDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'target/gpui-feasibility-selftest')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$mergeScript = Join-Path $PSScriptRoot 'gpui-feasibility-merge.ps1'
$runDirectory = Join-Path ([System.IO.Path]::GetFullPath($ScratchDirectory)) ([guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)

foreach ($schemaPath in @(
    (Join-Path $PSScriptRoot 'gpui-feasibility-manual.schema.json'),
    (Join-Path $PSScriptRoot 'gpui-feasibility-result.schema.json'),
    (Join-Path $PSScriptRoot 'gpui-feasibility-summary.schema.json')
)) {
    Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json -Depth 100 | Out-Null
}
$collectorSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'gpui-feasibility-collect.ps1') -Raw
if ($collectorSource.Contains('$startParameters.WindowStyle = ''Hidden''', [System.StringComparison]::Ordinal)) {
    throw 'Unattended collection must present a real GPUI frame before accepting readiness.'
}
$manualFixture = [pscustomobject][ordered]@{
    schema = 'lovelyres-feasibility-manual/v1'
    scenario_id = 'fixture-manual'
    binary_sha256 = ('A' * 64)
    operator = 'selftest'
    recorded_at_utc = [DateTime]::UtcNow.ToString('o')
    checks = @([pscustomobject][ordered]@{ id = 'd3d11_gpu_driver'; status = 'PASS'; evidence = 'fixture' })
} | ConvertTo-Json -Depth 20
if (-not ($manualFixture | Test-Json -SchemaFile (Join-Path $PSScriptRoot 'gpui-feasibility-manual.schema.json') -ErrorAction Stop)) {
    throw 'Manual evidence fixture did not validate against its JSON Schema.'
}

$noticeFixtures = @(
    @{ Path = (Join-Path $repositoryRoot 'crates/lovelyres-terminal/THIRD_PARTY_NOTICES.md'); Required = @('gpui-terminal 0.1.0', 'alacritty_terminal 0.25.1') },
    @{ Path = (Join-Path $repositoryRoot 'crates/lovelyres-gpui/THIRD_PARTY_NOTICES.md'); Required = @('Inter 4.1', 'Cascadia Mono 2407.24', 'SIL OPEN FONT LICENSE Version 1.1') }
)
foreach ($fixture in $noticeFixtures) {
    $text = Get-Content -LiteralPath $fixture.Path -Raw
    foreach ($required in $fixture.Required) {
        if (-not $text.Contains($required, [System.StringComparison]::Ordinal)) {
            throw "Notice fixture '$($fixture.Path)' is missing '$required'."
        }
    }
}

$automaticIds = @('root_window', 'portable_store', 'page_registry', 'theme_registry', 'embedded_assets', 'font_assets', 'terminal_no_loss')
$manualIds = @('d3d11_gpu_driver', 'custom_titlebar', 'native_multi_window', 'chinese_ime', 'clipboard', 'file_dialog', 'folder_dialog', 'theme_switch', 'virtual_large_table', 'mixed_dpi', 'rdp', 'virtual_machine', 'integrated_gpu', 'offline_startup')
$harnessIds = @('smoke_marker', 'process_alive', 'portable_persistence', 'app_result', 'environment_match')
$baseManualIds = $manualIds[0..8]

function New-FixtureCheck {
    param([string]$Id, [string]$Category, [string]$Status, [bool]$Required, [string]$Source = 'selftest-fixture')
    return [pscustomobject][ordered]@{
        id = $Id
        category = $Category
        status = $Status
        evidence = "synthetic contract fixture for $Id"
        source = $Source
        required_for_scenario = $Required
    }
}

function New-FixtureResult {
    param([string]$ScenarioId, [string]$OperatingSystem, [int]$Dpi, [bool]$Special)
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $harnessIds) { $checks.Add((New-FixtureCheck -Id $id -Category 'harness' -Status 'PASS' -Required $true)) }
    foreach ($id in $automaticIds) { $checks.Add((New-FixtureCheck -Id $id -Category 'app-automatic' -Status 'PASS' -Required $true -Source 'app-result')) }
    $operatorChecks = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $manualIds) {
        $isBase = $id -in $baseManualIds
        $status = if ($isBase -or $Special) { 'PASS' } else { 'NOT_RUN' }
        $source = if ($status -eq 'NOT_RUN') { 'app-default' } else { 'operator:selftest' }
        $check = New-FixtureCheck -Id $id -Category 'manual' -Status $status -Required ($isBase -or $Special) -Source $source
        $checks.Add($check)
        if ($status -ne 'NOT_RUN') {
            $operatorChecks.Add([pscustomobject][ordered]@{ id = $id; status = $status; evidence = $check.evidence })
        }
    }
    $appChecks = @($automaticIds | ForEach-Object { [pscustomobject][ordered]@{ id = $_; status = 'PASS'; evidence = "synthetic contract fixture for $_" } })
    $appManual = @($manualIds | ForEach-Object { [pscustomobject][ordered]@{ id = $_; status = 'NOT_RUN'; evidence = 'fixture app default' } })
    return [pscustomobject][ordered]@{
        schema = 'lovelyres-feasibility-result/v1'
        fixture = $true
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        scenario = [pscustomobject][ordered]@{
            id = $ScenarioId
            expected = [pscustomobject][ordered]@{
                operating_system = $OperatingSystem
                dpi_percent = $Dpi
                mixed_dpi = $Special
                rdp = $Special
                virtual_machine = $Special
                integrated_gpu = $Special
                offline = $Special
            }
        }
        build = [pscustomobject][ordered]@{
            source_path = 'fixture/LovelyRes.exe'
            launch_path = 'fixture-run/LovelyRes.exe'
            sha256 = ('A' * 64)
            size_bytes = 1
            file_version = '1.0.0'
            pe_machine = 'x86_64'
        }
        environment = [pscustomobject][ordered]@{
            collected_at_utc = [DateTime]::UtcNow.ToString('o')
            os = [pscustomobject][ordered]@{ caption = if ($OperatingSystem -eq 'Windows10-22H2') { 'Microsoft Windows 10 Pro' } else { 'Microsoft Windows 11 Pro' }; version = 'fixture'; build_number = if ($OperatingSystem -eq 'Windows10-22H2') { 19045 } else { 22631 }; display_version = if ($OperatingSystem -eq 'Windows10-22H2') { '22H2' } else { '23H2' } }
            powershell = [pscustomobject][ordered]@{ version = $PSVersionTable.PSVersion.ToString(); architecture = 'X64' }
            session = [pscustomobject][ordered]@{ name = if ($Special) { 'RDP-fixture' } else { 'Console' }; client_name = $null; is_rdp = $Special }
            computer = [pscustomobject][ordered]@{ manufacturer = 'fixture'; model = 'fixture'; is_virtual_machine = $Special; evidence = 'fixture' }
            displays = @(
                [pscustomobject][ordered]@{ device_name = 'A'; primary = $true; left = 0; top = 0; width = 1920; height = 1080; dpi_percent = $Dpi },
                [pscustomobject][ordered]@{ device_name = 'B'; primary = $false; left = 1920; top = 0; width = 1920; height = 1080; dpi_percent = if ($Special) { 150 } else { $Dpi } }
            )
            gpus = @([pscustomobject][ordered]@{ name = 'fixture'; driver_version = 'fixture'; adapter_compatibility = 'fixture'; pnp_device_id = 'fixture'; classification = if ($Special) { 'integrated' } else { 'unknown' } })
            network = [pscustomobject][ordered]@{ is_offline = $Special; probes = @() }
            collection_errors = @()
        }
        artifacts = [pscustomobject][ordered]@{ run_directory = 'fixture'; smoke_marker = 'fixture'; app_result = 'fixture'; stdout_log = 'fixture'; stderr_log = 'fixture'; profile_root = 'fixture-profile' }
        app_diagnostics = [pscustomobject][ordered]@{
            schema = 'lovelyres-gpui-feasibility/v1'; status = 'READY'; generated_unix_ms = 1; app_version = '1.0.0'; gpui_version = '0.2.2'; operating_system = 'windows'; architecture = 'x86_64'; portable_data_root = 'fixture/data'
            automatic_checks = $appChecks
            terminal_stress = [pscustomobject][ordered]@{ requested_bytes = 16777216; processed_bytes = 16777216; elapsed_ms = 10; throughput_mib_per_second = 1600.0; no_loss = $true }
            manual_checks = $appManual
        }
        operator_evidence = [pscustomobject][ordered]@{
            schema = 'lovelyres-feasibility-manual/v1'
            scenario_id = $ScenarioId
            binary_sha256 = ('A' * 64)
            operator = 'selftest'
            recorded_at_utc = [DateTime]::UtcNow.ToString('o')
            checks = @($operatorChecks)
        }
        checks = @($checks)
        outcome = [pscustomobject][ordered]@{ status = 'PASS'; failed_checks = @(); required_not_run_checks = @(); optional_not_run_checks = @($checks | Where-Object { $_.status -eq 'NOT_RUN' } | ForEach-Object { $_.id }) }
    }
}

$paths = [System.Collections.Generic.List[string]]::new()
$index = 0
foreach ($operatingSystem in @('Windows10-22H2', 'Windows11')) {
    foreach ($dpi in @(100, 150, 200)) {
        $index++
        $path = Join-Path $runDirectory "scenario-$index.json"
        $fixture = New-FixtureResult -ScenarioId "fixture-$index" -OperatingSystem $operatingSystem -Dpi $dpi -Special ($index -eq 1)
        [System.IO.File]::WriteAllText($path, (($fixture | ConvertTo-Json -Depth 100) + "`n"), $utf8NoBom)
        $paths.Add($path)
    }
}

& $mergeScript -ResultPath @($paths) -SummaryJsonPath (Join-Path $runDirectory 'complete.json') -SummaryMarkdownPath (Join-Path $runDirectory 'complete.md') -AllowFixture
$complete = Get-Content -LiteralPath (Join-Path $runDirectory 'complete.json') -Raw | ConvertFrom-Json -Depth 100
if ($complete.acceptance.status -ne 'PASSED') { throw 'Complete fixture matrix did not pass.' }

try {
    & $mergeScript -ResultPath @($paths) -SummaryJsonPath (Join-Path $runDirectory 'fixture-rejected.json') -SummaryMarkdownPath (Join-Path $runDirectory 'fixture-rejected.md')
    throw 'Merge unexpectedly accepted fixture evidence without -AllowFixture.'
} catch {
    if ($_.Exception.Message -eq 'Merge unexpectedly accepted fixture evidence without -AllowFixture.' -or $_.Exception.Message -notmatch 'fixture evidence') { throw }
}

& $mergeScript -ResultPath $paths[0] -SummaryJsonPath (Join-Path $runDirectory 'incomplete.json') -SummaryMarkdownPath (Join-Path $runDirectory 'incomplete.md') -AllowFixture -ReportOnly
$incomplete = Get-Content -LiteralPath (Join-Path $runDirectory 'incomplete.json') -Raw | ConvertFrom-Json -Depth 100
if ($incomplete.acceptance.status -ne 'FAILED') { throw 'Incomplete fixture matrix unexpectedly passed.' }

$mismatchPath = Join-Path $runDirectory 'mismatched-observed-environment.json'
$mismatch = Get-Content -LiteralPath $paths[3] -Raw | ConvertFrom-Json -Depth 100
$mismatch.environment.os.caption = 'Microsoft Windows 10 Pro'
$mismatch.environment.os.build_number = 19045
$mismatch.environment.os.display_version = '22H2'
[System.IO.File]::WriteAllText($mismatchPath, (($mismatch | ConvertTo-Json -Depth 100) + "`n"), $utf8NoBom)
$mismatchPaths = [string[]]@($paths)
$mismatchPaths[3] = $mismatchPath
& $mergeScript -ResultPath $mismatchPaths -SummaryJsonPath (Join-Path $runDirectory 'mismatch.json') -SummaryMarkdownPath (Join-Path $runDirectory 'mismatch.md') -AllowFixture -ReportOnly
$mismatchSummary = Get-Content -LiteralPath (Join-Path $runDirectory 'mismatch.json') -Raw | ConvertFrom-Json -Depth 100
if ($mismatchSummary.acceptance.status -ne 'FAILED') { throw 'Expected/observed OS mismatch unexpectedly passed.' }
$win11At100 = @($mismatchSummary.matrix | Where-Object { $_.id -eq 'Windows11@100%' }) | Select-Object -First 1
if ($null -eq $win11At100 -or $win11At100.status -ne 'MISSING') { throw 'Expected/observed OS mismatch was still counted for the Win11@100 matrix cell.' }

function Assert-TamperedResultRejected {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$ExpectedErrorPattern
    )
    $path = Join-Path $runDirectory "$Name.json"
    [System.IO.File]::WriteAllText($path, (($Fixture | ConvertTo-Json -Depth 100) + "`n"), $utf8NoBom)
    $sentinel = "Merge unexpectedly accepted tampered fixture '$Name'."
    try {
        & $mergeScript -ResultPath $path -SummaryJsonPath (Join-Path $runDirectory "$Name-summary.json") -SummaryMarkdownPath (Join-Path $runDirectory "$Name-summary.md") -AllowFixture -ReportOnly
        throw $sentinel
    } catch {
        if ($_.Exception.Message -eq $sentinel -or $_.Exception.Message -notmatch $ExpectedErrorPattern) { throw }
    }
}

$missingOperator = Get-Content -LiteralPath $paths[0] -Raw | ConvertFrom-Json -Depth 100
$missingOperator.operator_evidence = $null
Assert-TamperedResultRejected -Name 'missing-operator' -Fixture $missingOperator -ExpectedErrorPattern 'no matching operator evidence'

$appPrefilledManual = Get-Content -LiteralPath $paths[0] -Raw | ConvertFrom-Json -Depth 100
$appPrefilledManual.app_diagnostics.manual_checks[0].status = 'PASS'
Assert-TamperedResultRejected -Name 'app-prefilled-manual' -Fixture $appPrefilledManual -ExpectedErrorPattern 'only operator evidence may set manual results'

$wrongOperatorBinary = Get-Content -LiteralPath $paths[0] -Raw | ConvertFrom-Json -Depth 100
$wrongOperatorBinary.operator_evidence.binary_sha256 = ('B' * 64)
Assert-TamperedResultRejected -Name 'wrong-operator-binary' -Fixture $wrongOperatorBinary -ExpectedErrorPattern 'operator evidence binary SHA-256 does not match'

Write-Host "GPUI feasibility harness self-test passed. Fixtures are retained at '$runDirectory'."
