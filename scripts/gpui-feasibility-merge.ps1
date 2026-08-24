#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ResultPath,
    [Parameter(Mandatory = $true)]
    [string]$SummaryJsonPath,
    [Parameter(Mandatory = $true)]
    [string]$SummaryMarkdownPath,
    [switch]$AllowFixture,
    [switch]$ReportOnly,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$baseCheckIds = @(
    'smoke_marker',
    'process_alive',
    'portable_persistence',
    'app_result',
    'environment_match',
    'root_window',
    'portable_store',
    'page_registry',
    'theme_registry',
    'embedded_assets',
    'font_assets',
    'terminal_no_loss',
    'd3d11_gpu_driver',
    'custom_titlebar',
    'native_multi_window',
    'chinese_ime',
    'clipboard',
    'file_dialog',
    'folder_dialog',
    'theme_switch',
    'virtual_large_table'
)
$automaticCheckIds = @('root_window', 'portable_store', 'page_registry', 'theme_registry', 'embedded_assets', 'font_assets', 'terminal_no_loss')
$manualCheckIds = @('d3d11_gpu_driver', 'custom_titlebar', 'native_multi_window', 'chinese_ime', 'clipboard', 'file_dialog', 'folder_dialog', 'theme_switch', 'virtual_large_table', 'mixed_dpi', 'rdp', 'virtual_machine', 'integrated_gpu', 'offline_startup')
$commonManualCheckIds = $manualCheckIds[0..8]

function Assert-Property {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
        throw "$Context is missing required property '$Name'."
    }
}

function Get-CheckMap {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Context
    )

    Assert-Property -Object $Result -Name 'checks' -Context $Context
    $map = [ordered]@{}
    foreach ($check in @($Result.checks)) {
        foreach ($property in @('id', 'status', 'evidence', 'category', 'source', 'required_for_scenario')) {
            Assert-Property -Object $check -Name $property -Context "$Context check"
        }
        $id = [string]$check.id
        if ([string]::IsNullOrWhiteSpace($id)) {
            throw "$Context contains a check with an empty id."
        }
        if ($map.Contains($id)) {
            throw "$Context contains duplicate check id '$id'."
        }
        if ([string]$check.status -notin @('PASS', 'FAIL', 'NOT_RUN')) {
            throw "$Context check '$id' has invalid status '$($check.status)'."
        }
        $map[$id] = $check
    }
    return $map
}

function Get-EmbeddedCheckMap {
    param(
        [Parameter(Mandatory = $true)]$Items,
        [Parameter(Mandatory = $true)][string[]]$ExpectedIds,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $map = [ordered]@{}
    foreach ($check in @($Items)) {
        foreach ($property in @('id', 'status', 'evidence')) {
            Assert-Property -Object $check -Name $property -Context "$Context check"
        }
        $id = [string]$check.id
        if ($id -notin $ExpectedIds) { throw "$Context contains unexpected check id '$id'." }
        if ($map.Contains($id)) { throw "$Context contains duplicate check id '$id'." }
        $map[$id] = $check
    }
    foreach ($id in $ExpectedIds) {
        if (-not $map.Contains($id)) { throw "$Context is missing check '$id'." }
    }
    return $map
}

function Assert-EvidenceConsistency {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Checks,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $automatic = Get-EmbeddedCheckMap -Items $Result.app_diagnostics.automatic_checks -ExpectedIds $automaticCheckIds -Context "$Context automatic_checks"
    foreach ($id in $automaticCheckIds) {
        if (-not $Checks.Contains($id)) { throw "$Context flattened checks are missing '$id'." }
        $flattened = $Checks[$id]
        $embedded = $automatic[$id]
        if ([string]$flattened.category -ne 'app-automatic' -or
            [string]$flattened.source -ne 'app-result' -or
            -not [bool]$flattened.required_for_scenario -or
            [string]$flattened.status -ne [string]$embedded.status -or
            [string]$flattened.evidence -ne [string]$embedded.evidence) {
            throw "$Context flattened automatic check '$id' does not match app diagnostics."
        }
    }

    $appManual = Get-EmbeddedCheckMap -Items $Result.app_diagnostics.manual_checks -ExpectedIds $manualCheckIds -Context "$Context app manual_checks"
    foreach ($id in $manualCheckIds) {
        if ([string]$appManual[$id].status -ne 'NOT_RUN') {
            throw "$Context app manual check '$id' is not NOT_RUN; only operator evidence may set manual results."
        }
    }

    $operator = [ordered]@{}
    if ($null -ne $Result.operator_evidence) {
        if ([string]$Result.operator_evidence.scenario_id -ne [string]$Result.scenario.id) {
            throw "$Context operator evidence scenario id does not match the collected scenario."
        }
        if (([string]$Result.operator_evidence.binary_sha256).ToUpperInvariant() -ne ([string]$Result.build.sha256).ToUpperInvariant()) {
            throw "$Context operator evidence binary SHA-256 does not match the collected binary."
        }
        foreach ($check in @($Result.operator_evidence.checks)) {
            foreach ($property in @('id', 'status', 'evidence')) {
                Assert-Property -Object $check -Name $property -Context "$Context operator evidence check"
            }
            $id = [string]$check.id
            if ($id -notin $manualCheckIds) { throw "$Context operator evidence contains unexpected check id '$id'." }
            if ($operator.Contains($id)) { throw "$Context operator evidence contains duplicate check id '$id'." }
            $operator[$id] = $check
        }
    }

    $specialExpectedProperties = [ordered]@{
        mixed_dpi = 'mixed_dpi'
        rdp = 'rdp'
        virtual_machine = 'virtual_machine'
        integrated_gpu = 'integrated_gpu'
        offline_startup = 'offline'
    }
    foreach ($id in $manualCheckIds) {
        if (-not $Checks.Contains($id)) { throw "$Context flattened checks are missing '$id'." }
        $flattened = $Checks[$id]
        $required = if ($id -in $commonManualCheckIds) { $true } else { [bool]$Result.scenario.expected.($specialExpectedProperties[$id]) }
        if ([string]$flattened.category -ne 'manual' -or [bool]$flattened.required_for_scenario -ne $required) {
            throw "$Context flattened manual check '$id' has inconsistent category or required flag."
        }
        if ($operator.Contains($id)) {
            $evidence = $operator[$id]
            $expectedSource = "operator:$([string]$Result.operator_evidence.operator)"
            if ([string]$flattened.status -ne [string]$evidence.status -or
                [string]$flattened.evidence -ne [string]$evidence.evidence -or
                [string]$flattened.source -ne $expectedSource) {
                throw "$Context flattened manual check '$id' does not match operator evidence."
            }
        } elseif ([string]$flattened.status -ne 'NOT_RUN' -or [string]$flattened.source -ne 'app-default') {
            throw "$Context flattened manual check '$id' has no matching operator evidence."
        }
    }
}

function Test-BaseChecksPass {
    param(
        [Parameter(Mandatory = $true)]$Wrapper
    )

    if ([string]$Wrapper.Data.outcome.status -ne 'PASS') {
        return $false
    }
    if (-not (Test-ObservedBaseEnvironment -Wrapper $Wrapper)) {
        return $false
    }
    foreach ($check in $Wrapper.Checks.Values) {
        if ([string]$check.status -eq 'FAIL' -or ([bool]$check.required_for_scenario -and [string]$check.status -ne 'PASS')) {
            return $false
        }
    }
    foreach ($id in $baseCheckIds) {
        if (-not $Wrapper.Checks.Contains($id) -or [string]$Wrapper.Checks[$id].status -ne 'PASS') {
            return $false
        }
    }
    return $true
}

function Test-ObservedBaseEnvironment {
    param([Parameter(Mandatory = $true)]$Wrapper)
    $result = $Wrapper.Data
    if ([string]$result.build.pe_machine -ne 'x86_64') { return $false }
    if ([string]$result.app_diagnostics.schema -ne 'lovelyres-gpui-feasibility/v1' -or
        [string]$result.app_diagnostics.status -ne 'READY' -or
        [string]$result.app_diagnostics.operating_system -ne 'windows' -or
        [string]$result.app_diagnostics.architecture -ne 'x86_64') {
        return $false
    }

    $expectedOs = [string]$result.scenario.expected.operating_system
    $observedCaption = [string]$result.environment.os.caption
    $observedBuild = [int]$result.environment.os.build_number
    if ($expectedOs -eq 'Windows10-22H2') {
        if ($observedBuild -ne 19045 -or [string]$result.environment.os.display_version -ne '22H2' -or $observedCaption -notmatch 'Windows 10') { return $false }
    } elseif ($expectedOs -eq 'Windows11') {
        if ($observedBuild -lt 22000 -or $observedCaption -notmatch 'Windows 11') { return $false }
    } else {
        return $false
    }

    $primaryDisplay = @($result.environment.displays | Where-Object { $_.primary }) | Select-Object -First 1
    if ($null -eq $primaryDisplay) { $primaryDisplay = @($result.environment.displays) | Select-Object -First 1 }
    return $null -ne $primaryDisplay -and $null -ne $primaryDisplay.dpi_percent -and [int]$primaryDisplay.dpi_percent -eq [int]$result.scenario.expected.dpi_percent
}

function Get-SpecialCoverageMatch {
    param(
        [Parameter(Mandatory = $true)]$Wrapper,
        [Parameter(Mandatory = $true)][string]$Id
    )

    if (-not (Test-BaseChecksPass -Wrapper $Wrapper)) {
        return $false
    }
    if (-not $Wrapper.Checks.Contains($Id) -or [string]$Wrapper.Checks[$Id].status -ne 'PASS') {
        return $false
    }

    $result = $Wrapper.Data
    switch ($Id) {
        'mixed_dpi' {
            if (-not [bool]$result.scenario.expected.mixed_dpi) { return $false }
            $dpiValues = @($result.environment.displays | Where-Object { $null -ne $_.dpi_percent } | ForEach-Object { [int]$_.dpi_percent } | Sort-Object -Unique)
            return $dpiValues.Count -ge 2
        }
        'rdp' {
            return [bool]$result.scenario.expected.rdp -and [bool]$result.environment.session.is_rdp
        }
        'virtual_machine' {
            return [bool]$result.scenario.expected.virtual_machine -and $null -ne $result.environment.computer.is_virtual_machine -and [bool]$result.environment.computer.is_virtual_machine
        }
        'integrated_gpu' {
            $integrated = @($result.environment.gpus | Where-Object { [string]$_.classification -eq 'integrated' }).Count -gt 0
            return [bool]$result.scenario.expected.integrated_gpu -and $integrated
        }
        'offline_startup' {
            return [bool]$result.scenario.expected.offline -and $null -ne $result.environment.network.is_offline -and [bool]$result.environment.network.is_offline
        }
        default {
            throw "Unknown special coverage id '$Id'."
        }
    }
}

function Write-AtomicUtf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content,
        [switch]$Replace
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "Output path '$Path' must include a parent directory."
    }
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    if ((Test-Path -LiteralPath $fullPath) -and -not $Replace) {
        throw "Output '$fullPath' already exists. Pass -Force to replace that exact file."
    }

    $temporary = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($fullPath) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($temporary, $Content, $utf8NoBom)
        [System.IO.File]::Move($temporary, $fullPath, [bool]$Replace)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

if ($ResultPath.Count -eq 0) {
    throw 'At least one -ResultPath is required.'
}

$summaryJson = [System.IO.Path]::GetFullPath($SummaryJsonPath)
$summaryMarkdown = [System.IO.Path]::GetFullPath($SummaryMarkdownPath)
if ($summaryJson -eq $summaryMarkdown) {
    throw 'SummaryJsonPath and SummaryMarkdownPath must be different files.'
}

$resolvedInputs = [System.Collections.Generic.List[string]]::new()
foreach ($path in $ResultPath) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    if ($resolved -eq $summaryJson -or $resolved -eq $summaryMarkdown) {
        throw "Summary output '$resolved' cannot also be an input result."
    }
    if (-not $resolvedInputs.Contains($resolved)) {
        $resolvedInputs.Add($resolved)
    }
}

$wrappers = [System.Collections.Generic.List[object]]::new()
$scenarioIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$resultSchemaPath = Join-Path $PSScriptRoot 'gpui-feasibility-result.schema.json'
foreach ($path in $resolvedInputs) {
    try {
        $json = Get-Content -LiteralPath $path -Raw
        if (-not ($json | Test-Json -SchemaFile $resultSchemaPath -ErrorAction Stop)) {
            throw 'JSON does not match gpui-feasibility-result.schema.json'
        }
        $result = $json | ConvertFrom-Json -Depth 100
    } catch {
        throw "Cannot parse feasibility result '$path': $($_.Exception.Message)"
    }

    foreach ($property in @('schema', 'fixture', 'scenario', 'build', 'environment', 'app_diagnostics', 'checks', 'outcome')) {
        Assert-Property -Object $result -Name $property -Context "result '$path'"
    }
    if ([string]$result.schema -ne 'lovelyres-feasibility-result/v1') {
        throw "Result '$path' has unsupported schema '$($result.schema)'."
    }
    if ($result.fixture -isnot [bool]) {
        throw "Result '$path' fixture property must be boolean."
    }
    if ([bool]$result.fixture -and -not $AllowFixture) {
        throw "Result '$path' is fixture evidence. Fixture evidence is never accepted unless -AllowFixture is explicitly used for harness self-tests."
    }
    foreach ($property in @('id', 'expected')) {
        Assert-Property -Object $result.scenario -Name $property -Context "result '$path' scenario"
    }
    $scenarioId = [string]$result.scenario.id
    if (-not $scenarioIds.Add($scenarioId)) {
        throw "Duplicate scenario id '$scenarioId'."
    }
    foreach ($property in @('operating_system', 'dpi_percent', 'mixed_dpi', 'rdp', 'virtual_machine', 'integrated_gpu', 'offline')) {
        Assert-Property -Object $result.scenario.expected -Name $property -Context "result '$path' expected environment"
    }
    foreach ($property in @('sha256', 'size_bytes', 'pe_machine')) {
        Assert-Property -Object $result.build -Name $property -Context "result '$path' build"
    }
    if ($null -eq $result.app_diagnostics) {
        throw "Result '$path' has no app_diagnostics object."
    }
    foreach ($property in @('app_version', 'gpui_version')) {
        Assert-Property -Object $result.app_diagnostics -Name $property -Context "result '$path' app_diagnostics"
    }
    if ([string]$result.app_diagnostics.gpui_version -ne '0.2.2') {
        throw "Result '$path' used GPUI '$($result.app_diagnostics.gpui_version)', expected exactly 0.2.2."
    }
    Assert-Property -Object $result.outcome -Name 'status' -Context "result '$path' outcome"
    if ([string]$result.outcome.status -notin @('PASS', 'FAIL', 'NOT_RUN')) {
        throw "Result '$path' has invalid outcome '$($result.outcome.status)'."
    }

    $checkMap = Get-CheckMap -Result $result -Context "result '$path'"
    Assert-EvidenceConsistency -Result $result -Checks $checkMap -Context "result '$path'"
    $wrappers.Add([pscustomobject][ordered]@{
        Path = $path
        Data = $result
        Checks = $checkMap
    })
}

$reasons = [System.Collections.Generic.List[string]]::new()
$reference = $wrappers[0].Data
$buildHash = ([string]$reference.build.sha256).ToUpperInvariant()
$appVersion = [string]$reference.app_diagnostics.app_version
$gpuiVersion = [string]$reference.app_diagnostics.gpui_version
foreach ($wrapper in $wrappers) {
    $result = $wrapper.Data
    if (([string]$result.build.sha256).ToUpperInvariant() -ne $buildHash) {
        $reasons.Add("Scenario '$($result.scenario.id)' used a different binary SHA-256.")
    }
    if ([string]$result.app_diagnostics.app_version -ne $appVersion) {
        $reasons.Add("Scenario '$($result.scenario.id)' used app version '$($result.app_diagnostics.app_version)' instead of '$appVersion'.")
    }
    if ([string]$result.app_diagnostics.gpui_version -ne $gpuiVersion) {
        $reasons.Add("Scenario '$($result.scenario.id)' used a different GPUI version.")
    }
    if ([string]$result.outcome.status -ne 'PASS') {
        $reasons.Add("Scenario '$($result.scenario.id)' outcome is $($result.outcome.status), not PASS.")
    }
}

$matrix = [System.Collections.Generic.List[object]]::new()
foreach ($operatingSystem in @('Windows10-22H2', 'Windows11')) {
    foreach ($dpi in @(100, 150, 200)) {
        $matches = @($wrappers | Where-Object {
            [string]$_.Data.scenario.expected.operating_system -eq $operatingSystem -and
            [int]$_.Data.scenario.expected.dpi_percent -eq $dpi -and
            (Test-BaseChecksPass -Wrapper $_)
        } | ForEach-Object { [string]$_.Data.scenario.id })
        $status = if ($matches.Count -gt 0) { 'PASS' } else { 'MISSING' }
        $id = "$operatingSystem@$dpi%"
        $matrix.Add([pscustomobject][ordered]@{
            id = $id
            status = $status
            scenario_ids = @($matches)
        })
        if ($status -ne 'PASS') {
            $reasons.Add("Required matrix cell '$id' has no fully passing real scenario.")
        }
    }
}

$specialCoverage = [System.Collections.Generic.List[object]]::new()
foreach ($id in @('mixed_dpi', 'rdp', 'virtual_machine', 'integrated_gpu', 'offline_startup')) {
    $matches = @($wrappers | Where-Object { Get-SpecialCoverageMatch -Wrapper $_ -Id $id } | ForEach-Object { [string]$_.Data.scenario.id })
    $status = if ($matches.Count -gt 0) { 'PASS' } else { 'MISSING' }
    $specialCoverage.Add([pscustomobject][ordered]@{
        id = $id
        status = $status
        scenario_ids = @($matches)
    })
    if ($status -ne 'PASS') {
        $reasons.Add("Required special coverage '$id' has no passing scenario with matching observed environment evidence.")
    }
}

$acceptanceStatus = if ($reasons.Count -eq 0) { 'PASSED' } else { 'FAILED' }
$summary = [pscustomobject][ordered]@{
    schema = 'lovelyres-feasibility-summary/v1'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    fixture_evidence_allowed = [bool]$AllowFixture
    result_count = $wrappers.Count
    build = [pscustomobject][ordered]@{
        sha256 = $buildHash
        app_version = $appVersion
        gpui_version = $gpuiVersion
    }
    matrix = @($matrix)
    special_coverage = @($specialCoverage)
    scenarios = @($wrappers | ForEach-Object {
        [pscustomobject][ordered]@{
            id = [string]$_.Data.scenario.id
            status = [string]$_.Data.outcome.status
            fixture = [bool]$_.Data.fixture
            source = [string]$_.Path
        }
    })
    acceptance = [pscustomobject][ordered]@{
        status = $acceptanceStatus
        reasons = @($reasons)
    }
}
$summaryJsonContent = ($summary | ConvertTo-Json -Depth 100) + "`n"
$summarySchemaPath = Join-Path $PSScriptRoot 'gpui-feasibility-summary.schema.json'
if (-not ($summaryJsonContent | Test-Json -SchemaFile $summarySchemaPath -ErrorAction Stop)) {
    throw 'Generated summary does not match gpui-feasibility-summary.schema.json.'
}

function Escape-MarkdownCell {
    param([AllowEmptyString()][string]$Value)
    return ($Value -replace '\|', '\|' -replace "`r?`n", '<br>')
}

$markdown = [System.Text.StringBuilder]::new()
[void]$markdown.AppendLine('# LovelyRes GPUI Windows feasibility acceptance')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine("- Result: **$acceptanceStatus**")
[void]$markdown.AppendLine("- Generated: $($summary.generated_at_utc)")
[void]$markdown.AppendLine("- Results: $($summary.result_count)")
[void]$markdown.AppendLine("- Binary SHA-256: ``$buildHash``")
[void]$markdown.AppendLine("- App / GPUI: ``$appVersion`` / ``$gpuiVersion``")
[void]$markdown.AppendLine("- Fixture evidence allowed: ``$([bool]$AllowFixture)``")
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## OS and DPI matrix')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('| Cell | Status | Scenarios |')
[void]$markdown.AppendLine('|---|---|---|')
foreach ($entry in $matrix) {
    [void]$markdown.AppendLine("| $($entry.id) | $($entry.status) | $(Escape-MarkdownCell -Value ($entry.scenario_ids -join ', ')) |")
}
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Special environments')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('| Coverage | Status | Scenarios |')
[void]$markdown.AppendLine('|---|---|---|')
foreach ($entry in $specialCoverage) {
    [void]$markdown.AppendLine("| $($entry.id) | $($entry.status) | $(Escape-MarkdownCell -Value ($entry.scenario_ids -join ', ')) |")
}
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Scenario results')
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('| Scenario | Status | Fixture | Source |')
[void]$markdown.AppendLine('|---|---|---|---|')
foreach ($wrapper in $wrappers) {
    $scenarioCell = Escape-MarkdownCell -Value ([string]$wrapper.Data.scenario.id)
    $sourceCell = Escape-MarkdownCell -Value ([string]$wrapper.Path)
    [void]$markdown.AppendLine("| $scenarioCell | $($wrapper.Data.outcome.status) | $([bool]$wrapper.Data.fixture) | $sourceCell |")
}
[void]$markdown.AppendLine()
[void]$markdown.AppendLine('## Blocking reasons')
[void]$markdown.AppendLine()
if ($reasons.Count -eq 0) {
    [void]$markdown.AppendLine('- None.')
} else {
    foreach ($reason in $reasons) {
        [void]$markdown.AppendLine("- $reason")
    }
}

Write-AtomicUtf8 -Path $summaryJson -Content $summaryJsonContent -Replace:$Force
Write-AtomicUtf8 -Path $summaryMarkdown -Content $markdown.ToString() -Replace:$Force

Write-Host "Wrote feasibility summary JSON to '$summaryJson'."
Write-Host "Wrote feasibility summary Markdown to '$summaryMarkdown'."
if ($acceptanceStatus -ne 'PASSED' -and -not $ReportOnly) {
    throw "GPUI feasibility release acceptance failed with $($reasons.Count) blocking reason(s). See '$summaryMarkdown'."
}
