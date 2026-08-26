[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredCspDirectives = [ordered]@{
    'default-src' = "'none'"
    'script-src' = "'self'"
    'style-src' = "'self'"
    'img-src' = "'self' data:"
    'font-src' = "'self'"
    'connect-src' = "'self'"
    'object-src' = "'none'"
    'base-uri' = "'none'"
    'form-action' = "'none'"
}
$requiredTerminalCspDirectives = [ordered]@{
    'default-src' = "'none'"
    'script-src' = "'self'"
    'style-src' = "'self' 'unsafe-inline'"
    'img-src' = "'self'"
    'font-src' = "'self'"
    'connect-src' = "'self'"
    'worker-src' = "'none'"
    'frame-src' = "'none'"
    'object-src' = "'none'"
    'base-uri' = "'none'"
    'form-action' = "'none'"
}

$rendererCodePatterns = [ordered]@{
    'Node child_process API' = '(?i)(?:["'']node:child_process["'']|(?:from\s*|import\s*\(|require\s*\()\s*["'']child_process["''])'
    'Node fs API' = '(?i)(?:["'']node:fs(?:/promises)?["'']|(?:from\s*|import\s*\(|require\s*\()\s*["'']fs(?:/promises)?["''])'
    'direct Electron API import' = '(?i)(?:from\s*|import\s*\(|require\s*\()\s*["'']electron(?:/renderer)?["'']'
    'Electron shell API' = '(?i)\b(?:electron\s*\.\s*)?shell\s*\.'
    'innerHTML DOM sink' = '(?i)(?:\.\s*innerHTML\b|\bdangerouslySetInnerHTML\b)'
    'eval execution' = '(?i)(?<![A-Za-z0-9_$])eval\s*\('
    'new Function execution' = '(?i)\bnew\s+Function\s*\('
    'system-level dialog' = '(?i)\bwindow\s*\.\s*(?:alert|confirm|prompt)\s*\('
}

$expectedPreloadBindings = @(
    @{ Name = 'bootstrap'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:bootstrap' },
    @{ Name = 'listConnections'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:list' },
    @{ Name = 'getConnection'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:get' },
    @{ Name = 'createConnection'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:create' },
    @{ Name = 'updateConnection'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:update' },
    @{ Name = 'planConnectionDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:delete:plan' },
    @{ Name = 'confirmConnectionDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:delete:confirm' },
    @{ Name = 'cancelConnectionDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:delete:cancel' },
    @{ Name = 'importConnections'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:import' },
    @{ Name = 'exportConnections'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:connections:export' },
    @{ Name = 'startSshConnect'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:connect:start' },
    @{ Name = 'startSshProbe'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:probe:start' },
    @{ Name = 'getSshAttempt'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:attempt:get' },
    @{ Name = 'confirmSshHostKey'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:host-key:confirm' },
    @{ Name = 'respondSshMfa'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:mfa:respond' },
    @{ Name = 'cancelSshAttempt'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:attempt:cancel' },
    @{ Name = 'disconnectSshBinding'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ssh:binding:disconnect' },
    @{ Name = 'openSshTerminal'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:terminal-window:open' },
    @{ Name = 'getSystemInfoCatalog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:system-info:catalog:get' },
    @{ Name = 'getSystemInfoSummary'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:system-info:summary:get' },
    @{ Name = 'collectSystemInfo'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:system-info:table:collect' },
    @{ Name = 'getSystemInfoDetail'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:system-info:detail:get' },
    @{ Name = 'listSnapshots'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:snapshot:list' },
    @{ Name = 'getSnapshotDetail'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:snapshot:detail:get' },
    @{ Name = 'diffForensicSnapshots'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:snapshot:forensic:diff' },
    @{ Name = 'inspectFirewall'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:firewall:inspect' },
    @{ Name = 'listFirewallChangeHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:firewall:change-history:list' },
    @{ Name = 'getBaselineCatalog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:baseline:catalog:get' },
    @{ Name = 'scanBaseline'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:baseline:scan' },
    @{ Name = 'listBaselineHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:baseline:history:list' },
    @{ Name = 'discoverMiddleware'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:middleware:discover' },
    @{ Name = 'loadMiddlewareConfiguration'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:middleware:configuration:load' },
    @{ Name = 'listMiddlewareHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:middleware:history:list' },
    @{ Name = 'getCheckAuditCatalog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:check-audit:catalog:get' },
    @{ Name = 'collectCheckAuditStatus'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:check-audit:status:collect' },
    @{ Name = 'readCheckAuditLog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:check-audit:log:read' },
    @{ Name = 'discoverLogSources'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:log-analysis:sources:discover' },
    @{ Name = 'readLogSource'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:log-analysis:source:read' },
    @{ Name = 'correlateLogSources'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:log-analysis:sources:correlate' },
    @{ Name = 'searchLogIocs'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:log-analysis:iocs:search' },
    @{ Name = 'getKubernetesAvailability'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:kubernetes:availability:get' },
    @{ Name = 'listKubernetesResources'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:kubernetes:resources:list' },
    @{ Name = 'getKubernetesResourceDetail'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:kubernetes:resource:detail:get' },
    @{ Name = 'getKubernetesPodLogs'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:kubernetes:pod:logs:get' },
    @{ Name = 'refreshDockerContainers'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:docker:containers:refresh' },
    @{ Name = 'getDockerCollection'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:docker:collection:get' },
    @{ Name = 'inspectDockerResource'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:docker:resource:inspect' },
    @{ Name = 'getDockerSecurityAudit'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:docker:security:audit:get' },
    @{ Name = 'getDockerLogs'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:docker:container:logs:get' },
    @{ Name = 'loadEmergencyCommandCatalog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:catalog:load' },
    @{ Name = 'runEmergencyCommand'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:run' },
    @{ Name = 'inspectEmergencyPath'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:path:inspect' },
    @{ Name = 'planEmergencyPathAction'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:path:plan' },
    @{ Name = 'confirmEmergencyPathAction'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:path:confirm' },
    @{ Name = 'executeEmergencyPathAction'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:path:execute' },
    @{ Name = 'cancelEmergencyPathAction'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:emergency-command:path:cancel' },
    @{ Name = 'listPacketCaptureInterfaces'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:packet-capture:interfaces:list' },
    @{ Name = 'startPacketCapture'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:packet-capture:start' },
    @{ Name = 'pollPacketCapture'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:packet-capture:poll' },
    @{ Name = 'stopPacketCapture'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:packet-capture:stop' },
    @{ Name = 'listApplicationLogs'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:application-log:list' },
    @{ Name = 'setApplicationLogLevel'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:application-log:level:set' },
    @{ Name = 'clearApplicationLogBuffer'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:application-log:buffer:clear' },
    @{ Name = 'getApplicationLogPreview'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:application-log:preview:get' },
    @{ Name = 'exportApplicationLogs'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:application-log:export' },
    @{ Name = 'getIntegrityPresets'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:integrity:presets:get' },
    @{ Name = 'listIntegrityBaselines'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:integrity:baselines:list' },
    @{ Name = 'startIntegrityComparison'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:integrity:comparison:start' },
    @{ Name = 'pollIntegrityComparison'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:integrity:comparison:poll' },
    @{ Name = 'cancelIntegrityComparison'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:integrity:comparison:cancel' },
    @{ Name = 'loadSettings'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:get' },
    @{ Name = 'saveSettings'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:save' },
    @{ Name = 'setWindowTheme'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ui:window-theme' },
    @{ Name = 'replaceSettingsAiApiKey'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:ai-api-key:replace' },
    @{ Name = 'planSettingsAiApiKeyClear'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:ai-api-key:clear:plan' },
    @{ Name = 'planSettingsAiProviderRemoval'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:ai-provider:remove:plan' },
    @{ Name = 'confirmSettingsMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:mutation:confirm' },
    @{ Name = 'cancelSettingsMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:settings:mutation:cancel' },
    @{ Name = 'listAiHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:list' },
    @{ Name = 'getAiHistoryRecord'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:get' },
    @{ Name = 'planAiHistoryRemove'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:remove:plan' },
    @{ Name = 'planAiHistoryClear'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:clear:plan' },
    @{ Name = 'confirmAiHistoryMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:mutation:confirm' },
    @{ Name = 'cancelAiHistoryMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:mutation:cancel' },
    @{ Name = 'exportAiHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:ai-history:export' },
    @{ Name = 'listCommandHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:list' },
    @{ Name = 'getCommandHistory'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:get' },
    @{ Name = 'planCommandReplay'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:replay:plan' },
    @{ Name = 'planCommandHistoryRemove'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:remove:plan' },
    @{ Name = 'planCommandHistoryClear'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:clear:plan' },
    @{ Name = 'confirmCommandHistoryMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:mutation:confirm' },
    @{ Name = 'cancelCommandHistoryMutation'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:command-history:mutation:cancel' },
    @{ Name = 'generateDisposalReport'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:disposal-report:generate' },
    @{ Name = 'getDisposalReportContent'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:disposal-report:content:get' },
    @{ Name = 'exportDisposalReport'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:disposal-report:export' },
    @{ Name = 'getConfigCatalog'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:catalog:get' },
    @{ Name = 'generateConfig'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:generate' },
    @{ Name = 'reviseConfig'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:revise' },
    @{ Name = 'copyConfig'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:copy' },
    @{ Name = 'exportConfigArtifact'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:artifact:export' },
    @{ Name = 'closeConfigDraft'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:config:draft:close' },
    @{ Name = 'setSecurityReferenceFavorites'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:security-reference:set-favorites' },
    @{ Name = 'listNotes'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:list' },
    @{ Name = 'getNote'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:get' },
    @{ Name = 'createNote'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:create' },
    @{ Name = 'updateNote'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:update' },
    @{ Name = 'setNotePinned'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:set-pinned' },
    @{ Name = 'addNoteTag'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:add-tag' },
    @{ Name = 'removeNoteTag'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:remove-tag' },
    @{ Name = 'planNoteDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:delete:plan' },
    @{ Name = 'confirmNoteDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:delete:confirm' },
    @{ Name = 'cancelNoteDelete'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:delete:cancel' },
    @{ Name = 'exportNotes'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:notes:export' },
    @{ Name = 'writeClipboard'; Method = 'invoke'; Registration = 'handle'; Channel = 'lovelyres:clipboard:write-text' },
    @{ Name = 'onBeforeClose'; Method = 'main-to-renderer'; Registration = 'on'; Channel = 'lovelyres:before-close' },
    @{ Name = 'notifyRendererReady'; Method = 'send'; Registration = 'on'; Channel = 'lovelyres:renderer-ready' }
)

if ($expectedPreloadBindings.Count -ne 116) {
    throw "Electron main preload allowlist must contain exactly 116 methods; found $($expectedPreloadBindings.Count)."
}

function Get-CspPolicyViolation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Policy,
        [switch]$RequireFrameAncestors,
        [switch]$TerminalStyleException
    )

    $expected = [ordered]@{}
    $required = $requiredCspDirectives
    if ($TerminalStyleException) { $required = $requiredTerminalCspDirectives }
    foreach ($entry in $required.GetEnumerator()) {
        $expected[$entry.Key] = $entry.Value
    }
    if ($RequireFrameAncestors) {
        $expected['frame-ancestors'] = "'none'"
    }

    $actual = [ordered]@{}
    foreach ($rawDirective in ($Policy -split ';')) {
        $directive = $rawDirective.Trim()
        if ([string]::IsNullOrWhiteSpace($directive)) { continue }
        $parts = @($directive -split '\s+', 2)
        $name = $parts[0]
        $value = if ($parts.Count -eq 2) { $parts[1].Trim() } else { '' }
        if ($actual.Contains($name)) {
            Write-Output "duplicates directive '$name'"
            continue
        }
        $actual[$name] = $value
    }

    foreach ($entry in $expected.GetEnumerator()) {
        if (-not $actual.Contains($entry.Key)) {
            Write-Output "is missing directive '$($entry.Key)'"
        } elseif (-not [string]::Equals([string]$actual[$entry.Key], [string]$entry.Value, [System.StringComparison]::Ordinal)) {
            Write-Output "directive '$($entry.Key)' must be exactly '$($entry.Value)'"
        }
    }
    foreach ($name in $actual.Keys) {
        if (-not $expected.Contains($name)) {
            Write-Output "contains unexpected directive '$name'"
        }
    }
    if ($TerminalStyleException) {
        $withoutApprovedStyle = $Policy.Replace("style-src 'self' 'unsafe-inline'", "style-src 'self'")
        if ($withoutApprovedStyle -match '(?i)(?:unsafe-inline|unsafe-eval|wasm-unsafe-eval|https?://|data:|\*)') {
            Write-Output 'contains an unsafe or remote expression outside the terminal-only inline CSS allowance'
        }
    } elseif ($Policy -match '(?i)(?:unsafe-inline|unsafe-eval|wasm-unsafe-eval|https?://|\*)') {
        Write-Output 'contains an unsafe or remote source expression'
    }
}

function Get-HtmlCspPolicy {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Html)

    $meta = [regex]::Match(
        $Html,
        '(?is)<meta\b(?=[^>]*\bhttp-equiv\s*=\s*["'']Content-Security-Policy["''])[^>]*>'
    )
    if (-not $meta.Success) { return $null }
    $content = [regex]::Match($meta.Value, '(?is)\bcontent\s*=\s*"(?<policy>[^"]*)"')
    if (-not $content.Success) { return $null }
    return $content.Groups['policy'].Value
}

function Get-RendererCodeViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    foreach ($entry in $rendererCodePatterns.GetEnumerator()) {
        if ($Text -match $entry.Value) {
            Write-Output ([string]$entry.Key)
        }
    }
}

function Get-RemoteUiResourceViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $withoutXmlNamespaces = $Text.Replace('http://www.w3.org/2000/svg', '')
    $withoutXmlNamespaces = $withoutXmlNamespaces.Replace('http://www.w3.org/1999/xlink', '')
    if ($withoutXmlNamespaces -match '(?i)https?://') {
        return 'remote HTTP(S) UI resource or URL'
    }
    return $null
}

function ConvertTo-ByteCount {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Expression)

    if ($Expression -notmatch '^\s*[0-9_]+(?:\s*\*\s*[0-9_]+)*\s*$') { return $null }
    [decimal]$product = 1
    foreach ($factorText in ($Expression -split '\*')) {
        [decimal]$factor = 0
        if (-not [decimal]::TryParse($factorText.Trim().Replace('_', ''), [ref]$factor)) {
            return $null
        }
        $product *= $factor
        if ($product -gt [int64]::MaxValue) { return $null }
    }
    return [int64]$product
}

function Get-DeclaredByteLimit {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Name,
        [ValidateSet('TypeScript', 'Rust')][string]$Language
    )

    $escapedName = [regex]::Escape($Name)
    $pattern = if ($Language -eq 'Rust') {
        "(?m)^\s*pub\s+const\s+$escapedName\s*:\s*usize\s*=\s*(?<expression>[0-9_ `t*]+)\s*;"
    } else {
        "(?m)^\s*const\s+$escapedName\s*=\s*(?<expression>[0-9_ `t*]+)\s*;"
    }
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) { return $null }
    return ConvertTo-ByteCount -Expression $match.Groups['expression'].Value
}

function Get-WebPreferencesViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Source)

    $windowCount = [regex]::Matches($Source, '\bnew\s+BrowserWindow\s*\(').Count
    $blocks = [regex]::Matches($Source, '(?s)\bwebPreferences\s*:\s*\{(?<body>[^{}]*)\}')
    if ($windowCount -eq 0) {
        Write-Output 'does not construct a BrowserWindow'
        return
    }
    if ($blocks.Count -ne $windowCount) {
        Write-Output "must define one explicit webPreferences block per BrowserWindow ($windowCount window(s), $($blocks.Count) block(s))"
    }
    $index = 0
    foreach ($block in $blocks) {
        $index++
        $body = $block.Groups['body'].Value
        if ($body -match '(?m)^\s*\.\.\.') {
            Write-Output "BrowserWindow $index must not spread overridable webPreferences"
        }
        foreach ($setting in @(
            @{ Name = 'contextIsolation'; Value = 'true' },
            @{ Name = 'nodeIntegration'; Value = 'false' },
            @{ Name = 'sandbox'; Value = 'true' },
            @{ Name = 'webSecurity'; Value = 'true' }
        )) {
            $name = [regex]::Escape($setting.Name)
            $value = [regex]::Escape($setting.Value)
            if ([regex]::Matches($body, "(?m)^\s*$name\s*:").Count -ne 1) {
                Write-Output "BrowserWindow $index must declare $($setting.Name) exactly once"
            } elseif ($body -notmatch "(?m)^\s*$name\s*:\s*$value\s*,?\s*$" ) {
                Write-Output "BrowserWindow $index must set $($setting.Name): $($setting.Value)"
            }
        }
        if ($body -notmatch '(?m)^\s*preload\s*:\s*path\.join\s*\(') {
            Write-Output "BrowserWindow $index must use a local path.join preload"
        }
    }
    $sandboxMatch = [regex]::Match($Source, '\bapp\.enableSandbox\s*\(\s*\)')
    if (-not $sandboxMatch.Success) {
        Write-Output 'must call app.enableSandbox() before app readiness'
    } else {
        $readyMatch = [regex]::Match($Source, '\bapp\.whenReady\s*\(')
        if ($readyMatch.Success -and $sandboxMatch.Index -gt $readyMatch.Index) {
            Write-Output 'must call app.enableSandbox() before app.whenReady()'
        }
    }
}

function Get-ActiveCiViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    if ($Text -notmatch '(?m)^name:\s*Electron CI\s*$') {
        Write-Output "must declare the active workflow name as 'Electron CI'"
    }
    foreach ($requiredCommand in @(
        'pnpm install --frozen-lockfile',
        './scripts/electron-quality-gates.ps1 -SelfTest',
        './scripts/electron-source-gate.ps1 -SelfTest',
        './scripts/electron-dependency-gate.ps1 -SelfTest',
        './scripts/electron-ui-ledger-gate.ps1 -SelfTest',
        './scripts/electron-quality-gates.ps1'
    )) {
        if (-not $Text.Contains($requiredCommand, [System.StringComparison]::Ordinal)) {
            Write-Output "must run '$requiredCommand'"
        }
    }
    if ($Text -match '(?i)(?:gpui-(?:quality|source|dependency)-gate\.ps1|lovelyres-gpui)') {
        Write-Output 'must not run a GPUI gate, package, or binary from the active Electron CI workflow'
    }
}

function Assert-SelfTest {
    $goodCsp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"
    if (@(Get-CspPolicyViolation -Policy $goodCsp).Count -ne 0) {
        throw 'Electron source-gate self-test rejected the strict CSP fixture.'
    }
    $badCsp = $goodCsp.Replace("script-src 'self'", "script-src 'self' 'unsafe-eval' https://cdn.invalid")
    if (@(Get-CspPolicyViolation -Policy $badCsp).Count -eq 0) {
        throw 'Electron source-gate self-test missed the unsafe CSP fixture.'
    }
    $badMainInlineCsp = $goodCsp.Replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")
    if (@(Get-CspPolicyViolation -Policy $badMainInlineCsp).Count -eq 0) {
        throw 'Electron source-gate self-test missed a loosened main renderer script CSP.'
    }
    $goodTerminalCsp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    if (@(Get-CspPolicyViolation -Policy $goodTerminalCsp -TerminalStyleException).Count -ne 0) {
        throw 'Electron source-gate self-test rejected the terminal-only xterm CSS fixture.'
    }
    $badTerminalScriptCsp = $goodTerminalCsp.Replace("script-src 'self'", "script-src 'self' 'unsafe-inline' data:")
    if (@(Get-CspPolicyViolation -Policy $badTerminalScriptCsp -TerminalStyleException).Count -eq 0) {
        throw 'Electron source-gate self-test missed a loosened terminal script CSP.'
    }

    $badRendererFixtures = @(
        'import fs from "node:fs";',
        'const child = require("child_process");',
        'element.innerHTML = attackerInput;',
        'return eval(attackerInput);',
        'const compiled = new Function(attackerInput);',
        'shell.openExternal(attackerInput);'
    )
    foreach ($fixture in $badRendererFixtures) {
        if (@(Get-RendererCodeViolation -Text $fixture).Count -eq 0) {
            throw "Electron source-gate self-test missed forbidden renderer fixture: $fixture"
        }
    }
    if (@(Get-RendererCodeViolation -Text 'element.textContent = hostilePlainText;').Count -ne 0) {
        throw 'Electron source-gate self-test rejected safe plain-text rendering.'
    }
    if ($null -eq (Get-RemoteUiResourceViolation -Text '<img src="https://cdn.invalid/logo.png">')) {
        throw 'Electron source-gate self-test missed a remote UI resource.'
    }
    if ((ConvertTo-ByteCount -Expression '256 * 1024') -ne 262144) {
        throw 'Electron source-gate self-test could not parse a bounded byte expression.'
    }
    if ($null -ne (ConvertTo-ByteCount -Expression 'Number.MAX_SAFE_INTEGER')) {
        throw 'Electron source-gate self-test accepted a non-literal byte expression.'
    }

    $goodWindow = @'
app.enableSandbox();
const window = new BrowserWindow({
  webPreferences: {
    preload: path.join(__dirname, "preload.js"),
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: true,
    webSecurity: true,
  },
});
'@
    if (@(Get-WebPreferencesViolation -Source $goodWindow).Count -ne 0) {
        throw 'Electron source-gate self-test rejected hardened BrowserWindow preferences.'
    }
    $badWindow = $goodWindow.Replace('contextIsolation: true', 'contextIsolation: false')
    if (@(Get-WebPreferencesViolation -Source $badWindow).Count -eq 0) {
        throw 'Electron source-gate self-test missed unsafe BrowserWindow preferences.'
    }

    $goodActiveCi = @'
name: Electron CI
run: pnpm install --frozen-lockfile
run: |
  ./scripts/electron-quality-gates.ps1 -SelfTest
  ./scripts/electron-source-gate.ps1 -SelfTest
  ./scripts/electron-dependency-gate.ps1 -SelfTest
  ./scripts/electron-ui-ledger-gate.ps1 -SelfTest
  ./scripts/electron-config-test-ledger-gate.ps1 -SelfTest
run: ./scripts/electron-quality-gates.ps1
'@
    if (@(Get-ActiveCiViolation -Text $goodActiveCi).Count -ne 0) {
        throw 'Electron source-gate self-test rejected the Electron-only active CI fixture.'
    }
    $badActiveCi = $goodActiveCi.Replace(
        './scripts/electron-quality-gates.ps1',
        './scripts/gpui-quality-gates.ps1'
    )
    if (@(Get-ActiveCiViolation -Text $badActiveCi).Count -eq 0) {
        throw 'Electron source-gate self-test missed an active CI regression to GPUI.'
    }

    Write-Host 'Electron source gate fixture self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$electronRoot = Join-Path $root 'electron'
$backendRoot = Join-Path $root 'crates/lovelyres-electron-backend'
$violations = [System.Collections.Generic.List[string]]::new()

function Add-GateViolation {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:violations.Add($Message)
}

function Get-RelativeName {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetRelativePath($root, $Path).Replace('\', '/')
}

$requiredDirectories = @(
    $electronRoot,
    (Join-Path $electronRoot 'assets'),
    (Join-Path $electronRoot 'src/renderer'),
    (Join-Path $electronRoot 'src/shared'),
    $backendRoot
)
foreach ($directory in $requiredDirectories) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        Add-GateViolation "missing required Electron migration directory '$(Get-RelativeName -Path $directory)'"
    }
}

$requiredFiles = @(
    (Join-Path $root '.github/workflows/ci.yml'),
    (Join-Path $root 'package.json'),
    (Join-Path $root 'pnpm-lock.yaml'),
    (Join-Path $root 'pnpm-workspace.yaml'),
    (Join-Path $electronRoot 'package.json'),
    (Join-Path $electronRoot 'index.html'),
    (Join-Path $electronRoot 'terminal.html'),
    (Join-Path $electronRoot 'vite.config.mts'),
    (Join-Path $electronRoot 'src/main/index.ts'),
    (Join-Path $electronRoot 'src/main/app-lifecycle.ts'),
    (Join-Path $electronRoot 'src/main/backend-client.ts'),
    (Join-Path $electronRoot 'src/main/integrity-boundary.test.ts'),
    (Join-Path $electronRoot 'src/main/log-analysis-read-boundary.test.ts'),
    (Join-Path $electronRoot 'src/main/kubernetes-read-boundary.test.ts'),
    (Join-Path $electronRoot 'src/main/docker-read-boundary.test.ts'),
    (Join-Path $electronRoot 'src/main/emergency-command-boundary.test.ts'),
    (Join-Path $electronRoot 'src/main/renderer-protocol.ts'),
    (Join-Path $electronRoot 'src/main/terminal-open-boundary.ts'),
    (Join-Path $electronRoot 'src/preload/index.ts'),
    (Join-Path $electronRoot 'src/preload/terminal.ts'),
    (Join-Path $electronRoot 'src/renderer/global.d.ts'),
    (Join-Path $electronRoot 'src/renderer/App.tsx'),
    (Join-Path $electronRoot 'src/renderer/AppTitleBar.tsx'),
    (Join-Path $electronRoot 'src/renderer/TerminalWindow.tsx'),
    (Join-Path $electronRoot 'src/renderer/TerminalSurface.tsx'),
    (Join-Path $electronRoot 'src/renderer/terminal-main.tsx'),
    (Join-Path $electronRoot 'src/renderer/terminal-controller.ts'),
    (Join-Path $electronRoot 'src/renderer/terminal-surface.css'),
    (Join-Path $electronRoot 'src/renderer/SettingsPanel.tsx'),
    (Join-Path $electronRoot 'src/renderer/AiHistoryPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/CommandHistoryPanel.tsx'),
    (Join-Path $electronRoot 'src/renderer/command-history.css'),
    (Join-Path $electronRoot 'src/renderer/DisposalReportOverlay.tsx'),
    (Join-Path $electronRoot 'src/renderer/disposal-report.css'),
    (Join-Path $electronRoot 'src/renderer/SnapshotPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/snapshot-page.css'),
    (Join-Path $electronRoot 'src/renderer/FirewallPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/firewall-page.css'),
    (Join-Path $electronRoot 'src/renderer/firewall-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/firewall-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/BaselinePage.tsx'),
    (Join-Path $electronRoot 'src/renderer/baseline-page.css'),
    (Join-Path $electronRoot 'src/renderer/baseline-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/baseline-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/MiddlewarePage.tsx'),
    (Join-Path $electronRoot 'src/renderer/middleware-page.css'),
    (Join-Path $electronRoot 'src/renderer/middleware-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/middleware-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/CheckAuditPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/check-audit-page.css'),
    (Join-Path $electronRoot 'src/renderer/check-audit-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/check-audit-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/LogAnalysisPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/log-analysis-page.css'),
    (Join-Path $electronRoot 'src/renderer/log-analysis-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/log-analysis-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/KubernetesPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/kubernetes-page.css'),
    (Join-Path $electronRoot 'src/renderer/kubernetes-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/kubernetes-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/DockerPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/docker-page.css'),
    (Join-Path $electronRoot 'src/renderer/docker-read-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/docker-read-state.ts'),
    (Join-Path $electronRoot 'src/renderer/EmergencyCommandsPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/emergency-commands.css'),
    (Join-Path $electronRoot 'src/renderer/emergency-command-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/emergency-command-state.ts'),
    (Join-Path $electronRoot 'src/renderer/EmergencyPathMenu.tsx'),
    (Join-Path $electronRoot 'src/renderer/EmergencyPathDialog.tsx'),
    (Join-Path $electronRoot 'src/renderer/emergency-path-actions.ts'),
    (Join-Path $electronRoot 'src/renderer/PacketCapturePage.tsx'),
    (Join-Path $electronRoot 'src/renderer/packet-capture-page.css'),
    (Join-Path $electronRoot 'src/renderer/packet-capture-live-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/packet-capture-live-state.ts'),
    (Join-Path $electronRoot 'src/renderer/ApplicationLogOverlay.tsx'),
    (Join-Path $electronRoot 'src/renderer/application-log.css'),
    (Join-Path $electronRoot 'src/renderer/application-log-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/application-log-state.ts'),
    (Join-Path $electronRoot 'src/renderer/IntegrityPage.tsx'),
    (Join-Path $electronRoot 'src/renderer/integrity.css'),
    (Join-Path $electronRoot 'src/renderer/integrity-helpers.ts'),
    (Join-Path $electronRoot 'src/renderer/integrity-state.ts'),
    (Join-Path $electronRoot 'src/renderer/styles.css'),
    (Join-Path $electronRoot 'src/shared/contract.ts'),
    (Join-Path $electronRoot 'src/shared/settings-contract.ts'),
    (Join-Path $electronRoot 'src/shared/ai-history-contract.ts'),
    (Join-Path $electronRoot 'src/shared/command-history-contract.ts'),
    (Join-Path $electronRoot 'src/shared/disposal-report-contract.ts'),
    (Join-Path $electronRoot 'src/shared/snapshot-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/firewall-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/baseline-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/middleware-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/check-audit-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/log-analysis-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/kubernetes-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/docker-read-contract.ts'),
    (Join-Path $electronRoot 'src/shared/emergency-command-contract.ts'),
    (Join-Path $electronRoot 'src/shared/packet-capture-live-contract.ts'),
    (Join-Path $electronRoot 'src/shared/application-log-contract.ts'),
    (Join-Path $electronRoot 'src/shared/integrity-contract.ts'),
    (Join-Path $electronRoot 'src/shared/terminal-contract.ts'),
    (Join-Path $electronRoot 'src/main/ai-history-export-boundary.ts'),
    (Join-Path $electronRoot 'src/main/disposal-report-export-boundary.ts'),
    (Join-Path $electronRoot 'src/main/application-log-export-boundary.ts'),
    (Join-Path $backendRoot 'Cargo.toml'),
    (Join-Path $backendRoot 'src/lib.rs'),
    (Join-Path $backendRoot 'src/settings_api.rs'),
    (Join-Path $backendRoot 'src/ai_history_api.rs'),
    (Join-Path $backendRoot 'src/command_history_api.rs'),
    (Join-Path $backendRoot 'src/disposal_report_api.rs'),
    (Join-Path $backendRoot 'src/snapshot_read_api.rs'),
    (Join-Path $backendRoot 'src/firewall_read_api.rs'),
    (Join-Path $backendRoot 'src/baseline_read_api.rs'),
    (Join-Path $backendRoot 'src/middleware_read_api.rs'),
    (Join-Path $backendRoot 'src/check_audit_read_api.rs'),
    (Join-Path $backendRoot 'src/log_analysis_read_api.rs'),
    (Join-Path $backendRoot 'src/kubernetes_read_api.rs'),
    (Join-Path $backendRoot 'src/docker_read_api.rs'),
    (Join-Path $backendRoot 'src/emergency_command_api.rs'),
    (Join-Path $backendRoot 'src/emergency_path_api.rs'),
    (Join-Path $backendRoot 'src/packet_capture_live_api.rs'),
    (Join-Path $backendRoot 'src/diagnostic_log_api.rs'),
    (Join-Path $backendRoot 'src/integrity_api.rs'),
    (Join-Path $backendRoot 'src/terminal_api.rs'),
    (Join-Path $backendRoot 'src/main.rs'),
    (Join-Path $root 'crates/lovelyres-core/src/firewall.rs'),
    (Join-Path $root 'crates/lovelyres-core/src/baseline.rs'),
    (Join-Path $root 'crates/lovelyres-core/src/integrity.rs'),
    (Join-Path $root 'crates/lovelyres-core/src/command_paths.rs')
)
foreach ($file in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        Add-GateViolation "missing required Electron migration file '$(Get-RelativeName -Path $file)'"
    }
}
if ($violations.Count -gt 0) {
    throw "Electron source gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}

$mainPath = Join-Path $electronRoot 'src/main/index.ts'
$activeCiPath = Join-Path $root '.github/workflows/ci.yml'
$appLifecyclePath = Join-Path $electronRoot 'src/main/app-lifecycle.ts'
$backendClientPath = Join-Path $electronRoot 'src/main/backend-client.ts'
$rendererProtocolPath = Join-Path $electronRoot 'src/main/renderer-protocol.ts'
$terminalOpenBoundaryPath = Join-Path $electronRoot 'src/main/terminal-open-boundary.ts'
$preloadPath = Join-Path $electronRoot 'src/preload/index.ts'
$terminalPreloadPath = Join-Path $electronRoot 'src/preload/terminal.ts'
$contractPath = Join-Path $electronRoot 'src/shared/contract.ts'
$settingsContractPath = Join-Path $electronRoot 'src/shared/settings-contract.ts'
$aiHistoryContractPath = Join-Path $electronRoot 'src/shared/ai-history-contract.ts'
$commandHistoryContractPath = Join-Path $electronRoot 'src/shared/command-history-contract.ts'
$disposalReportContractPath = Join-Path $electronRoot 'src/shared/disposal-report-contract.ts'
$snapshotReadContractPath = Join-Path $electronRoot 'src/shared/snapshot-read-contract.ts'
$firewallReadContractPath = Join-Path $electronRoot 'src/shared/firewall-read-contract.ts'
$baselineReadContractPath = Join-Path $electronRoot 'src/shared/baseline-read-contract.ts'
$middlewareReadContractPath = Join-Path $electronRoot 'src/shared/middleware-read-contract.ts'
$checkAuditReadContractPath = Join-Path $electronRoot 'src/shared/check-audit-read-contract.ts'
$logAnalysisReadContractPath = Join-Path $electronRoot 'src/shared/log-analysis-read-contract.ts'
$kubernetesReadContractPath = Join-Path $electronRoot 'src/shared/kubernetes-read-contract.ts'
$dockerReadContractPath = Join-Path $electronRoot 'src/shared/docker-read-contract.ts'
$emergencyCommandContractPath = Join-Path $electronRoot 'src/shared/emergency-command-contract.ts'
$packetCaptureLiveContractPath = Join-Path $electronRoot 'src/shared/packet-capture-live-contract.ts'
$applicationLogContractPath = Join-Path $electronRoot 'src/shared/application-log-contract.ts'
$integrityContractPath = Join-Path $electronRoot 'src/shared/integrity-contract.ts'
$terminalContractPath = Join-Path $electronRoot 'src/shared/terminal-contract.ts'
$appPath = Join-Path $electronRoot 'src/renderer/App.tsx'
$settingsPanelPath = Join-Path $electronRoot 'src/renderer/SettingsPanel.tsx'
$aiHistoryPagePath = Join-Path $electronRoot 'src/renderer/AiHistoryPage.tsx'
$commandHistoryPanelPath = Join-Path $electronRoot 'src/renderer/CommandHistoryPanel.tsx'
$commandHistoryCssPath = Join-Path $electronRoot 'src/renderer/command-history.css'
$disposalReportOverlayPath = Join-Path $electronRoot 'src/renderer/DisposalReportOverlay.tsx'
$disposalReportCssPath = Join-Path $electronRoot 'src/renderer/disposal-report.css'
$snapshotPagePath = Join-Path $electronRoot 'src/renderer/SnapshotPage.tsx'
$snapshotCssPath = Join-Path $electronRoot 'src/renderer/snapshot-page.css'
$firewallPagePath = Join-Path $electronRoot 'src/renderer/FirewallPage.tsx'
$firewallCssPath = Join-Path $electronRoot 'src/renderer/firewall-page.css'
$firewallHelpersPath = Join-Path $electronRoot 'src/renderer/firewall-read-helpers.ts'
$firewallStatePath = Join-Path $electronRoot 'src/renderer/firewall-read-state.ts'
$baselinePagePath = Join-Path $electronRoot 'src/renderer/BaselinePage.tsx'
$baselineCssPath = Join-Path $electronRoot 'src/renderer/baseline-page.css'
$baselineHelpersPath = Join-Path $electronRoot 'src/renderer/baseline-read-helpers.ts'
$baselineStatePath = Join-Path $electronRoot 'src/renderer/baseline-read-state.ts'
$middlewarePagePath = Join-Path $electronRoot 'src/renderer/MiddlewarePage.tsx'
$middlewareHelpersPath = Join-Path $electronRoot 'src/renderer/middleware-read-helpers.ts'
$middlewareStatePath = Join-Path $electronRoot 'src/renderer/middleware-read-state.ts'
$checkAuditPagePath = Join-Path $electronRoot 'src/renderer/CheckAuditPage.tsx'
$checkAuditHelpersPath = Join-Path $electronRoot 'src/renderer/check-audit-read-helpers.ts'
$checkAuditStatePath = Join-Path $electronRoot 'src/renderer/check-audit-read-state.ts'
$logAnalysisPagePath = Join-Path $electronRoot 'src/renderer/LogAnalysisPage.tsx'
$logAnalysisHelpersPath = Join-Path $electronRoot 'src/renderer/log-analysis-read-helpers.ts'
$logAnalysisStatePath = Join-Path $electronRoot 'src/renderer/log-analysis-read-state.ts'
$kubernetesPagePath = Join-Path $electronRoot 'src/renderer/KubernetesPage.tsx'
$kubernetesHelpersPath = Join-Path $electronRoot 'src/renderer/kubernetes-read-helpers.ts'
$kubernetesStatePath = Join-Path $electronRoot 'src/renderer/kubernetes-read-state.ts'
$dockerPagePath = Join-Path $electronRoot 'src/renderer/DockerPage.tsx'
$dockerHelpersPath = Join-Path $electronRoot 'src/renderer/docker-read-helpers.ts'
$dockerStatePath = Join-Path $electronRoot 'src/renderer/docker-read-state.ts'
$emergencyCommandPagePath = Join-Path $electronRoot 'src/renderer/EmergencyCommandsPage.tsx'
$emergencyCommandHelpersPath = Join-Path $electronRoot 'src/renderer/emergency-command-helpers.ts'
$emergencyCommandStatePath = Join-Path $electronRoot 'src/renderer/emergency-command-state.ts'
$packetCapturePagePath = Join-Path $electronRoot 'src/renderer/PacketCapturePage.tsx'
$packetCaptureHelpersPath = Join-Path $electronRoot 'src/renderer/packet-capture-live-helpers.ts'
$packetCaptureStatePath = Join-Path $electronRoot 'src/renderer/packet-capture-live-state.ts'
$applicationLogOverlayPath = Join-Path $electronRoot 'src/renderer/ApplicationLogOverlay.tsx'
$applicationLogHelpersPath = Join-Path $electronRoot 'src/renderer/application-log-helpers.ts'
$applicationLogStatePath = Join-Path $electronRoot 'src/renderer/application-log-state.ts'
$integrityPagePath = Join-Path $electronRoot 'src/renderer/IntegrityPage.tsx'
$integrityCssPath = Join-Path $electronRoot 'src/renderer/integrity.css'
$integrityHelpersPath = Join-Path $electronRoot 'src/renderer/integrity-helpers.ts'
$integrityStatePath = Join-Path $electronRoot 'src/renderer/integrity-state.ts'
$terminalWindowPath = Join-Path $electronRoot 'src/renderer/TerminalWindow.tsx'
$terminalSurfacePath = Join-Path $electronRoot 'src/renderer/TerminalSurface.tsx'
$terminalControllerPath = Join-Path $electronRoot 'src/renderer/terminal-controller.ts'
$globalStylesPath = Join-Path $electronRoot 'src/renderer/styles.css'
$aiHistoryExportPath = Join-Path $electronRoot 'src/main/ai-history-export-boundary.ts'
$disposalReportExportPath = Join-Path $electronRoot 'src/main/disposal-report-export-boundary.ts'
$applicationLogExportPath = Join-Path $electronRoot 'src/main/application-log-export-boundary.ts'
$globalPath = Join-Path $electronRoot 'src/renderer/global.d.ts'
$htmlPath = Join-Path $electronRoot 'index.html'
$terminalHtmlPath = Join-Path $electronRoot 'terminal.html'
$terminalMainPath = Join-Path $electronRoot 'src/renderer/terminal-main.tsx'
$vitePath = Join-Path $electronRoot 'vite.config.mts'
$backendLibPath = Join-Path $backendRoot 'src/lib.rs'
$settingsApiPath = Join-Path $backendRoot 'src/settings_api.rs'
$aiHistoryApiPath = Join-Path $backendRoot 'src/ai_history_api.rs'
$commandHistoryApiPath = Join-Path $backendRoot 'src/command_history_api.rs'
$disposalReportApiPath = Join-Path $backendRoot 'src/disposal_report_api.rs'
$snapshotReadApiPath = Join-Path $backendRoot 'src/snapshot_read_api.rs'
$firewallReadApiPath = Join-Path $backendRoot 'src/firewall_read_api.rs'
$baselineReadApiPath = Join-Path $backendRoot 'src/baseline_read_api.rs'
$middlewareReadApiPath = Join-Path $backendRoot 'src/middleware_read_api.rs'
$checkAuditReadApiPath = Join-Path $backendRoot 'src/check_audit_read_api.rs'
$logAnalysisReadApiPath = Join-Path $backendRoot 'src/log_analysis_read_api.rs'
$kubernetesReadApiPath = Join-Path $backendRoot 'src/kubernetes_read_api.rs'
$dockerReadApiPath = Join-Path $backendRoot 'src/docker_read_api.rs'
$emergencyCommandApiPath = Join-Path $backendRoot 'src/emergency_command_api.rs'
$packetCaptureLiveApiPath = Join-Path $backendRoot 'src/packet_capture_live_api.rs'
$diagnosticLogApiPath = Join-Path $backendRoot 'src/diagnostic_log_api.rs'
$integrityApiPath = Join-Path $backendRoot 'src/integrity_api.rs'
$backendMainPath = Join-Path $backendRoot 'src/main.rs'
$coreSnapshotPath = Join-Path $root 'crates/lovelyres-core/src/snapshot.rs'
$coreFirewallPath = Join-Path $root 'crates/lovelyres-core/src/firewall.rs'
$coreBaselinePath = Join-Path $root 'crates/lovelyres-core/src/baseline.rs'
$coreIntegrityPath = Join-Path $root 'crates/lovelyres-core/src/integrity.rs'
$terminalApiPath = Join-Path $backendRoot 'src/terminal_api.rs'

$activeCiText = Get-Content -LiteralPath $activeCiPath -Raw
$mainText = Get-Content -LiteralPath $mainPath -Raw
$appLifecycleText = Get-Content -LiteralPath $appLifecyclePath -Raw
$backendClientText = Get-Content -LiteralPath $backendClientPath -Raw
$rendererProtocolText = Get-Content -LiteralPath $rendererProtocolPath -Raw
$terminalOpenBoundaryText = Get-Content -LiteralPath $terminalOpenBoundaryPath -Raw
$preloadText = Get-Content -LiteralPath $preloadPath -Raw
$terminalPreloadText = Get-Content -LiteralPath $terminalPreloadPath -Raw
$contractText = Get-Content -LiteralPath $contractPath -Raw
$settingsContractText = Get-Content -LiteralPath $settingsContractPath -Raw
$aiHistoryContractText = Get-Content -LiteralPath $aiHistoryContractPath -Raw
$commandHistoryContractText = Get-Content -LiteralPath $commandHistoryContractPath -Raw
$disposalReportContractText = Get-Content -LiteralPath $disposalReportContractPath -Raw
$snapshotReadContractText = Get-Content -LiteralPath $snapshotReadContractPath -Raw
$firewallReadContractText = Get-Content -LiteralPath $firewallReadContractPath -Raw
$baselineReadContractText = Get-Content -LiteralPath $baselineReadContractPath -Raw
$middlewareReadContractText = Get-Content -LiteralPath $middlewareReadContractPath -Raw
$checkAuditReadContractText = Get-Content -LiteralPath $checkAuditReadContractPath -Raw
$logAnalysisReadContractText = Get-Content -LiteralPath $logAnalysisReadContractPath -Raw
$kubernetesReadContractText = Get-Content -LiteralPath $kubernetesReadContractPath -Raw
$dockerReadContractText = Get-Content -LiteralPath $dockerReadContractPath -Raw
$emergencyCommandContractText = Get-Content -LiteralPath $emergencyCommandContractPath -Raw
$packetCaptureLiveContractText = Get-Content -LiteralPath $packetCaptureLiveContractPath -Raw
$applicationLogContractText = Get-Content -LiteralPath $applicationLogContractPath -Raw
$integrityContractText = Get-Content -LiteralPath $integrityContractPath -Raw
$terminalContractText = Get-Content -LiteralPath $terminalContractPath -Raw
$appText = Get-Content -LiteralPath $appPath -Raw
$settingsPanelText = Get-Content -LiteralPath $settingsPanelPath -Raw
$aiHistoryPageText = Get-Content -LiteralPath $aiHistoryPagePath -Raw
$commandHistoryPanelText = Get-Content -LiteralPath $commandHistoryPanelPath -Raw
$commandHistoryCssText = Get-Content -LiteralPath $commandHistoryCssPath -Raw
$disposalReportOverlayText = Get-Content -LiteralPath $disposalReportOverlayPath -Raw
$disposalReportCssText = Get-Content -LiteralPath $disposalReportCssPath -Raw
$snapshotPageText = Get-Content -LiteralPath $snapshotPagePath -Raw
$snapshotCssText = Get-Content -LiteralPath $snapshotCssPath -Raw
$firewallPageText = Get-Content -LiteralPath $firewallPagePath -Raw
$firewallCssText = Get-Content -LiteralPath $firewallCssPath -Raw
$firewallHelpersText = Get-Content -LiteralPath $firewallHelpersPath -Raw
$firewallStateText = Get-Content -LiteralPath $firewallStatePath -Raw
$baselinePageText = Get-Content -LiteralPath $baselinePagePath -Raw
$baselineCssText = Get-Content -LiteralPath $baselineCssPath -Raw
$baselineHelpersText = Get-Content -LiteralPath $baselineHelpersPath -Raw
$baselineStateText = Get-Content -LiteralPath $baselineStatePath -Raw
$middlewarePageText = Get-Content -LiteralPath $middlewarePagePath -Raw
$middlewareHelpersText = Get-Content -LiteralPath $middlewareHelpersPath -Raw
$middlewareStateText = Get-Content -LiteralPath $middlewareStatePath -Raw
$checkAuditPageText = Get-Content -LiteralPath $checkAuditPagePath -Raw
$checkAuditHelpersText = Get-Content -LiteralPath $checkAuditHelpersPath -Raw
$checkAuditStateText = Get-Content -LiteralPath $checkAuditStatePath -Raw
$logAnalysisPageText = Get-Content -LiteralPath $logAnalysisPagePath -Raw
$logAnalysisHelpersText = Get-Content -LiteralPath $logAnalysisHelpersPath -Raw
$logAnalysisStateText = Get-Content -LiteralPath $logAnalysisStatePath -Raw
$kubernetesPageText = Get-Content -LiteralPath $kubernetesPagePath -Raw
$kubernetesHelpersText = Get-Content -LiteralPath $kubernetesHelpersPath -Raw
$kubernetesStateText = Get-Content -LiteralPath $kubernetesStatePath -Raw
$dockerPageText = Get-Content -LiteralPath $dockerPagePath -Raw
$dockerHelpersText = Get-Content -LiteralPath $dockerHelpersPath -Raw
$dockerStateText = Get-Content -LiteralPath $dockerStatePath -Raw
$emergencyCommandPageText = Get-Content -LiteralPath $emergencyCommandPagePath -Raw
$emergencyCommandHelpersText = Get-Content -LiteralPath $emergencyCommandHelpersPath -Raw
$emergencyCommandStateText = Get-Content -LiteralPath $emergencyCommandStatePath -Raw
$packetCapturePageText = Get-Content -LiteralPath $packetCapturePagePath -Raw
$packetCaptureHelpersText = Get-Content -LiteralPath $packetCaptureHelpersPath -Raw
$packetCaptureStateText = Get-Content -LiteralPath $packetCaptureStatePath -Raw
$applicationLogOverlayText = Get-Content -LiteralPath $applicationLogOverlayPath -Raw
$applicationLogHelpersText = Get-Content -LiteralPath $applicationLogHelpersPath -Raw
$applicationLogStateText = Get-Content -LiteralPath $applicationLogStatePath -Raw
$integrityPageText = Get-Content -LiteralPath $integrityPagePath -Raw
$integrityCssText = Get-Content -LiteralPath $integrityCssPath -Raw
$integrityHelpersText = Get-Content -LiteralPath $integrityHelpersPath -Raw
$integrityStateText = Get-Content -LiteralPath $integrityStatePath -Raw
$terminalWindowText = Get-Content -LiteralPath $terminalWindowPath -Raw
$terminalSurfaceText = Get-Content -LiteralPath $terminalSurfacePath -Raw
$terminalControllerText = Get-Content -LiteralPath $terminalControllerPath -Raw
$globalStylesText = Get-Content -LiteralPath $globalStylesPath -Raw
$appTitleBarText = Get-Content -LiteralPath (Join-Path $electronRoot 'src/renderer/AppTitleBar.tsx') -Raw
$themeTokensText = Get-Content -LiteralPath (Join-Path $electronRoot 'src/renderer/theme/themes.css') -Raw
$aiHistoryExportText = Get-Content -LiteralPath $aiHistoryExportPath -Raw
$disposalReportExportText = Get-Content -LiteralPath $disposalReportExportPath -Raw
$applicationLogExportText = Get-Content -LiteralPath $applicationLogExportPath -Raw
$globalText = Get-Content -LiteralPath $globalPath -Raw
$htmlText = Get-Content -LiteralPath $htmlPath -Raw
$terminalHtmlText = Get-Content -LiteralPath $terminalHtmlPath -Raw
$terminalMainText = Get-Content -LiteralPath $terminalMainPath -Raw
$viteText = Get-Content -LiteralPath $vitePath -Raw
$backendLibText = Get-Content -LiteralPath $backendLibPath -Raw
$settingsApiText = Get-Content -LiteralPath $settingsApiPath -Raw
$aiHistoryApiText = Get-Content -LiteralPath $aiHistoryApiPath -Raw
$commandHistoryApiText = Get-Content -LiteralPath $commandHistoryApiPath -Raw
$disposalReportApiText = Get-Content -LiteralPath $disposalReportApiPath -Raw
$snapshotReadApiText = Get-Content -LiteralPath $snapshotReadApiPath -Raw
$firewallReadApiText = Get-Content -LiteralPath $firewallReadApiPath -Raw
$baselineReadApiText = Get-Content -LiteralPath $baselineReadApiPath -Raw
$middlewareReadApiText = Get-Content -LiteralPath $middlewareReadApiPath -Raw
$checkAuditReadApiText = Get-Content -LiteralPath $checkAuditReadApiPath -Raw
$logAnalysisReadApiText = Get-Content -LiteralPath $logAnalysisReadApiPath -Raw
$kubernetesReadApiText = Get-Content -LiteralPath $kubernetesReadApiPath -Raw
$dockerReadApiText = Get-Content -LiteralPath $dockerReadApiPath -Raw
$emergencyCommandApiText = Get-Content -LiteralPath $emergencyCommandApiPath -Raw
$packetCaptureLiveApiText = Get-Content -LiteralPath $packetCaptureLiveApiPath -Raw
$diagnosticLogApiText = Get-Content -LiteralPath $diagnosticLogApiPath -Raw
$integrityApiText = Get-Content -LiteralPath $integrityApiPath -Raw
$backendMainText = Get-Content -LiteralPath $backendMainPath -Raw
$coreSnapshotText = Get-Content -LiteralPath $coreSnapshotPath -Raw
$coreFirewallText = Get-Content -LiteralPath $coreFirewallPath -Raw
$coreBaselineText = Get-Content -LiteralPath $coreBaselinePath -Raw
$coreIntegrityText = Get-Content -LiteralPath $coreIntegrityPath -Raw
$terminalApiText = Get-Content -LiteralPath $terminalApiPath -Raw

foreach ($reason in @(Get-ActiveCiViolation -Text $activeCiText)) {
    Add-GateViolation ".github/workflows/ci.yml $reason"
}

foreach ($reason in @(Get-WebPreferencesViolation -Source $mainText)) {
    Add-GateViolation "electron/src/main/index.ts $reason"
}

$mainWindowStart = $mainText.IndexOf('function createWindow(): void {', [System.StringComparison]::Ordinal)
$mainWindowEnd = $mainText.IndexOf('function writeRequestedSmokeMarker', [System.StringComparison]::Ordinal)
if ($mainWindowStart -lt 0 -or $mainWindowEnd -le $mainWindowStart) {
    Add-GateViolation 'electron/src/main/index.ts must retain the bounded main-window composition block'
} else {
    $mainWindowText = $mainText.Substring($mainWindowStart, $mainWindowEnd - $mainWindowStart)
    foreach ($marker in @(
        'titleBarStyle: "hidden",',
        'titleBarOverlay: {',
        'color: theme.chromeColor,',
        'symbolColor: theme.chromeSymbolColor,',
        'height: TITLE_BAR_HEIGHT,'
    )) {
        if (-not $mainWindowText.Contains($marker, [System.StringComparison]::Ordinal)) {
            Add-GateViolation "electron/src/main/index.ts main window is missing custom-titlebar marker '$marker'"
        }
    }
    if (-not $mainText.Contains('const TITLE_BAR_HEIGHT = 40;', [System.StringComparison]::Ordinal)) {
        Add-GateViolation 'electron/src/main/index.ts must keep the custom title bar exactly 40px tall'
    }
    if ($mainWindowText.Contains('frame: false', [System.StringComparison]::Ordinal)) {
        Add-GateViolation 'electron/src/main/index.ts must retain native window controls instead of exposing renderer window-control IPC'
    }
}

$portablePathsCall = [regex]::Match($mainText, '\bconfigurePortableElectronPaths\s*\(')
$singleInstanceCall = [regex]::Match($mainText, '\bapp\.requestSingleInstanceLock\s*\(')
if (-not $portablePathsCall.Success -or -not $singleInstanceCall.Success -or $portablePathsCall.Index -gt $singleInstanceCall.Index) {
    Add-GateViolation 'electron/src/main/index.ts must configure portable Electron paths before requesting the single-instance lock'
}
foreach ($portablePathName in @('appData', 'userData', 'sessionData', 'temp', 'logs', 'crashDumps')) {
    $marker = "app.setPath(`"$portablePathName`", paths.$portablePathName);"
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts must pin Electron path '$portablePathName' under the portable data root"
    }
}
foreach ($smokeMarker in @(
    'LOVELYRES_SMOKE_READY_ROOT',
    'LOVELYRES_SMOKE_READY_NONCE',
    'fs.realpathSync(path.resolve(os.tmpdir()))',
    'fs.linkSync(temporary, destination)'
)) {
    if (-not $mainText.Contains($smokeMarker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing bounded smoke-marker token '$smokeMarker'"
    }
}
if ($mainText.Contains('LOVELYRES_SMOKE_READY_FILE', [System.StringComparison]::Ordinal) -or
    $mainText.Contains('fs.rmSync(destination)', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'electron/src/main/index.ts contains the retired arbitrary-path/overwrite smoke marker hook'
}
foreach ($marker in @(
    'resolveArchiveRootPath({',
    'createBeforeQuitHandler(',
    'stopBackendWithTerminalWindows()',
    '() => app.quit()'
)) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing lifecycle marker '$marker'"
    }
}
foreach ($marker in @(
    'list: "ai-history.list"',
    'get: "ai-history.get"',
    'planRemove: "ai-history.remove.plan"',
    'planClear: "ai-history.clear.plan"',
    'confirm: "ai-history.mutation.confirm"',
    'cancel: "ai-history.mutation.cancel"',
    'export: "ai-history.export"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one AI history RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'get: "settings.get"',
    'save: "settings.save"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one settings RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'input.platform !== "darwin"',
    '.endsWith(".app")',
    'return pathApi.dirname(candidate);',
    'if (backendStopped) return;',
    'event.preventDefault();'
)) {
    if (-not $appLifecycleText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/app-lifecycle.ts is missing portable lifecycle marker '$marker'"
    }
}
foreach ($marker in @(
    'child.once("exit", onExit);',
    'child.kill("SIGKILL");',
    'const stopPromise = stopChildProcess(child).finally('
)) {
    if (-not $backendClientText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing process-shutdown marker '$marker'"
    }
}
foreach ($marker in @(
    'catalog: "system-info.catalog.get"',
    'summary: "system-info.summary.get"',
    'collect: "system-info.table.collect"',
    'detail: "system-info.detail.get"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one system-info RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'list: "snapshot.list"',
    'detail: "snapshot.detail.get"',
    'diff: "snapshot.forensic.diff"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one snapshot RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'inspect: "firewall.inspect"',
    'listHistory: "firewall.change-history.list"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Firewall RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'catalog: "baseline.catalog.get"',
    'scan: "baseline.scan"',
    'listHistory: "baseline.history.list"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Baseline RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'discover: "middleware.discover"',
    'loadConfiguration: "middleware.configuration.load"',
    'listHistory: "middleware.history.list"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Middleware RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'catalog: "check-audit.catalog.get"',
    'collectStatus: "check-audit.status.collect"',
    'readLog: "check-audit.log.read"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Check Audit RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'discoverSources: "log-analysis.sources.discover"',
    'readSource: "log-analysis.source.read"',
    'correlateSources: "log-analysis.sources.correlate"',
    'searchIocs: "log-analysis.iocs.search"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Log Analysis RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'availability: "kubernetes.availability.get"',
    'listResources: "kubernetes.resources.list"',
    'resourceDetail: "kubernetes.resource.detail.get"',
    'podLogs: "kubernetes.pod.logs.get"'
)) {
    if ([regex]::Matches($backendClientText, [regex]::Escape($marker)).Count -ne 1) {
        Add-GateViolation "electron/src/main/backend-client.ts must pin exactly one Kubernetes RPC marker '$marker'"
    }
}

$htmlPolicy = Get-HtmlCspPolicy -Html $htmlText
if ($null -eq $htmlPolicy) {
    Add-GateViolation 'electron/index.html must contain a double-quoted Content-Security-Policy meta tag'
} else {
    foreach ($reason in @(Get-CspPolicyViolation -Policy $htmlPolicy)) {
        Add-GateViolation "electron/index.html CSP $reason"
    }
}

$mainCspMatch = [regex]::Match(
    $mainText,
    '(?s)\bconst\s+CSP\s*=\s*\[(?<body>.*?)\]\s*\.join\s*\(\s*["''];\s*["'']\s*\)'
)
if (-not $mainCspMatch.Success) {
    Add-GateViolation 'electron/src/main/index.ts must declare the response-header CSP as a literal directive list'
} else {
    $directiveMatches = [regex]::Matches($mainCspMatch.Groups['body'].Value, '"(?<directive>[^"\r\n]+)"')
    $mainPolicy = ($directiveMatches | ForEach-Object { $_.Groups['directive'].Value }) -join '; '
    foreach ($reason in @(Get-CspPolicyViolation -Policy $mainPolicy -RequireFrameAncestors)) {
        Add-GateViolation "electron/src/main/index.ts CSP $reason"
    }
}
$terminalHtmlPolicy = Get-HtmlCspPolicy -Html $terminalHtmlText
if ($null -eq $terminalHtmlPolicy) {
    Add-GateViolation 'electron/terminal.html must contain a double-quoted Content-Security-Policy meta tag'
} else {
    foreach ($reason in @(Get-CspPolicyViolation -Policy $terminalHtmlPolicy -TerminalStyleException)) {
        Add-GateViolation "electron/terminal.html CSP $reason"
    }
}
$terminalMainCspMatch = [regex]::Match(
    $mainText,
    '(?s)\bconst\s+TERMINAL_CSP\s*=\s*\[(?<body>.*?)\]\s*\.join\s*\(\s*["''];\s*["'']\s*\)'
)
if (-not $terminalMainCspMatch.Success) {
    Add-GateViolation 'electron/src/main/index.ts must declare the terminal response-header CSP as a literal directive list'
} else {
    $terminalDirectiveMatches = [regex]::Matches($terminalMainCspMatch.Groups['body'].Value, '"(?<directive>[^"\r\n]+)"')
    $terminalMainPolicy = ($terminalDirectiveMatches | ForEach-Object { $_.Groups['directive'].Value }) -join '; '
    foreach ($reason in @(Get-CspPolicyViolation -Policy $terminalMainPolicy -RequireFrameAncestors -TerminalStyleException)) {
        Add-GateViolation "electron/src/main/index.ts terminal CSP $reason"
    }
    $terminalComparableMainPolicy = $terminalMainPolicy.Replace("; frame-ancestors 'none'", '')
    if ($null -ne $terminalHtmlPolicy -and
        -not [string]::Equals($terminalComparableMainPolicy, $terminalHtmlPolicy, [System.StringComparison]::Ordinal)) {
        Add-GateViolation 'electron/terminal.html meta CSP must exactly match its response-header CSP except frame-ancestors'
    }
}
if ([regex]::Matches($terminalHtmlText, [regex]::Escape("style-src 'self' 'unsafe-inline'"), 'IgnoreCase').Count -ne 1 -or
    [regex]::Matches($mainText, [regex]::Escape("style-src 'self' 'unsafe-inline'"), 'IgnoreCase').Count -ne 1 -or
    $htmlText -match '(?i)unsafe-inline') {
    Add-GateViolation 'the xterm inline-style CSP exception must exist only in terminal.html and TERMINAL_CSP'
}
foreach ($marker in @(
    'else if (isTerminalRendererUrl(rawUrl)) relative = "terminal.html";',
    'terminal: path.resolve(projectRoot, "terminal.html")',
    'src="/src/renderer/terminal-main.tsx"',
    'createRoot(root).render(<TerminalWindow />);',
    '"Content-Security-Policy": [isTerminalRendererUrl(details.url) ? TERMINAL_CSP : CSP]'
)) {
    if (-not ($rendererProtocolText.Contains($marker, [System.StringComparison]::Ordinal) -or
              $viteText.Contains($marker, [System.StringComparison]::Ordinal) -or
              $terminalHtmlText.Contains($marker, [System.StringComparison]::Ordinal) -or
              $terminalMainText.Contains($marker, [System.StringComparison]::Ordinal) -or
              $mainText.Contains($marker, [System.StringComparison]::Ordinal))) {
        Add-GateViolation "Electron terminal-only entry/CSP boundary is missing marker '$marker'"
    }
}
if ($terminalMainText -match '(?i)\bApp\b' -or
    [regex]::Matches($terminalHtmlText, '(?i)<script\b').Count -ne 1 -or
    $terminalHtmlText -match '(?i)<script\b[^>]*(?:unsafe-inline|https?://|data:)') {
    Add-GateViolation 'electron terminal entry must load only its local dedicated module without the main App'
}
if ($mainText -notmatch '\bsetPermissionRequestHandler\s*\(' -or $mainText -notmatch '\bcallback\s*\(\s*false\s*\)') {
    Add-GateViolation 'electron/src/main/index.ts must deny renderer permission requests'
}
if ($mainText -notmatch '\bsetPermissionCheckHandler\s*\(\s*\(\s*\)\s*=>\s*false\s*\)') {
    Add-GateViolation 'electron/src/main/index.ts must deny renderer permission checks'
}

$schemeMatch = [regex]::Match($rendererProtocolText, '(?m)^\s*export\s+const\s+RENDERER_SCHEME\s*=\s*"(?<value>[a-z][a-z0-9+.-]*)"\s*;')
$hostMatch = [regex]::Match($rendererProtocolText, '(?m)^\s*export\s+const\s+RENDERER_HOST\s*=\s*"(?<value>[a-z0-9.-]+)"\s*;')
if (-not $schemeMatch.Success -or $schemeMatch.Groups['value'].Value -ne 'lovelyres') {
    Add-GateViolation 'electron/src/main/renderer-protocol.ts must pin RENDERER_SCHEME to "lovelyres"'
}
if (-not $hostMatch.Success -or $hostMatch.Groups['value'].Value -ne 'app') {
    Add-GateViolation 'electron/src/main/renderer-protocol.ts must pin RENDERER_HOST to "app"'
}
foreach ($marker in @(
    'protocol.registerSchemesAsPrivileged',
    'protocol.handle(RENDERER_SCHEME',
    'resolveRendererAsset(request.url, rendererRoot)',
    'net.fetch(pathToFileURL(asset).toString())',
    '"Content-Security-Policy": [isTerminalRendererUrl(details.url) ? TERMINAL_CSP : CSP]',
    'mainWindow.loadURL(`${RENDERER_SCHEME}://${RENDERER_HOST}/`)'
)) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing local custom-protocol marker '$marker'"
    }
}
foreach ($marker in @('standard: true', 'secure: true', 'supportFetchAPI: true')) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts custom protocol is missing privilege '$marker'"
    }
}
foreach ($marker in @(
    'url.protocol === `${RENDERER_SCHEME}:`',
    'url.host === RENDERER_HOST',
    'decodedRawPath.includes("\\")',
    'segment === ".."',
    'candidate.startsWith(`${normalizedRoot}${path.sep}`)'
)) {
    if (-not $rendererProtocolText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/renderer-protocol.ts is missing trusted local-path marker '$marker'"
    }
}
if ($mainText -match '(?i)\b(?:loadURL|loadFile)\s*\(\s*["'']https?://') {
    Add-GateViolation 'electron/src/main/index.ts loads a remote renderer URL'
}
$trustedLoadMarker = 'mainWindow.loadURL(`${RENDERER_SCHEME}://${RENDERER_HOST}/`)'
$trustedTerminalLoadMarker = 'terminalWindow.loadURL(TERMINAL_WINDOW_URL)'
$loadUrlCount = [regex]::Matches($mainText, '\.loadURL\s*\(').Count
$trustedLoadCount = [regex]::Matches($mainText, [regex]::Escape($trustedLoadMarker)).Count +
    [regex]::Matches($mainText, [regex]::Escape($trustedTerminalLoadMarker)).Count
if ($loadUrlCount -ne $trustedLoadCount -or
    [regex]::Matches($mainText, [regex]::Escape($trustedLoadMarker)).Count -ne 1 -or
    [regex]::Matches($mainText, [regex]::Escape($trustedTerminalLoadMarker)).Count -ne 1) {
    Add-GateViolation 'electron/src/main/index.ts must load every renderer only through lovelyres://app/'
}
if ($mainText -match '\.loadFile\s*\(') {
    Add-GateViolation 'electron/src/main/index.ts must not bypass the custom protocol with loadFile()'
}

$apiMatch = [regex]::Match(
    $preloadText,
    '(?ms)\bconst\s+api\s*:\s*LovelyResApi\s*=\s*Object\.freeze\s*\(\s*\{(?<body>.*?)^\s*\}\s*\)\s*;'
)
if (-not $apiMatch.Success) {
    Add-GateViolation 'electron/src/preload/index.ts must expose one frozen, typed API object'
} else {
    $apiBody = $apiMatch.Groups['body'].Value
    $actualNames = @([regex]::Matches($apiBody, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*:') | ForEach-Object { $_.Groups['name'].Value })
    $expectedNames = @($expectedPreloadBindings | ForEach-Object { $_.Name })
    if (($actualNames -join "`n") -cne ($expectedNames -join "`n")) {
        Add-GateViolation "electron/src/preload/index.ts API keys must be exactly [$($expectedNames -join ', ')]; found [$($actualNames -join ', ')]"
    }
    foreach ($binding in $expectedPreloadBindings) {
        if ($binding.Method -eq 'main-to-renderer') {
            if ($apiBody -notmatch '(?s)\bonBeforeClose\s*:.{0,200}?=>\s*\{' -or
                $apiBody -notmatch '\bipcRenderer\.on\s*\(\s*["'']lovelyres:before-close["'']' -or
                $apiBody -notmatch '\bipcRenderer\.removeListener\s*\(\s*["'']lovelyres:before-close["'']' -or
                $apiBody -notmatch '\bipcRenderer\.send\s*\(\s*["'']lovelyres:before-close-result["'']') {
                Add-GateViolation 'electron/src/preload/index.ts must expose only the fixed before-close request/result handshake'
            }
            if ($mainText -notmatch '\.webContents\.send\s*\(\s*["'']lovelyres:before-close["'']' -or
                $mainText -notmatch '\bipcMain\.on\s*\(\s*["'']lovelyres:before-close-result["'']') {
                Add-GateViolation 'electron/src/main/index.ts must own the fixed before-close request/result handshake'
            }
            continue
        }
        $name = [regex]::Escape($binding.Name)
        $method = [regex]::Escape($binding.Method)
        $channel = [regex]::Escape($binding.Channel)
        $bindingPattern = '(?s)\b{0}\s*:.{{0,300}}?=>.{{0,1000}}?ipcRenderer\.{1}\s*\(\s*["'']{2}["'']' -f $name, $method, $channel
        if ($apiBody -notmatch $bindingPattern) {
            Add-GateViolation "electron/src/preload/index.ts must bind $($binding.Name) only to ipcRenderer.$($binding.Method)('$($binding.Channel)')"
        }
        $registration = [regex]::Escape($binding.Registration)
        $registrationPattern = '\bipcMain\.{0}\s*\(\s*["'']{1}["'']' -f $registration, $channel
        if ($mainText -notmatch $registrationPattern) {
            Add-GateViolation "electron/src/main/index.ts must register $($binding.Channel) with ipcMain.$($binding.Registration)"
        }
    }
    $ordinaryBindingCount = @($expectedPreloadBindings | Where-Object { $_.Method -ne 'main-to-renderer' }).Count
    if ([regex]::Matches($apiBody, '\bipcRenderer\.(?:invoke|send)\s*\(').Count -ne ($ordinaryBindingCount + 2)) {
        Add-GateViolation 'electron/src/preload/index.ts contains an IPC call outside the fixed API allowlist'
    }
}
if ([regex]::Matches($preloadText, '\bcontextBridge\.exposeInMainWorld\s*\(').Count -ne 1 -or
    $preloadText -notmatch '\bcontextBridge\.exposeInMainWorld\s*\(\s*"lovelyres"\s*,\s*api\s*\)') {
    Add-GateViolation 'electron/src/preload/index.ts must expose only the fixed "lovelyres" API'
}
if ($preloadText -match '\bipcRenderer\.(?:once|sendSync|postMessage)\s*\(' -or
    [regex]::Matches($preloadText, '\bipcRenderer\.on\s*\(').Count -ne 1 -or
    $preloadText -notmatch '\bipcRenderer\.on\s*\(\s*["'']lovelyres:before-close["'']') {
    Add-GateViolation 'electron/src/preload/index.ts exposes a forbidden generic or synchronous IPC capability'
}

$terminalPreloadMatch = [regex]::Match(
    $terminalPreloadText,
    '(?ms)\bconst\s+terminalApi\s*:\s*TerminalApi\s*=\s*Object\.freeze\s*\(\s*\{(?<body>.*?)^\s*\}\s*\)\s*;'
)
$expectedTerminalBindings = [ordered]@{
    open = 'lovelyres:terminal:open'
    poll = 'lovelyres:terminal:poll'
    input = 'lovelyres:terminal:input'
    resize = 'lovelyres:terminal:resize'
    search = 'lovelyres:terminal:search'
    copySelection = 'lovelyres:terminal:copy-selection'
    close = 'lovelyres:terminal:close'
    openSftpBrowser = 'lovelyres:terminal:sftp:open'
    listSftpDirectory = 'lovelyres:terminal:sftp:directory:list'
    readSftpText = 'lovelyres:terminal:sftp:text:read'
    downloadSftpEntry = 'lovelyres:terminal:sftp:download'
    planSftpOperation = 'lovelyres:terminal:sftp:operation:plan'
    confirmSftpOperation = 'lovelyres:terminal:sftp:operation:confirm'
    executeSftpOperation = 'lovelyres:terminal:sftp:operation:execute'
    cancelSftpOperation = 'lovelyres:terminal:sftp:operation:cancel'
    stageSftpUpload = 'lovelyres:terminal:sftp:upload:stage'
    openLocalBrowser = 'lovelyres:terminal:local:open'
    listLocalDirectory = 'lovelyres:terminal:local:list'
}
if (-not $terminalPreloadMatch.Success) {
    Add-GateViolation 'electron/src/preload/terminal.ts must expose one frozen, typed terminal API object'
} else {
    $terminalPreloadBody = $terminalPreloadMatch.Groups['body'].Value
    $terminalNames = @([regex]::Matches($terminalPreloadBody, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*:') | ForEach-Object { $_.Groups['name'].Value })
    if (($terminalNames -join "`n") -cne (@($expectedTerminalBindings.Keys) -join "`n")) {
        Add-GateViolation 'electron/src/preload/terminal.ts API keys must be exactly [open, poll, input, resize, search, copySelection, close, openSftpBrowser, listSftpDirectory, readSftpText, downloadSftpEntry, the five operation methods, openLocalBrowser, listLocalDirectory]'
    }
    foreach ($binding in $expectedTerminalBindings.GetEnumerator()) {
        $pattern = '(?s)\b{0}\s*:.{{0,400}}?=>.{{0,400}}?ipcRenderer\.invoke\s*\(\s*["'']{1}["'']' -f [regex]::Escape($binding.Key), [regex]::Escape($binding.Value)
        if ($terminalPreloadBody -notmatch $pattern) {
            Add-GateViolation "electron/src/preload/terminal.ts must bind $($binding.Key) only to $($binding.Value)"
        }
        if ($mainText -notmatch ('\bipcMain\.handle\s*\(\s*["'']{0}["'']' -f [regex]::Escape($binding.Value))) {
            Add-GateViolation "electron/src/main/index.ts must register dedicated terminal channel $($binding.Value)"
        }
    }
    if ([regex]::Matches($terminalPreloadBody, '\bipcRenderer\.invoke\s*\(').Count -ne 18) {
        Add-GateViolation 'electron/src/preload/terminal.ts contains an IPC call outside the exact eighteen-method allowlist'
    }
}
if ([regex]::Matches($terminalPreloadText, '\bcontextBridge\.exposeInMainWorld\s*\(').Count -ne 1 -or
    $terminalPreloadText -notmatch '\bcontextBridge\.exposeInMainWorld\s*\(\s*["'']lovelyresTerminal["'']\s*,\s*terminalApi\s*\)' -or
    $terminalPreloadText -match '\bipcRenderer\.(?:on|once|send|sendSync|postMessage)\s*\(') {
    Add-GateViolation 'electron/src/preload/terminal.ts must expose only the fixed invoke-only lovelyresTerminal API'
}
if ($terminalPreloadText -match '(?i)\b(?:bindingHandle|sessionId|targetGuard|host|path|command|launchToken|handle)\b') {
    Add-GateViolation 'electron/src/preload/terminal.ts exposes a forbidden binding, session, host, path, command, token, or handle field'
}

$contractApiMatch = [regex]::Match($contractText, '(?ms)\bexport\s+interface\s+LovelyResApi\s*\{(?<body>.*?)^\s*\}')
if (-not $contractApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/contract.ts is missing LovelyResApi'
} else {
    $contractNames = @([regex]::Matches($contractApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    $expectedNames = @($expectedPreloadBindings | ForEach-Object { $_.Name })
    if (($contractNames -join "`n") -cne ($expectedNames -join "`n")) {
        Add-GateViolation "electron/src/shared/contract.ts LovelyResApi keys must be exactly [$($expectedNames -join ', ')]"
    }
}
$snapshotApiMatch = [regex]::Match(
    $snapshotReadContractText,
    '(?ms)\bexport\s+interface\s+SnapshotReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $snapshotApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/snapshot-read-contract.ts is missing SnapshotReadApi'
} else {
    $snapshotNames = @([regex]::Matches($snapshotApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($snapshotNames -join "`n") -cne (@('listSnapshots', 'getSnapshotDetail', 'diffForensicSnapshots') -join "`n")) {
        Add-GateViolation 'electron/src/shared/snapshot-read-contract.ts must expose exactly listSnapshots/getSnapshotDetail/diffForensicSnapshots'
    }
    if ($snapshotApiMatch.Groups['body'].Value -notmatch 'listSnapshots\(bindingHandle:\s*string\):\s*Promise<SnapshotListResult>;' -or
        $snapshotApiMatch.Groups['body'].Value -notmatch 'getSnapshotDetail\(bindingHandle:\s*string,\s*snapshotHandle:\s*string\):\s*Promise<SnapshotDetail>;' -or
        $snapshotApiMatch.Groups['body'].Value -notmatch '(?s)diffForensicSnapshots\(\s*bindingHandle:\s*string,\s*input:\s*SnapshotDiffInput,?\s*\):\s*Promise<SnapshotDiffResult>;') {
        Add-GateViolation 'electron/src/shared/snapshot-read-contract.ts must pin the three concrete read-only Promise signatures'
    }
}
foreach ($marker in @(
    'listSnapshots(bindingHandle: string): Promise<SnapshotListResult>;',
    'getSnapshotDetail(bindingHandle: string, snapshotHandle: string): Promise<SnapshotDetail>;',
    'diffForensicSnapshots(',
    'input: SnapshotDiffInput,',
    '): Promise<SnapshotDiffResult>;'
)) {
    if (-not $contractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/contract.ts is missing exact Snapshot API marker '$marker'"
    }
}
if ($snapshotReadContractText -match '(?im)^\s*(?:connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|command|password|apiKey|authorization|digest)\??\s*:') {
    Add-GateViolation 'electron/src/shared/snapshot-read-contract.ts exposes target identity, path, command, secret, authorization, or digest internals'
}
foreach ($channel in @(
    'lovelyres:snapshot:list',
    'lovelyres:snapshot:detail:get',
    'lovelyres:snapshot:forensic:diff'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Snapshot IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Snapshot IPC '$channel'"
    }
}
foreach ($marker in @(
    'hasOnlyKeys(value, ["bindingHandle", "snapshotHandle"])',
    'hasOnlyKeys(value, ["bindingHandle", "input"])',
    'isSnapshotOpaqueHandle(values[0])',
    'isSnapshotDiffInput(value.input)'
)) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing exact Snapshot validation marker '$marker'"
    }
}
foreach ($marker in @(
    'mod snapshot_read_api;',
    'SnapshotReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.snapshot_read.close_binding(&params.binding_handle);',
    'SnapshotBindingParams',
    'SnapshotDetailParams',
    'SnapshotDiffParams',
    'fn snapshot_read_failure(error: SnapshotReadApiError)'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Snapshot boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_DIRECTORY_SNAPSHOTS: usize = 64',
    'MAX_FORENSIC_SNAPSHOTS: usize = 10',
    'SNAPSHOT_TTL: Duration',
    'pub(crate) fn close_binding(&self, binding_handle: &str)'
)) {
    if (-not $snapshotReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/snapshot_read_api.rs is missing bounded Snapshot marker '$marker'"
    }
}
foreach ($marker in @(
    'const REDACTED_LINE: &str = "[SENSITIVE SNAPSHOT TEXT REDACTED]";',
    'const FAILED_COLLECTOR_LINE: &str = "[FORENSIC COLLECTOR FAILED]";',
    'fn forensic_sensitive_values(snapshot: &ForensicSnapshot) -> Vec<String>',
    '.any(|marker| lower.contains(marker.as_str()))'
)) {
    if (-not $snapshotReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/snapshot_read_api.rs is missing collector-safe projection marker '$marker'"
    }
}
# Every collector is bounded plain text. A projection that decides what to show
# from the collector name would be the old fully-redacted policy coming back.
if ($snapshotReadApiText -match 'CollectorProjection::FullyRedacted' -or
    $snapshotReadApiText -match 'fn collector_policy_marker\(') {
    Add-GateViolation 'crates/lovelyres-electron-backend/src/snapshot_read_api.rs must not reintroduce a per-collector redaction policy'
}
if ($snapshotReadContractText -match 'fullyRedactedForensicCollectors' -or
    $snapshotReadContractText -match 'isCollectorPolicyMarker') {
    Add-GateViolation 'electron/src/shared/snapshot-read-contract.ts must not reject a collector for what it collected'
}
foreach ($marker in @('mysql -uroot -pS3cr3t', 'PASSWORD = secret', 'BEGIN OPENSSH PRIVATE KEY', '/etc/shadow')) {
    if (-not $snapshotReadApiText.Contains($marker, [System.StringComparison]::Ordinal) -or
        -not (Get-Content -LiteralPath (Join-Path $electronRoot 'src/shared/snapshot-read-contract.test.ts') -Raw).Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "Snapshot Rust and TypeScript tests must cover hostile collector marker '$marker'"
    }
}
foreach ($marker in @(
    'MAX_SNAPSHOT_DOCUMENT_BYTES: usize = 128 * 1024 * 1024',
    'deserialize_directory_snapshots',
    'deserialize_forensic_snapshots',
    'read_or_default_bounded::<SnapshotDocument>',
    'MAX_FORENSIC_DIFF_INPUT_LINES_PER_FIELD: usize = 2_048',
    'MAX_FORENSIC_DIFF_INPUT_LINES_TOTAL: usize = 8_192'
)) {
    if (-not $coreSnapshotText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-core/src/snapshot.rs is missing pre-projection hardening marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"snapshot".{0,220}<SnapshotPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount SnapshotPage with only the current opaque binding handle and fixed API'
}
if ($snapshotPageText -match '(?i)\b(?:ActiveSshTarget|SnapshotConnection|connectionId|sessionId|TargetGuard|host|port|username|dataRoot|filePath|snapshotId|command|password|apiKey)\b') {
    Add-GateViolation 'electron/src/renderer/SnapshotPage.tsx retains forbidden target identity, path, raw snapshot, command, or secret state'
}
if ($snapshotPageText -match '(?i)\b(?:createSnapshot|deleteSnapshot|restoreSnapshot|exportSnapshot|executeSnapshot)\b' -or
    $snapshotPageText -match '(?i)\b(?:innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/SnapshotPage.tsx exceeds the read-only plain-text Phase 1 surface'
}
$firewallApiMatch = [regex]::Match(
    $firewallReadContractText,
    '(?ms)\bexport\s+interface\s+FirewallReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $firewallApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/firewall-read-contract.ts is missing FirewallReadApi'
} else {
    $firewallNames = @([regex]::Matches($firewallApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($firewallNames -join "`n") -cne (@('inspectFirewall', 'listFirewallChangeHistory') -join "`n")) {
        Add-GateViolation 'electron/src/shared/firewall-read-contract.ts must expose exactly inspectFirewall/listFirewallChangeHistory'
    }
    if ($firewallApiMatch.Groups['body'].Value -notmatch 'inspectFirewall\(bindingHandle:\s*string\):\s*Promise<FirewallInspection>;' -or
        $firewallApiMatch.Groups['body'].Value -notmatch 'listFirewallChangeHistory\(bindingHandle:\s*string\):\s*Promise<FirewallHistory>;' -or
        $firewallApiMatch.Groups['body'].Value -match '(?i)\b(?:path|command|terminal|export|plan|confirm|execute|mutation|session|guard|target)\b') {
        Add-GateViolation 'electron/src/shared/firewall-read-contract.ts must pin two concrete opaque-binding read-only signatures'
    }
}
foreach ($marker in @(
    'inspectFirewall(bindingHandle: string): Promise<FirewallInspection>;',
    'listFirewallChangeHistory(bindingHandle: string): Promise<FirewallHistory>;'
)) {
    if (-not $contractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/contract.ts is missing exact Firewall API marker '$marker'"
    }
}
foreach ($channel in @(
    'lovelyres:firewall:inspect',
    'lovelyres:firewall:change-history:list'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Firewall IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Firewall IPC '$channel'"
    }
}
if ([regex]::Matches($mainText, 'values\.length\s*!==\s*1\s*\|\|\s*!isFirewallOpaqueHandle\(values\[0\]\)').Count -ne 2) {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Firewall IPC ingredients and accept only one canonical binding handle'
}
foreach ($marker in @(
    'mod firewall_read_api;',
    'FirewallReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.firewall_read.close_binding(&params.binding_handle);',
    'FirewallBindingParams',
    '#[serde(rename_all = "camelCase", deny_unknown_fields)]',
    'fn firewall_read_failure(error: FirewallReadApiError)',
    'firewall.inspect',
    'firewall.change-history.list'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Firewall boundary marker '$marker'"
    }
}
if ($backendLibText -notmatch '(?s)self\.snapshot_read\.close_binding\(&params\.binding_handle\);\s*self\.firewall_read\.close_binding\(&params\.binding_handle\);\s*self\.baseline_read\.close_binding\(&params\.binding_handle\);\s*self\.middleware_read\.close_binding\(&params\.binding_handle\);\s*self\.check_audit_read\.close_binding\(&params\.binding_handle\);\s*self\.integrity\.close_binding\(&params\.binding_handle\);\s*self\.log_analysis_read\.close_binding\(&params\.binding_handle\);\s*self\.kubernetes_read\.close_binding\(&params\.binding_handle\);\s*self\.emergency_command\.close_binding\(&params\.binding_handle\);\s*self\.docker_read\.close_binding\(&params\.binding_handle\);\s*self\.sftp_browser\.close_binding\(&params\.binding_handle\);\s*self\.packet_capture_live\s*\.close_binding\(&params\.binding_handle\)\s*\.await;\s*self\.ssh\s*\.disconnect_binding') {
    Add-GateViolation 'SSH disconnect must eagerly close Snapshot, Firewall, Baseline, Middleware, Check Audit, File Integrity, Log Analysis, Kubernetes, Emergency Commands, Docker, Quick Detection, SFTP browser, and Packet Capture capabilities before the real disconnect'
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_HISTORY_ENTRIES: usize = 256',
    'MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024',
    'MAX_READS_PER_BINDING: usize = 2',
    'pub(crate) fn close_binding(&self, binding_handle: &str)'
)) {
    if (-not $firewallReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/firewall_read_api.rs is missing bounded Firewall marker '$marker'"
    }
}
foreach ($marker in @(
    'MAX_FIREWALL_DOCUMENT_BYTES: usize = 4 * 1024 * 1024',
    'MAX_RECORDS: usize = 256',
    '#[serde(deserialize_with = "deserialize_firewall_changes")]',
    'fn deserialize_firewall_changes',
    'read_or_default_bounded::<StoredFirewall>',
    'fn load_stored_firewall(&self)',
    'encoded_firewall_document_is_rejected_before_json_decode',
    'stored_change_limit_rejects_257_on_every_load_path_without_echo',
    'exactly_256_stored_changes_are_valid_on_every_load_path'
)) {
    if (-not $coreFirewallText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-core/src/firewall.rs is missing pre-allocation Firewall hardening marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"firewall".{0,260}<FirewallPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}\s+writeClipboard=\{window\.lovelyres\.writeClipboard\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount FirewallPage with only the current opaque binding handle and fixed read/clipboard APIs'
}
if ($firewallPageText -match '(?i)\b(?:SshTargetSummary|FirewallReadConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|password|apiKey)\b' -or
    $firewallPageText -match '(?i)\b(?:planFirewall|confirmFirewall|executeFirewall|mutateFirewall|exportFirewall|openFirewallTerminal|readFirewallFile|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/FirewallPage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'MAX_FIREWALL_CLIPBOARD_BYTES = 128 * 1_024',
    'boundFirewallText(inspection.rules, MAX_FIREWALL_CLIPBOARD_BYTES)',
    'return { text, truncated: text !== inspection.rules };'
)) {
    if (-not $firewallHelpersText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/firewall-read-helpers.ts is missing UTF-8-safe clipboard marker '$marker'"
    }
}
if (-not $firewallStateText.Contains('128 KiB 限制安全截断并复制', [System.StringComparison]::Ordinal) -or
    -not $firewallPageText.Contains('await writeClipboard(copy.text);', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Firewall copy must use the existing 128 KiB main clipboard boundary and explicitly report truncation'
}
$baselineApiMatch = [regex]::Match(
    $baselineReadContractText,
    '(?ms)\bexport\s+interface\s+BaselineReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $baselineApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/baseline-read-contract.ts is missing BaselineReadApi'
} else {
    $baselineNames = @([regex]::Matches($baselineApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($baselineNames -join "`n") -cne (@('getBaselineCatalog', 'scanBaseline', 'listBaselineHistory') -join "`n")) {
        Add-GateViolation 'electron/src/shared/baseline-read-contract.ts must expose exactly getBaselineCatalog/scanBaseline/listBaselineHistory'
    }
    if ($baselineApiMatch.Groups['body'].Value -notmatch 'getBaselineCatalog\(\):\s*Promise<unknown>;' -or
        $baselineApiMatch.Groups['body'].Value -notmatch 'scanBaseline\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $baselineApiMatch.Groups['body'].Value -notmatch 'listBaselineHistory\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $baselineApiMatch.Groups['body'].Value -match '(?i)\b(?:path|command|terminal|export|plan|confirm|execute|mutation|session|guard|target)\b') {
        Add-GateViolation 'electron/src/shared/baseline-read-contract.ts must pin three raw-unknown responses behind strict validators'
    }
}
foreach ($marker in @(
    'getBaselineCatalog(): Promise<BaselineCatalog>;',
    'scanBaseline(bindingHandle: string): Promise<BaselineScan>;',
    'listBaselineHistory(bindingHandle: string): Promise<BaselineHistory>;'
)) {
    if (-not $contractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/contract.ts is missing exact Baseline API marker '$marker'"
    }
}
foreach ($channel in @(
    'lovelyres:baseline:catalog:get',
    'lovelyres:baseline:scan',
    'lovelyres:baseline:history:list'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Baseline IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Baseline IPC '$channel'"
    }
}
if ($mainText -notmatch '(?s)ipcMain\.handle\("lovelyres:baseline:catalog:get".{0,240}?values\.length\s*!==\s*0' -or
    [regex]::Matches($mainText, 'values\.length\s*!==\s*1\s*\|\|\s*!isBaselineOpaqueHandle\(values\[0\]\)').Count -ne 2) {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Baseline IPC ingredients with exact arity zero/one validators'
}
foreach ($marker in @(
    'mod baseline_read_api;',
    'BaselineReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.baseline_read.close_binding(&params.binding_handle);',
    'BaselineBindingParams',
    'fn baseline_read_failure(error: BaselineReadApiError)',
    'baseline.catalog.get',
    'baseline.scan',
    'baseline.history.list'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Baseline boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_CATALOG_ITEMS: usize = 64',
    'MAX_HISTORY_ENTRIES: usize = 256',
    'MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024',
    'MAX_READS_PER_BINDING: usize = 1',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'SnapshotData::History',
    'if let Err(error) = self.validate_binding(&scope)'
)) {
    if (-not $baselineReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/baseline_read_api.rs is missing bounded Baseline marker '$marker'"
    }
}
$baselineTestMarker = $baselineReadApiText.IndexOf('#[cfg(test)]', [System.StringComparison]::Ordinal)
$baselineReadProductionText = if ($baselineTestMarker -ge 0) {
    $baselineReadApiText.Substring(0, $baselineTestMarker)
} else {
    $baselineReadApiText
}
if ($baselineReadProductionText -match '(?m)^\s*History\s*\{' -or
    [regex]::Matches($baselineReadProductionText, [regex]::Escape('if let Err(error) = self.validate_binding(&scope)')).Count -ne 2) {
    Add-GateViolation 'Baseline Phase 1 must not retain raw history records and must reject late scan/history results after insertion'
}
foreach ($marker in @(
    'MAX_BASELINE_HISTORY_DOCUMENT_BYTES: usize = 4 * 1024 * 1024',
    'MAX_HISTORY: usize = 256',
    '#[serde(deserialize_with = "deserialize_baseline_history_changes")]',
    'fn deserialize_baseline_history_changes',
    'read_or_default_bounded::<StoredBaselineHistory>',
    'fn load_stored_baseline_history(&self)',
    'encoded_baseline_history_is_rejected_before_json_decode',
    'stored_history_limit_rejects_257_on_every_load_path_without_echo',
    'exactly_256_stored_history_records_are_valid_on_every_load_path'
)) {
    if (-not $coreBaselineText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-core/src/baseline.rs is missing pre-allocation Baseline hardening marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"baseline-quick-edit".{0,260}<BaselinePage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount BaselinePage with only the current opaque binding handle and fixed API'
}
if ($baselinePageText -match '(?i)\b(?:SshTargetSummary|BaselineConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|recordId|operationId|digest|apiKey)\b' -or
    $baselinePageText -match '(?i)\b(?:planBaseline|confirmBaseline|executeBaseline|restoreBaseline|reloadBaseline|exportBaseline|openBaselineTerminal|readBaselineFile|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/BaselinePage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : baselineScope(bindingHandle);',
    'dispatch({ type: "deactivated", scope });',
    'scanBaseline(bindingHandle)',
    'listBaselineHistory(bindingHandle)'
)) {
    if (-not $baselinePageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/BaselinePage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $baselineStateText.Contains('| { type: "deactivated"; scope: string | null }', [System.StringComparison]::Ordinal) -or
    -not $baselineHelpersText.Contains('export function baselineScope(bindingHandle: string): string', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Baseline renderer lifecycle must scope and deactivate only by opaque binding handle'
}
$middlewareApiMatch = [regex]::Match(
    $middlewareReadContractText,
    '(?ms)\bexport\s+interface\s+MiddlewareReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $middlewareApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/middleware-read-contract.ts is missing MiddlewareReadApi'
} else {
    $middlewareNames = @([regex]::Matches($middlewareApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($middlewareNames -join "`n") -cne (@('discoverMiddleware', 'loadMiddlewareConfiguration', 'listMiddlewareHistory') -join "`n")) {
        Add-GateViolation 'electron/src/shared/middleware-read-contract.ts must expose exactly discoverMiddleware/loadMiddlewareConfiguration/listMiddlewareHistory'
    }
    if ($middlewareApiMatch.Groups['body'].Value -notmatch 'discoverMiddleware\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $middlewareApiMatch.Groups['body'].Value -notmatch '(?s)loadMiddlewareConfiguration\(\s*bindingHandle:\s*string,\s*discoveryHandle:\s*string,\s*instanceHandle:\s*string,\s*\):\s*Promise<unknown>;' -or
        $middlewareApiMatch.Groups['body'].Value -notmatch 'listMiddlewareHistory\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $middlewareApiMatch.Groups['body'].Value -match '(?i)\b(?:path|command|terminal|export|plan|confirm|execute|mutation|session|guard|target|secret)\b') {
        Add-GateViolation 'electron/src/shared/middleware-read-contract.ts must pin three raw-unknown responses behind strict validators and opaque handles'
    }
}
foreach ($marker in @(
    'discoverMiddleware(bindingHandle: string): Promise<MiddlewareDiscovery>;',
    '): Promise<MiddlewareConfiguration>;',
    'listMiddlewareHistory(bindingHandle: string): Promise<MiddlewareHistory>;'
)) {
    if (-not $contractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/contract.ts is missing exact Middleware API marker '$marker'"
    }
}
foreach ($channel in @(
    'lovelyres:middleware:discover',
    'lovelyres:middleware:configuration:load',
    'lovelyres:middleware:history:list'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Middleware IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Middleware IPC '$channel'"
    }
}
if ([regex]::Matches($mainText, 'values\.length\s*!==\s*1\s*\|\|\s*!isMiddlewareOpaqueHandle\(values\[0\]\)').Count -ne 2 -or
    $mainText -notmatch '(?s)ipcMain\.handle\(\s*"lovelyres:middleware:configuration:load".{0,900}?hasOnlyKeys\(value, \["bindingHandle", "discoveryHandle", "instanceHandle"\]\).{0,500}?isMiddlewareOpaqueHandle\(value\.instanceHandle\)') {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Middleware IPC ingredients with exact one/object validators'
}
foreach ($marker in @(
    'mod middleware_read_api;',
    'MiddlewareReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.middleware_read.close_binding(&params.binding_handle);',
    'MiddlewareBindingParams',
    'MiddlewareConfigurationParams',
    'fn middleware_read_failure(error: MiddlewareReadApiError)',
    'middleware.discover',
    'middleware.configuration.load',
    'middleware.history.list'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Middleware boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_DISCOVERY_INSTANCES: usize = 32',
    'MAX_CONFIGURATION_RESPONSE_BYTES: usize = 1024 * 1024',
    'MAX_GLOBAL_READS: usize = 4',
    'MAX_READS_PER_BINDING: usize = 1',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'self.verify_instance_access(&access)?;'
)) {
    if (-not $middlewareReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/middleware_read_api.rs is missing bounded Middleware marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"middleware".{0,300}<MiddlewarePage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount MiddlewarePage with only the current opaque binding handle and fixed API'
}
if ($middlewarePageText -match '(?i)\b(?:SshTargetSummary|MiddlewareConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|operationId|digest|apiKey)\b' -or
    $middlewarePageText -match '(?i)\b(?:planMiddleware|confirmMiddleware|executeMiddleware|restoreMiddleware|exportMiddleware|openMiddlewareTerminal|readMiddlewareFile|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/MiddlewarePage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : middlewareScope(bindingHandle);',
    'discoverMiddleware(bindingHandle)',
    'loadMiddlewareConfiguration(',
    'listMiddlewareHistory(bindingHandle)'
)) {
    if (-not $middlewarePageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/MiddlewarePage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $middlewareHelpersText.Contains('export function middlewareScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $middlewareStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Middleware renderer lifecycle must scope only by opaque binding handle'
}
$checkAuditApiMatch = [regex]::Match(
    $checkAuditReadContractText,
    '(?ms)\bexport\s+interface\s+CheckAuditReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $checkAuditApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/check-audit-read-contract.ts is missing CheckAuditReadApi'
} else {
    $checkAuditNames = @([regex]::Matches($checkAuditApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($checkAuditNames -join "`n") -cne (@('getCheckAuditCatalog', 'collectCheckAuditStatus', 'readCheckAuditLog') -join "`n")) {
        Add-GateViolation 'electron/src/shared/check-audit-read-contract.ts must expose exactly getCheckAuditCatalog/collectCheckAuditStatus/readCheckAuditLog'
    }
    if ($checkAuditApiMatch.Groups['body'].Value -notmatch 'getCheckAuditCatalog\(bindingHandle:\s*string,\s*input:\s*CheckAuditCatalogInput\):\s*Promise<unknown>;' -or
        $checkAuditApiMatch.Groups['body'].Value -notmatch 'collectCheckAuditStatus\(bindingHandle:\s*string,\s*snapshotHandle:\s*string\):\s*Promise<unknown>;' -or
        $checkAuditApiMatch.Groups['body'].Value -notmatch '(?s)readCheckAuditLog\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*input:\s*CheckAuditLogInput,\s*\):\s*Promise<unknown>;' -or
        $checkAuditApiMatch.Groups['body'].Value -match '(?i)\b(?:path|commandLine|terminal|export|plan|confirm|execute|mutation|session|guard|target|secret)\b') {
        Add-GateViolation 'electron/src/shared/check-audit-read-contract.ts must pin three raw-unknown responses behind strict validators and opaque handles'
    }
}
foreach ($marker in @(
    '): Promise<CheckAuditCatalog>;',
    '): Promise<CheckAuditStatus>;',
    '): Promise<CheckAuditLogResult>;'
)) {
    if (-not $contractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/contract.ts is missing exact Check Audit API marker '$marker'"
    }
}
foreach ($channel in @(
    'lovelyres:check-audit:catalog:get',
    'lovelyres:check-audit:status:collect',
    'lovelyres:check-audit:log:read'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Check Audit IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Check Audit IPC '$channel'"
    }
}
$checkAuditMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:check-audit:catalog:get"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:log-analysis:sources:discover"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:check-audit:catalog:get"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($checkAuditMainBoundary, 'values\.length\s*!==\s*1').Count -ne 3 -or
    -not $checkAuditMainBoundary.Contains('hasOnlyKeys(value, ["bindingHandle", "input"])', [System.StringComparison]::Ordinal) -or
    -not $checkAuditMainBoundary.Contains('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle"])', [System.StringComparison]::Ordinal) -or
    -not $checkAuditMainBoundary.Contains('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"])', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Check Audit IPC ingredients with three exact object validators'
}
foreach ($marker in @(
    'mod check_audit_read_api;',
    'CheckAuditReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.check_audit_read.close_binding(&params.binding_handle);',
    'CheckAuditCatalogParams',
    'CheckAuditSnapshotParams',
    'CheckAuditLogParams',
    'fn check_audit_read_failure(error: CheckAuditReadApiError)',
    'check-audit.catalog.get',
    'check-audit.status.collect',
    'check-audit.log.read'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Check Audit boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_COMMANDS: usize = 32',
    'MAX_SNAPSHOTS: usize = 8',
    'MAX_REGISTRY_BYTES: usize = 512 * 1024',
    'MAX_GLOBAL_READS: usize = 8',
    'MAX_READS_PER_BINDING: usize = 2',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'self.verify_access(&access, &commands)?;'
)) {
    if (-not $checkAuditReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/check_audit_read_api.rs is missing bounded Check Audit marker '$marker'"
    }
}
if (-not $checkAuditReadContractText.Contains('value.matchedSuspiciousCount <= value.suspiciousCount', [System.StringComparison]::Ordinal) -or
    -not $checkAuditReadContractText.Contains('let remainingCycleCount = value.fetchedCount;', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Check Audit log validator must reject impossible suspicious and cycle aggregates without overflow-prone summation'
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"check-audit".{0,300}<CheckAuditPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount CheckAuditPage with only the current opaque binding handle and fixed API'
}
if ($checkAuditPageText -match '(?i)\b(?:SshTargetSummary|CheckAuditConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|operationId|digest|apiKey)\b' -or
    $checkAuditPageText -match '(?i)\b(?:planCheckAudit|confirmCheckAudit|executeCheckAudit|restoreCheckAudit|exportCheckAudit|openCheckAuditTerminal|readCheckAuditFile|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/CheckAuditPage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : checkAuditScope(bindingHandle);',
    'getCheckAuditCatalog(bindingHandle,',
    'collectCheckAuditStatus(bindingHandle, snapshotHandle)',
    'readCheckAuditLog(bindingHandle, snapshotHandle, request.input)'
)) {
    if (-not $checkAuditPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/CheckAuditPage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $checkAuditHelpersText.Contains('export function checkAuditScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $checkAuditStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Check Audit renderer lifecycle must scope only by opaque binding handle'
}
$logAnalysisApiMatch = [regex]::Match(
    $logAnalysisReadContractText,
    '(?ms)\bexport\s+interface\s+LogAnalysisReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $logAnalysisApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/log-analysis-read-contract.ts is missing LogAnalysisReadApi'
} else {
    $logAnalysisNames = @([regex]::Matches($logAnalysisApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($logAnalysisNames -join "`n") -cne (@('discoverLogSources', 'readLogSource', 'correlateLogSources', 'searchLogIocs') -join "`n")) {
        Add-GateViolation 'electron/src/shared/log-analysis-read-contract.ts must expose exactly discoverLogSources/readLogSource/correlateLogSources/searchLogIocs'
    }
    if ($logAnalysisApiMatch.Groups['body'].Value -notmatch 'discoverLogSources\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $logAnalysisApiMatch.Groups['body'].Value -notmatch '(?s)readLogSource\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*sourceHandle:\s*string,\s*input:\s*LogSourceReadInput,\s*\):\s*Promise<unknown>;' -or
        $logAnalysisApiMatch.Groups['body'].Value -notmatch '(?s)correlateLogSources\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*input:\s*LogCorrelationInput,\s*\):\s*Promise<unknown>;' -or
        $logAnalysisApiMatch.Groups['body'].Value -notmatch '(?s)searchLogIocs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*input:\s*LogIocSearchInput,\s*\):\s*Promise<unknown>;' -or
        $logAnalysisApiMatch.Groups['body'].Value -match '(?i)\b(?:remotePath|command|commandLine|terminal|export|plan|confirm|execute|mutation|session|guard|target|secret)\b') {
        Add-GateViolation 'electron/src/shared/log-analysis-read-contract.ts must pin four raw-unknown responses behind strict validators and opaque handles'
    }
}
foreach ($pattern in @(
    'discoverLogSources\(bindingHandle:\s*string\):\s*Promise<LogSourceSnapshot>;',
    '(?s)readLogSource\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*sourceHandle:\s*string,\s*input:\s*LogSourceReadInput,\s*\):\s*Promise<LogSourceReadResult>;',
    '(?s)correlateLogSources\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*input:\s*LogCorrelationInput,\s*\):\s*Promise<LogCorrelationResult>;',
    '(?s)searchLogIocs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*input:\s*LogIocSearchInput,\s*\):\s*Promise<LogIocSearchResult>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Log Analysis API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:log-analysis:sources:discover',
    'lovelyres:log-analysis:source:read',
    'lovelyres:log-analysis:sources:correlate',
    'lovelyres:log-analysis:iocs:search'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Log Analysis IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Log Analysis IPC '$channel'"
    }
}
$logAnalysisMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:log-analysis:sources:discover"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:kubernetes:availability:get"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:log-analysis:sources:discover"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($logAnalysisMainBoundary, 'values\.length\s*!==\s*1').Count -ne 4 -or
    [regex]::Matches($logAnalysisMainBoundary, '!isLogAnalysisOpaqueHandle\(values\[0\]\)').Count -ne 1 -or
    -not $logAnalysisMainBoundary.Contains('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "sourceHandle", "input"])', [System.StringComparison]::Ordinal) -or
    [regex]::Matches($logAnalysisMainBoundary, [regex]::Escape('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "input"])')).Count -ne 2 -or
    [regex]::Matches($logAnalysisMainBoundary, 'isLogSourceReadInput\(value\.input\)').Count -ne 1 -or
    [regex]::Matches($logAnalysisMainBoundary, 'isLogCorrelationInput\(value\.input\)').Count -ne 1 -or
    [regex]::Matches($logAnalysisMainBoundary, 'isLogIocSearchInput\(value\.input\)').Count -ne 1) {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Log Analysis IPC ingredients with one exact handle and three exact object validators'
}
foreach ($marker in @(
    'mod log_analysis_read_api;',
    'LogAnalysisReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.log_analysis_read.close_binding(&params.binding_handle);',
    'LogAnalysisBindingParams',
    'LogAnalysisSourceReadParams',
    'LogAnalysisCorrelationParams',
    'LogAnalysisIocSearchParams',
    'fn log_analysis_read_failure(error: LogAnalysisReadApiError)',
    'log-analysis.sources.discover',
    'log-analysis.source.read',
    'log-analysis.sources.correlate',
    'log-analysis.iocs.search'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Log Analysis boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_SNAPSHOTS: usize = 8',
    'MAX_SNAPSHOT_BYTES: usize = 1024 * 1024',
    'MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024',
    'MAX_ACTIVE_READS: usize = 3',
    'MAX_ACTIVE_DISCOVERIES: usize = 2',
    'MAX_FILE_SOURCES: usize = 100',
    'MAX_PAGE_SIZE: usize = 200',
    'MAX_CORRELATION_SOURCES: usize = 8',
    'MAX_CORRELATION_ENTRIES: usize = 1_000',
    'MAX_IOC_PAIRS: usize = 64',
    'MAX_IOC_RESULTS: usize = 64',
    'SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60)',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'self.verify_source(&access, source_handle, &source)?;',
    'self.verify_sources(&access, &sources)?;',
    '.list_files(&session)',
    '.read_file(&session',
    '.read_journal(&session',
    '.analyze_multi(',
    '.search_iocs('
)) {
    if (-not $logAnalysisReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/log_analysis_read_api.rs is missing bounded Log Analysis marker '$marker'"
    }
}
foreach ($marker in @(
    'export function isLogSourceReadInput',
    'export function isLogCorrelationInput',
    'export function isLogIocSearchInput',
    'export function isLogSourceSnapshot',
    'export function isLogSourceReadResult',
    'export function isLogCorrelationResult',
    'export function isLogIocSearchResult',
    'value.sources.length > 101',
    'value.entries.length > 200',
    'value.entries.length > 1_000',
    'value.results.length > 64',
    'withinTextBudget('
)) {
    if (-not $logAnalysisReadContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/log-analysis-read-contract.ts is missing strict bounded validator marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"log-analysis".{0,300}<LogAnalysisPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount LogAnalysisPage with only the current opaque binding handle and fixed API'
}
if ($logAnalysisPageText -match '(?i)\b(?:SshTargetSummary|LogAnalysisConnection|connectionId|sessionId|targetGuard|generation|host|port|dataRoot|filePath|remotePath|operationId|digest|apiKey)\b' -or
    $logAnalysisPageText -match '(?i)\b(?:analyzeLogWithAi|addLogRule|removeLogRule|mutateLogRule|planLogRule|confirmLogRule|executeLogRule|exportLogAnalysis|openLogFile|openLogTerminal|launchLogTerminal|executeLogCommand|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/LogAnalysisPage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : logAnalysisScope(bindingHandle);',
    'api.discoverLogSources(bindingHandle)',
    'api.readLogSource(',
    'api.correlateLogSources(bindingHandle, snapshotHandle, input)',
    'api.searchLogIocs(bindingHandle, snapshotHandle, input)'
)) {
    if (-not $logAnalysisPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/LogAnalysisPage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $logAnalysisHelpersText.Contains('export function logAnalysisScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $logAnalysisStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Log Analysis renderer lifecycle must scope only by opaque binding handle'
}
$kubernetesApiMatch = [regex]::Match(
    $kubernetesReadContractText,
    '(?ms)\bexport\s+interface\s+KubernetesReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $kubernetesApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/kubernetes-read-contract.ts is missing KubernetesReadApi'
} else {
    $kubernetesNames = @([regex]::Matches($kubernetesApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($kubernetesNames -join "`n") -cne (@('getKubernetesAvailability', 'listKubernetesResources', 'getKubernetesResourceDetail', 'getKubernetesPodLogs') -join "`n")) {
        Add-GateViolation 'electron/src/shared/kubernetes-read-contract.ts must expose exactly availability/list/detail/pod-logs'
    }
    if ($kubernetesApiMatch.Groups['body'].Value -notmatch 'getKubernetesAvailability\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $kubernetesApiMatch.Groups['body'].Value -notmatch 'listKubernetesResources\(bindingHandle:\s*string,\s*input:\s*KubernetesListInput\):\s*Promise<unknown>;' -or
        $kubernetesApiMatch.Groups['body'].Value -notmatch '(?s)getKubernetesResourceDetail\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*rowHandle:\s*string,\s*\):\s*Promise<unknown>;' -or
        $kubernetesApiMatch.Groups['body'].Value -notmatch '(?s)getKubernetesPodLogs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*rowHandle:\s*string,\s*\):\s*Promise<unknown>;' -or
        $kubernetesApiMatch.Groups['body'].Value -match '(?i)\b(?:command|commandLine|filePath|remotePath|terminal|export|scale|restart|delete|cordon|drain|execute|mutation|session|guard|target|secret)\b') {
        Add-GateViolation 'electron/src/shared/kubernetes-read-contract.ts must pin four raw-unknown responses behind strict validators and opaque handles'
    }
}
foreach ($pattern in @(
    'getKubernetesAvailability\(bindingHandle:\s*string\):\s*Promise<KubernetesAvailability>;',
    '(?s)listKubernetesResources\(\s*bindingHandle:\s*string,\s*input:\s*KubernetesListInput,\s*\):\s*Promise<KubernetesSnapshot>;',
    '(?s)getKubernetesResourceDetail\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*rowHandle:\s*string,\s*\):\s*Promise<KubernetesTextResult>;',
    '(?s)getKubernetesPodLogs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*rowHandle:\s*string,\s*\):\s*Promise<KubernetesTextResult>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Kubernetes API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:kubernetes:availability:get',
    'lovelyres:kubernetes:resources:list',
    'lovelyres:kubernetes:resource:detail:get',
    'lovelyres:kubernetes:pod:logs:get'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Kubernetes IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Kubernetes IPC '$channel'"
    }
}
$kubernetesMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:kubernetes:availability:get"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:docker:containers:refresh"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:kubernetes:availability:get"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($kubernetesMainBoundary, 'values\.length\s*!==\s*1').Count -ne 4 -or
    [regex]::Matches($kubernetesMainBoundary, '!isKubernetesOpaqueHandle\(values\[0\]\)').Count -ne 1 -or
    [regex]::Matches($kubernetesMainBoundary, [regex]::Escape('hasOnlyKeys(value, ["bindingHandle", "input"])')).Count -ne 1 -or
    [regex]::Matches($kubernetesMainBoundary, [regex]::Escape('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "rowHandle"])')).Count -ne 2 -or
    [regex]::Matches($kubernetesMainBoundary, 'isKubernetesListInput\(value\.input\)').Count -ne 1) {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Kubernetes IPC ingredients with one exact handle and three exact object validators'
}
foreach ($marker in @(
    'mod kubernetes_read_api;',
    'KubernetesReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.kubernetes_read.close_binding(&params.binding_handle);',
    'KubernetesBindingParams',
    'KubernetesListParams',
    'KubernetesRowParams',
    'fn kubernetes_read_failure(error: KubernetesReadApiError)',
    'kubernetes.availability.get',
    'kubernetes.resources.list',
    'kubernetes.resource.detail.get',
    'kubernetes.pod.logs.get',
    'source: None'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Kubernetes boundary/redaction marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_ROWS: usize = 500',
    'MAX_LIST_BYTES: usize = 2 * 1024 * 1024',
    'MAX_DETAIL_BYTES: usize = 256 * 1024',
    'MAX_LOG_BYTES: usize = 512 * 1024',
    'MAX_SNAPSHOTS: usize = 24',
    'MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024',
    'MAX_REGISTRY_BYTES: usize = 32 * 1024 * 1024',
    'MAX_GLOBAL_READS: usize = 8',
    'MAX_READS_PER_BINDING: usize = 4',
    'SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60)',
    'REDACTED_KUBERNETES_TEXT',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    '.availability(&session)',
    '.namespaces(&session, MAX_ROWS)',
    '.pods(&session, &namespace_scope, MAX_ROWS)',
    '.deployments(&session, &namespace_scope, MAX_ROWS)',
    '.nodes(&session, MAX_ROWS)',
    '.detail(&session, &request)',
    '.pod_logs(&session, &request)',
    'sensitive_literals()'
)) {
    if (-not $kubernetesReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/kubernetes_read_api.rs is missing bounded/redacted Kubernetes marker '$marker'"
    }
}
foreach ($marker in @(
    'export function isKubernetesListInput',
    'export function isKubernetesAvailability',
    'export function isKubernetesSnapshot',
    'export function isKubernetesTextResult',
    'value.rows.length !== value.displayed',
    'unsigned(value.displayed, 500)',
    'jsonBytesAtMost(value, 2 * 1_024 * 1_024)',
    'value.contentKind === "detail" ? 256 * 1_024 : 512 * 1_024',
    'KUBERNETES_REDACTED_TEXT'
)) {
    if (-not $kubernetesReadContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/kubernetes-read-contract.ts is missing strict bounded/redacted validator marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"kubernetes".{0,300}<KubernetesPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount KubernetesPage with only the current opaque binding handle and fixed API'
}
if ($kubernetesPageText -match '(?i)\b(?:SshTargetSummary|KubernetesReadConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|operationId|digest|apiKey)\b' -or
    $kubernetesPageText -match '(?i)\b(?:scaleKubernetes|restartKubernetes|deleteKubernetes|cordon|drain|executeCommand|execKubernetes|openKubernetesFile|openKubernetesTerminal|exportKubernetes|genericInvoke|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/KubernetesPage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : kubernetesReadScope(bindingHandle);',
    'api.getKubernetesAvailability(bindingHandle)',
    'api.listKubernetesResources(bindingHandle, input)',
    'api.getKubernetesResourceDetail(bindingHandle, snapshotHandle, rowHandle)',
    'api.getKubernetesPodLogs(bindingHandle, snapshotHandle, rowHandle)'
)) {
    if (-not $kubernetesPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/KubernetesPage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $kubernetesHelpersText.Contains('export function kubernetesReadScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $kubernetesStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Kubernetes renderer lifecycle must scope only by opaque binding handle'
}
$dockerApiMatch = [regex]::Match(
    $dockerReadContractText,
    '(?ms)\bexport\s+interface\s+DockerReadApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $dockerApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/docker-read-contract.ts is missing DockerReadApi'
} else {
    $dockerNames = @([regex]::Matches($dockerApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($dockerNames -join [Environment]::NewLine) -cne (@('refreshDockerContainers', 'getDockerCollection', 'inspectDockerResource', 'getDockerSecurityAudit', 'getDockerLogs') -join [Environment]::NewLine)) {
        Add-GateViolation 'electron/src/shared/docker-read-contract.ts must expose exactly refresh/collection/inspect/audit/logs'
    }
    if ($dockerApiMatch.Groups['body'].Value -notmatch 'refreshDockerContainers\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $dockerApiMatch.Groups['body'].Value -notmatch '(?s)getDockerCollection\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*kind:\s*DockerCollectionKind,\s*\):\s*Promise<unknown>;' -or
        $dockerApiMatch.Groups['body'].Value -notmatch '(?s)inspectDockerResource\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*kind:\s*DockerResourceKind,\s*resourceHandle:\s*string,\s*\):\s*Promise<unknown>;' -or
        $dockerApiMatch.Groups['body'].Value -notmatch 'getDockerSecurityAudit\(bindingHandle:\s*string,\s*snapshotHandle:\s*string\):\s*Promise<unknown>;' -or
        $dockerApiMatch.Groups['body'].Value -notmatch '(?s)getDockerLogs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*containerHandle:\s*string,\s*tail:\s*number,\s*\):\s*Promise<unknown>;' -or
        $dockerApiMatch.Groups['body'].Value -match '(?i)\b(?:command|commandLine|shell|filePath|remotePath|terminal|export|mutation|session|guard|target|connection|secret|genericInvoke)\b') {
        Add-GateViolation 'electron/src/shared/docker-read-contract.ts must pin five raw-unknown responses behind typed kinds, bounded tail, and opaque handles'
    }
}
foreach ($pattern in @(
    'refreshDockerContainers\(bindingHandle:\s*string\):\s*Promise<DockerContainerSnapshot>;',
    '(?s)getDockerCollection\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*kind:\s*DockerCollectionKind,\s*\):\s*Promise<DockerReadCollection>;',
    '(?s)inspectDockerResource\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*kind:\s*DockerResourceKind,\s*resourceHandle:\s*string,\s*\):\s*Promise<DockerReadInspection>;',
    '(?s)getDockerSecurityAudit\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*\):\s*Promise<DockerSecurityAudit>;',
    '(?s)getDockerLogs\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*containerHandle:\s*string,\s*tail:\s*number,\s*\):\s*Promise<DockerLogs>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Docker API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:docker:containers:refresh',
    'lovelyres:docker:collection:get',
    'lovelyres:docker:resource:inspect',
    'lovelyres:docker:security:audit:get',
    'lovelyres:docker:container:logs:get'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Docker IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape(('ipcRenderer.invoke("' + $channel + '"'))).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Docker IPC '$channel'"
    }
}
$dockerMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:docker:containers:refresh"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:docker:containers:refresh"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($dockerMainBoundary, 'validateSender\(event\)').Count -ne 5 -or
    [regex]::Matches($dockerMainBoundary, 'values\.length\s*!==\s*1').Count -ne 5 -or
    [regex]::Matches($dockerMainBoundary, 'hasExactKeys\(value,').Count -ne 5 -or
    [regex]::Matches($dockerMainBoundary, 'isDockerOpaqueHandle').Count -ne 11 -or
    [regex]::Matches($dockerMainBoundary, 'isDockerCollectionKind').Count -ne 1 -or
    [regex]::Matches($dockerMainBoundary, 'isDockerResourceKind').Count -ne 1 -or
    [regex]::Matches($dockerMainBoundary, 'isDockerLogTail').Count -ne 1 -or
    $dockerMainBoundary -match '(?i)\b(?:commandText|shellText|filePath|remotePath|targetIdentity|targetGeneration|connectionId|sessionId|mutationHandle|exportPath|terminalHandle|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/index.ts must accept only exact Docker binding/snapshot/kind/resource/tail capability objects'
}
foreach ($marker in @(
    'mod docker_read_api;',
    'DockerReadApi::new(services.clone(), Arc::clone(&ssh))',
    'self.docker_read.close_binding(&params.binding_handle);',
    'DockerBindingParams',
    'DockerCollectionParams',
    'DockerInspectParams',
    'DockerSnapshotParams',
    'DockerLogsParams',
    'fn docker_read_failure(error: DockerReadApiError)',
    'docker.containers.refresh',
    'docker.collection.get',
    'docker.resource.inspect',
    'docker.security.audit.get',
    'docker.container.logs.get',
    'source: None'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Docker boundary/redaction marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_SNAPSHOTS: usize = 8',
    'MAX_ACTIVE_REFRESHES: usize = 2',
    'MAX_ACTIVE_READS: usize = 8',
    'MAX_ACTIVE_READS_PER_BINDING: usize = 4',
    'MAX_ACTIVE_PER_SNAPSHOT: usize = 3',
    'MAX_CONTAINERS: usize = 500',
    'MAX_LOG_TAIL: usize = 1_000',
    'MAX_LOG_BYTES: usize = 256 * 1024',
    'MAX_SNAPSHOT_BYTES: usize = 2 * 1024 * 1024',
    'MAX_INSPECTION_TEXT_BYTES: usize = 512 * 1024',
    'SNAPSHOT_TTL: Duration = Duration::from_secs(5 * 60)',
    'REDACTED_DOCKER_TEXT',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'sensitive_literals()'
)) {
    if (-not $dockerReadApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/docker_read_api.rs is missing bounded/redacted Docker marker '$marker'"
    }
}
foreach ($marker in @(
    'export function isDockerOpaqueHandle',
    'export function isDockerCollectionKind',
    'export function isDockerResourceKind',
    'export function isDockerLogTail',
    'export function isDockerContainerSnapshot',
    'export function isDockerReadCollection',
    'export function isDockerReadInspection',
    'export function isDockerSecurityAudit',
    'export function isDockerLogs',
    'DOCKER_REDACTED_TEXT',
    'withinTextBudget(values, 1_024 * 1_024)',
    'multilineText(value.text, 256 * 1_024)',
    'markerRequiresProjectionFlag'
)) {
    if (-not $dockerReadContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/docker-read-contract.ts is missing strict bounded/redacted validator marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"docker".{0,300}<DockerPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount DockerPage with only the current opaque binding handle and fixed API'
}
if ($dockerPageText -match '(?i)\b(?:SshTargetSummary|DockerReadConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|targetIdentity|targetGeneration|apiKey)\b' -or
    $dockerPageText -match '(?i)\b(?:startDocker|stopDocker|restartDocker|removeDocker|executeCommand|execDocker|openDockerFile|openDockerTerminal|exportDocker|genericInvoke|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/DockerPage.tsx exceeds the opaque read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : dockerReadScope(bindingHandle);',
    'api.refreshDockerContainers(bindingHandle)',
    'api.getDockerCollection(bindingHandle, snapshotHandle, collectionKind)',
    'api.inspectDockerResource(bindingHandle, snapshotHandle, kind, handle)',
    'api.getDockerSecurityAudit(bindingHandle, snapshotHandle)',
    'api.getDockerLogs(bindingHandle, snapshot.snapshotHandle, handle, LOG_TAIL)',
    'cancelled = true;'
)) {
    if (-not $dockerPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/DockerPage.tsx is missing lifecycle marker '$marker'"
    }
}
if ($dockerHelpersText -notmatch '(?s)export\s+function\s+dockerReadScope\(\s*bindingHandle:\s*string,?\s*\):\s*string' -or
    -not $dockerStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Docker renderer lifecycle must scope only by opaque binding handle'
}
$emergencyCommandApiMatch = [regex]::Match(
    $emergencyCommandContractText,
    '(?ms)\bexport\s+interface\s+EmergencyCommandApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $emergencyCommandApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/emergency-command-contract.ts is missing EmergencyCommandApi'
} else {
    $emergencyCommandNames = @([regex]::Matches($emergencyCommandApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($emergencyCommandNames -join "`n") -cne (@(
        'loadEmergencyCommandCatalog',
        'runEmergencyCommand',
        'inspectEmergencyPath',
        'planEmergencyPathAction',
        'confirmEmergencyPathAction',
        'executeEmergencyPathAction',
        'cancelEmergencyPathAction'
    ) -join "`n")) {
        Add-GateViolation 'electron/src/shared/emergency-command-contract.ts must expose exactly catalog-load, closed-run and the five path capabilities'
    }
    if ($emergencyCommandApiMatch.Groups['body'].Value -notmatch 'loadEmergencyCommandCatalog\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $emergencyCommandApiMatch.Groups['body'].Value -notmatch '(?s)runEmergencyCommand\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*commandHandle:\s*string,?\s*\):\s*Promise<unknown>;' -or
        $emergencyCommandApiMatch.Groups['body'].Value -match '(?i)\b(?:commandText|shellText|filePath|remotePath|terminal|export|mutation|session|guard|target|connection|secret|genericInvoke)\b') {
        Add-GateViolation 'electron/src/shared/emergency-command-contract.ts must pin two raw-unknown responses behind opaque handles without renderer-provided execution ingredients'
    }
}
foreach ($pattern in @(
    'loadEmergencyCommandCatalog\(bindingHandle:\s*string\):\s*Promise<EmergencyCommandCatalog>;',
    '(?s)runEmergencyCommand\(\s*bindingHandle:\s*string,\s*snapshotHandle:\s*string,\s*commandHandle:\s*string,\s*\):\s*Promise<EmergencyCommandResult>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Emergency Commands API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:emergency-command:catalog:load',
    'lovelyres:emergency-command:run'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Emergency Commands IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape("ipcRenderer.invoke(`"$channel`"" )).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Emergency Commands IPC '$channel'"
    }
}
$emergencyCommandMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:emergency-command:catalog:load"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($emergencyCommandMainBoundary, 'validateSender\(event\)').Count -ne 7 -or
    [regex]::Matches($emergencyCommandMainBoundary, 'values\.length\s*!==\s*1').Count -ne 7 -or
    [regex]::Matches($emergencyCommandMainBoundary, 'isEmergencyCommandOpaqueHandle').Count -ne 14 -or
    [regex]::Matches($emergencyCommandMainBoundary, 'isEmergencyPathAction\(value\.action\)').Count -ne 1 -or
    [regex]::Matches($emergencyCommandMainBoundary, [regex]::Escape('hasExactKeys(value, ["bindingHandle", "pathHandle", "action"])')).Count -ne 1 -or
    [regex]::Matches($emergencyCommandMainBoundary, [regex]::Escape('hasOnlyKeys(value, ["bindingHandle", "snapshotHandle", "commandHandle"])')).Count -ne 1 -or
    $emergencyCommandMainBoundary -match '(?i)\b(?:commandText|shellText|filePath|remotePath|targetIdentity|targetGeneration|connectionId|sessionId|mutationHandle|exportPath|terminalHandle|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/index.ts must reject unknown Emergency Commands IPC ingredients and accept only binding/catalog/command opaque handles'
}
foreach ($marker in @(
    'mod emergency_command_api;',
    'mod emergency_path_api;',
    'fn emergency_path_failure(error: EmergencyPathApiError)',
    'emergency-command.path.inspect',
    'emergency-command.path.plan',
    'emergency-command.path.confirm',
    'emergency-command.path.execute',
    'emergency-command.path.cancel',
    'EmergencyCommandApi::new(services.clone(), Arc::clone(&ssh))',
    'self.emergency_command.close_binding(&params.binding_handle);',
    'EmergencyCommandBindingParams',
    'EmergencyCommandRunParams',
    'fn emergency_command_failure(error: EmergencyCommandApiError)',
    'emergency-command.catalog.load',
    'emergency-command.run',
    'source: None'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Emergency Commands boundary/redaction marker '$marker'"
    }
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_CATALOG_COMMANDS: usize = 256',
    'MAX_CATALOG_BYTES: usize = 256 * 1024',
    'MAX_REGISTRY_BYTES: usize = 2 * 1024 * 1024',
    'MAX_ACTIVE_LOADS: usize = 2',
    'MAX_ACTIVE_RUNS: usize = 4',
    'MAX_OUTPUT_LINES: usize = 2_000',
    'MAX_OUTPUT_BYTES: usize = 256 * 1024',
    'CATALOG_TTL: Duration = Duration::from_secs(5 * 60)',
    'DETECTION_DEADLINE: Duration = Duration::from_secs(15)',
    'EXECUTION_DEADLINE: Duration = Duration::from_secs(75)',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'normalize_plain_line',
    '.offer(&scope.to_path_scope(), &dto.output, &clipped_lines)',
    'clipped_lines: Vec<u32>'
)) {
    if (-not $emergencyCommandApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/emergency_command_api.rs is missing bounded/redacted Emergency Commands marker '$marker'"
    }
}
$emergencyPathApiPath = Join-Path $backendRoot 'src/emergency_path_api.rs'
$emergencyPathApiText = Get-Content -LiteralPath $emergencyPathApiPath -Raw
foreach ($marker in @(
    'MAX_STORED_PATHS: usize = 2_000',
    'MAX_PLANS: usize = 16',
    'PATH_TTL: Duration = Duration::from_secs(15 * 60)',
    'PLAN_TTL: Duration = Duration::from_secs(5 * 60)',
    'EXECUTE_DEADLINE: Duration = Duration::from_secs(60)',
    'EXECUTE_BITS: u32 = 0o6111',
    'PERMISSION_BITS: u32 = 0o7777',
    'pub(crate) fn close_binding(&self, binding_handle: &str)',
    'self.validate_binding(&scope)?;',
    'fn take_confirmed_plan(',
    'DangerousConfirmation::approve(plan.operation.definition())',
    'plan.operation.execute_and_verify()',
    'plan.operation.restore().await.is_ok()',
    'SftpMutation::ChmodIfMode',
    'SftpMutation::Remove'
)) {
    if (-not $emergencyPathApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/emergency_path_api.rs is missing bounded path-capability marker '$marker'"
    }
}
# A path only ever enters through the core's own reading of its own output.
if ($emergencyPathApiText -match '(?m)^\s*pub\(crate\) (?:async )?fn \w+\([^)]*\bpath: (?:&str|String)\b') {
    Add-GateViolation 'crates/lovelyres-electron-backend/src/emergency_path_api.rs must not accept a caller-supplied path'
}
foreach ($marker in @(
    'export function isEmergencyCommandOpaqueHandle',
    'export function isEmergencyCommandCatalog',
    'export function isEmergencyCommandResult',
    'value.commands.length > 256',
    'serializedWithin(value, 256 * 1_024)',
    'text(value.output, 256 * 1_024)',
    'unsigned(value.displayedLineCount, 2_000)',
    'function outputLine',
    'export function isEmergencyPathDetail',
    'export function isEmergencyPathPlan',
    'export function isEmergencyPathReceipt',
    'export function isEmergencyPathAction',
    'value.paths.length > 500',
    'function offeredPath'
)) {
    if (-not $emergencyCommandContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/emergency-command-contract.ts is missing strict bounded/redacted validator marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"emergency-commands".{0,300}<EmergencyCommandsPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount EmergencyCommandsPage with only the current opaque binding handle and fixed API'
}
if ($emergencyCommandPageText -match '(?i)\b(?:SshTargetSummary|EmergencyCommandsConnection|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|targetIdentity|targetGeneration|apiKey)\b' -or
    $emergencyCommandPageText -match '(?i)\b(?:commandText|shellText|runCustomCommand|openTerminal|openFile|exportCommand|planMutation|genericInvoke|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/EmergencyCommandsPage.tsx exceeds the opaque closed-catalog plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : emergencyCommandScope(bindingHandle);',
    'api.loadEmergencyCommandCatalog(bindingHandle)',
    'api.runEmergencyCommand(bindingHandle, request.snapshotHandle, request.commandHandle)',
    'onPathMenu={pathActions.openMenu}',
    'paths={result.paths}',
    'cancelled = true;'
)) {
    if (-not $emergencyCommandPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/EmergencyCommandsPage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $emergencyCommandHelpersText.Contains('export function emergencyCommandScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $emergencyCommandStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Emergency Commands renderer lifecycle must scope only by opaque binding handle'
}
$emergencyPathActionsPath = Join-Path $electronRoot 'src/renderer/emergency-path-actions.ts'
$emergencyPathActionsText = Get-Content -LiteralPath $emergencyPathActionsPath -Raw
foreach ($marker in @(
    'api.inspectEmergencyPath(bindingHandle, offer.pathHandle)',
    'api.planEmergencyPathAction(bindingHandle, offer.pathHandle, action)',
    'api.confirmEmergencyPathAction(bindingHandle, planHandle)',
    'api.executeEmergencyPathAction(bindingHandle, planHandle)',
    'api.cancelEmergencyPathAction(bindingHandle, abandoned)',
    'isEmergencyPathDetail(detail)',
    'isEmergencyPathPlan(plan)',
    'isEmergencyPathPlan(confirmed)',
    'isEmergencyPathReceipt(receipt)',
    'inFlight.current'
)) {
    if (-not $emergencyPathActionsText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/emergency-path-actions.ts is missing capability marker '$marker'"
    }
}
# The window shows the path and acts on the handle. It never sends the path.
if ($emergencyPathActionsText -match 'api\.\w+\([^)]*offer\.path[^H]') {
    Add-GateViolation 'electron/src/renderer/emergency-path-actions.ts must act through the path handle, never a path string'
}
$packetCaptureApiMatch = [regex]::Match(
    $packetCaptureLiveContractText,
    '(?ms)\bexport\s+interface\s+PacketCaptureLiveApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $packetCaptureApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/packet-capture-live-contract.ts is missing PacketCaptureLiveApi'
} else {
    $packetCaptureNames = @([regex]::Matches($packetCaptureApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($packetCaptureNames -join "`n") -cne (@('listPacketCaptureInterfaces', 'startPacketCapture', 'pollPacketCapture', 'stopPacketCapture') -join "`n")) {
        Add-GateViolation 'electron/src/shared/packet-capture-live-contract.ts must expose exactly list/start/poll/stop'
    }
    if ($packetCaptureApiMatch.Groups['body'].Value -notmatch 'listPacketCaptureInterfaces\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $packetCaptureApiMatch.Groups['body'].Value -notmatch '(?s)startPacketCapture\(\s*bindingHandle:\s*string,\s*interfaceHandle:\s*string,\s*input:\s*PacketCaptureStartInput,?\s*\):\s*Promise<unknown>;' -or
        $packetCaptureApiMatch.Groups['body'].Value -notmatch '(?s)pollPacketCapture\(\s*bindingHandle:\s*string,\s*captureHandle:\s*string,\s*afterSequence:\s*number,?\s*\):\s*Promise<unknown>;' -or
        $packetCaptureApiMatch.Groups['body'].Value -notmatch 'stopPacketCapture\(bindingHandle:\s*string,\s*captureHandle:\s*string\):\s*Promise<unknown>;' -or
        $packetCaptureApiMatch.Groups['body'].Value -match '(?i)\b(?:command|commandLine|shell|filePath|remotePath|terminal|download|export|mutation|session|guard|target|connection|secret|genericInvoke)\b') {
        Add-GateViolation 'electron/src/shared/packet-capture-live-contract.ts must pin four raw-unknown responses behind typed bounded input and opaque handles'
    }
}
foreach ($pattern in @(
    'listPacketCaptureInterfaces\(bindingHandle:\s*string\):\s*Promise<PacketCaptureInterfaceList>;',
    '(?s)startPacketCapture\(\s*bindingHandle:\s*string,\s*interfaceHandle:\s*string,\s*input:\s*PacketCaptureStartInput,?\s*\):\s*Promise<PacketCaptureStarted>;',
    '(?s)pollPacketCapture\(\s*bindingHandle:\s*string,\s*captureHandle:\s*string,\s*afterSequence:\s*number,?\s*\):\s*Promise<PacketCapturePoll>;',
    '(?s)stopPacketCapture\(\s*bindingHandle:\s*string,\s*captureHandle:\s*string,?\s*\):\s*Promise<PacketCaptureStopped>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Packet Capture API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:packet-capture:interfaces:list',
    'lovelyres:packet-capture:start',
    'lovelyres:packet-capture:poll',
    'lovelyres:packet-capture:stop'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Packet Capture IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape(('ipcRenderer.invoke("' + $channel + '"'))).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Packet Capture IPC '$channel'"
    }
}
$packetCaptureMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:application-log:list"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:packet-capture:interfaces:list"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($packetCaptureMainBoundary, 'validateSender\(event\)').Count -ne 4 -or
    [regex]::Matches($packetCaptureMainBoundary, 'values\.length\s*!==\s*1').Count -ne 4 -or
    [regex]::Matches($packetCaptureMainBoundary, 'hasExactKeys\(value,').Count -ne 4 -or
    [regex]::Matches($packetCaptureMainBoundary, 'isPacketCaptureOpaqueHandle').Count -ne 7 -or
    [regex]::Matches($packetCaptureMainBoundary, 'isPacketCaptureStartInput').Count -ne 1 -or
    [regex]::Matches($packetCaptureMainBoundary, 'isPacketCaptureCursor').Count -ne 1 -or
    $packetCaptureMainBoundary -match '(?i)\b(?:commandText|shellText|filePath|remotePath|targetIdentity|targetGeneration|connectionId|sessionId|mutationHandle|exportPath|terminalHandle|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/index.ts must accept only exact Packet Capture binding/interface/capture/input/cursor capability objects'
}
foreach ($marker in @(
    'mod packet_capture_live_api;',
    'PacketCaptureLiveApi::new(services.clone(), Arc::clone(&ssh))',
    'self.packet_capture_live',
    'PacketCaptureBindingParams',
    'PacketCaptureStartParams',
    'PacketCapturePollParams',
    'PacketCaptureHandleParams',
    'fn packet_capture_live_failure(error: PacketCaptureLiveApiError)',
    'packet-capture.interfaces.list',
    'packet-capture.start',
    'packet-capture.poll',
    'packet-capture.stop',
    'source: None'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Packet Capture boundary/redaction marker '$marker'"
    }
}
if ($backendLibText -notmatch '(?s)self\.packet_capture_live\s*\.close_binding\(&params\.binding_handle\)\s*\.await;\s*self\.ssh\s*\.disconnect_binding') {
    Add-GateViolation 'Packet Capture capabilities must close before the real SSH disconnect'
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_INTERFACES: usize = 128',
    'MAX_INTERFACE_REGISTRY_BYTES: usize = 2 * 1024 * 1024',
    'INTERFACE_TTL: Duration = Duration::from_secs(5 * 60)',
    'MAX_CAPTURES: usize = 8',
    'MAX_CAPTURES_PER_BINDING: usize = 1',
    'MAX_RETAINED_EVENTS: usize = 512',
    'MAX_RETAINED_PACKETS: usize = 400',
    'MAX_CAPTURE_JOURNAL_BYTES: usize = 4 * 1024 * 1024',
    'MAX_POLL_EVENTS: usize = 100',
    'MAX_POLL_BYTES: usize = 512 * 1024',
    'MAX_GLOBAL_OPERATIONS: usize = 12',
    'MAX_OPERATIONS_PER_BINDING: usize = 3',
    'REDACTED_PACKET_CAPTURE_TEXT',
    'pub(crate) async fn close_binding(&self, binding_handle: &str)',
    'request.validate()?;',
    'start_live(&binding, request)',
    'self.ensure_binding',
    'request_stop()'
)) {
    if (-not $packetCaptureLiveApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/packet_capture_live_api.rs is missing bounded/redacted Packet Capture marker '$marker'"
    }
}
foreach ($marker in @(
    'export function isPacketCaptureOpaqueHandle',
    'export function isPacketCaptureStartInput',
    'export function isPacketCaptureInterfaceList',
    'export function isPacketCaptureStarted',
    'export function isPacketCaptureLiveEvent',
    'export function isPacketCapturePoll',
    'export function isPacketCaptureStopped',
    'jsonBytesAtMost(value, 256 * 1_024)',
    'jsonBytesAtMost(value, 64 * 1_024)',
    'jsonBytesAtMost(value, 512 * 1_024)',
    'value.events.length > 100',
    'value.interfaces.length > 128'
)) {
    if (-not $packetCaptureLiveContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/packet-capture-live-contract.ts is missing strict bounded/redacted validator marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"packet-capture".{0,300}<PacketCapturePage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount PacketCapturePage with only the current opaque binding handle and fixed API'
}
if ($packetCapturePageText -match '(?i)\b(?:SshTargetSummary|PacketCaptureConnection|connectionId|sessionId|targetGuard|generation|host|username|dataRoot|filePath|remotePath|targetIdentity|targetGeneration|apiKey)\b' -or
    $packetCapturePageText -match '(?i)\b(?:executeCommand|openPacketCaptureFile|openPacketCaptureTerminal|downloadPacketCapture|exportPacketCapture|analyzePacketCapture|genericInvoke|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/PacketCapturePage.tsx exceeds the opaque bounded live-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'bindingHandle: string | null;',
    'const scope = bindingHandle === null ? null : packetCaptureScope(bindingHandle);',
    'api.listPacketCaptureInterfaces(bindingHandle)',
    'api.startPacketCapture(',
    'api.pollPacketCapture(',
    'api.stopPacketCapture(owner.bindingHandle, owner.captureHandle)',
    'ownerRef.current = null;',
    'cancelled = true;'
)) {
    if (-not $packetCapturePageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/PacketCapturePage.tsx is missing lifecycle marker '$marker'"
    }
}
if (-not $packetCaptureHelpersText.Contains('export function packetCaptureScope(bindingHandle: string): string', [System.StringComparison]::Ordinal) -or
    -not $packetCaptureStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Packet Capture renderer lifecycle must scope only by opaque binding handle'
}
$applicationLogApiMatch = [regex]::Match(
    $applicationLogContractText,
    '(?ms)\bexport\s+interface\s+ApplicationLogApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $applicationLogApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/application-log-contract.ts is missing ApplicationLogApi'
} else {
    $applicationLogNames = @([regex]::Matches($applicationLogApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($applicationLogNames -join "`n") -cne (@('listApplicationLogs', 'setApplicationLogLevel', 'clearApplicationLogBuffer', 'getApplicationLogPreview', 'exportApplicationLogs') -join "`n")) {
        Add-GateViolation 'electron/src/shared/application-log-contract.ts must expose exactly list/level/clear/preview/export'
    }
    if ($applicationLogApiMatch.Groups['body'].Value -notmatch 'listApplicationLogs\(filter:\s*ApplicationLogFilter\):\s*Promise<unknown>;' -or
        $applicationLogApiMatch.Groups['body'].Value -notmatch 'setApplicationLogLevel\(level:\s*ApplicationLogLevel\):\s*Promise<unknown>;' -or
        $applicationLogApiMatch.Groups['body'].Value -notmatch 'clearApplicationLogBuffer\(\):\s*Promise<unknown>;' -or
        $applicationLogApiMatch.Groups['body'].Value -notmatch 'getApplicationLogPreview\(filter:\s*ApplicationLogFilter\):\s*Promise<unknown>;' -or
        $applicationLogApiMatch.Groups['body'].Value -notmatch 'exportApplicationLogs\(filter:\s*ApplicationLogFilter\):\s*Promise<unknown>;' -or
        $applicationLogApiMatch.Groups['body'].Value -match '(?i)\b(?:filePath|selectedPath|suggestedName|contents|stderr|shell|command|target|session|connection|secret|genericInvoke)\b') {
        Add-GateViolation 'electron/src/shared/application-log-contract.ts must keep list/level/clear/preview/export pathless and payload-free'
    }
}
foreach ($pattern in @(
    'listApplicationLogs\(filter:\s*ApplicationLogFilter\):\s*Promise<ApplicationLogSnapshot>;',
    'setApplicationLogLevel\(level:\s*ApplicationLogLevel\):\s*Promise<ApplicationLogLevelResult>;',
    'clearApplicationLogBuffer\(\):\s*Promise<ApplicationLogClearResult>;',
    'getApplicationLogPreview\(filter:\s*ApplicationLogFilter\):\s*Promise<ApplicationLogPreview>;',
    'exportApplicationLogs\(filter:\s*ApplicationLogFilter\):\s*Promise<ApplicationLogExportResult>;'
)) {
    if ($contractText -notmatch $pattern) {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact Application Log API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:application-log:list',
    'lovelyres:application-log:level:set',
    'lovelyres:application-log:buffer:clear',
    'lovelyres:application-log:preview:get',
    'lovelyres:application-log:export'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed Application Log IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape(('ipcRenderer.invoke("' + $channel + '"'))).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed Application Log IPC '$channel'"
    }
}
$applicationLogMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:application-log:list"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:integrity:presets:get"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:application-log:list"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($applicationLogMainBoundary, 'validateSender\(event\)').Count -ne 5 -or
    [regex]::Matches($applicationLogMainBoundary, 'values\.length\s*!==\s*0').Count -ne 1 -or
    [regex]::Matches($applicationLogMainBoundary, 'values\.length\s*!==\s*1').Count -ne 4 -or
    [regex]::Matches($applicationLogMainBoundary, 'isApplicationLogFilter').Count -ne 3 -or
    [regex]::Matches($applicationLogMainBoundary, 'isApplicationLogLevel').Count -ne 1 -or
    [regex]::Matches($applicationLogMainBoundary, 'dialog\.showSaveDialog\(mainWindow').Count -ne 1 -or
    [regex]::Matches($applicationLogMainBoundary, 'backend\.prepareApplicationLogExport').Count -ne 1 -or
    [regex]::Matches($applicationLogMainBoundary, 'saveApplicationLogExport\(selection\.filePath,\s*payload\)').Count -ne 1 -or
    $applicationLogMainBoundary -match '(?i)\b(?:targetIdentity|targetGeneration|bindingHandle|connectionId|sessionId|shellText|commandText|remotePath|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/index.ts must accept only exact Application Log filters/levels and keep native export path/payload in main'
}
foreach ($marker in @(
    'mod diagnostic_log_api;',
    'pub use diagnostic_log_api::{DiagnosticLogCapture, DiagnosticLogLayer, DiagnosticLogLevel};',
    'diagnostic_log: DiagnosticLogApi',
    'BackendState::open_with_diagnostic_capture',
    'DiagnosticLogApi::new(diagnostic_capture)',
    'ApplicationLogFilterParams',
    'ApplicationLogLevelParams',
    'fn diagnostic_log_failure(error: DiagnosticLogApiError)',
    'application-log.list',
    'application-log.level.set',
    'application-log.buffer.clear',
    'application-log.preview.get',
    'application-log.export.prepare',
    'source: None'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Application Log boundary/redaction marker '$marker'"
    }
}
foreach ($marker in @(
    'let diagnostic_capture = DiagnosticLogCapture::new(DiagnosticLogLevel::Info);',
    'let stderr_filter = tracing_subscriber::EnvFilter::try_from_default_env()',
    'tracing_subscriber::registry()',
    'tracing_subscriber::fmt::layer()',
    '.with_writer(std::io::stderr)',
    '.with_filter(stderr_filter)',
    '.with(diagnostic_capture.layer())',
    'subscriber.try_init()',
    'BackendState::open_with_diagnostic_capture(archive_root, diagnostic_capture)'
)) {
    if (-not $backendMainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/main.rs is missing single-subscriber Application Log marker '$marker'"
    }
}
if ([regex]::Matches($backendMainText, 'tracing_subscriber::registry\(\)').Count -ne 1 -or
    [regex]::Matches($backendMainText, 'subscriber\.try_init\(\)').Count -ne 1) {
    Add-GateViolation 'the sidecar must install exactly one tracing subscriber shared by fmt stderr and Application Log capture'
}
foreach ($marker in @(
    'DIAGNOSTIC_CAPACITY: usize = 500',
    'DISPLAY_ENTRY_LIMIT: usize = 100',
    'MAX_SEARCH_BYTES: usize = 256',
    'MAX_MESSAGE_BYTES: usize = 4 * 1024',
    'MAX_DETAILS_BYTES: usize = 16 * 1024',
    'MAX_FIELDS: usize = 32',
    'PREVIEW_MAX_BYTES: usize = 128 * 1024',
    'EXPORT_MAX_BYTES: usize = 256 * 1024',
    'MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991',
    'DEBUG_REDACTED',
    'ERROR_REDACTED',
    'impl<S> Layer<S> for DiagnosticLogLayer',
    'if !self.capture.allows(event.metadata())',
    'fn record_error(&mut self, field: &tracing::field::Field, _: &(dyn StdError + ''static))',
    'self.record_fixed(field, ERROR_REDACTED);',
    'next_public_generation'
)) {
    if (-not $diagnosticLogApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/diagnostic_log_api.rs is missing bounded/redacted Application Log marker '$marker'"
    }
}
foreach ($marker in @(
    'export function isApplicationLogLevel',
    'export function isApplicationLogFilter',
    'export function isApplicationLogEntry',
    'export function isApplicationLogSnapshot',
    'export function isApplicationLogLevelResult',
    'export function isApplicationLogClearResult',
    'export function isApplicationLogPreview',
    'export function isApplicationLogExportResult',
    'value.capacity !== 500',
    'value.entries.length > 100',
    'value.details.length > 32',
    'isApplicationLogPublicMultiline(value.content, 128 * 1_024, true)',
    'containsUriUserinfo'
)) {
    if (-not $applicationLogContractText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/shared/application-log-contract.ts is missing strict bounded/redacted validator marker '$marker'"
    }
}
foreach ($marker in @(
    'InternalApplicationLogExportPayload',
    'This payload is sidecar-to-main only and must never cross the renderer IPC boundary.',
    'isApplicationLogPublicMultiline(record.contents, MAX_EXPORT_BYTES, true)',
    'path.isAbsolute(selectedPath)',
    'fs.promises.open(selectedPath, "wx", 0o600)',
    'await file.sync();',
    'fileName: path.basename(selectedPath)'
)) {
    if (-not $applicationLogExportText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/application-log-export-boundary.ts is missing create-only main-owned export marker '$marker'"
    }
}
if ($preloadText -match '(?i)\b(?:prepareApplicationLogExport|InternalApplicationLogExportPayload|applicationLogContents|applicationLogPath)\b' -or
    $contractText -match '(?i)\b(?:prepareApplicationLogExport|InternalApplicationLogExportPayload|applicationLogContents|applicationLogPath)\b') {
    Add-GateViolation 'Application Log internal export payload or path crossed the renderer contract'
}
if ($appText -notmatch 'data-testid="open-application-log"[^
]{0,160}>应用日志</button>' -or
    $appText -notmatch '(?s)applicationLogOpen\s*\?\s*\(\s*<ApplicationLogOverlay\s+ref=\{applicationLogOverlayRef\}\s+api=\{window\.lovelyres\}\s+onClose=\{finishApplicationLogClose\}\s+returnFocusElement=\{applicationLogReturnFocusRef\.current\}\s+writeClipboard=\{window\.lovelyres\.writeClipboard\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount ApplicationLogOverlay through the fixed toolbar control and typed API'
}
foreach ($marker in @(
    'if (applicationLogOpen) applicationLogOverlayRef.current?.beforeClose();',
    'if (applicationLogOpen) closeApplicationLog();',
    'applicationLogOverlayRef.current?.beforeClose();',
    'const overlayOpen = connectionManagerRequest !== undefined || settingsOpen || commandHistoryOpen ||',
    'disposalReportOpen || applicationLogOpen;'
)) {
    if (-not $appText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/App.tsx is missing Application Log overlay lifecycle marker '$marker'"
    }
}
if ($applicationLogOverlayText -match '(?i)\b(?:filePath|selectedPath|suggestedName|contents|targetGuard|bindingHandle|connectionId|sessionId|shellText|commandText|genericInvoke|dangerouslySetInnerHTML|innerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/ApplicationLogOverlay.tsx exceeds the pathless process-local plain-text surface'
}
foreach ($marker in @(
    'useImperativeHandle(ref, () => ({ beforeClose }), [beforeClose]);',
    'deactivateApplicationLogOverlay(alive, request, operation);',
    'api.listApplicationLogs(filter)',
    'api.setApplicationLogLevel(level)',
    'api.clearApplicationLogBuffer()',
    'api.getApplicationLogPreview(filter)',
    'api.exportApplicationLogs(filter)',
    'role="dialog"',
    'aria-modal="true"',
    'restoreApplicationLogFocus(previousFocus)'
)) {
    if (-not $applicationLogOverlayText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/ApplicationLogOverlay.tsx is missing lifecycle/accessibility marker '$marker'"
    }
}
if ($applicationLogOverlayText -match '(?:\.inert\s*=|setAttribute\(\s*["'']aria-hidden)') {
    Add-GateViolation 'electron/src/renderer/ApplicationLogOverlay.tsx must leave sibling inert ownership to App'
}
if (-not $applicationLogHelpersText.Contains('export function deactivateApplicationLogOverlay(', [System.StringComparison]::Ordinal) -or
    -not $applicationLogStateText.Contains('export function applicationLogReducer(', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Application Log overlay must retain explicit operation invalidation and reducer-owned bounded state'
}
$integrityApiMatch = [regex]::Match(
    $integrityContractText,
    '(?ms)\bexport\s+interface\s+IntegrityApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $integrityApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/integrity-contract.ts is missing IntegrityApi'
} else {
    $integrityNames = @([regex]::Matches($integrityApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($integrityNames -join "`n") -cne (@('getIntegrityPresets', 'listIntegrityBaselines', 'startIntegrityComparison', 'pollIntegrityComparison', 'cancelIntegrityComparison') -join "`n")) {
        Add-GateViolation 'electron/src/shared/integrity-contract.ts must expose exactly presets/list/start/poll/cancel'
    }
    if ($integrityApiMatch.Groups['body'].Value -notmatch 'getIntegrityPresets\(\):\s*Promise<unknown>;' -or
        $integrityApiMatch.Groups['body'].Value -notmatch 'listIntegrityBaselines\(bindingHandle:\s*string\):\s*Promise<unknown>;' -or
        $integrityApiMatch.Groups['body'].Value -notmatch 'startIntegrityComparison\(bindingHandle:\s*string,\s*baselineHandle:\s*string\):\s*Promise<unknown>;' -or
        $integrityApiMatch.Groups['body'].Value -notmatch '(?s)pollIntegrityComparison\(\s*bindingHandle:\s*string,\s*operationHandle:\s*string,\s*afterEvent:\s*number,\s*limit:\s*number,?\s*\):\s*Promise<unknown>;' -or
        $integrityApiMatch.Groups['body'].Value -notmatch 'cancelIntegrityComparison\(bindingHandle:\s*string,\s*operationHandle:\s*string\):\s*Promise<unknown>;' -or
        $integrityApiMatch.Groups['body'].Value -match '(?i)\b(?:host|port|username|connection|session|targetGuard|generation|shell|command|filePath|remotePath|export|quarantine|mutation|secret|genericInvoke)\b') {
        Add-GateViolation 'electron/src/shared/integrity-contract.ts must pin five raw-unknown responses behind opaque handles and bounded cursors'
    }
}
foreach ($pattern in @(
    'getIntegrityPresets\(\):\s*Promise<IntegrityPresetCatalog>;',
    'listIntegrityBaselines\(bindingHandle:\s*string\):\s*Promise<IntegrityBaselineList>;',
    'startIntegrityComparison\(\s*bindingHandle:\s*string,\s*baselineHandle:\s*string,?\s*\):\s*Promise<IntegrityComparisonStarted>;',
    'pollIntegrityComparison\(\s*bindingHandle:\s*string,\s*operationHandle:\s*string,\s*afterEvent:\s*number,\s*limit:\s*number,?\s*\):\s*Promise<IntegrityComparisonPoll>;',
    'cancelIntegrityComparison\(\s*bindingHandle:\s*string,\s*operationHandle:\s*string,?\s*\):\s*Promise<IntegrityComparisonCancellation>;'
)) {
    if ($contractText -notmatch "(?s)$pattern") {
        Add-GateViolation "electron/src/shared/contract.ts is missing an exact File Integrity API signature matching '$pattern'"
    }
}
foreach ($channel in @(
    'lovelyres:integrity:presets:get',
    'lovelyres:integrity:baselines:list',
    'lovelyres:integrity:comparison:start',
    'lovelyres:integrity:comparison:poll',
    'lovelyres:integrity:comparison:cancel'
)) {
    if ([regex]::Matches($mainText, [regex]::Escape($channel)).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register exactly one fixed File Integrity IPC '$channel'"
    }
    if ([regex]::Matches($preloadText, [regex]::Escape(('ipcRenderer.invoke("' + $channel + '"'))).Count -ne 1) {
        Add-GateViolation "electron/src/preload/index.ts must invoke exactly one fixed File Integrity IPC '$channel'"
    }
}
$integrityMainBoundary = $mainText.Substring(
    $mainText.IndexOf('ipcMain.handle("lovelyres:integrity:presets:get"', [System.StringComparison]::Ordinal),
    $mainText.IndexOf('ipcMain.handle("lovelyres:settings:get"', [System.StringComparison]::Ordinal) -
        $mainText.IndexOf('ipcMain.handle("lovelyres:integrity:presets:get"', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($integrityMainBoundary, 'validateSender\(event\)').Count -ne 5 -or
    [regex]::Matches($integrityMainBoundary, 'values\.length\s*!==\s*0').Count -ne 1 -or
    [regex]::Matches($integrityMainBoundary, 'values\.length\s*!==\s*1').Count -ne 4 -or
    [regex]::Matches($integrityMainBoundary, 'hasExactKeys').Count -ne 4 -or
    [regex]::Matches($integrityMainBoundary, 'isIntegrityOpaqueHandle').Count -ne 7 -or
    [regex]::Matches($integrityMainBoundary, 'isIntegrityPollRequest').Count -ne 1 -or
    [regex]::Matches($integrityMainBoundary, 'value\.bindingHandle\s*===\s*value\.(?:baselineHandle|operationHandle)').Count -ne 3 -or
    $integrityMainBoundary -match '(?i)\b(?:host|port|username|connectionId|sessionId|targetIdentity|targetGeneration|targetGuard|shellText|commandText|filePath|remotePath|exportPath|quarantine|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/index.ts must accept only exact File Integrity binding/baseline/operation/cursor capability objects'
}
$integrityPreloadBoundary = $preloadText.Substring(
    $preloadText.IndexOf('getIntegrityPresets:', [System.StringComparison]::Ordinal),
    $preloadText.IndexOf('loadSettings:', [System.StringComparison]::Ordinal) -
        $preloadText.IndexOf('getIntegrityPresets:', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($integrityPreloadBoundary, 'ipcRenderer\.invoke\(').Count -ne 5 -or
    $integrityPreloadBoundary -notmatch 'listIntegrityBaselines:\s*\(bindingHandle:\s*string\)\s*=>\s*ipcRenderer\.invoke\("lovelyres:integrity:baselines:list",\s*\{\s*bindingHandle\s*\}\)' -or
    $integrityPreloadBoundary -match '(?i)\b(?:host|port|username|connectionId|sessionId|targetGuard|generation|shell|command|filePath|remotePath|export|quarantine|genericInvoke)\b') {
    Add-GateViolation 'electron/src/preload/index.ts must expose only the five fixed File Integrity capability calls'
}
$integrityRpcMatch = [regex]::Match(
    $backendClientText,
    '(?ms)export\s+const\s+INTEGRITY_RPC_METHODS\s*=\s*Object\.freeze\s*\(\s*\{(?<body>.*?)^\}\s+as\s+const\s*\)\s*;'
)
if (-not $integrityRpcMatch.Success -or
    ($integrityRpcMatch.Groups['body'].Value -notmatch 'presets:\s*"integrity\.presets\.get"' -or
     $integrityRpcMatch.Groups['body'].Value -notmatch 'listBaselines:\s*"integrity\.baselines\.list"' -or
     $integrityRpcMatch.Groups['body'].Value -notmatch 'startComparison:\s*"integrity\.comparison\.start"' -or
     $integrityRpcMatch.Groups['body'].Value -notmatch 'pollComparison:\s*"integrity\.comparison\.poll"' -or
     $integrityRpcMatch.Groups['body'].Value -notmatch 'cancelComparison:\s*"integrity\.comparison\.cancel"')) {
    Add-GateViolation 'electron/src/main/backend-client.ts must freeze the exact five File Integrity RPC names'
}
$integrityClientBoundary = $backendClientText.Substring(
    $backendClientText.IndexOf('async getIntegrityPresets', [System.StringComparison]::Ordinal),
    $backendClientText.IndexOf('async loadSettings', [System.StringComparison]::Ordinal) -
        $backendClientText.IndexOf('async getIntegrityPresets', [System.StringComparison]::Ordinal)
)
foreach ($marker in @(
    'isIntegrityPresetCatalog(value)',
    'isIntegrityOpaqueHandle(bindingHandle)',
    'isIntegrityBaselineList(value)',
    'baseline.baselineHandle === bindingHandle',
    'isIntegrityComparisonStarted(value)',
    'value.baselineHandle !== baselineHandle',
    'value.operationHandle === bindingHandle',
    'value.operationHandle === baselineHandle',
    'isIntegrityPollRequest(afterEvent, limit)',
    'isIntegrityComparisonPoll(value)',
    'value.operationHandle !== operationHandle',
    'value.baselineHandle === operationHandle',
    'value.nextEventCursor < afterEvent',
    'event.sequence <= afterEvent',
    'isIntegrityComparisonCancellation(value)'
)) {
    if (-not $integrityClientBoundary.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing File Integrity validation/correlation marker '$marker'"
    }
}
if ([regex]::Matches($integrityClientBoundary, 'this\.#request\(INTEGRITY_RPC_METHODS\.').Count -ne 5 -or
    $integrityClientBoundary -match '(?i)\b(?:host|port|username|connectionId|sessionId|targetGuard|generation|shell|command|filePath|remotePath|export|quarantine|genericInvoke)\b') {
    Add-GateViolation 'electron/src/main/backend-client.ts must retain five bounded, correlated File Integrity requests'
}
foreach ($marker in @(
    'mod integrity_api;',
    'integrity_api::{IntegrityApi, IntegrityApiError}',
    'integrity: Arc<IntegrityApi>',
    'Arc::new(IntegrityApi::new(services.clone(), Arc::clone(&ssh)))',
    'IntegrityBindingParams',
    'IntegrityBaselineParams',
    'IntegrityPollParams',
    'IntegrityOperationParams',
    'fn integrity_failure(error: IntegrityApiError)',
    'integrity.presets.get',
    'integrity.baselines.list',
    'integrity.comparison.start',
    'integrity.comparison.poll',
    'integrity.comparison.cancel'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing File Integrity central boundary marker '$marker'"
    }
}
$integrityBackendStateBoundary = $backendLibText.Substring(
    $backendLibText.IndexOf('pub struct BackendState', [System.StringComparison]::Ordinal),
    $backendLibText.IndexOf('struct NoteReplayEntry', [System.StringComparison]::Ordinal) -
        $backendLibText.IndexOf('pub struct BackendState', [System.StringComparison]::Ordinal)
)
if ([regex]::Matches($integrityBackendStateBoundary, 'integrity:\s*Arc<IntegrityApi>').Count -ne 1 -or
    [regex]::Matches($backendLibText, 'Arc::new\(IntegrityApi::new\(services\.clone\(\),\s*Arc::clone\(&ssh\)\)\)').Count -ne 1) {
    Add-GateViolation 'BackendState must own and construct exactly one shared Arc<IntegrityApi>'
}
foreach ($marker in @(
    'BoundSshSession',
    'TargetGuard',
    'MAX_BASELINES_PER_LIST: usize = 64',
    'MAX_DIFF_ENTRIES: usize = 500',
    'MAX_OPERATIONS: usize = 16',
    'MAX_ACTIVE_OPERATIONS: usize = 4',
    'MAX_ACTIVE_OPERATIONS_PER_BINDING: usize = 1',
    'MAX_OPERATION_EVENTS: usize = 8',
    'MAX_POLL_EVENTS: usize = 8',
    'BASELINE_HANDLE_TTL: Duration = Duration::from_secs(10 * 60)',
    'RUNNING_OPERATION_TTL: Duration = Duration::from_secs(5 * 60)',
    'TERMINAL_OPERATION_TTL: Duration = Duration::from_secs(5 * 60)',
    'REDACTED_INTEGRITY_PATH',
    'pub(crate) fn close_binding(&self, binding_handle: &str)'
)) {
    if (-not $integrityApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/integrity_api.rs is missing bounded/redacted lifecycle marker '$marker'"
    }
}
if ($appText -notmatch '(?s)activePage\.id\s*===\s*"integrity".{0,260}<IntegrityPage\s+bindingHandle=\{activeTarget\?\.bindingHandle\s*\?\?\s*null\}\s+api=\{window\.lovelyres\}') {
    Add-GateViolation 'electron/src/renderer/App.tsx must mount IntegrityPage with only the current opaque binding handle and fixed API'
}
if ($integrityPageText -match '(?i)\b(?:SshTargetSummary|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|targetIdentity|targetGeneration|apiKey)\b' -or
    $integrityPageText -match '(?i)\b(?:createIntegrityBaseline|quarantineIntegrity|customPath|pathInput|executeCommand|runCustomCommand|openTerminal|openFile|downloadReport|exportReport|planMutation|genericInvoke|innerHTML|dangerouslySetInnerHTML)\b') {
    Add-GateViolation 'electron/src/renderer/IntegrityPage.tsx exceeds the opaque bounded read-only plain-text Phase 1 surface'
}
foreach ($marker in @(
    'api.getIntegrityPresets()',
    'api.listIntegrityBaselines(bindingHandle)',
    'api.startIntegrityComparison(bindingHandle, baselineHandle)',
    'api.pollIntegrityComparison(',
    'api.cancelIntegrityComparison(bindingHandle, operationHandle)',
    'dispatch({ type: "scope-changed", scope });',
    'cancelIntegrityLifecycle(',
    'void api.cancelIntegrityComparison(bindingHandle, result.operationHandle)',
    'currentBindingRef.current !== bindingHandle',
    'className="integrity-page integrity-connect-state"',
    '连接目标后检查文件完整性',
    '连接目标后可比对文件完整性基线'
)) {
    if (-not $integrityPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/IntegrityPage.tsx is missing lifecycle/read-only marker '$marker'"
    }
}
if (-not $integrityHelpersText.Contains('export async function cancelIntegrityLifecycle(', [System.StringComparison]::Ordinal) -or
    -not $integrityStateText.Contains('| { type: "scope-changed"; scope: string | null }', [System.StringComparison]::Ordinal) -or
    -not $integrityStateText.Contains('action.scope === state.scope ? state : createIntegrityState(action.scope)', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'File Integrity renderer lifecycle must cancel active work and clear stale binding-scoped state'
}
if ($integrityCssText -notmatch '(?s)\.integrity-page\s*\{[^}]*background:\s*var\(--console-bg\);') {
    Add-GateViolation 'electron/src/renderer/integrity.css must give the File Integrity surface an explicit opaque contrast background'
}
if ($globalText -notmatch '(?m)^\s*lovelyres\s*:\s*LovelyResApi\s*;') {
    Add-GateViolation 'electron/src/renderer/global.d.ts must type window.lovelyres as LovelyResApi'
}
if ($globalText -notmatch '(?m)^\s*lovelyresTerminal\s*:\s*TerminalApi\s*;') {
    Add-GateViolation 'electron/src/renderer/global.d.ts must type window.lovelyresTerminal as TerminalApi'
}
if ($contractApiMatch.Success -and $contractApiMatch.Groups['body'].Value -match '(?i)\b(?:sessionId|targetGuard|authorization|digest)\b') {
    Add-GateViolation 'electron/src/shared/contract.ts must not expose SSH session, target guard, authorization, or digest internals'
}
foreach ($check in @(
    @{ Pattern = '\bconst\s+payload\s*=\s*await\s+backend\.copyConfigDraft\s*\(\s*value\.handle\s*,\s*value\.revision\s*\)'; Name = 'main-owned configuration copy fetch' },
    @{ Pattern = '\bclipboard\.writeText\s*\(\s*text\s*\)'; Name = 'main-owned configuration clipboard write' },
    @{ Pattern = '\bbackend\.getConfigArtifact\s*\('; Name = 'main-owned configuration artifact fetch' },
    @{ Pattern = '\bdialog\.showSaveDialog\s*\(\s*mainWindow\s*,'; Name = 'native configuration save dialog' },
    @{ Pattern = '\bfs\.promises\.open\s*\(\s*result\.filePath\s*,\s*"wx"\s*,\s*0o600\s*\)'; Name = 'create-only configuration export open' },
    @{ Pattern = '\bawait\s+file\.sync\s*\(\s*\)'; Name = 'configuration export fsync' }
)) {
    if ($mainText -notmatch $check.Pattern) {
        Add-GateViolation "electron/src/main/index.ts is missing the $($check.Name) boundary"
    }
}
if ($preloadText -match '(?i)\b(?:filePath|contents|suggestedName)\b') {
    Add-GateViolation 'electron/src/preload/index.ts must not accept configuration paths, suggested names, or generated contents'
}
foreach ($check in @(
    @{ Pattern = '\bdialog\.showOpenDialog\s*\(\s*mainWindow\s*,'; Name = 'native connection import dialog' },
    @{ Pattern = '\bbackend\.importConnectionsFile\s*\(\s*selection\.filePaths\[0\]\s*\)'; Name = 'main-owned connection import path dispatch' },
    @{ Pattern = '\bbackend\.exportConnectionsFile\s*\(\s*selection\.filePath\s*\)'; Name = 'main-owned connection export path dispatch' },
    @{ Pattern = '\bcompletedConnectionExport\s*\(\s*result\s*,\s*selection\.filePath\s*\)'; Name = 'basename-only connection export result projection' }
)) {
    if ($mainText -notmatch $check.Pattern) {
        Add-GateViolation "electron/src/main/index.ts is missing the $($check.Name) boundary"
    }
}
if ($contractApiMatch.Success -and (
    $contractApiMatch.Groups['body'].Value -notmatch '(?m)^\s{2}importConnections\(\):\s*Promise<ConnectionImportResult>;' -or
    $contractApiMatch.Groups['body'].Value -notmatch '(?m)^\s{2}exportConnections\(\):\s*Promise<ConnectionExportResult>;'
)) {
    Add-GateViolation 'electron/src/shared/contract.ts connection import/export APIs must accept no renderer arguments'
}
if ($contractApiMatch.Success -and (
    $contractApiMatch.Groups['body'].Value -notmatch '(?m)^\s{2}loadSettings\(\):\s*Promise<SettingsSnapshot>;' -or
    $contractApiMatch.Groups['body'].Value -notmatch '(?m)^\s{2}saveSettings\(input:\s*SettingsSaveInput\):\s*Promise<SettingsSnapshot>;'
)) {
    Add-GateViolation 'electron/src/shared/contract.ts must expose only the fixed loadSettings/saveSettings signatures'
}
$apiKeyDeclarations = [regex]::Matches($settingsContractText, '(?im)^\s*apiKey\??\s*:\s*string\s*;')
$apiKeyInput = [regex]::Match(
    $settingsContractText,
    '(?ms)export\s+interface\s+SettingsAiApiKeyReplacementInput\s*\{(?<body>.*?)^\s*\}'
)
if ($apiKeyDeclarations.Count -ne 1 -or -not $apiKeyInput.Success -or
    $apiKeyInput.Groups['body'].Value -notmatch '(?m)^\s*providerId:\s*string\s*;' -or
    $apiKeyInput.Groups['body'].Value -notmatch '(?m)^\s*apiKey:\s*string\s*;') {
    Add-GateViolation 'electron/src/shared/settings-contract.ts must expose exactly one bounded write-only API-key request field'
}
if ($settingsContractText -match '(?im)^\s*(?:secret|ciphertext|dataRoot|path)\??\s*:') {
    Add-GateViolation 'electron/src/shared/settings-contract.ts exposes a path or secret response/storage field'
}
if ([regex]::Matches($settingsPanelText, '(?i)type\s*=\s*["'']password["'']').Count -ne 1 -or
    $settingsPanelText -notmatch 'value=\{apiKeyDraft\}' -or
    $settingsPanelText -notmatch 'autoComplete=["'']new-password["'']' -or
    $settingsPanelText -notmatch 'useState\s*\(\s*["'']["'']\s*\)' -or
    [regex]::Matches($settingsPanelText, 'setApiKeyDraft\s*\(\s*["'']["'']\s*\)').Count -lt 2 -or
    [regex]::Matches($settingsPanelText, 'input\.apiKey\s*=\s*["'']["'']').Count -lt 2) {
    Add-GateViolation 'electron/src/renderer/SettingsPanel.tsx must keep one empty write-only password input and clear every local secret copy'
}
if ($settingsPanelText -match '(?i)defaultValue\s*=.*apiKey|(?:localStorage|sessionStorage|indexedDB|console\.)[^\r\n]*apiKey|JSON\.stringify\s*\([^\)]*apiKey') {
    Add-GateViolation 'electron/src/renderer/SettingsPanel.tsx must not default, log, snapshot, or browser-persist an API key'
}
if ($contractApiMatch.Success) {
    foreach ($signature in @(
        'replaceSettingsAiApiKey\(\s*input:\s*SettingsAiApiKeyReplacementInput,?\s*\):\s*Promise<SettingsAiApiKeyReplacementResult>;',
        'planSettingsAiApiKeyClear\(providerId:\s*string\):\s*Promise<SettingsMutationProposal>;',
        'planSettingsAiProviderRemoval\(providerId:\s*string\):\s*Promise<SettingsMutationProposal>;',
        'confirmSettingsMutation\(mutationHandle:\s*string\):\s*Promise<SettingsMutationResult>;',
        'cancelSettingsMutation\(mutationHandle:\s*string\):\s*Promise<SettingsMutationCancellation>;'
    )) {
        if ($contractApiMatch.Groups['body'].Value -notmatch $signature) {
            Add-GateViolation "electron/src/shared/contract.ts is missing fixed Settings secret lifecycle signature '$signature'"
        }
    }
}
if ($contractApiMatch.Success) {
    foreach ($signature in @(
        'listAiHistory\(query:\s*string,\s*offset:\s*number,\s*limit:\s*number\):\s*Promise<AiHistoryListPage>;',
        'getAiHistoryRecord\(id:\s*string\):\s*Promise<AiHistoryRecord>;',
        'planAiHistoryRemove\(id:\s*string\):\s*Promise<AiHistoryMutationProposal>;',
        'planAiHistoryClear\(\):\s*Promise<AiHistoryMutationProposal>;',
        'confirmAiHistoryMutation\(handle:\s*string\):\s*Promise<AiHistoryMutationResult>;',
        'cancelAiHistoryMutation\(handle:\s*string\):\s*Promise<AiHistoryMutationCancellation>;',
        'exportAiHistory\(format:\s*AiHistoryExportFormat\):\s*Promise<AiHistoryExportResult>;'
    )) {
        if ($contractApiMatch.Groups['body'].Value -notmatch $signature) {
            Add-GateViolation "electron/src/shared/contract.ts is missing fixed AI history signature '$signature'"
        }
    }
}
if ($aiHistoryContractText -match '(?im)^\s*(?:path|contents|sessionId|targetGuard|authorization|digest)\??\s*:') {
    Add-GateViolation 'electron/src/shared/ai-history-contract.ts exposes an internal path, body, or target capability'
}
foreach ($marker in @('AiHistoryPage', 'activePage.id === "ai-history"')) {
    if (-not $appText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/App.tsx is missing AI history route marker '$marker'"
    }
}
foreach ($marker in @('aria-modal="true"', 'inert={proposalOpen ? true : undefined}', 'event.key === "Escape"', 'proposalReturnFocusRef')) {
    if (-not $aiHistoryPageText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/AiHistoryPage.tsx is missing modal boundary marker '$marker'"
    }
}
foreach ($marker in @('fs.promises.open(selectedPath, "wx", 0o600)', 'await file.sync()', 'path.basename(selectedPath)')) {
    if (-not $aiHistoryExportText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/ai-history-export-boundary.ts is missing native export marker '$marker'"
    }
}
foreach ($marker in @('mod ai_history_api;', 'AiHistoryList', 'AiHistoryGet', 'AiHistoryPlanRemove', 'AiHistoryPlanClear', 'AiHistoryConfirmMutation', 'AiHistoryCancelMutation', 'AiHistoryExport')) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing AI history RPC marker '$marker'"
    }
}
foreach ($marker in @('AiHistoryRecord', 'DangerousConfirmation', 'MAX_EXPORT_BYTES', '.ai_history()')) {
    if (-not $aiHistoryApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/ai_history_api.rs is missing portable safety marker '$marker'"
    }
}
if ($contractApiMatch.Success) {
    foreach ($signature in @(
        'listCommandHistory\(\s*bindingHandle:\s*string,\s*query:\s*string,\s*offset:\s*number,\s*limit:\s*number,?\s*\):\s*Promise<CommandHistoryListPage>;',
        'getCommandHistory\(bindingHandle:\s*string,\s*recordId:\s*string\):\s*Promise<CommandHistoryRecord>;',
        'planCommandReplay\(bindingHandle:\s*string,\s*recordId:\s*string\):\s*Promise<CommandReplayIntent>;',
        'planCommandHistoryRemove\(bindingHandle:\s*string,\s*recordId:\s*string\):\s*Promise<CommandHistoryMutationProposal>;',
        'planCommandHistoryClear\(bindingHandle:\s*string\):\s*Promise<CommandHistoryMutationProposal>;',
        'confirmCommandHistoryMutation\(bindingHandle:\s*string,\s*mutationHandle:\s*string\):\s*Promise<CommandHistoryMutationResult>;',
        'cancelCommandHistoryMutation\(bindingHandle:\s*string,\s*mutationHandle:\s*string\):\s*Promise<CommandHistoryMutationCancellation>;'
    )) {
        if ($contractApiMatch.Groups['body'].Value -notmatch $signature) {
            Add-GateViolation "electron/src/shared/contract.ts is missing fixed command history signature '$signature'"
        }
    }
    if ($contractApiMatch.Groups['body'].Value -match '(?im)^\s{2}(?:execute|executeCommand|runCommand|shell)\s*\(') {
        Add-GateViolation 'electron/src/shared/contract.ts exposes a forbidden command execution capability'
    }
}
if ($commandHistoryContractText -match '(?im)^\s*(?:sessionId|targetGuard|authorization|commandSha256)\??\s*:' -or
    $commandHistoryContractText -notmatch 'executionAvailable:\s*false') {
    Add-GateViolation 'electron/src/shared/command-history-contract.ts exposes SSH internals or permits command execution'
}
if (-not $appTitleBarText.Contains('data-testid="open-command-history"', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'electron/src/renderer/AppTitleBar.tsx is missing the command history control'
}
foreach ($marker in @('CommandHistoryPanel', 'onOpenCommandHistory: openCommandHistory', 'commandHistoryOpen', 'commandHistoryPanelRef.current?.beforeClose()', 'inert={overlayOpen ? true : undefined}')) {
    if (-not $appText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/App.tsx is missing command history overlay marker '$marker'"
    }
}
foreach ($marker in @('aria-modal="true"', 'inert={proposalOpen ? true : undefined}', 'event.key === "Escape"', 'beforeClose', 'cancelHandleBestEffort', 'lifecycleRef')) {
    if (-not $commandHistoryPanelText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/CommandHistoryPanel.tsx is missing fail-closed modal marker '$marker'"
    }
}
foreach ($token in @('--surface:', '--surface-alt:', '--text:', '--muted:', '--border:', '--accent:', '--danger:', '--success:', '--warning:', '--console-bg:', '--console-text:')) {
    if (-not $themeTokensText.Contains($token, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/theme/themes.css is missing readable theme token '$token'"
    }
}
foreach ($marker in @('background: var(--surface);', 'color: var(--text);', 'color: var(--muted);', 'background: var(--surface-alt);')) {
    if (-not $commandHistoryCssText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/command-history.css is missing theme marker '$marker'"
    }
}
foreach ($marker in @('mod command_history_api;', 'CommandHistoryList', 'CommandHistoryGet', 'CommandHistoryPlanReplay', 'CommandHistoryPlanRemove', 'CommandHistoryPlanClear', 'CommandHistoryConfirmMutation', 'CommandHistoryCancelMutation')) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing command history RPC marker '$marker'"
    }
}
foreach ($marker in @('CommandReplayIntentDto', 'execution_available: false', 'BoundSshSession', 'DangerousConfirmation', 'MAX_PENDING_MUTATIONS')) {
    if (-not $commandHistoryApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/command_history_api.rs is missing target-bound safety marker '$marker'"
    }
}
foreach ($marker in @('COMMAND_HISTORY_RPC_METHODS', 'command-history.list', 'command-history.get', 'command-history.replay.plan', 'command-history.remove.plan', 'command-history.clear.plan', 'command-history.mutation.confirm', 'command-history.mutation.cancel')) {
    if (-not $backendClientText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing fixed command history marker '$marker'"
    }
}
if ($contractApiMatch.Success) {
    foreach ($signature in @(
        'generateDisposalReport\(bindingHandle:\s*string\):\s*Promise<DisposalReportSnapshot>;',
        'getDisposalReportContent\(\s*bindingHandle:\s*string,\s*reportHandle:\s*string,\s*format:\s*DisposalReportPreviewFormat,?\s*\):\s*Promise<DisposalReportContent>;',
        'exportDisposalReport\(\s*bindingHandle:\s*string,\s*reportHandle:\s*string,\s*format:\s*DisposalReportExportFormat,?\s*\):\s*Promise<DisposalReportExportResult>;'
    )) {
        if ($contractApiMatch.Groups['body'].Value -notmatch $signature) {
            Add-GateViolation "electron/src/shared/contract.ts is missing fixed disposal report signature '$signature'"
        }
    }
}
$disposalApiMatch = [regex]::Match(
    $disposalReportContractText,
    '(?ms)export\s+interface\s+DisposalReportApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $disposalApiMatch.Success -or
    $disposalApiMatch.Groups['body'].Value -match '(?i)\b(?:target|guard|session|journal|detection|body|path|snapshot|digest)\b') {
    Add-GateViolation 'electron/src/shared/disposal-report-contract.ts must expose only handles/formats as request parameters'
}
$disposalSnapshotMatch = [regex]::Match(
    $disposalReportContractText,
    '(?ms)export\s+interface\s+DisposalReportSnapshot\s*\{(?<body>.*?)^\s*\}'
)
if (-not $disposalSnapshotMatch.Success -or
    $disposalSnapshotMatch.Groups['body'].Value -notmatch '(?m)^\s*snapshotSha256:\s*string;' -or
    $disposalSnapshotMatch.Groups['body'].Value -notmatch '(?m)^\s*detectionIncluded:\s*false;' -or
    $disposalSnapshotMatch.Groups['body'].Value -match '(?im)^\s*(?:target|targetGuard|session|journal|operations|detection)\??\s*:') {
    Add-GateViolation 'electron/src/shared/disposal-report-contract.ts must keep only the sidecar integrity digest and detectionIncluded:false summary'
}
$disposalExportResultMatch = [regex]::Match(
    $disposalReportContractText,
    '(?ms)export\s+interface\s+DisposalReportExportResult\s*\{(?<body>.*?)^\s*\}'
)
if (-not $disposalExportResultMatch.Success -or
    $disposalExportResultMatch.Groups['body'].Value -notmatch '(?m)^\s*saved:\s*boolean;' -or
    $disposalExportResultMatch.Groups['body'].Value -notmatch '(?m)^\s*fileName:\s*string\s*\|\s*null;' -or
    $disposalExportResultMatch.Groups['body'].Value -notmatch '(?m)^\s*operationCount:\s*number;' -or
    $disposalExportResultMatch.Groups['body'].Value -match '(?im)^\s*(?:path|contents?|body)\??\s*:') {
    Add-GateViolation 'electron/src/shared/disposal-report-contract.ts export response must contain only saved/fileName/operationCount'
}
foreach ($marker in @('DisposalReportOverlay', 'data-testid="open-disposal-report"', 'disposalReportOpen', 'disposalReportOverlayRef.current?.beforeClose()', 'inert={overlayOpen ? true : undefined}')) {
    if (-not $appText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/App.tsx is missing disposal report overlay marker '$marker'"
    }
}
foreach ($marker in @('aria-modal="true"', 'event.key === "Escape"', 'beforeClose', 'returnFocusElement', 'lifecycleRef', '<pre>{state.content.content}</pre>', '所有格式均按纯文本显示，不会渲染 HTML')) {
    if (-not $disposalReportOverlayText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/DisposalReportOverlay.tsx is missing fail-closed plain-text modal marker '$marker'"
    }
}
if ($disposalReportOverlayText -match '(?:\.inert\s*=|setAttribute\(\s*["'']aria-hidden)') {
    Add-GateViolation 'electron/src/renderer/DisposalReportOverlay.tsx must leave sibling inert ownership to App'
}
foreach ($marker in @('background: var(--surface);', 'color: var(--text);', 'color: var(--muted);', 'background: var(--console-bg);', 'color: var(--console-text);')) {
    if (-not $disposalReportCssText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/disposal-report.css is missing readable theme marker '$marker'"
    }
}
foreach ($marker in @('mod disposal_report_api;', 'DisposalReportGenerate', 'DisposalReportContentGet', 'DisposalReportExport', 'deny_unknown_fields')) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing disposal report RPC marker '$marker'"
    }
}
foreach ($marker in @('detection_included: false', 'BoundSshSession', 'MAX_REPORTS', 'MAX_FORMAT_BYTES', 'InternalDisposalReportExport', 'snapshot_sha256')) {
    if (-not $disposalReportApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/disposal_report_api.rs is missing target-bound safety marker '$marker'"
    }
}
foreach ($marker in @('DISPOSAL_REPORT_RPC_METHODS', 'disposal-report.generate', 'disposal-report.content.get', 'disposal-report.export', 'isDisposalReportSnapshot', 'isDisposalReportContent', 'isInternalDisposalReportExportPayload')) {
    if (-not $backendClientText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing fixed disposal report marker '$marker'"
    }
}
foreach ($marker in @('cancelledDisposalReportExport', 'saveDisposalReportExport', 'dialog.showSaveDialog', 'DISPOSAL_REPORT_MARKDOWN_FILTER', 'DISPOSAL_REPORT_HTML_FILTER')) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing native disposal report export marker '$marker'"
    }
}
foreach ($marker in @('fs.promises.open(selectedPath, "wx", 0o600)', 'await file.sync()', 'path.basename(selectedPath)')) {
    if (-not $disposalReportExportText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/disposal-report-export-boundary.ts is missing native export marker '$marker'"
    }
}
if ([regex]::Matches($appText, 'beforeSettingsTransition\(settingsOpen,\s*settingsPanelRef\.current\)').Count -lt 2) {
    Add-GateViolation 'electron/src/renderer/App.tsx must guard both window close and navigation with SettingsPanel.beforeClose'
}
if ([regex]::Matches($appText, 'inert=\{overlayOpen\s*\?\s*true\s*:\s*undefined\}').Count -ne 3) {
    Add-GateViolation 'electron/src/renderer/App.tsx must make the sidebar, workspace, and status bar inert for either overlay'
}
foreach ($marker in @(
    'mod settings_api;', 'SettingsGet', 'SettingsSave',
    'SettingsAiApiKeyReplace', 'SettingsAiApiKeyClearPlan', 'SettingsAiProviderRemovePlan',
    'SettingsMutationConfirm', 'SettingsMutationCancel',
    'settings.get', 'settings.save', 'settings.ai-api-key.replace',
    'settings.ai-api-key.clear.plan', 'settings.ai-provider.remove.plan',
    'settings.mutation.confirm', 'settings.mutation.cancel'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing Settings RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'SettingsRepository', 'has_api_key: false', 'MAX_SETTINGS_TEXT_BYTES',
    'SecretValue::new(api_key)', 'DangerousConfirmation::approve',
    'MAX_PENDING_MUTATIONS', 'MUTATION_TTL', 'independently_verified'
)) {
    if (-not $settingsApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/settings_api.rs is missing boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'SETTINGS_RPC_METHODS', 'settings.ai-api-key.replace', 'settings.ai-api-key.clear.plan',
    'settings.ai-provider.remove.plan', 'settings.mutation.confirm', 'settings.mutation.cancel',
    'isSettingsAiApiKeyReplacementInput', 'isSettingsAiApiKeyReplacementResult',
    'isSettingsMutationProposal', 'isSettingsMutationResult', 'isSettingsMutationCancellation'
)) {
    if (-not $backendClientText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing Settings secret lifecycle marker '$marker'"
    }
}
foreach ($marker in @(
    'data-testid="settings-api-key-input"', 'data-testid="settings-api-key-replace"',
    'data-testid="settings-api-key-clear"', 'data-testid="settings-provider-remove"',
    'data-testid="settings-mutation-cancel"', 'data-testid="settings-mutation-confirm"',
    'setApiKeyDraft("")', 'input.apiKey = ""', 'type="password"',
    'autoComplete="new-password"', 'applySettingsMutation', 'settingsEscapeIntent'
)) {
    if (-not $settingsPanelText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/SettingsPanel.tsx is missing Settings secret lifecycle marker '$marker'"
    }
}

if ($contractApiMatch.Success -and
    $contractApiMatch.Groups['body'].Value -notmatch 'openSshTerminal\(\s*\):\s*Promise<TerminalWindowLaunchResult>;') {
    Add-GateViolation 'electron/src/shared/contract.ts must expose exactly one handle-free openSshTerminal launch method'
}
$terminalApiMatch = [regex]::Match(
    $terminalContractText,
    '(?ms)export\s+interface\s+TerminalApi\s*\{(?<body>.*?)^\s*\}'
)
if (-not $terminalApiMatch.Success) {
    Add-GateViolation 'electron/src/shared/terminal-contract.ts is missing TerminalApi'
} else {
    $terminalApiNames = @([regex]::Matches($terminalApiMatch.Groups['body'].Value, '(?m)^\s{2}(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(') | ForEach-Object { $_.Groups['name'].Value })
    if (($terminalApiNames -join "`n") -cne (@('open', 'poll', 'input', 'resize', 'search', 'copySelection', 'close', 'openSftpBrowser', 'listSftpDirectory', 'readSftpText', 'downloadSftpEntry', 'planSftpOperation', 'confirmSftpOperation',
        'executeSftpOperation', 'cancelSftpOperation', 'stageSftpUpload',
        'openLocalBrowser', 'listLocalDirectory') -join "`n")) {
        Add-GateViolation 'electron/src/shared/terminal-contract.ts TerminalApi must expose exactly eighteen methods'
    }
    # The browser capabilities are opaque, window-scoped handles; target
    # identity stays forbidden.
    $terminalApiBody = $terminalApiMatch.Groups['body'].Value -replace 'browserHandle|directoryHandle|fileHandle|planHandle|stagedHandle', 'capability'
    if ($terminalApiBody -match '(?i)\b(?:binding|session|guard|host|path|command|token|handle|snapshot|invoke)\b') {
        Add-GateViolation 'electron/src/shared/terminal-contract.ts TerminalApi exposes a forbidden capability or internal field'
    }
}
foreach ($marker in @(
    'const TERMINAL_WINDOW_KIND = "ssh-terminal";',
    'const TERMINAL_WINDOW_URL = `${RENDERER_SCHEME}://${RENDERER_HOST}/?window=terminal`;',
    'const terminalBindingState = new TerminalBindingLaunchState();',
    'const terminalWindowsByKey = new Map<string, TerminalWindowContext>();',
    'launchToken: randomUUID()',
    'context.launchToken = null;',
    'terminalWindowKey(bindingHandle)',
    'terminalWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }))',
    'contextIsolation: true', 'nodeIntegration: false', 'sandbox: true', 'webSecurity: true',
    'closeTerminalWindowsForBinding(bindingHandle)',
    'stopBackendWithTerminalWindows()',
    'terminalBindingState.currentBindingHandle() !== context.bindingHandle',
    'openTerminalWithFailureCleanup(',
    '() => closeTerminalContext(context, true)'
)) {
    if (-not $mainText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/index.ts is missing terminal window boundary marker '$marker'"
    }
}
foreach ($marker in @(
    'await closeContext().catch(() => undefined);',
    'throw new Error(TERMINAL_OPEN_FAILURE);',
    'terminalIsOpen && values.length === 1 && isTerminalSelectionCopyText(values[0])'
)) {
    if (-not $terminalOpenBoundaryText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/terminal-open-boundary.ts is missing fail-closed marker '$marker'"
    }
}
if ($mainText -match '(?i)\bwindow\.name\s*=') {
    Add-GateViolation 'electron/src/main/index.ts puts a terminal capability into URL, hash, query, or window.name'
}
foreach ($channel in @(
    'lovelyres:terminal:open', 'lovelyres:terminal:poll', 'lovelyres:terminal:input',
    'lovelyres:terminal:resize', 'lovelyres:terminal:search',
    'lovelyres:terminal:copy-selection', 'lovelyres:terminal:close'
)) {
    if ([regex]::Matches($mainText, ('\bipcMain\.handle\s*\(\s*["'']{0}["'']' -f [regex]::Escape($channel))).Count -ne 1) {
        Add-GateViolation "electron/src/main/index.ts must register terminal IPC '$channel' exactly once"
    }
}
foreach ($marker in @(
    'mod terminal_api;', 'TerminalOpen', 'TerminalPoll', 'TerminalInput', 'TerminalResize',
    'TerminalRenderSnapshot', 'TerminalSearch', 'TerminalClose',
    'terminal.open', 'terminal.poll', 'terminal.input', 'terminal.resize',
    'terminal.render-snapshot', 'terminal.search', 'terminal.close'
)) {
    if (-not $backendLibText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/lib.rs is missing terminal RPC marker '$marker'"
    }
}
foreach ($marker in @(
    'TERMINAL_RPC_METHODS', 'isTerminalOpened', 'isTerminalPoll',
    'isTerminalInputAcknowledgement', 'isTerminalResized', 'isTerminalRenderSnapshot',
    'isTerminalSearch', 'isTerminalClosed'
)) {
    if (-not $backendClientText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/main/backend-client.ts is missing terminal validator marker '$marker'"
    }
}
foreach ($marker in @(
    'MAX_TERMINALS', 'MAX_TERMINALS_PER_TARGET', 'MAX_INPUT_BYTES', 'MAX_POLL_BYTES',
    'MAX_TOTAL_OUTPUT_BYTES', 'MAX_SNAPSHOT_BYTES', 'MAX_SEARCH_RESULTS',
    'ensure_binding_unchanged', 'close_binding', 'shutdown', 'ProtocolViolation'
)) {
    if (-not $terminalApiText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "crates/lovelyres-electron-backend/src/terminal_api.rs is missing bounded lifecycle marker '$marker'"
    }
}
foreach ($marker in @(
    'window.lovelyres.openSshTerminal()', 'sshTerminalDisabled: activeTarget === null'
)) {
    if (-not $appText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/App.tsx is missing terminal launch marker '$marker'"
    }
}
foreach ($marker in @(
    'data-testid="open-ssh-terminal"', 'disabled={actions.sshTerminalDisabled}'
)) {
    if (-not $appTitleBarText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/src/renderer/AppTitleBar.tsx is missing terminal launch marker '$marker'"
    }
}
# The window may name its own local state; it may never hold target identity
# or reach the main-window API.
$terminalWindowIdentity = $terminalWindowText -replace '\btoken\b', 'local'
if ($terminalWindowText -notmatch '(?s)<TerminalSurface\s+api=\{window\.lovelyresTerminal\}\s+writeClipboard=\{window\.lovelyresTerminal\.copySelection\}' -or
    $terminalWindowText -notmatch '(?s)<SftpBrowserPage\s' -or
    $terminalWindowIdentity -match '(?i)\b(?:bindingHandle|sessionId|connectionId|targetIdentity|hostKey|remotePath|guard|snapshotHandle|handle)\b' -or
    $terminalWindowText -match 'window\.lovelyres\b') {
    Add-GateViolation 'electron/src/renderer/TerminalWindow.tsx must mount only the handle-free dedicated terminal API and its trusted copy boundary'
}
if ($terminalSurfaceText -match '(?i)\b(?:bindingHandle|scopeKey|sessionId|targetGuard|launchToken)\b' -or
    $terminalControllerText -match '(?i)\b(?:bindingHandle|sessionId|targetGuard|launchToken|render_snapshot)\b') {
    Add-GateViolation 'Electron terminal renderer retains a forbidden binding, session, guard, token, or snapshot capability'
}
if ($terminalPreloadText -match '(?i)(?:\bnavigator\.clipboard\b|\bdocument\.execCommand\b|\breadClipboard\b|\breadText\b|\bclipboardData\b)' -or
    $terminalWindowText -match '(?i)(?:\bnavigator\.clipboard\b|\bdocument\.execCommand\b|\breadClipboard\b|\breadText\b|\bclipboardData\b)' -or
    $terminalSurfaceText -match '(?i)(?:\bnavigator\.clipboard\b|\bdocument\.execCommand\b|\breadClipboard\b|\breadText\b|\bclipboardData\b)' -or
    -not $terminalContractText.Contains('maximumSelectionCopyBytes: 128 * 1_024', [System.StringComparison]::Ordinal) -or
    -not $mainText.Contains('isTerminalSelectionCopyRequest(context.terminalHandle !== null, values)', [System.StringComparison]::Ordinal) -or
    -not $mainText.Contains('clipboard.writeText(values[0]);', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'Electron terminal selection copy must be write-only, main-owned, sender-bound, and limited to 128 KiB UTF-8'
}
foreach ($marker in @(
    'copyBoundedTerminalSelection(terminal, writeClipboard)',
    'if (!terminal.hasSelection()) return false;',
    'event.preventDefault();',
    'event.stopImmediatePropagation();',
    'host.addEventListener("copy", copyListener, true);',
    'host.removeEventListener("copy", copyListener, true);'
)) {
    if (-not $terminalSurfaceText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "Electron terminal keyboard/button copy boundary is missing marker '$marker'"
    }
}

$rendererRoots = @(
    (Join-Path $electronRoot 'src/renderer'),
    (Join-Path $electronRoot 'src/shared')
)
$rendererFiles = @($rendererRoots | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -Recurse -File | Where-Object {
        $_.Name -notmatch '\.(?:test|spec)\.[^.]+$' -and
        $_.Extension.ToLowerInvariant() -in @('.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.css', '.html')
    }
})
foreach ($file in $rendererFiles) {
    $relative = Get-RelativeName -Path $file.FullName
    $text = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($reason in @(Get-RendererCodeViolation -Text $text)) {
        Add-GateViolation "$relative contains forbidden $reason"
    }
    $remoteReason = Get-RemoteUiResourceViolation -Text $text
    if ($null -ne $remoteReason) {
        Add-GateViolation "$relative contains a $remoteReason"
    }
}
$htmlRemoteReason = Get-RemoteUiResourceViolation -Text $htmlText
if ($null -ne $htmlRemoteReason) {
    Add-GateViolation "electron/index.html contains a $htmlRemoteReason"
}
$assetTextFiles = @(Get-ChildItem -LiteralPath (Join-Path $electronRoot 'assets') -Recurse -File | Where-Object {
    $_.Extension.ToLowerInvariant() -in @('.css', '.html', '.svg', '.js', '.mjs', '.cjs')
})
foreach ($file in $assetTextFiles) {
    $reason = Get-RemoteUiResourceViolation -Text (Get-Content -LiteralPath $file.FullName -Raw)
    if ($null -ne $reason) {
        Add-GateViolation "$(Get-RelativeName -Path $file.FullName) contains a $reason"
    }
}

$tsRequestLimit = Get-DeclaredByteLimit -Text $backendClientText -Name 'MAX_REQUEST_BYTES' -Language TypeScript
$tsResponseLimit = Get-DeclaredByteLimit -Text $backendClientText -Name 'MAX_RESPONSE_BYTES' -Language TypeScript
$rustRequestLimit = Get-DeclaredByteLimit -Text $backendLibText -Name 'MAX_REQUEST_BYTES' -Language Rust
$rustResponseLimit = Get-DeclaredByteLimit -Text $backendLibText -Name 'MAX_RESPONSE_BYTES' -Language Rust
foreach ($limit in @(
    @{ Name = 'TypeScript MAX_REQUEST_BYTES'; Value = $tsRequestLimit; Maximum = 16MB },
    @{ Name = 'TypeScript MAX_RESPONSE_BYTES'; Value = $tsResponseLimit; Maximum = 16MB },
    @{ Name = 'Rust MAX_REQUEST_BYTES'; Value = $rustRequestLimit; Maximum = 16MB },
    @{ Name = 'Rust MAX_RESPONSE_BYTES'; Value = $rustResponseLimit; Maximum = 16MB }
)) {
    if ($null -eq $limit.Value) {
        Add-GateViolation "$($limit.Name) must be a positive literal multiplication expression"
    } elseif ([int64]$limit.Value -le 0 -or [int64]$limit.Value -gt [int64]$limit.Maximum) {
        Add-GateViolation "$($limit.Name) is outside the allowed bound of 1..$($limit.Maximum) bytes"
    }
}
if ($null -ne $tsRequestLimit -and $null -ne $rustRequestLimit -and $tsRequestLimit -ne $rustRequestLimit) {
    Add-GateViolation 'TypeScript and Rust MAX_REQUEST_BYTES limits must match'
}
if ($null -ne $tsResponseLimit -and $null -ne $rustResponseLimit -and $tsResponseLimit -ne $rustResponseLimit) {
    Add-GateViolation 'TypeScript and Rust MAX_RESPONSE_BYTES limits must match'
}
if ($null -ne $tsRequestLimit -and $null -ne $tsResponseLimit -and $tsResponseLimit -lt $tsRequestLimit) {
    Add-GateViolation 'MAX_RESPONSE_BYTES must not be smaller than MAX_REQUEST_BYTES'
}
foreach ($check in @(
    @{ File = 'electron/src/main/backend-client.ts'; Text = $backendClientText; Pattern = 'Buffer\.byteLength\s*\(\s*encoded\s*,\s*"utf8"\s*\)\s*>\s*MAX_REQUEST_BYTES'; Name = 'encoded request byte check' },
    @{ File = 'electron/src/main/backend-client.ts'; Text = $backendClientText; Pattern = 'Buffer\.byteLength\s*\(\s*this\.#stdoutBuffer\s*,\s*"utf8"\s*\)\s*>\s*MAX_RESPONSE_BYTES'; Name = 'buffered response byte check' },
    @{ File = 'crates/lovelyres-electron-backend/src/lib.rs'; Text = $backendLibText; Pattern = 'frame\.len\(\)\.saturating_add\(payload_len\)\s*>\s*MAX_REQUEST_BYTES'; Name = 'frame request byte check' },
    @{ File = 'crates/lovelyres-electron-backend/src/lib.rs'; Text = $backendLibText; Pattern = 'encoded\.len\(\)\s*>\s*MAX_RESPONSE_BYTES'; Name = 'serialized response byte check' }
)) {
    if ($check.Text -notmatch $check.Pattern) {
        Add-GateViolation "$($check.File) is missing the $($check.Name)"
    }
}
if ($backendClientText -notmatch '(?m)^\s*const\s+REQUEST_TIMEOUT_MS\s*=\s*[0-9_]+\s*;' -or
    $backendClientText -notmatch 'setTimeout\s*\(') {
    Add-GateViolation 'electron/src/main/backend-client.ts must bound request lifetime with REQUEST_TIMEOUT_MS'
}
if ($mainText -notmatch '(?m)^\s*const\s+MAX_CLIPBOARD_BYTES\s*=\s*[0-9_ `t*]+\s*;' -or
    $mainText -notmatch 'Buffer\.byteLength\s*\(\s*value\s*,\s*"utf8"\s*\)\s*>\s*MAX_CLIPBOARD_BYTES') {
    Add-GateViolation 'electron/src/main/index.ts must enforce a byte limit on clipboard IPC'
}
if ($mainText -notmatch 'value\.length\s*>\s*[0-9_]+' -or
    $mainText -notmatch 'item\.length\s*<=\s*[0-9_]+') {
    Add-GateViolation 'electron/src/main/index.ts must enforce item and string limits on favorites IPC'
}

$requiredAssets = [ordered]@{
    'assets/app.ico' = 'A00B2CFF979B9F21AA0DD2A00661448406CA33B3081E197C13762C6832083E17'
    'assets/logo.png' = 'C1C0B0181719FE4FA66D0395D69A776FA9C8DD13D65A4F0CE7D2801D0CDB3297'
    'assets/fonts/Inter-Regular.ttf' = '40D692FCE188E4471E2B3CBA937BE967878F631AD3EBBBDCD587687C7EBE0C82'
    'assets/fonts/Inter-SemiBold.ttf' = '78A843FADE9D4612A5567302FB595B56976EB5FCEBF4FEA5A5912D638BAFCDE3'
    'assets/fonts/CascadiaMono.ttf' = '08026F617EEA315CACA59898784E999F6CDB2D0C34D2040DEEB042BCDC359FA2'
    'assets/security_reference.json' = '8694D9022C20919AB6F73EEAF4F041F2660D1CF0EA3E94033E5732E06F2BE731'
}
foreach ($entry in $requiredAssets.GetEnumerator()) {
    $path = Join-Path $electronRoot $entry.Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Add-GateViolation "missing pinned Electron asset 'electron/$($entry.Key)'"
        continue
    }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actualHash -ne $entry.Value) {
        Add-GateViolation "electron/$($entry.Key) SHA-256 is $actualHash, expected $($entry.Value)"
    }
}
$viteText = Get-Content -LiteralPath (Join-Path $electronRoot 'vite.config.mts') -Raw
foreach ($marker in @('base: "./"', 'publicDir: path.resolve(projectRoot, "assets")')) {
    if (-not $viteText.Contains($marker, [System.StringComparison]::Ordinal)) {
        Add-GateViolation "electron/vite.config.mts is missing local-asset marker '$marker'"
    }
}

$lockNames = @('pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'bun.lock', 'bun.lockb')
$skipDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($name in @('.git', 'node_modules', 'target', 'coverage', 'data', 'dist-electron', 'dist-renderer')) {
    [void]$skipDirectories.Add($name)
}
$lockFiles = [System.Collections.Generic.List[string]]::new()
$pendingDirectories = [System.Collections.Generic.Queue[string]]::new()
$pendingDirectories.Enqueue($root)
while ($pendingDirectories.Count -gt 0) {
    $directory = $pendingDirectories.Dequeue()
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -File -Force)) {
        if ($file.Name -in $lockNames) { $lockFiles.Add($file.FullName) }
    }
    foreach ($child in @(Get-ChildItem -LiteralPath $directory -Directory -Force)) {
        if ($skipDirectories.Contains($child.Name)) { continue }
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $pendingDirectories.Enqueue($child.FullName)
    }
}
$relativeLocks = @($lockFiles | ForEach-Object { Get-RelativeName -Path $_ } | Sort-Object)
if ($relativeLocks.Count -ne 1 -or $relativeLocks[0] -cne 'pnpm-lock.yaml') {
    Add-GateViolation "the repository must use one root pnpm-lock.yaml and no npm/yarn/bun lockfiles; found [$($relativeLocks -join ', ')]"
}
$rootPackageText = Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw
if ($rootPackageText -notmatch '"packageManager"\s*:\s*"pnpm@[0-9]+(?:\.[0-9]+){2}"') {
    Add-GateViolation 'package.json must pin packageManager to an exact pnpm version'
}
$workspaceText = Get-Content -LiteralPath (Join-Path $root 'pnpm-workspace.yaml') -Raw
if ($workspaceText -notmatch '(?m)^\s*-\s+electron\s*$') {
    Add-GateViolation 'pnpm-workspace.yaml must include the Electron workspace entry'
}

if ($violations.Count -gt 0) {
    throw "Electron source gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}

Write-Host "Electron source gate passed ($($rendererFiles.Count) renderer-reachable source files, $($requiredAssets.Count) pinned assets; BrowserWindow, CSP, custom protocol, preload API, IPC bounds, and pnpm lock verified)."
