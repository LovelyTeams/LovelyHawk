[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SelfTest,
    # Only scan the built UI bundle; the release build runs this right after
    # building it, because that bundle is what gets embedded.
    [switch]$BundleOnly
)

# Source and security gate for the Tauri 2 desktop application.
#
# The host (crates/lovelyhawk-desktop) is the trust boundary: it owns windows,
# local paths, exports, the clipboard and the method allowlist. Pages (ui/) only
# reach it through the host bridge in ui/src/host. This gate fails closed on any
# change that would widen what a page can do.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredMainCsp = [ordered]@{
    'default-src' = "'none'"
    'script-src' = "'self'"
    'style-src' = "'self'"
    'img-src' = "'self' data:"
    'font-src' = "'self'"
    'connect-src' = 'ipc: http://ipc.localhost https://ipc.localhost'
    'worker-src' = "'none'"
    'frame-src' = "'none'"
    'object-src' = "'none'"
    'base-uri' = "'none'"
    'form-action' = "'none'"
}
$requiredTerminalCsp = [ordered]@{
    'default-src' = "'none'"
    'script-src' = "'self'"
    # xterm's DOM renderer computes dimensions and palette rules at runtime.
    'style-src' = "'self' 'unsafe-inline'"
    'img-src' = "'self'"
    'font-src' = "'self'"
    'connect-src' = 'ipc: http://ipc.localhost https://ipc.localhost'
    'worker-src' = "'none'"
    'frame-src' = "'none'"
    'object-src' = "'none'"
    'base-uri' = "'none'"
    'form-action' = "'none'"
}
# The host-wide header policy is the union of the page policies; each page then
# narrows it with its own meta policy.
$requiredHostCsp = [ordered]@{
    'default-src' = "'none'"
    'script-src' = "'self'"
    'style-src' = "'self' 'unsafe-inline'"
    'img-src' = "'self' data:"
    'font-src' = "'self'"
    'connect-src' = 'ipc: http://ipc.localhost https://ipc.localhost'
    'worker-src' = "'none'"
    'frame-src' = "'none'"
    'object-src' = "'none'"
    'base-uri' = "'none'"
    'form-action' = "'none'"
}

$pageCodePatterns = [ordered]@{
    'Node child_process API' = '(?i)(?:["'']node:child_process["'']|(?:from\s*|import\s*\(|require\s*\()\s*["'']child_process["''])'
    'Node fs API' = '(?i)(?:["'']node:fs(?:/promises)?["'']|(?:from\s*|import\s*\(|require\s*\()\s*["'']fs(?:/promises)?["''])'
    'Electron API import' = '(?i)(?:from\s*|import\s*\(|require\s*\()\s*["'']electron(?:/renderer)?["'']'
    'Tauri plugin package' = '(?i)["'']@tauri-apps/plugin-[a-z-]+["'']'
    'raw Tauri internals' = '__TAURI_INTERNALS__'
    'innerHTML DOM sink' = '(?i)(?:\.\s*innerHTML\b|\bdangerouslySetInnerHTML\b)'
    'eval execution' = '(?i)(?<![A-Za-z0-9_$])eval\s*\('
    'new Function execution' = '(?i)\bnew\s+Function\s*\('
    'system-level dialog' = '(?i)\bwindow\s*\.\s*(?:alert|confirm|prompt)\s*\('
    'window.open navigation' = '(?i)\bwindow\s*\.\s*open\s*\('
}

$requiredHostMarkers = [ordered]@{
    'lib.rs' = @('#![forbid(unsafe_code)]', 'instance_lock::acquire(&data_directory)', 'development', 'tokio::time::timeout(BACKEND_STOP_GRACE, bridge.shutdown())')
    'host.rs' = @(
        '.decorations(false)',
        '.data_directory(self.webview_data.clone())',
        '.incognito(true)',
        '.disable_drag_drop_handler()',
        '.general_autofill_enabled(false)',
        '.devtools(self.debug_mode)',
        '.on_navigation(move |url| page.allows(url))',
        '.on_new_window(|_, _| NewWindowResponse::Deny)',
        '.on_download(|_, _| false)',
        '.on_permission_request(|_, _| PermissionResponse::Deny)'
    )
    'backend_bridge.rs' = @('const MAIN_WINDOW_METHODS', 'pub fn main_window_may_call', 'tokio::sync::Mutex<()>')
    'main_commands.rs' = @('fn require_main', 'main_window_may_call(&method, &params)')
    'child_commands.rs' = @('fn scope<R: Runtime>', 'is_child_label(label)', 'fn still_current')
    'local_files.rs' = @('.create_new(true)', '.filter(|path| path.is_absolute())')
    'test_hooks.rs' = @('#[cfg(debug_assertions)]', '#[cfg(not(debug_assertions))]')
}
# Local paths and export payloads stay inside the host.
$forbiddenPageMethods = @(
    'connections.import-file',
    'connections.export-file',
    'sftp-browser.download',
    'sftp-browser.upload.stage',
    'application-log.export.prepare',
    'ai-history.export',
    'disposal-report.export',
    'config.quick.copy',
    'config.quick.artifact',
    'config.quick.bundle.export',
    'terminal.open',
    'terminal.poll',
    'terminal.input',
    'terminal.resize',
    'terminal.search',
    'terminal.close',
    'terminal.render-snapshot',
    'docker.container.terminal.open',
    'kubernetes.pod.terminal.open'
)
$allowedCorePermissions = @(
    'core:event:allow-listen',
    'core:event:allow-unlisten',
    'core:window:allow-minimize',
    'core:window:allow-toggle-maximize',
    'core:window:allow-internal-toggle-maximize',
    'core:window:allow-is-maximized',
    'core:window:allow-start-dragging',
    'core:window:allow-close'
)

function Get-CspViolation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Policy,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Expected,
        [switch]$AllowInlineStyle
    )

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
    foreach ($entry in $Expected.GetEnumerator()) {
        if (-not $actual.Contains($entry.Key)) {
            Write-Output "is missing directive '$($entry.Key)'"
        } elseif (-not [string]::Equals([string]$actual[$entry.Key], [string]$entry.Value, [System.StringComparison]::Ordinal)) {
            Write-Output "directive '$($entry.Key)' must be exactly '$($entry.Value)'"
        }
    }
    foreach ($name in $actual.Keys) {
        if (-not $Expected.Contains($name)) {
            Write-Output "contains unexpected directive '$name'"
        }
    }
    $checked = $Policy.Replace('http://ipc.localhost', '').Replace('https://ipc.localhost', '')
    if ($AllowInlineStyle) {
        $checked = $checked.Replace("style-src 'self' 'unsafe-inline'", "style-src 'self'")
    }
    if ($checked -match '(?i)(?:unsafe-inline|unsafe-eval|wasm-unsafe-eval|https?://|\*)') {
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

function Get-PageCodeViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    foreach ($entry in $pageCodePatterns.GetEnumerator()) {
        if ($Text -match $entry.Value) {
            Write-Output ([string]$entry.Key)
        }
    }
}

function Get-RemoteResourceViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $withoutNamespaces = $Text.Replace('http://www.w3.org/2000/svg', '').Replace('http://www.w3.org/1999/xlink', '')
    if ($withoutNamespaces -match '(?i)https?://') {
        return 'remote HTTP(S) UI resource or URL'
    }
    return $null
}

# The built bundle (ui/dist, embedded in the executable) carries third-party
# code whose strings mention URLs it never loads — React's error links, for
# one. There, only an actual load of a remote resource is a violation.
function Get-BundleResourceViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $patterns = @(
        'url\(\s*[''"]?(?:https?:)?//',
        '\b(?:src|href|poster|action|data)\s*=\s*[''"](?:https?:)?//',
        '@import\s+(?:url\(\s*)?[''"]?(?:https?:)?//',
        '\bimport\s*\(\s*[''"`](?:https?:)?//',
        '\bfrom\s*[''"](?:https?:)?//',
        '\b(?:fetch|importScripts|sendBeacon)\s*\(\s*[''"`](?:https?:)?//',
        '\bnew\s+(?:WebSocket|EventSource|Worker|SharedWorker)\s*\(\s*[''"`](?:wss?|https?):?//',
        '\.(?:src|href)\s*=\s*[''"`](?:https?:)?//'
    )
    foreach ($pattern in $patterns) {
        if ($Text -match "(?i)$pattern") { return "a remote resource load ($($Matches[0]))" }
    }
    return $null
}

function Get-CapabilityViolation {
    param(
        [Parameter(Mandatory = $true)]$Capability,
        [Parameter(Mandatory = $true)][string]$Identifier,
        [Parameter(Mandatory = $true)][string[]]$Windows,
        [Parameter(Mandatory = $true)][string[]]$Commands,
        [Parameter(Mandatory = $true)][string[]]$ForeignCommands
    )

    if ($Capability.identifier -cne $Identifier) { Write-Output "identifier must be '$Identifier'" }
    if ($Capability.PSObject.Properties['remote']) { Write-Output 'must not grant remote URLs' }
    if ($Capability.local -ne $true) { Write-Output 'must be local' }
    if ((@($Capability.windows) -join ',') -cne ($Windows -join ',')) {
        Write-Output "windows must be exactly [$($Windows -join ', ')]"
    }
    $permissions = @($Capability.permissions | ForEach-Object { [string]$_ })
    foreach ($permission in $permissions) {
        if ($permission -like 'core:*') {
            if ($allowedCorePermissions -notcontains $permission) { Write-Output "grants unapproved core permission '$permission'" }
        } elseif ($permission -notmatch '^allow-[a-z-]+$') {
            Write-Output "grants plugin or unknown permission '$permission'"
        }
    }
    foreach ($command in $Commands) {
        $name = 'allow-' + $command.Replace('_', '-')
        if ($permissions -notcontains $name) { Write-Output "is missing '$name'" }
    }
    foreach ($command in $ForeignCommands) {
        $name = 'allow-' + $command.Replace('_', '-')
        if ($permissions -contains $name) { Write-Output "must not grant the other window kind's '$name'" }
    }
}

function Assert-SelfTest {
    $good = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src ipc: http://ipc.localhost https://ipc.localhost; worker-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"
    if (@(Get-CspViolation -Policy $good -Expected $requiredMainCsp).Count -ne 0) {
        throw 'Desktop source gate self-test rejected the approved main-window CSP.'
    }
    foreach ($bad in @(
        $good.Replace("script-src 'self'", "script-src 'self' 'unsafe-eval'"),
        $good.Replace("style-src 'self'", "style-src 'self' 'unsafe-inline'"),
        $good.Replace("connect-src ipc: http://ipc.localhost https://ipc.localhost", "connect-src ipc: https://evil.example"),
        $good.Replace("; object-src 'none'", '')
    )) {
        if (@(Get-CspViolation -Policy $bad -Expected $requiredMainCsp).Count -eq 0) {
            throw "Desktop source gate self-test accepted an unsafe CSP: $bad"
        }
    }
    foreach ($sample in @('el.innerHTML = x', 'import { open } from "@tauri-apps/plugin-shell"', 'window.__TAURI_INTERNALS__.invoke("x")', 'eval("1")', 'window.open("https://x")', 'import { readFileSync } from "node:fs"', 'const cp = require("child_process")', 'import("electron")')) {
        if (@(Get-PageCodeViolation -Text $sample).Count -eq 0) {
            throw "Desktop source gate self-test accepted forbidden page code: $sample"
        }
    }
    if ($null -eq (Get-RemoteResourceViolation -Text 'url(https://fonts.example/a.woff2)')) {
        throw 'Desktop source gate self-test accepted a remote UI resource.'
    }
    foreach ($load in @(
        '@font-face{src:url(https://fonts.example/a.woff2)}',
        '<script src="https://cdn.example/react.js"></script>',
        '<link rel="stylesheet" href="//cdn.example/a.css">',
        '@import "https://cdn.example/x.css";',
        'fetch("https://api.example/v1")',
        'new WebSocket("wss://relay.example")',
        'img.src="https://tracker.example/p.gif"',
        'import("https://cdn.example/mod.js")'
    )) {
        if ($null -eq (Get-BundleResourceViolation -Text $load)) {
            throw "Desktop source gate self-test accepted a remote load in the bundle: $load"
        }
    }
    foreach ($harmless in @(
        'throw Error("Minified React error #"+e+"; visit https://react.dev/errors/"+e)',
        '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
        '@font-face{src:url(./fonts/inter.woff2)}',
        'fetch(url)'
    )) {
        if ($null -ne (Get-BundleResourceViolation -Text $harmless)) {
            throw "Desktop source gate self-test rejected harmless bundle text: $harmless"
        }
    }
    $capability = [pscustomobject]@{ identifier = 'main-window'; local = $true; windows = @('main'); permissions = @('core:window:allow-close', 'allow-backend-call', 'dialog:default') }
    if (@(Get-CapabilityViolation -Capability $capability -Identifier 'main-window' -Windows @('main') -Commands @('backend_call') -ForeignCommands @('terminal_open')).Count -eq 0) {
        throw 'Desktop source gate self-test accepted a plugin permission on a page.'
    }
    Write-Host 'Desktop source gate fixture self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$uiRoot = Join-Path $root 'ui'
$hostRoot = Join-Path $root 'crates/lovelyhawk-desktop'
$violations = [System.Collections.Generic.List[string]]::new()
function Add-GateViolation([string]$Message) { $violations.Add($Message) }
function Get-RelativeName([string]$Path) { return [System.IO.Path]::GetRelativePath($root, $Path).Replace('\', '/') }

function Get-BundleFiles {
    $bundle = Join-Path $uiRoot 'dist'
    if (-not (Test-Path -LiteralPath $bundle -PathType Container)) { return @() }
    return @(Get-ChildItem -LiteralPath $bundle -Recurse -File -Include '*.html', '*.css', '*.js', '*.mjs', '*.svg', '*.json')
}
function Add-BundleViolations([object[]]$Files) {
    foreach ($file in $Files) {
        $violation = Get-BundleResourceViolation -Text (Get-Content -LiteralPath $file.FullName -Raw)
        if ($null -ne $violation) { Add-GateViolation "$(Get-RelativeName $file.FullName) contains $violation" }
    }
}

if ($BundleOnly) {
    $bundleFiles = @(Get-BundleFiles)
    if ($bundleFiles.Count -eq 0) { throw 'Desktop source gate found no built UI bundle under ui/dist.' }
    Add-BundleViolations $bundleFiles
    if ($violations.Count -gt 0) {
        throw "Desktop bundle check failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
    }
    Write-Host "Desktop bundle check passed ($($bundleFiles.Count) built files load nothing remote)."
    return
}

$requiredFiles = @(
    'Cargo.toml', 'Cargo.lock', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml', '.github/workflows/ci.yml',
    'ui/package.json', 'ui/index.html', 'ui/terminal.html', 'ui/vite.config.mts',
    'ui/src/host/install.ts', 'ui/src/host/main-api.ts', 'ui/src/host/terminal-api.ts', 'ui/src/host/backend-client.ts',
    'ui/src/host/transport.ts', 'ui/src/host/window-chrome.ts', 'ui/src/renderer/main.tsx', 'ui/src/renderer/terminal-main.tsx',
    'ui/src/renderer/global.d.ts', 'ui/src/shared/contract.ts', 'ui/src/shared/terminal-contract.ts',
    'crates/lovelyhawk-desktop/Cargo.toml', 'crates/lovelyhawk-desktop/build.rs', 'crates/lovelyhawk-desktop/tauri.conf.json',
    'crates/lovelyhawk-desktop/capabilities/main-window.json', 'crates/lovelyhawk-desktop/capabilities/child-windows.json',
    'crates/lovelyhawk-desktop/icons/icon.ico',
    'crates/lovelyhawk-backend/src/lib.rs', 'crates/lovelyhawk-core/src/lib.rs'
)
foreach ($relative in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) {
        Add-GateViolation "missing required file '$relative'"
    }
}
foreach ($retired in @('electron', 'crates/lovelyres-electron-backend', 'crates/lovelyres-core', 'crates/lovelyres-gpui', 'ui/src/main', 'ui/src/preload')) {
    if (Test-Path -LiteralPath (Join-Path $root $retired)) {
        Add-GateViolation "retired desktop path '$retired' must not come back"
    }
}

# Tauri configuration: no global API, no dev server, no remote content.
$configPath = Join-Path $hostRoot 'tauri.conf.json'
if (Test-Path -LiteralPath $configPath) {
    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ($config.app.withGlobalTauri -ne $false) { Add-GateViolation 'tauri.conf.json must set app.withGlobalTauri to false' }
    if ($config.build.PSObject.Properties['devUrl']) { Add-GateViolation 'tauri.conf.json must not load a development server' }
    if ($config.build.frontendDist -cne '../../ui/dist') { Add-GateViolation "tauri.conf.json frontendDist must be '../../ui/dist'" }
    if (@($config.app.windows).Count -ne 0) { Add-GateViolation 'windows are created by the host, not declared in tauri.conf.json' }
    if ((@($config.app.security.capabilities) -join ',') -cne 'main-window,child-windows') {
        Add-GateViolation 'tauri.conf.json must enable exactly the main-window and child-windows capabilities'
    }
    if ((@($config.app.security.dangerousDisableAssetCspModification) -join ',') -cne 'style-src') {
        Add-GateViolation 'only style-src may opt out of asset CSP modification'
    }
    $csp = @($config.app.security.csp.PSObject.Properties | ForEach-Object { "$($_.Name) $($_.Value)" }) -join '; '
    foreach ($violation in @(Get-CspViolation -Policy $csp -Expected $requiredHostCsp -AllowInlineStyle)) {
        Add-GateViolation "tauri.conf.json CSP $violation"
    }
    if ($config.bundle.active -ne $false) { Add-GateViolation 'the portable build does not bundle installers; bundle.active must be false' }
}

# Page policies narrow the host policy.
foreach ($page in @(
    @{ File = 'index.html'; Expected = $requiredMainCsp; Inline = $false },
    @{ File = 'terminal.html'; Expected = $requiredTerminalCsp; Inline = $true }
)) {
    $path = Join-Path $uiRoot $page.File
    if (-not (Test-Path -LiteralPath $path)) { continue }
    $html = Get-Content -LiteralPath $path -Raw
    $policy = Get-HtmlCspPolicy -Html $html
    if ($null -eq $policy) {
        Add-GateViolation "ui/$($page.File) has no Content-Security-Policy meta tag"
        continue
    }
    foreach ($violation in @(Get-CspViolation -Policy $policy -Expected $page.Expected -AllowInlineStyle:$page.Inline)) {
        Add-GateViolation "ui/$($page.File) CSP $violation"
    }
    if ($html -match '(?is)<script\b(?![^>]*\bsrc=)') { Add-GateViolation "ui/$($page.File) contains an inline script" }
}

# The host's window and boundary hardening.
foreach ($entry in $requiredHostMarkers.GetEnumerator()) {
    $path = Join-Path $hostRoot "src/$($entry.Key)"
    if (-not (Test-Path -LiteralPath $path)) { Add-GateViolation "missing host source 'src/$($entry.Key)'"; continue }
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($marker in $entry.Value) {
        if (-not $text.Contains($marker, [System.StringComparison]::Ordinal)) {
            Add-GateViolation "host src/$($entry.Key) no longer contains '$marker'"
        }
    }
}
foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $hostRoot 'src') -Filter '*.rs' -File)) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    if ($text -match '\bunsafe\s*\{|\bunsafe\s+fn\b|\bunsafe\s+impl\b') { Add-GateViolation "host $(Get-RelativeName $file.FullName) uses unsafe code" }
    if ($text -match 'std::process::Command|tokio::process::Command') { Add-GateViolation "host $(Get-RelativeName $file.FullName) starts local processes" }
    if ($text -match 'tauri_plugin_(?:shell|fs|http|opener|process|updater)') { Add-GateViolation "host $(Get-RelativeName $file.FullName) uses a forbidden Tauri plugin" }
}

# The method allowlist keeps paths and export payloads in the host.
$bridgePath = Join-Path $hostRoot 'src/backend_bridge.rs'
if (Test-Path -LiteralPath $bridgePath) {
    $bridge = Get-Content -LiteralPath $bridgePath -Raw
    $start = $bridge.IndexOf('const MAIN_WINDOW_METHODS', [System.StringComparison]::Ordinal)
    $end = if ($start -ge 0) { $bridge.IndexOf('];', $start, [System.StringComparison]::Ordinal) } else { -1 }
    if ($start -lt 0 -or $end -lt 0) {
        Add-GateViolation 'backend_bridge.rs has no MAIN_WINDOW_METHODS list'
    } else {
        $allowed = $bridge.Substring($start, $end - $start)
        foreach ($method in $forbiddenPageMethods) {
            if ($allowed.Contains("`"$method`"", [System.StringComparison]::Ordinal)) {
                Add-GateViolation "main window may call '$method', which carries a local path, an export payload or another window's terminal"
            }
        }
    }
}

# Commands and their per-window permissions.
$buildScriptPath = Join-Path $hostRoot 'build.rs'
if (Test-Path -LiteralPath $buildScriptPath) {
    $buildScript = Get-Content -LiteralPath $buildScriptPath -Raw
    $names = @([regex]::Matches($buildScript, '(?m)^\s{4}"(?<name>[a-z_]+)",\s*$') | ForEach-Object { $_.Groups['name'].Value })
    $split = [array]::IndexOf($names, 'terminal_open')
    if ($split -lt 1) {
        Add-GateViolation 'build.rs command list must start the terminal-family block at terminal_open'
    } else {
        $mainCommands = @($names[0..($split - 1)])
        $childCommands = @($names[$split..($names.Count - 1)])
        $main = Get-Content -LiteralPath (Join-Path $hostRoot 'capabilities/main-window.json') -Raw | ConvertFrom-Json
        $child = Get-Content -LiteralPath (Join-Path $hostRoot 'capabilities/child-windows.json') -Raw | ConvertFrom-Json
        foreach ($violation in @(Get-CapabilityViolation -Capability $main -Identifier 'main-window' -Windows @('main') -Commands $mainCommands -ForeignCommands $childCommands)) {
            Add-GateViolation "main-window capability $violation"
        }
        foreach ($violation in @(Get-CapabilityViolation -Capability $child -Identifier 'child-windows' -Windows @('child-*') -Commands $childCommands -ForeignCommands $mainCommands)) {
            Add-GateViolation "child-windows capability $violation"
        }
        $libText = Get-Content -LiteralPath (Join-Path $hostRoot 'src/lib.rs') -Raw
        foreach ($name in $names) {
            if (-not $libText.Contains("::$name,", [System.StringComparison]::Ordinal)) {
                Add-GateViolation "command '$name' is listed in build.rs but not registered in lib.rs"
            }
        }
    }
}

# Page code: no Node, no raw Tauri internals or plugins, no DOM sinks.
$pageFiles = @(Get-ChildItem -LiteralPath (Join-Path $uiRoot 'src') -Recurse -File -Include '*.ts', '*.tsx' | Where-Object {
    $_.Name -notmatch '\.test\.tsx?$' -and $_.Name -notmatch '\.test-support\.ts$'
})
foreach ($file in $pageFiles) {
    $text = Get-Content -LiteralPath $file.FullName -Raw
    foreach ($violation in @(Get-PageCodeViolation -Text $text)) {
        Add-GateViolation "$(Get-RelativeName $file.FullName) contains $violation"
    }
    $relative = Get-RelativeName $file.FullName
    if ($relative -notlike 'ui/src/host/*' -and $text -match '["'']@tauri-apps/api(?:/[a-z]+)?["'']') {
        Add-GateViolation "$relative imports the Tauri API directly; pages go through ui/src/host"
    }
}
$styleAndAssetFiles = @(Get-ChildItem -LiteralPath (Join-Path $uiRoot 'src') -Recurse -File -Include '*.css') +
    @(Get-ChildItem -LiteralPath (Join-Path $uiRoot 'assets') -Recurse -File -Include '*.css', '*.html', '*.svg')
foreach ($file in $styleAndAssetFiles) {
    $violation = Get-RemoteResourceViolation -Text (Get-Content -LiteralPath $file.FullName -Raw)
    if ($null -ne $violation) { Add-GateViolation "$(Get-RelativeName $file.FullName) contains $violation" }
}
# A built bundle, when present, is what the next build embeds.
Add-BundleViolations @(Get-BundleFiles)

# Target pages name things only by the opaque handles their own snapshots
# minted: no target identity, no paths, no ad-hoc remote actions. Carried over
# from the Electron gate unchanged.
$identityWords = 'SshTargetSummary|connectionId|sessionId|targetGuard|generation|host|port|username|dataRoot|filePath|remotePath|apiKey'
$pageVocabularyRules = [ordered]@{
    'ConfigurationPage.tsx' = @("(?i)\b(?:$identityWords)\b")
    'BaselinePage.tsx' = @("(?i)\b(?:$identityWords|BaselineConnection|recordId|operationId|digest)\b",
        '(?i)\b(?:planBaseline|confirmBaseline|executeBaseline|restoreBaseline|reloadBaseline|exportBaseline|openBaselineTerminal|writeBaselineFile)\b')
    'CheckAuditPage.tsx' = @("(?i)\b(?:$identityWords|CheckAuditConnection|operationId|digest)\b",
        '(?i)\b(?:planCheckAudit|confirmCheckAudit|executeCheckAudit|restoreCheckAudit|exportCheckAudit|openCheckAuditTerminal|readCheckAuditFile)\b')
    'LogAnalysisPage.tsx' = @('(?i)\b(?:SshTargetSummary|LogAnalysisConnection|connectionId|sessionId|targetGuard|generation|host|port|dataRoot|filePath|remotePath|operationId|digest|apiKey)\b',
        '(?i)\b(?:analyzeLogWithAi|addLogRule|removeLogRule|mutateLogRule|planLogRule|confirmLogRule|executeLogRule|exportLogAnalysis|openLogFile|openLogTerminal|launchLogTerminal|executeLogCommand)\b')
    'KubernetesPage.tsx' = @("(?i)\b(?:$identityWords|KubernetesReadConnection|operationId|digest)\b",
        '(?i)\b(?:scaleKubernetes|restartKubernetes|deleteKubernetes|cordon|drain|executeCommand|execKubernetes|openKubernetesFile|openKubernetesTerminal|exportKubernetes|genericInvoke)\b')
    'DockerPage.tsx' = @("(?i)\b(?:$identityWords|DockerReadConnection|targetIdentity|targetGeneration)\b",
        '(?i)\b(?:startDocker|stopDocker|restartDocker|removeDocker|executeCommand|execDocker|openDockerFile|openDockerTerminal|exportDocker|genericInvoke)\b')
    'EmergencyCommandsPage.tsx' = @("(?i)\b(?:$identityWords|EmergencyCommandsConnection|targetIdentity|targetGeneration)\b",
        '(?i)\b(?:commandText|shellText|runCustomCommand|openTerminal|openFile|exportCommand|planMutation|genericInvoke)\b')
    'PacketCapturePage.tsx' = @('(?i)\b(?:SshTargetSummary|PacketCaptureConnection|connectionId|sessionId|targetGuard|generation|host|username|dataRoot|filePath|remotePath|targetIdentity|targetGeneration|apiKey)\b',
        '(?i)\b(?:executeCommand|openPacketCaptureFile|openPacketCaptureTerminal|downloadPacketCapture|exportPacketCapture|analyzePacketCapture|genericInvoke)\b')
    'IntegrityPage.tsx' = @("(?i)\b(?:$identityWords|targetIdentity|targetGeneration)\b",
        '(?i)\b(?:createIntegrityBaseline|quarantineIntegrity|customPath|pathInput|executeCommand|runCustomCommand|openTerminal|openFile|downloadReport|exportReport|planMutation|genericInvoke)\b')
}
foreach ($entry in $pageVocabularyRules.GetEnumerator()) {
    $path = Join-Path $uiRoot "src/renderer/$($entry.Key)"
    if (-not (Test-Path -LiteralPath $path)) { Add-GateViolation "missing target page 'ui/src/renderer/$($entry.Key)'"; continue }
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($pattern in $entry.Value) {
        $match = [regex]::Match($text, $pattern)
        if ($match.Success) { Add-GateViolation "ui/src/renderer/$($entry.Key) names '$($match.Value)', which a target page must not hold" }
    }
}

# Creating a window from a synchronous command deadlocks on Windows.
foreach ($file in @('main_commands.rs', 'child_commands.rs')) {
    $path = Join-Path $hostRoot "src/$file"
    if (-not (Test-Path -LiteralPath $path)) { continue }
    foreach ($command in ((Get-Content -LiteralPath $path -Raw) -split '#\[tauri::command\]' | Select-Object -Skip 1)) {
        if ($command -match 'open_child\(' -and $command -notmatch '^\s*pub async fn') {
            $name = [regex]::Match($command, 'pub fn (?<name>[a-z_]+)').Groups['name'].Value
            Add-GateViolation "host command '$name' creates a window but is not async"
        }
    }
}

# One JavaScript lockfile, at the root.
$lockNames = @('pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'bun.lock', 'bun.lockb')
$lockFiles = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include $lockNames -ErrorAction SilentlyContinue | Where-Object {
    $_.FullName -notmatch '[\\/](node_modules|target|\.git|artifacts|tmp|\.codex-build-cache)[\\/]'
} | ForEach-Object { Get-RelativeName $_.FullName } | Sort-Object)
if (($lockFiles -join ',') -cne 'pnpm-lock.yaml') {
    Add-GateViolation "exactly one JavaScript lockfile (pnpm-lock.yaml) is allowed; found [$($lockFiles -join ', ')]"
}

# CI must run the desktop gates.
$ciPath = Join-Path $root '.github/workflows/ci.yml'
if (Test-Path -LiteralPath $ciPath) {
    $ci = Get-Content -LiteralPath $ciPath -Raw
    foreach ($marker in @('desktop-quality-gates.ps1', 'desktop-source-gate.ps1 -SelfTest', 'pnpm install --frozen-lockfile')) {
        if (-not $ci.Contains($marker, [System.StringComparison]::Ordinal)) { Add-GateViolation ".github/workflows/ci.yml no longer runs '$marker'" }
    }
    if ($ci -match '(?i)electron') { Add-GateViolation '.github/workflows/ci.yml still refers to Electron' }
}

if ($violations.Count -gt 0) {
    throw "Desktop source gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}
Write-Host "Desktop source gate passed ($($pageFiles.Count) page modules, $($styleAndAssetFiles.Count) style/asset files, host hardening and per-window permissions)."
