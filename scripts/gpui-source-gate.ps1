[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml'),
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourcePatterns = [ordered]@{
    'Tauri API/runtime' = '(?i)\btauri\b'
    'wry API/runtime' = '(?i)\bwry\b'
    'WebView API/runtime' = '(?i)\bweb[-_]?view\b'
    'Vue runtime' = '(?i)\bvue(?:\.js)?\b'
    'xterm.js runtime' = '(?i)\bxterm(?:\.js|js)\b'
    'Web Terminal feature/entry' = '(?i)\bweb[-_ ]?terminal\b'
    'external Web Terminal server' = '(?i)\b(?:ttyd|wetty|shellinabox|gotty)\b'
}
$remoteRuntimePatterns = [ordered]@{
    'CDN or remote web-font host' = '(?i)\b(?:fonts\.googleapis\.com|fonts\.gstatic\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|use\.typekit\.net|api\.fontshare\.com|raw\.githubusercontent\.com)\b'
    'remote script/style/font/image asset' = '(?i)https?://[^\s"'')]+\.(?:css|js|mjs|woff2?|ttf|otf|eot|svg|png|jpe?g|gif|ico)(?:[?#][^\s"'')]+)?'
    'remote HTML resource attribute' = '(?i)\b(?:src|href)\s*=\s*["'']https?://'
    'remote CSS resource' = '(?i)(?:@import\s+|(?<![A-Za-z0-9_])url\(\s*["'']?)https?://'
    'remote GPUI image' = '(?i)\bimg\s*\(\s*["'']https?://'
}

function Get-SourceViolation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    $trimmed = $Line.Trim()
    if ($trimmed.StartsWith('//')) {
        return $null
    }
    foreach ($entry in $sourcePatterns.GetEnumerator()) {
        if ($Line -match $entry.Value) { return [string]$entry.Key }
    }
    foreach ($entry in $remoteRuntimePatterns.GetEnumerator()) {
        if ($Line -match $entry.Value) { return [string]$entry.Key }
    }
    return $null
}

function Get-ManifestViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line)
    $trimmed = $Line.Trim()
    if ($trimmed.StartsWith('#')) { return $null }
    if ($trimmed -match '(?i)^\[.*(?:dependencies|dev-dependencies|build-dependencies)\.\s*["'']?(?:tauri(?:[-_]\w*)?|wry(?:[-_]\w*)?|web[-_]?view(?:[-_]\w*)?|vue(?:[-_]\w*)?|xterm(?:[-_]?js)?(?:[-_]\w*)?)["'']?\s*\]$') {
        return 'forbidden dependency table'
    }
    if ($trimmed -match '(?i)^["'']?(?:tauri(?:[-_]\w*)?|wry(?:[-_]\w*)?|web[-_]?view(?:[-_]\w*)?|vue(?:[-_]\w*)?|xterm(?:[-_]?js)?(?:[-_]\w*)?)["'']?\s*=') {
        return 'forbidden dependency declaration'
    }
    if ($trimmed -match '(?i)\bpackage\s*=\s*["''](?:tauri(?:[-_]\w*)?|wry(?:[-_]\w*)?|web[-_]?view(?:[-_]\w*)?|vue(?:[-_]\w*)?|xterm(?:[-_]?js)?(?:[-_]\w*)?)["'']') {
        return 'forbidden renamed dependency declaration'
    }
    if ($trimmed -match '(?i)\b(?:features|default-features)\b.*\b(?:web[-_]?view|web[-_]?terminal|ttyd|wetty|shellinabox|gotty)\b') {
        return 'forbidden web feature'
    }
    if ($trimmed -match '(?i)\b(?:web[-_]?terminal|ttyd|wetty|shellinabox|gotty)\b') {
        return 'forbidden Web Terminal manifest entry'
    }
    return $null
}

function Get-AssetTextViolation {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    $withoutSvgNamespace = $Text.Replace('http://www.w3.org/2000/svg', '')
    if ($withoutSvgNamespace -match '(?i)https?://') { return 'remote runtime resource URL' }
    if ($Text -match '(?i)\b(?:href|xlink:href)\s*=\s*["'']\s*(?:https?:)?//') {
        return 'external asset reference'
    }
    return $null
}

function Get-ButtonIconViolation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Line,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    if (
        $Line -match '\bButton::new\s*\(' -and
        $RelativePath -ne 'crates/lovelyres-gpui/src/buttons.rs'
    ) {
        return 'raw GPUI Button constructor bypasses the required SVG icon factory'
    }
    return $null
}

if ($SelfTest) {
    $badSourceFixtures = @(
        'use tauri::Manager;',
        'let view = wry::WebView::new();',
        'const ROUTE: &str = "web-terminal";',
        'let terminal = "xterm.js";',
        'img("https://cdn.jsdelivr.net/app.js")',
        '<link href="https://fonts.googleapis.com/css2">'
    )
    foreach ($fixture in $badSourceFixtures) {
        if ($null -eq (Get-SourceViolation -Line $fixture -RelativePath 'crates/lovelyres-gpui/src/fixture.rs')) {
            throw "Source-gate self-test missed forbidden fixture: $fixture"
        }
    }
    foreach ($fixture in @(
        'let term = "xterm-256color";',
        'validate_outbound_url("https://api.openai.com/v1/chat/completions")?;'
    )) {
        if ($null -ne (Get-SourceViolation -Line $fixture -RelativePath 'crates/lovelyres-core/src/fixture.rs')) {
            throw "Source-gate self-test rejected legitimate fixture: $fixture"
        }
    }
    foreach ($fixture in @(
        '{"logo":"https://cdn.example.invalid/logo.svg"}',
        '<image href="https://cdn.example.invalid/pixel.png" />'
    )) {
        if ($null -eq (Get-AssetTextViolation -Text $fixture)) {
            throw "Source-gate self-test missed malicious remote asset fixture: $fixture"
        }
    }
    foreach ($fixture in @('tauri = "2"', '"tauri" = "2"', '[target.''cfg(windows)''.dependencies.wry]', 'desktop = { package = "tauri", version = "2" }', 'features = ["webview"]', 'web-terminal = []')) {
        if ($null -eq (Get-ManifestViolation -Line $fixture)) {
            throw "Manifest self-test missed forbidden fixture: $fixture"
        }
    }
    if ($null -eq (Get-ButtonIconViolation -Line 'Button::new("missing-icon")' -RelativePath 'crates/lovelyres-gpui/src/fixture.rs')) {
        throw 'Source-gate self-test missed a raw GPUI button without the SVG icon factory.'
    }
    if ($null -ne (Get-ButtonIconViolation -Line 'Button::new(id).icon(icon)' -RelativePath 'crates/lovelyres-gpui/src/buttons.rs')) {
        throw 'Source-gate self-test rejected the single icon factory constructor.'
    }
    Write-Host 'GPUI source gate pattern self-test passed.'
    return
}

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$repositoryRoot = Split-Path -Parent $manifest
$crateRoots = @(
    (Join-Path $repositoryRoot 'crates/lovelyres-core'),
    (Join-Path $repositoryRoot 'crates/lovelyres-terminal'),
    (Join-Path $repositoryRoot 'crates/lovelyres-gpui')
)
$violations = [System.Collections.Generic.List[string]]::new()

function Add-GateViolation {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:violations.Add($Message)
}

function Get-RelativeName {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetRelativePath($repositoryRoot, $Path).Replace('\', '/')
}

foreach ($crateRoot in $crateRoots) {
    if (-not (Test-Path -LiteralPath $crateRoot -PathType Container)) {
        Add-GateViolation "missing workspace crate directory '$(Get-RelativeName -Path $crateRoot)'"
    }
}
if ($violations.Count -gt 0) {
    throw "GPUI source gate failed:`n - $($violations -join "`n - ")"
}

$manifestPaths = @($manifest) + @($crateRoots | ForEach-Object { Join-Path $_ 'Cargo.toml' })
foreach ($manifestFile in $manifestPaths) {
    if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) {
        Add-GateViolation "missing manifest '$(Get-RelativeName -Path $manifestFile)'"
        continue
    }
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $manifestFile) {
        $lineNumber++
        $reason = Get-ManifestViolation -Line ([string]$line)
        if ($null -ne $reason) {
            Add-GateViolation "$(Get-RelativeName -Path $manifestFile):$lineNumber $reason"
        }
    }
}

$rootManifestText = Get-Content -LiteralPath $manifest -Raw
$gpuiLines = @($rootManifestText -split "`r?`n" | Where-Object { $_ -match '^\s*gpui\s*=' })
if ($gpuiLines.Count -ne 1 -or $gpuiLines[0] -notmatch '^\s*gpui\s*=\s*"=0\.2\.2"\s*$') {
    Add-GateViolation 'Cargo.toml must declare gpui = "=0.2.2" exactly once'
}
$componentLines = @($rootManifestText -split "`r?`n" | Where-Object { $_ -match '^\s*gpui-component\s*=' })
if ($componentLines.Count -ne 1) {
    Add-GateViolation 'Cargo.toml must declare gpui-component exactly once'
} else {
    $componentLine = $componentLines[0]
    if ($componentLine -notmatch 'version\s*=\s*"=0\.5\.1"') { Add-GateViolation 'gpui-component must be pinned to =0.5.1' }
    if ($componentLine -notmatch 'default-features\s*=\s*false') { Add-GateViolation 'gpui-component must set default-features = false' }
    if ($componentLine -match '(?i)features\s*=.*web[-_]?view') { Add-GateViolation 'gpui-component webview feature must not be enabled' }
}

$rustFiles = @($crateRoots | ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -File -Filter '*.rs' })
foreach ($file in $rustFiles) {
    $relative = Get-RelativeName -Path $file.FullName
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++
        $reason = Get-SourceViolation -Line ([string]$line) -RelativePath $relative
        if ($null -ne $reason) { Add-GateViolation "${relative}:$lineNumber $reason" }
        $buttonReason = Get-ButtonIconViolation -Line ([string]$line) -RelativePath $relative
        if ($null -ne $buttonReason) {
            Add-GateViolation "${relative}:$lineNumber $buttonReason"
        }
    }
}

$forbiddenRuntimeExtensions = @('.html', '.htm', '.css', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.vue')
foreach ($file in @($crateRoots | ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -File })) {
    if ($file.Extension.ToLowerInvariant() -in $forbiddenRuntimeExtensions) {
        Add-GateViolation "$(Get-RelativeName -Path $file.FullName) is a forbidden web-runtime source/resource"
    }
}

$gpuiRoot = Join-Path $repositoryRoot 'crates/lovelyres-gpui'
$pagesPath = Join-Path $gpuiRoot 'src/pages.rs'
$windowsPath = Join-Path $gpuiRoot 'src/windows.rs'
$appPath = Join-Path $gpuiRoot 'src/app.rs'
$assetsSourcePath = Join-Path $gpuiRoot 'src/assets.rs'
$buttonsSourcePath = Join-Path $gpuiRoot 'src/buttons.rs'
$buildSourcePath = Join-Path $gpuiRoot 'build.rs'
foreach ($requiredSource in @($pagesPath, $windowsPath, $appPath, $assetsSourcePath, $buttonsSourcePath, $buildSourcePath)) {
    if (-not (Test-Path -LiteralPath $requiredSource -PathType Leaf)) {
        Add-GateViolation "missing required GPUI source '$(Get-RelativeName -Path $requiredSource)'"
    }
}

$buttonFactoryCallCount = 0
if (Test-Path -LiteralPath $buttonsSourcePath -PathType Leaf) {
    $buttonSource = Get-Content -LiteralPath $buttonsSourcePath -Raw
    $rawButtonConstructors = [regex]::Matches($buttonSource, '\bButton::new\s*\(').Count
    if ($rawButtonConstructors -ne 1) {
        Add-GateViolation "buttons.rs must contain exactly one raw Button constructor; found $rawButtonConstructors"
    }
    foreach ($requiredText in @('pub(crate) fn button(', 'Button::new(id).icon(icon)', 'fn icon_for_button_id(')) {
        if (-not $buttonSource.Contains($requiredText, [System.StringComparison]::Ordinal)) {
            Add-GateViolation "buttons.rs is missing required SVG icon factory marker '$requiredText'"
        }
    }
    foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $gpuiRoot 'src') -File -Filter '*.rs')) {
        if ($file.FullName -eq $buttonsSourcePath) { continue }
        $source = Get-Content -LiteralPath $file.FullName -Raw
        $buttonFactoryCallCount += [regex]::Matches($source, 'crate::buttons::button\s*\(').Count
    }
    if ($buttonFactoryCallCount -eq 0) {
        Add-GateViolation 'no application button uses the required SVG icon factory'
    }
}

if ($violations.Count -eq 0) {
    $pagesText = Get-Content -LiteralPath $pagesPath -Raw
    $windowsText = Get-Content -LiteralPath $windowsPath -Raw
    $appText = Get-Content -LiteralPath $appPath -Raw
    $pageEnum = [regex]::Match($pagesText, '(?s)pub enum PageId\s*\{(?<body>.*?)\n\}').Groups['body'].Value
    $windowEnum = [regex]::Match($windowsText, '(?s)pub enum NativeWindowKind\s*\{(?<body>.*?)\n\}').Groups['body'].Value
    $actionRegistry = [regex]::Match($appText, '(?s)actions!\s*\(\s*lovelyres\s*,\s*\[(?<body>.*?)\]\s*\);').Groups['body'].Value
    foreach ($registry in @(
        @{ Name = 'PageId'; Text = $pageEnum },
        @{ Name = 'NativeWindowKind'; Text = $windowEnum },
        @{ Name = 'LovelyRes actions'; Text = $actionRegistry }
    )) {
        if ([string]::IsNullOrWhiteSpace($registry.Text)) {
            Add-GateViolation "$($registry.Name) registry could not be parsed"
        } elseif ($registry.Text -match '(?i)(?:web[-_ ]?terminal|web[-_]?view|ttyd|wetty|shellinabox|gotty|xterm(?:\.js|js))') {
            Add-GateViolation "$($registry.Name) contains a Web Terminal/WebView action or entry"
        }
    }
    if ($pagesText -notmatch 'pub const ALL:\s*\[Self;\s*20\]') { Add-GateViolation 'PageId::ALL must contain exactly 20 pages' }
    if ($pagesText -notmatch 'pub const PAGE_DESCRIPTORS:\s*\[PageDescriptor;\s*20\]') { Add-GateViolation 'PAGE_DESCRIPTORS must contain exactly 20 descriptors' }
    foreach ($variant in @('Main', 'SshTerminal', 'Sftp', 'ContainerTerminal\s*\(\s*ContainerTerminalWindowKey\s*\)')) {
        if ($windowEnum -notmatch "(?m)^\s*$variant\s*,?") { Add-GateViolation "NativeWindowKind is missing required variant '$variant'" }
    }
    foreach ($field in @('target_identity:\s*Arc<str>', 'target_generation:\s*u64', 'container:\s*Arc<str>')) {
        if ($windowsText -notmatch $field) { Add-GateViolation "ContainerTerminalWindowKey is missing required field '$field'" }
    }
}

$requiredAssets = [ordered]@{
    'assets/app.ico' = 1024
    'assets/logo.png' = 20000
    'assets/fonts/Inter-Regular.ttf' = 10000
    'assets/fonts/Inter-SemiBold.ttf' = 10000
    'assets/fonts/CascadiaMono.ttf' = 10000
    'assets/security_reference.json' = 100000
}
foreach ($entry in $requiredAssets.GetEnumerator()) {
    $assetPath = Join-Path $gpuiRoot $entry.Key
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        Add-GateViolation "missing local asset 'crates/lovelyres-gpui/$($entry.Key)'"
    } elseif ((Get-Item -LiteralPath $assetPath).Length -lt [int64]$entry.Value) {
        Add-GateViolation "local asset 'crates/lovelyres-gpui/$($entry.Key)' is unexpectedly small"
    }
}

$pinnedAssetHashes = [ordered]@{
    'assets/app.ico' = 'A00B2CFF979B9F21AA0DD2A00661448406CA33B3081E197C13762C6832083E17'
    'assets/logo.png' = 'C1C0B0181719FE4FA66D0395D69A776FA9C8DD13D65A4F0CE7D2801D0CDB3297'
    'assets/fonts/Inter-Regular.ttf' = '40D692FCE188E4471E2B3CBA937BE967878F631AD3EBBBDCD587687C7EBE0C82'
    'assets/fonts/Inter-SemiBold.ttf' = '78A843FADE9D4612A5567302FB595B56976EB5FCEBF4FEA5A5912D638BAFCDE3'
    'assets/fonts/CascadiaMono.ttf' = '08026F617EEA315CACA59898784E999F6CDB2D0C34D2040DEEB042BCDC359FA2'
    'assets/security_reference.json' = '8694D9022C20919AB6F73EEAF4F041F2660D1CF0EA3E94033E5732E06F2BE731'
}
foreach ($entry in $pinnedAssetHashes.GetEnumerator()) {
    $assetPath = Join-Path $gpuiRoot $entry.Key
    if (Test-Path -LiteralPath $assetPath -PathType Leaf) {
        $actualHash = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actualHash -ne $entry.Value) {
            Add-GateViolation "local asset 'crates/lovelyres-gpui/$($entry.Key)' SHA-256 is $actualHash, expected $($entry.Value)"
        }
    }
}

if (Test-Path -LiteralPath $assetsSourcePath -PathType Leaf) {
    $assetsText = Get-Content -LiteralPath $assetsSourcePath -Raw
    foreach ($requiredText in @('#[derive(RustEmbed)]', '#[folder = "assets"]', 'fonts/Inter-Regular.ttf', 'fonts/Inter-SemiBold.ttf', 'fonts/CascadiaMono.ttf', 'LovelyResAssets::get')) {
        if (-not $assetsText.Contains($requiredText, [System.StringComparison]::Ordinal)) {
            Add-GateViolation "assets.rs does not embed required local asset marker '$requiredText'"
        }
    }
}
if ((Test-Path -LiteralPath $appPath -PathType Leaf) -and -not (Get-Content -LiteralPath $appPath -Raw).Contains('img(self.brand_logo.clone())', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'app.rs must render the synchronously decoded embedded brand logo'
}
if ((Test-Path -LiteralPath $assetsSourcePath -PathType Leaf) -and -not (Get-Content -LiteralPath $assetsSourcePath -Raw).Contains('include_bytes!("../assets/logo.png")', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'assets.rs must synchronously embed the checked-in brand PNG'
}
if ((Test-Path -LiteralPath $buildSourcePath -PathType Leaf) -and -not (Get-Content -LiteralPath $buildSourcePath -Raw).Contains('assets/app.ico', [System.StringComparison]::Ordinal)) {
    Add-GateViolation 'build.rs must use the checked-in local app.ico'
}

$assetTextFiles = @(Get-ChildItem -LiteralPath (Join-Path $gpuiRoot 'assets') -Recurse -File | Where-Object { $_.Extension -in @('.svg', '.css', '.html', '.js', '.json', '.md') })
foreach ($file in $assetTextFiles) {
    $relative = Get-RelativeName -Path $file.FullName
    if ($relative -eq 'crates/lovelyres-gpui/assets/fonts/README.md') { continue }
    # The pinned catalog contains literal advisory/command URLs rendered only as GPUI text.
    # Its exact SHA-256 above is the allowlist; any catalog byte change still fails this gate.
    if ($relative -eq 'crates/lovelyres-gpui/assets/security_reference.json') { continue }
    $text = Get-Content -LiteralPath $file.FullName -Raw
    $reason = Get-AssetTextViolation -Text $text
    if ($null -ne $reason) { Add-GateViolation "$relative contains a $reason" }
}

if ($violations.Count -gt 0) {
    throw "GPUI source gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}

Write-Host "GPUI source gate passed ($($rustFiles.Count) Rust files, $($manifestPaths.Count) manifests, $buttonFactoryCallCount SVG-icon buttons; native registries and local assets verified)."
