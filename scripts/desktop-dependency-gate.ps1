[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$approvedRuntimeDependencies = [ordered]@{
    '@tauri-apps/api' = '2.12.4'
    '@xterm/addon-fit' = '0.11.0'
    '@xterm/addon-search' = '0.16.0'
    '@xterm/xterm' = '6.0.0'
    'react' = '19.3.1'
    'react-dom' = '19.3.1'
}
$approvedDevelopmentDependencies = [ordered]@{
    '@tauri-apps/cli' = '2.12.4'
    '@types/node' = '26.6.6'
    '@types/react' = '19.3.0'
    '@types/react-dom' = '19.3.0'
    '@vitejs/plugin-react' = '6.1.2'
    'typescript' = '7.0.2'
    'vite' = '8.3.5'
    'vitest' = '5.0.5'
}
# A plugin's JavaScript package would hand pages a capability the host keeps.
$forbiddenUiPackagePattern = '^(?:electron|@electron/.+|electron-.+|node-pty|nw|wailsjs|@tauri-apps/plugin-.+)$'
# The backend and the terminal stay headless: no UI toolkit or webview.
$forbiddenHeadlessCrates = @('gpui', 'gpui-component', 'gpui-component-assets', 'tauri', 'wry', 'tao', 'webview2-com')
# The host may use only the plugins it calls from Rust.
$approvedHostPlugins = @('tauri-plugin-clipboard-manager', 'tauri-plugin-dialog')
$forbiddenHostCrates = @('tauri-plugin-shell', 'tauri-plugin-http', 'tauri-plugin-opener', 'tauri-plugin-process', 'tauri-plugin-updater', 'tauri-plugin-sql', 'tauri-plugin-store', 'gpui')

function Get-ExactDependencyViolations {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedRuntime,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$ExpectedDevelopment
    )

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($group in @(
        @{ Name = 'dependencies'; Expected = $ExpectedRuntime },
        @{ Name = 'devDependencies'; Expected = $ExpectedDevelopment }
    )) {
        $property = $Manifest.PSObject.Properties[$group.Name]
        if ($null -eq $property -or $null -eq $property.Value) {
            $violations.Add("ui/package.json is missing $($group.Name)")
            continue
        }
        $actualNames = @($property.Value.PSObject.Properties.Name | Sort-Object)
        $expectedNames = @($group.Expected.Keys | Sort-Object)
        if (($actualNames -join "`n") -cne ($expectedNames -join "`n")) {
            $violations.Add("$($group.Name) must be exactly [$($expectedNames -join ', ')]; found [$($actualNames -join ', ')]")
        }
        foreach ($name in $actualNames) {
            if ($name -match $forbiddenUiPackagePattern) {
                $violations.Add("forbidden UI dependency '$name' is declared")
            }
        }
        foreach ($name in $expectedNames) {
            $dependency = $property.Value.PSObject.Properties[$name]
            if ($null -eq $dependency) { continue }
            $version = [string]$dependency.Value
            if ($version -cne [string]$group.Expected[$name]) {
                $violations.Add("$($group.Name).$name must be pinned to $($group.Expected[$name]); found '$version'")
            }
            if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
                $violations.Add("$($group.Name).$name must use an exact semantic version")
            }
        }
    }
    return $violations
}

function Get-CargoTreeViolations {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Tree,
        [Parameter(Mandatory = $true)][string[]]$Forbidden,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Forbidden) {
        if ($Tree -match "(?m)^(?:[^A-Za-z0-9_-]*)(?:$([regex]::Escape($name)))\s+v[0-9]") {
            $violations.Add("$Label dependency tree contains '$name'")
        }
    }
    return $violations
}

function Get-RetiredCrateViolations {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RootManifest,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$CargoLock
    )

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($marker in @('gpui', 'gpui-component', 'gpui-component-assets')) {
        if ($RootManifest -match "(?m)^\s*$([regex]::Escape($marker))\s*=") { $violations.Add("root Cargo.toml declares retired '$marker'") }
        if ($CargoLock -match ('(?m)^name\s*=\s*"' + [regex]::Escape($marker) + '"\s*$')) { $violations.Add("Cargo.lock contains retired '$marker'") }
    }
    return $violations
}

function Get-MissingFileViolations {
    param([Parameter(Mandatory = $true)][string[]]$Paths)

    return @($Paths | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) } | ForEach-Object { "missing required file '$_'" })
}

function Assert-SelfTest {
    $runtime = [ordered]@{ react = '1.2.3' }
    $development = [ordered]@{ vite = '4.5.6' }
    $good = [pscustomobject]@{
        dependencies = [pscustomobject]@{ react = '1.2.3' }
        devDependencies = [pscustomobject]@{ vite = '4.5.6' }
    }
    if (@(Get-ExactDependencyViolations -Manifest $good -ExpectedRuntime $runtime -ExpectedDevelopment $development).Count -ne 0) {
        throw 'Desktop dependency gate self-test rejected exact pinned dependencies.'
    }
    $bad = [pscustomobject]@{
        dependencies = [pscustomobject]@{ react = '^1.2.3'; '@tauri-apps/plugin-shell' = '2.0.0' }
        devDependencies = [pscustomobject]@{ vite = '4.5.6'; electron = '1.0.0' }
    }
    if (@(Get-ExactDependencyViolations -Manifest $bad -ExpectedRuntime $runtime -ExpectedDevelopment $development).Count -lt 3) {
        throw 'Desktop dependency gate self-test accepted a range or forbidden package.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyhawk-backend v1.0.0`nwry v0.55.1" -Forbidden $forbiddenHeadlessCrates -Label 'backend').Count -eq 0) {
        throw 'Desktop dependency gate self-test accepted a webview in a headless tree.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyhawk-backend v1.0.0`nserde v1.0.0" -Forbidden $forbiddenHeadlessCrates -Label 'backend').Count -ne 0) {
        throw 'Desktop dependency gate self-test rejected a headless Rust tree.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyhawk-desktop v1.0.0`ngpui v0.2.0" -Forbidden $forbiddenHostCrates -Label 'host').Count -eq 0) {
        throw 'Desktop dependency gate self-test accepted GPUI in the host tree.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyhawk-desktop v1.0.0`ntauri-plugin-shell v2.0.0" -Forbidden $forbiddenHostCrates -Label 'host').Count -eq 0) {
        throw 'Desktop dependency gate self-test accepted a shell plugin in the host tree.'
    }
    if (@(Get-RetiredCrateViolations -RootManifest "[workspace.dependencies]`ngpui = `"0.2`"" -CargoLock "[[package]]`nname = `"gpui-component`"").Count -ne 2) {
        throw 'Desktop dependency gate self-test accepted a retired GPUI crate.'
    }
    if (@(Get-RetiredCrateViolations -RootManifest "[workspace.dependencies]`ntauri = `"2`"" -CargoLock "[[package]]`nname = `"tauri`"").Count -ne 0) {
        throw 'Desktop dependency gate self-test rejected a manifest without GPUI.'
    }
    $missing = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyhawk-no-such-lockfile-$([guid]::NewGuid().ToString('N')).yaml"
    if (@(Get-MissingFileViolations -Paths @($PSCommandPath, $missing)).Count -ne 1) {
        throw 'Desktop dependency gate self-test accepted a missing lockfile.'
    }
    Write-Host 'Desktop dependency gate fixture self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$uiManifestPath = Join-Path $root 'ui/package.json'
$rootManifestPath = Join-Path $root 'Cargo.toml'
$lockPath = Join-Path $root 'pnpm-lock.yaml'
$cargoLockPath = Join-Path $root 'Cargo.lock'
$missingFiles = @(Get-MissingFileViolations -Paths @($uiManifestPath, $rootManifestPath, $lockPath, $cargoLockPath))
if ($missingFiles.Count -gt 0) {
    throw "Desktop dependency gate failed:`n - $($missingFiles -join "`n - ")"
}

$violations = [System.Collections.Generic.List[string]]::new()
$uiManifest = Get-Content -LiteralPath $uiManifestPath -Raw | ConvertFrom-Json
foreach ($violation in @(Get-ExactDependencyViolations -Manifest $uiManifest `
    -ExpectedRuntime $approvedRuntimeDependencies -ExpectedDevelopment $approvedDevelopmentDependencies)) {
    $violations.Add($violation)
}

$lockText = Get-Content -LiteralPath $lockPath -Raw
if ($lockText -notmatch "(?m)^lockfileVersion:\s*'9\.0'\s*$") {
    $violations.Add("pnpm-lock.yaml must use lockfileVersion '9.0'")
}
if ($lockText -notmatch '(?m)^\s{2}ui:\s*$') {
    $violations.Add('pnpm-lock.yaml has no ui workspace importer')
}
foreach ($group in @($approvedRuntimeDependencies, $approvedDevelopmentDependencies)) {
    foreach ($name in $group.Keys) {
        $entryPattern = '(?ms)^\s{6}[''"]?' + [regex]::Escape($name) + '[''"]?:\s*\r?\n\s{8}specifier:\s*' + [regex]::Escape([string]$group[$name]) + '\s*$'
        if ($lockText -notmatch $entryPattern) {
            $violations.Add("pnpm-lock.yaml ui importer is missing exact '$name@$($group[$name])'")
        }
    }
}
if ($lockText -notmatch '(?m)^\s+resolution:\s*\{integrity:\s*sha512-') {
    $violations.Add('pnpm-lock.yaml contains no sha512 package integrity records')
}
if ($lockText -match "(?m)^\s{2}'?(?:electron|@tauri-apps/plugin-[a-z-]+|node-pty)@") {
    $violations.Add('pnpm-lock.yaml contains a forbidden desktop package')
}

# Rust dependencies are declared once, in the workspace manifest.
foreach ($crate in @('lovelyhawk-core', 'lovelyhawk-backend', 'lovelyhawk-terminal', 'lovelyhawk-desktop', 'lovelyhawk-win-dvc')) {
    $manifest = Join-Path $root "crates/$crate/Cargo.toml"
    if (-not (Test-Path -LiteralPath $manifest)) { $violations.Add("missing crates/$crate/Cargo.toml"); continue }
    $inDependencies = $false
    foreach ($line in (Get-Content -LiteralPath $manifest)) {
        if ($line -match '^\[(?<section>[^\]]+)\]') {
            $inDependencies = $Matches.section -match '(?:^|\.)(?:dependencies|dev-dependencies|build-dependencies)$|dependencies\]?$'
            continue
        }
        if (-not $inDependencies -or $line -match '^\s*(?:#|$)') { continue }
        if ($line -match '^\s*(?<name>[A-Za-z0-9_-]+)\s*=' -and $line -notmatch '\.workspace\s*=\s*true|workspace\s*=\s*true|path\s*=\s*"\.\./') {
            $violations.Add("crates/$crate/Cargo.toml declares '$($Matches.name)' outside the workspace dependency table")
        }
    }
}

Push-Location $root
try {
    foreach ($tree in @(
        @{ Label = 'lovelyhawk-backend'; Args = @('--package', 'lovelyhawk-backend') },
        @{ Label = 'headless lovelyhawk-terminal'; Args = @('--package', 'lovelyhawk-terminal', '--no-default-features') }
    )) {
        $text = (& cargo tree --locked @($tree.Args) --edges normal --prefix none 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            $violations.Add("cargo tree for $($tree.Label) failed: $($text.Trim())")
            continue
        }
        foreach ($violation in @(Get-CargoTreeViolations -Tree $text -Forbidden $forbiddenHeadlessCrates -Label $tree.Label)) {
            $violations.Add($violation)
        }
    }
    $hostTree = (& cargo tree --locked --package lovelyhawk-desktop --edges normal --prefix none 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        $violations.Add("cargo tree for lovelyhawk-desktop failed: $($hostTree.Trim())")
    } else {
        foreach ($violation in @(Get-CargoTreeViolations -Tree $hostTree -Forbidden $forbiddenHostCrates -Label 'lovelyhawk-desktop')) {
            $violations.Add($violation)
        }
        if ($hostTree -notmatch '(?m)^tauri v2\.12\.5\b') { $violations.Add('lovelyhawk-desktop must resolve tauri v2.12.5') }
        foreach ($plugin in @([regex]::Matches($hostTree, '(?m)^(?<name>tauri-plugin-[a-z-]+) v') | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)) {
            # The dialog plugin depends on the fs plugin's types; it is never registered.
            if ($approvedHostPlugins -notcontains $plugin -and $plugin -ne 'tauri-plugin-fs') {
                $violations.Add("lovelyhawk-desktop pulls in unapproved plugin '$plugin'")
            }
        }
    }
} finally {
    Pop-Location
}

$hostLib = Get-Content -LiteralPath (Join-Path $root 'crates/lovelyhawk-desktop/src/lib.rs') -Raw
$registered = @([regex]::Matches($hostLib, '\.plugin\((?<name>[a-z_]+)::init\(\)\)') | ForEach-Object { $_.Groups['name'].Value } | Sort-Object)
if (($registered -join ',') -cne 'tauri_plugin_clipboard_manager,tauri_plugin_dialog') {
    $violations.Add("the host must register exactly the clipboard and dialog plugins; found [$($registered -join ', ')]")
}

$terminalManifestText = Get-Content -LiteralPath (Join-Path $root 'crates/lovelyhawk-terminal/Cargo.toml') -Raw
if ($terminalManifestText -match '(?m)^default\s*=\s*\[\s*[^\]\s]') {
    $violations.Add('lovelyhawk-terminal default features must remain headless')
}
$rootManifestText = Get-Content -LiteralPath $rootManifestPath -Raw
$cargoLockText = Get-Content -LiteralPath $cargoLockPath -Raw
foreach ($violation in @(Get-RetiredCrateViolations -RootManifest $rootManifestText -CargoLock $cargoLockText)) {
    $violations.Add($violation)
}

if ($violations.Count -gt 0) {
    throw "Desktop dependency gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}
Write-Host 'Desktop dependency gate passed (exact UI dependencies, locked integrity records, workspace-managed Rust dependencies, headless backend/terminal trees, approved host plugins only).'
