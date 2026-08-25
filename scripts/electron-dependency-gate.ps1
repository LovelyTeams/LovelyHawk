[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$RequireGpuiRetired,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$approvedRuntimeDependencies = [ordered]@{
    '@xterm/addon-fit' = '0.11.0'
    '@xterm/addon-search' = '0.16.0'
    '@xterm/xterm' = '6.0.0'
    'react' = '19.2.8'
    'react-dom' = '19.2.8'
}
$approvedDevelopmentDependencies = [ordered]@{
    '@types/node' = '24.13.3'
    '@types/react' = '19.2.18'
    '@types/react-dom' = '19.2.5'
    '@vitejs/plugin-react' = '6.1.0'
    'electron' = '43.4.1'
    'typescript' = '7.0.2'
    'vite' = '8.2.2'
    'vitest' = '4.1.11'
}
$forbiddenDesktopPackages = @(
    '@electron/remote',
    'electron-rebuild',
    'electron-edge-js',
    'node-pty',
    'nw',
    'tauri',
    'wailsjs'
)
$forbiddenRustUiCrates = @(
    'gpui',
    'gpui-component',
    'gpui-component-assets'
)

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
            $violations.Add("electron/package.json is missing $($group.Name)")
            continue
        }
        $actualNames = @($property.Value.PSObject.Properties.Name | Sort-Object)
        $expectedNames = @($group.Expected.Keys | Sort-Object)
        if (($actualNames -join "`n") -cne ($expectedNames -join "`n")) {
            $violations.Add("$($group.Name) must be exactly [$($expectedNames -join ', ')]; found [$($actualNames -join ', ')]")
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
    foreach ($name in $forbiddenDesktopPackages) {
        if ($null -ne $Manifest.dependencies.PSObject.Properties[$name] -or
            $null -ne $Manifest.devDependencies.PSObject.Properties[$name]) {
            $violations.Add("forbidden desktop dependency '$name' is declared")
        }
    }
    return $violations
}

function Get-CargoTreeViolations {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Tree)

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $forbiddenRustUiCrates) {
        if ($Tree -match "(?m)^(?:[^A-Za-z0-9_-]*)(?:$([regex]::Escape($name)))\s+v[0-9]") {
            $violations.Add("headless Electron Rust dependency tree contains '$name'")
        }
    }
    return $violations
}

function Assert-SelfTest {
    $runtime = [ordered]@{ react = '1.2.3' }
    $development = [ordered]@{ electron = '4.5.6' }
    $good = [pscustomobject]@{
        dependencies = [pscustomobject]@{ react = '1.2.3' }
        devDependencies = [pscustomobject]@{ electron = '4.5.6' }
    }
    if (@(Get-ExactDependencyViolations -Manifest $good -ExpectedRuntime $runtime -ExpectedDevelopment $development).Count -ne 0) {
        throw 'Electron dependency gate self-test rejected exact pinned dependencies.'
    }
    $bad = [pscustomobject]@{
        dependencies = [pscustomobject]@{ react = '^1.2.3' }
        devDependencies = [pscustomobject]@{ electron = '4.5.6'; 'node-pty' = '1.0.0' }
    }
    if (@(Get-ExactDependencyViolations -Manifest $bad -ExpectedRuntime $runtime -ExpectedDevelopment $development).Count -eq 0) {
        throw 'Electron dependency gate self-test accepted a range or forbidden package.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyres-electron-backend v1.0.0`ngpui v0.2.2").Count -eq 0) {
        throw 'Electron dependency gate self-test accepted GPUI in a headless tree.'
    }
    if (@(Get-CargoTreeViolations -Tree "lovelyres-electron-backend v1.0.0`nserde v1.0.0").Count -ne 0) {
        throw 'Electron dependency gate self-test rejected a headless Rust tree.'
    }
    Write-Host 'Electron dependency gate fixture self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}

$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$electronManifestPath = Join-Path $root 'electron/package.json'
$rootManifestPath = Join-Path $root 'Cargo.toml'
$terminalManifestPath = Join-Path $root 'crates/lovelyres-terminal/Cargo.toml'
$lockPath = Join-Path $root 'pnpm-lock.yaml'
$cargoLockPath = Join-Path $root 'Cargo.lock'
$requiredFiles = @(
    $electronManifestPath,
    $rootManifestPath,
    $terminalManifestPath,
    $lockPath,
    $cargoLockPath
)
foreach ($path in $requiredFiles) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Electron dependency gate is missing required file '$path'."
    }
}

$violations = [System.Collections.Generic.List[string]]::new()
$electronManifest = Get-Content -LiteralPath $electronManifestPath -Raw | ConvertFrom-Json
foreach ($violation in @(Get-ExactDependencyViolations `
    -Manifest $electronManifest `
    -ExpectedRuntime $approvedRuntimeDependencies `
    -ExpectedDevelopment $approvedDevelopmentDependencies)) {
    $violations.Add($violation)
}

$lockText = Get-Content -LiteralPath $lockPath -Raw
if ($lockText -notmatch "(?m)^lockfileVersion:\s*'9\.0'\s*$") {
    $violations.Add("pnpm-lock.yaml must use lockfileVersion '9.0'")
}
if ($lockText -notmatch '(?m)^\s+electron:\s*$') {
    $violations.Add('pnpm-lock.yaml has no Electron workspace importer')
}
foreach ($group in @($approvedRuntimeDependencies, $approvedDevelopmentDependencies)) {
    foreach ($name in $group.Keys) {
        $escapedName = [regex]::Escape($name)
        $escapedVersion = [regex]::Escape([string]$group[$name])
        $entryPattern = '(?ms)^\s{6}[''"]?' + $escapedName + '[''"]?:\s*\r?\n\s{8}specifier:\s*' + $escapedVersion + '\s*$'
        if ($lockText -notmatch $entryPattern) {
            $violations.Add("pnpm-lock.yaml Electron importer is missing exact '$name@$($group[$name])'")
        }
    }
}
if ($lockText -notmatch '(?m)^\s+resolution:\s*\{integrity:\s*sha512-') {
    $violations.Add('pnpm-lock.yaml contains no sha512 package integrity records')
}
foreach ($name in $forbiddenDesktopPackages) {
    if ($lockText -match "(?m)^\s{2}'?$([regex]::Escape($name))@") {
        $violations.Add("pnpm-lock.yaml contains forbidden package '$name'")
    }
}

Push-Location $root
try {
    $backendTree = (& cargo tree --locked --package lovelyres-electron-backend --edges normal --prefix none 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        $violations.Add("cargo tree for lovelyres-electron-backend failed: $($backendTree.Trim())")
    } else {
        foreach ($violation in @(Get-CargoTreeViolations -Tree $backendTree)) {
            $violations.Add($violation)
        }
    }
    $terminalTree = (& cargo tree --locked --package lovelyres-terminal --no-default-features --edges normal --prefix none 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        $violations.Add("cargo tree for headless lovelyres-terminal failed: $($terminalTree.Trim())")
    } else {
        foreach ($violation in @(Get-CargoTreeViolations -Tree $terminalTree)) {
            $violations.Add($violation)
        }
    }
} finally {
    Pop-Location
}

$terminalManifestText = Get-Content -LiteralPath $terminalManifestPath -Raw
if ($terminalManifestText -match '(?m)^default\s*=\s*\[\s*[^\]\s]') {
    $violations.Add('lovelyres-terminal default features must remain headless')
}

if ($RequireGpuiRetired) {
    $rootManifestText = Get-Content -LiteralPath $rootManifestPath -Raw
    $cargoLockText = Get-Content -LiteralPath $cargoLockPath -Raw
    if (Test-Path -LiteralPath (Join-Path $root 'crates/lovelyres-gpui')) {
        $violations.Add('crates/lovelyres-gpui still exists')
    }
    foreach ($marker in @('crates/lovelyres-gpui', 'gpui =', 'gpui-component', 'gpui-component-assets')) {
        if ($rootManifestText.Contains($marker, [System.StringComparison]::Ordinal)) {
            $violations.Add("root Cargo.toml still contains '$marker'")
        }
    }
    foreach ($marker in @('gpui', 'gpui-component', 'gpui-component-assets')) {
        if ($terminalManifestText -match "(?m)^\s*$([regex]::Escape($marker))\s*=") {
            $violations.Add("lovelyres-terminal still declares '$marker'")
        }
        $lockMarkerPattern = '(?m)^name\s*=\s*"' + [regex]::Escape($marker) + '"\s*$'
        if ($cargoLockText -match $lockMarkerPattern) {
            $violations.Add("Cargo.lock still contains '$marker'")
        }
    }
}

if ($violations.Count -gt 0) {
    throw "Electron dependency gate failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
}

Write-Host "Electron dependency gate passed (exact pnpm direct dependencies, locked integrity records, headless Rust trees; GPUI retirement required: $([bool]$RequireGpuiRetired))."
