[CmdletBinding()]
param(
    [string]$ArchivePath,
    [switch]$SelfTest
)

# Validates a portable Windows package without running it: exact file set,
# manifest hashes, executable format, the side-by-side checksum, and that no
# runtime state or development artifact was shipped.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$expectedFiles = @('LICENSE', 'LovelyHawk.exe', 'lovelyhawk-win-agent.exe', 'PACKAGE_MANIFEST.json', 'README.txt', 'SBOM.cdx.json', 'THIRD_PARTY_LICENSES_RUST.txt', 'THIRD_PARTY_NOTICES.md')

# How each bundled UI package is named in THIRD_PARTY_NOTICES.md.
$noticeNames = @{
    'react' = 'React'; 'react-dom' = 'React DOM'; 'scheduler' = 'Scheduler'
    '@xterm/xterm' = 'xterm.js'; '@xterm/addon-fit' = 'Fit Addon'; '@xterm/addon-search' = 'Search Addon'
    '@tauri-apps/api' = '@tauri-apps/api'
}

function Get-ComponentField {
    param($Component, [string]$Name)
    $property = $Component.PSObject.Properties[$Name]
    if ($null -eq $property) { return '' }
    return [string]$property.Value
}

# The bill of materials names every component with a license and carries no
# retired GPUI crate; every crate it lists has its entry in the Rust license
# file, every UI package its notice, and every font its recorded hash.
function Get-InventoryViolations {
    param([Parameter(Mandatory = $true)][string]$PackageRoot)

    $violations = [System.Collections.Generic.List[string]]::new()
    $sbomPath = Join-Path $PackageRoot 'SBOM.cdx.json'
    $licensesPath = Join-Path $PackageRoot 'THIRD_PARTY_LICENSES_RUST.txt'
    $noticesPath = Join-Path $PackageRoot 'THIRD_PARTY_NOTICES.md'
    if (-not (Test-Path -LiteralPath $sbomPath) -or -not (Test-Path -LiteralPath $licensesPath) -or -not (Test-Path -LiteralPath $noticesPath)) { return $violations }
    try { $sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json } catch { $violations.Add('SBOM.cdx.json is not JSON'); return $violations }
    if ((Get-ComponentField $sbom 'bomFormat') -cne 'CycloneDX' -or (Get-ComponentField $sbom 'specVersion') -cne '1.5') { $violations.Add('SBOM.cdx.json is not a CycloneDX 1.5 document') }
    $components = @(if ($null -ne $sbom.PSObject.Properties['components']) { $sbom.components })
    if ($components.Count -eq 0) { $violations.Add('SBOM.cdx.json lists no components') }
    $licenseText = Get-Content -LiteralPath $licensesPath -Raw
    $noticesText = Get-Content -LiteralPath $noticesPath -Raw
    foreach ($component in $components) {
        $name = Get-ComponentField $component 'name'
        $version = Get-ComponentField $component 'version'
        $purl = Get-ComponentField $component 'purl'
        $licenses = @(if ($null -ne $component.PSObject.Properties['licenses']) { $component.licenses })
        if ($licenses.Count -eq 0) { $violations.Add("SBOM component '$name' has no license") }
        if ($name -match '^gpui') { $violations.Add("SBOM lists retired '$name'") }
        if ($purl -like 'pkg:cargo/*' -and -not $licenseText.Contains("`n$name $version ", [System.StringComparison]::Ordinal)) {
            $violations.Add("THIRD_PARTY_LICENSES_RUST.txt has no entry for $name $version")
        }
        if ($purl -like 'pkg:npm/*') {
            $alias = $noticeNames[$name]
            if ($null -eq $alias -or -not $noticesText.Contains("$alias $version", [System.StringComparison]::Ordinal)) {
                $violations.Add("THIRD_PARTY_NOTICES.md has no notice for $name $version")
            }
        }
        if ((Get-ComponentField $component 'type') -eq 'file' -and ($licenses | ConvertTo-Json -Compress) -match 'OFL-1\.1') {
            $hash = @($component.hashes | Where-Object { $_.alg -eq 'SHA-256' } | ForEach-Object { [string]$_.content })[0]
            if ([string]::IsNullOrEmpty($hash) -or -not $noticesText.Contains($hash, [System.StringComparison]::Ordinal)) {
                $violations.Add("THIRD_PARTY_NOTICES.md does not record the font $name")
            }
        }
    }
    return $violations
}

function Get-PackageViolations {
    param([Parameter(Mandatory = $true)][string]$Root)

    $violations = [System.Collections.Generic.List[string]]::new()
    $packages = @(Get-ChildItem -LiteralPath $Root -Directory -Force)
    if ($packages.Count -ne 1 -or $packages[0].Name -notmatch '^LovelyHawk-\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?-windows-x64$') {
        $violations.Add('the archive must contain exactly one LovelyHawk-<version>-windows-x64 folder')
        return $violations
    }
    $packageRoot = $packages[0].FullName
    $actual = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force | ForEach-Object {
        $relative = [System.IO.Path]::GetRelativePath($packageRoot, $_.FullName).Replace('\', '/')
        if ($_.PSIsContainer) { "$relative/" } else { $relative }
    } | Sort-Object)
    if (($actual -join "`n") -cne (($expectedFiles | Sort-Object) -join "`n")) {
        $violations.Add("package files must be exactly [$($expectedFiles -join ', ')]; found [$($actual -join ', ')]")
    }
    $manifestPath = Join-Path $packageRoot 'PACKAGE_MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) { return $violations }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema -cne 'lovelyhawk-portable-package/v1') { $violations.Add('unexpected manifest schema') }
    if ($packages[0].Name -cne "LovelyHawk-$($manifest.version)-windows-x64") { $violations.Add('folder name does not match the manifest version') }
    $listed = @($manifest.files | ForEach-Object { [string]$_.path } | Sort-Object)
    $shipped = @($expectedFiles | Where-Object { $_ -ne 'PACKAGE_MANIFEST.json' } | Sort-Object)
    if (($listed -join "`n") -cne ($shipped -join "`n")) { $violations.Add('the manifest must list every shipped file except itself') }
    foreach ($entry in @($manifest.files)) {
        $file = Join-Path $packageRoot ([string]$entry.path)
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $violations.Add("manifest lists missing '$($entry.path)'"); continue }
        $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -cne [string]$entry.sha256) { $violations.Add("hash mismatch for '$($entry.path)'") }
        if ((Get-Item -LiteralPath $file).Length -ne [int64]$entry.size) { $violations.Add("size mismatch for '$($entry.path)'") }
    }
    foreach ($violation in @(Get-InventoryViolations -PackageRoot $packageRoot)) { $violations.Add($violation) }
    $exe = Join-Path $packageRoot 'LovelyHawk.exe'
    if (Test-Path -LiteralPath $exe) {
        $bytes = [System.IO.File]::ReadAllBytes($exe)
        if ($bytes.Length -lt 512 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { $violations.Add('LovelyHawk.exe is not a PE executable') }
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($marker in @('LOVELYHAWK_DEBUG_PORT', 'LOVELYHAWK_TEST_DIALOG_ANSWERS', 'LOVELYHAWK_TEST_CLIPBOARD_FILE', 'LOVELYHAWK_ARCHIVE_ROOT', 'LOVELYHAWK_DEV_SERVER')) {
            if ($text.Contains($marker, [System.StringComparison]::Ordinal)) {
                $violations.Add("release executable still reads the debug-only variable '$marker'")
            }
        }
    }
    return $violations
}

function Assert-SelfTest {
    $scratch = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyhawk-validator-$([guid]::NewGuid().ToString('N'))"
    try {
        $package = Join-Path $scratch 'LovelyHawk-1.0.0-windows-x64'
        [System.IO.Directory]::CreateDirectory($package) | Out-Null
        [System.IO.File]::WriteAllBytes((Join-Path $package 'LovelyHawk.exe'), [byte[]](@(0x4D, 0x5A) + (,0 * 600)))
        [System.IO.File]::WriteAllBytes((Join-Path $package 'lovelyhawk-win-agent.exe'), [byte[]](@(0x4D, 0x5A) + (,0 * 600)))
        foreach ($name in @('LICENSE', 'README.txt')) { Set-Content -LiteralPath (Join-Path $package $name) -Value $name }
        Set-Content -LiteralPath (Join-Path $package 'THIRD_PARTY_NOTICES.md') -Value "## React 19.2.8`n- SHA-256: ``aaaa```n"
        Set-Content -LiteralPath (Join-Path $package 'THIRD_PARTY_LICENSES_RUST.txt') -Value "header`nserde 1.0.0 — MIT OR Apache-2.0 — texts #1"
        $crate = '{"name":"serde","version":"1.0.0","purl":"pkg:cargo/serde@1.0.0","licenses":[{"expression":"MIT OR Apache-2.0"}]}'
        $uiPackage = '{"name":"react","version":"19.2.8","purl":"pkg:npm/react@19.2.8","licenses":[{"license":{"id":"MIT"}}]}'
        $font = '{"type":"file","name":"ui/assets/fonts/Inter-Regular.ttf","hashes":[{"alg":"SHA-256","content":"aaaa"}],"licenses":[{"license":{"id":"OFL-1.1"}}]}'
        $goodSbom = "{`"bomFormat`":`"CycloneDX`",`"specVersion`":`"1.5`",`"components`":[$crate,$uiPackage,$font]}"
        Set-Content -LiteralPath (Join-Path $package 'SBOM.cdx.json') -Value $goodSbom
        $files = @('LICENSE', 'LovelyHawk.exe', 'lovelyhawk-win-agent.exe', 'README.txt', 'SBOM.cdx.json', 'THIRD_PARTY_LICENSES_RUST.txt', 'THIRD_PARTY_NOTICES.md') | ForEach-Object {
            $path = Join-Path $package $_
            [ordered]@{ path = $_; size = (Get-Item -LiteralPath $path).Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
        [ordered]@{ schema = 'lovelyhawk-portable-package/v1'; version = '1.0.0'; files = $files } | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $package 'PACKAGE_MANIFEST.json')
        if (@(Get-PackageViolations -Root $scratch).Count -ne 0) { throw 'Package validator self-test rejected a well-formed package.' }
        Remove-Item -LiteralPath (Join-Path $package 'lovelyhawk-win-agent.exe')
        if (@(Get-PackageViolations -Root $scratch).Count -eq 0) { throw 'Package validator self-test accepted a missing Windows session agent.' }
        [System.IO.File]::WriteAllBytes((Join-Path $package 'lovelyhawk-win-agent.exe'), [byte[]](@(0x4D, 0x5A) + (,0 * 600)))
        [System.IO.Directory]::CreateDirectory((Join-Path $package 'data')) | Out-Null
        if (@(Get-PackageViolations -Root $scratch).Count -eq 0) { throw 'Package validator self-test accepted shipped runtime data.' }
        Remove-Item -LiteralPath (Join-Path $package 'data') -Recurse -Force
        Add-Content -LiteralPath (Join-Path $package 'LICENSE') -Value 'tampered'
        if (@(Get-PackageViolations -Root $scratch).Count -eq 0) { throw 'Package validator self-test accepted a hash mismatch.' }
        if (@(Get-InventoryViolations -PackageRoot $package).Count -ne 0) { throw 'Package validator self-test rejected a complete inventory.' }
        foreach ($bad in @(
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"serde","version":"1.0.0","purl":"pkg:cargo/serde@1.0.0","licenses":[]}]}',
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"gpui","version":"0.2.0","purl":"pkg:cargo/gpui@0.2.0","licenses":[{"expression":"Apache-2.0"}]}]}',
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"ring","version":"0.17.0","purl":"pkg:cargo/ring@0.17.0","licenses":[{"expression":"ISC"}]}]}',
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","licenses":[{"license":{"id":"MIT"}}]}]}',
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"file","name":"ui/assets/fonts/Other.ttf","hashes":[{"alg":"SHA-256","content":"bbbb"}],"licenses":[{"license":{"id":"OFL-1.1"}}]}]}'
        )) {
            Set-Content -LiteralPath (Join-Path $package 'SBOM.cdx.json') -Value $bad
            if (@(Get-InventoryViolations -PackageRoot $package).Count -eq 0) { throw "Package validator self-test accepted a bad inventory: $bad" }
        }
    } finally {
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
    Write-Host 'Desktop package validator self-test passed.'
}

if ($SelfTest) {
    Assert-SelfTest
    return
}
if ([string]::IsNullOrWhiteSpace($ArchivePath)) { throw 'Pass -ArchivePath or -SelfTest.' }

$archive = (Resolve-Path -LiteralPath $ArchivePath).Path
$checksumPath = "$archive.sha256"
if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) { throw "Missing checksum file '$checksumPath'." }
$expectedHash = ((Get-Content -LiteralPath $checksumPath -Raw).Trim() -split '\s+')[0]
$actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expectedHash -cne $actualHash) { throw "Archive checksum mismatch for '$archive'." }

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyhawk-validate-$([guid]::NewGuid().ToString('N'))"
try {
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $scratch)
    $violations = @(Get-PackageViolations -Root $scratch)
    if ($violations.Count -gt 0) {
        throw "Portable package validation failed with $($violations.Count) violation(s):`n - $($violations -join "`n - ")"
    }
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
Write-Host "Portable package validated: '$archive'."
