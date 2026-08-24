[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml'),
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$ProjectNoticePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crates/lovelyres-terminal/THIRD_PARTY_NOTICES.md'),
    [string]$GpuiNoticePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crates/lovelyres-gpui/THIRD_PARTY_NOTICES.md')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$projectNotice = (Resolve-Path -LiteralPath $ProjectNoticePath).Path
$gpuiNotice = (Resolve-Path -LiteralPath $GpuiNoticePath).Path
$output = [System.IO.Path]::GetFullPath($OutputPath)
$outputParent = Split-Path -Parent $output
if ([string]::IsNullOrWhiteSpace($outputParent)) {
    throw 'OutputPath must include a parent directory.'
}
[System.IO.Directory]::CreateDirectory($outputParent) | Out-Null

$metadataText = (& cargo metadata --locked --format-version 1 --manifest-path $manifest | Out-String)
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed:`n$metadataText"
}
$metadata = $metadataText | ConvertFrom-Json

$workspaceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
foreach ($id in $metadata.workspace_members) {
    [void]$workspaceIds.Add([string]$id)
}

$builder = [System.Text.StringBuilder]::new()
[void]$builder.AppendLine('LovelyRes Third-Party Notices')
[void]$builder.AppendLine('=============================')
[void]$builder.AppendLine()
[void]$builder.AppendLine('This bundle is generated from the locked GPUI Cargo workspace.')
[void]$builder.AppendLine('Each dependency section records its declared license and includes license/notice files shipped in its Cargo package when present.')
[void]$builder.AppendLine()
[void]$builder.AppendLine('LovelyRes terminal attribution')
[void]$builder.AppendLine('------------------------------')
[void]$builder.AppendLine((Get-Content -LiteralPath $projectNotice -Raw))
[void]$builder.AppendLine()
[void]$builder.AppendLine('LovelyRes GPUI asset attribution')
[void]$builder.AppendLine('--------------------------------')
[void]$builder.AppendLine((Get-Content -LiteralPath $gpuiNotice -Raw))

$noticeFixture = $builder.ToString()
foreach ($requiredText in @('gpui-terminal 0.1.0', 'alacritty_terminal 0.25.1', 'Inter 4.1', 'Cascadia Mono 2407.24', 'SIL OPEN FONT LICENSE Version 1.1')) {
    if (-not $noticeFixture.Contains($requiredText, [System.StringComparison]::Ordinal)) {
        throw "Required project attribution '$requiredText' is missing from the notice inputs."
    }
}

$thirdPartyPackages = @($metadata.packages | Where-Object { -not $workspaceIds.Contains([string]$_.id) } | Sort-Object name, version)
foreach ($package in $thirdPartyPackages) {
    $packageRoot = Split-Path -Parent ([string]$package.manifest_path)
    $licenseExpression = if ($package.license) { [string]$package.license } else { 'NOASSERTION' }
    $source = if ($package.repository) {
        [string]$package.repository
    } elseif ($package.homepage) {
        [string]$package.homepage
    } elseif ($package.source) {
        [string]$package.source
    } else {
        'Source not declared'
    }

    [void]$builder.AppendLine()
    [void]$builder.AppendLine("==============================================================================")
    [void]$builder.AppendLine("$($package.name) $($package.version)")
    [void]$builder.AppendLine("License: $licenseExpression")
    [void]$builder.AppendLine("Source: $source")

    $licensePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path -LiteralPath $packageRoot -PathType Container) {
        foreach ($candidate in Get-ChildItem -LiteralPath $packageRoot -File) {
            if ($candidate.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)(?:[._-].*)?$') {
                [void]$licensePaths.Add($candidate.FullName)
            }
        }
    }
    if ($package.license_file) {
        $declaredLicense = [string]$package.license_file
        $declaredPath = if ([System.IO.Path]::IsPathRooted($declaredLicense)) {
            $declaredLicense
        } else {
            Join-Path $packageRoot $declaredLicense
        }
        if (Test-Path -LiteralPath $declaredPath -PathType Leaf) {
            [void]$licensePaths.Add((Resolve-Path -LiteralPath $declaredPath).Path)
        }
    }

    if ($licensePaths.Count -eq 0) {
        [void]$builder.AppendLine('License file: not shipped separately; see the SPDX expression above.')
        continue
    }

    foreach ($licensePath in $licensePaths | Sort-Object) {
        [void]$builder.AppendLine()
        [void]$builder.AppendLine("--- $([System.IO.Path]::GetFileName($licensePath)) ---")
        [void]$builder.AppendLine((Get-Content -LiteralPath $licensePath -Raw))
    }
}

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($output, $builder.ToString(), $utf8NoBom)
Write-Host "Wrote notices for $($thirdPartyPackages.Count) locked dependencies to '$output'."
