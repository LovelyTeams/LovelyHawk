[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SbomPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$path = (Resolve-Path -LiteralPath $SbomPath).Path
$sbom = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($sbom.bomFormat -ne 'CycloneDX') {
    throw "'$path' is not a CycloneDX SBOM."
}
if ([string]::IsNullOrWhiteSpace([string]$sbom.specVersion)) {
    throw "'$path' does not declare a CycloneDX specVersion."
}

$components = @($sbom.components)
if ($components.Count -eq 0) {
    throw "'$path' contains no dependency components."
}
$forbidden = @(
    $components |
        ForEach-Object { [string]$_.name } |
        Where-Object {
            $name = $_.ToLowerInvariant()
            $name.Contains('tauri') -or
            $name -eq 'wry' -or $name.StartsWith('wry-') -or
            $name.Contains('webview') -or $name.Contains('web-view') -or
            $name -eq 'vue' -or $name.StartsWith('vue-') -or
            $name.Contains('xterm')
        } |
        Sort-Object -Unique
)
if ($forbidden.Count -gt 0) {
    throw "Forbidden legacy components leaked into the GPUI SBOM: $($forbidden -join ', ')"
}

Write-Host "CycloneDX $($sbom.specVersion) SBOM gate passed ($($components.Count) components)."

