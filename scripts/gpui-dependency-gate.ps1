[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Cargo.toml')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$treeOutput = @(& cargo tree --locked --workspace --all-features --target all --prefix none --manifest-path $manifest 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "cargo tree failed:`n$($treeOutput -join [Environment]::NewLine)"
}

$packages = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$forbidden = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($line in $treeOutput) {
    $text = ([string]$line).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        continue
    }

    $packageName = ($text -split '\s+', 2)[0]
    [void]$packages.Add($packageName)
    $normalized = $packageName.ToLowerInvariant()
    if (
        $normalized.Contains('tauri') -or
        $normalized -eq 'wry' -or $normalized.StartsWith('wry-') -or
        $normalized.Contains('webview') -or $normalized.Contains('web-view') -or
        $normalized -eq 'vue' -or $normalized.StartsWith('vue-') -or
        $normalized.Contains('xterm')
    ) {
        [void]$forbidden.Add($packageName)
    }
}

if ($forbidden.Count -gt 0) {
    $names = ($forbidden | Sort-Object) -join ', '
    throw "Forbidden WebView/Tauri dependency found in the GPUI cargo tree: $names"
}

Write-Host "GPUI cargo tree gate passed ($($packages.Count) unique packages; no tauri/wry/webview/vue/xterm)."
