[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$Target = 'x86_64-pc-windows-msvc',
    [string]$LlvmObjdumpPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([System.IO.Path]::GetExtension($binary) -ne '.exe') {
    throw "Expected a Windows .exe sidecar, found '$binary'."
}

$cfg = @(& rustc --target $Target -C target-feature=+crt-static --print cfg 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "rustc CRT configuration probe failed:`n$($cfg -join [Environment]::NewLine)"
}
if (-not ($cfg | Where-Object { ([string]$_).Trim() -eq 'target_feature="crt-static"' })) {
    throw "rustc did not enable crt-static for target '$Target'."
}

if ([string]::IsNullOrWhiteSpace($LlvmObjdumpPath)) {
    $sysroot = (& rustc --print sysroot 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Unable to locate the Rust sysroot: $sysroot" }
    $bundledObjdump = Join-Path $sysroot "lib\rustlib\$Target\bin\llvm-objdump.exe"
    if (Test-Path -LiteralPath $bundledObjdump -PathType Leaf) {
        $LlvmObjdumpPath = $bundledObjdump
    } else {
        $command = Get-Command llvm-objdump -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            throw 'llvm-objdump is required for the static CRT/PE import gate.'
        }
        $LlvmObjdumpPath = $command.Source
    }
}
$objdump = (Resolve-Path -LiteralPath $LlvmObjdumpPath).Path

$headers = @(& $objdump -f $binary 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "llvm-objdump could not inspect '$binary':`n$($headers -join [Environment]::NewLine)"
}
$headerText = $headers -join [Environment]::NewLine
if ($headerText -notmatch '(?i)(coff-x86-64|pei-x86-64|i386:x86-64)') {
    throw "The sidecar is not an x86-64 PE/COFF executable:`n$headerText"
}

$importsOutput = @(& $objdump -p $binary 2>&1)
if ($LASTEXITCODE -ne 0) {
    throw "llvm-objdump import inspection failed:`n$($importsOutput -join [Environment]::NewLine)"
}
$imports = @(
    $importsOutput |
        ForEach-Object {
            if ([string]$_ -match '(?i)DLL Name:\s*([^\s]+)') { $Matches[1] }
        } |
        Sort-Object -Unique
)
$dynamicCrt = @($imports | Where-Object { $_ -match '(?i)^(vcruntime|msvcp|msvcr\d*|ucrtbase|api-ms-win-crt)' })
if ($dynamicCrt.Count -gt 0) {
    throw "Dynamic MSVC/UCRT imports violate the static CRT sidecar contract: $($dynamicCrt -join ', ')"
}

Write-Host "Electron sidecar static CRT/PE gate passed: '$binary'."
Write-Host "Imported DLLs: $($imports -join ', ')"
