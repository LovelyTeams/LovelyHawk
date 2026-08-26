# Brings the nine lab hosts up and writes them into the connection store.
#
# Safe to re-run: the images are cached, the containers are recreated, and the
# connection entries are refreshed in place rather than duplicated. Re-run it
# after a WSL restart, which gives the virtual machine a new address.
[CmdletBinding()]
param(
    # Rebuild the images before starting. Only needed after editing the lab
    # scripts under tools/lab/matrix.
    [switch]$Rebuild,
    # Bring the containers up without touching the connection store.
    [switch]$SkipImport
)

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$matrix = Join-Path $repository 'tools/lab/matrix'

function Invoke-Wsl {
    param([Parameter(Mandatory = $true)][string]$Command)
    $output = & wsl.exe -d Ubuntu -u root -e bash -lc $Command 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "WSL command failed ($LASTEXITCODE): $Command`n$output"
    }
    return $output
}

Write-Host 'Checking the Docker daemon inside WSL...'
Invoke-Wsl 'command -v docker >/dev/null 2>&1 || { echo "docker is not installed in WSL"; exit 1; }' | Out-Null
Invoke-Wsl 'docker info >/dev/null 2>&1 || systemctl start docker' | Out-Null

Write-Host 'Syncing the lab definitions into WSL...'
Invoke-Wsl 'mkdir -p /opt/lab-matrix' | Out-Null
$source = ($matrix -replace '\\', '/') -replace '^([A-Za-z]):', { "/mnt/$($_.Groups[1].Value.ToLower())" }
Invoke-Wsl "cp $source/* /opt/lab-matrix/ && sed -i 's/\r`$//' /opt/lab-matrix/*.sh && chmod +x /opt/lab-matrix/*.sh" | Out-Null

$running = (Invoke-Wsl 'docker ps --filter name=lab- --format "{{.Names}}" | wc -l') -join ''
if ($Rebuild -or [int]$running -lt 9) {
    Write-Host 'Building and starting the lab hosts (first run pulls nine images and takes a while)...'
    $build = Invoke-Wsl 'bash /opt/lab-matrix/build.sh'
    $build | Where-Object { $_ -match '^===|BUILD FAILED|running|exited' } | ForEach-Object { Write-Host "  $_" }
}
else {
    Write-Host "All nine lab hosts are already up."
}

$up = (Invoke-Wsl 'docker ps --filter name=lab- --format "{{.Names}} {{.Ports}}"')
Write-Host ''
$up | ForEach-Object { Write-Host "  $_" }

if (-not $SkipImport) {
    Write-Host ''
    Write-Host 'Writing the hosts into the connection store...'
    & node (Join-Path $repository 'tools/lab/import-labs.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Importing the lab connections failed.' }
}
