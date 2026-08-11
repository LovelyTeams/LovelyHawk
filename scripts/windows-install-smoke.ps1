[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallerPath,
  [ValidateRange(1, 60)]
  [int]$StartupWaitSeconds = 8
)

$ErrorActionPreference = 'Stop'
$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$installDir = Join-Path $env:LOCALAPPDATA 'LovelyRes'
$binary = Join-Path $installDir 'lovelyres.exe'
$uninstaller = Join-Path $installDir 'uninstall.exe'
$uninstallRegistry = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\LovelyRes'
$app = $null
$installedByThisRun = $false
$installedHash = $null
$startupAlive = $false
$frontendReady = $false
$failure = $null
$readyFile = Join-Path ([System.IO.Path]::GetTempPath()) "lovelyres-ready-$([guid]::NewGuid()).json"
$previousReadyFile = [Environment]::GetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', 'Process')

if ([System.IO.Path]::GetExtension($installer) -ne '.exe') {
  throw "Installer must be an executable: $installer"
}
if (Test-Path -LiteralPath $installDir) {
  throw "Refusing to overwrite an existing LovelyRes installation: $installDir"
}

try {
  $install = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
  if ($install.ExitCode -ne 0) {
    throw "NSIS install failed with exit code $($install.ExitCode)"
  }
  $installedByThisRun = $true

  if (-not (Test-Path -LiteralPath $binary)) {
    throw "Installed binary not found: $binary"
  }
  if (-not (Test-Path -LiteralPath $uninstaller)) {
    throw "Uninstaller not found: $uninstaller"
  }

  $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant()
  [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', $readyFile, 'Process')
  $app = Start-Process -FilePath $binary -PassThru -WindowStyle Hidden
  $deadline = [DateTime]::UtcNow.AddSeconds($StartupWaitSeconds)
  while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $readyFile)) {
    Start-Sleep -Milliseconds 250
    $app.Refresh()
    if ($app.HasExited) {
      throw "Installed application exited before frontend readiness with code $($app.ExitCode)"
    }
  }
  if (-not (Test-Path -LiteralPath $readyFile)) {
    throw "Frontend readiness marker was not created within $StartupWaitSeconds seconds"
  }
  $readyPayload = Get-Content -LiteralPath $readyFile -Raw | ConvertFrom-Json
  if ($readyPayload.schema -ne 'lovelyres-smoke-ready/v1' -or $readyPayload.status -ne 'ready') {
    throw 'Frontend readiness marker has an invalid contract'
  }
  $frontendReady = $true
  $startupAlive = $true
} catch {
  $failure = $_
} finally {
  if ($null -ne $app) {
    $app.Refresh()
    if (-not $app.HasExited) {
      Stop-Process -Id $app.Id
      $app.WaitForExit()
    }
  }

  if ($installedByThisRun -and (Test-Path -LiteralPath $uninstaller)) {
    $uninstall = Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
    if ($uninstall.ExitCode -ne 0 -and $null -eq $failure) {
      $failure = [System.Management.Automation.RuntimeException]::new(
        "NSIS uninstall failed with exit code $($uninstall.ExitCode)"
      )
    }
  }
  [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', $previousReadyFile, 'Process')
  if (Test-Path -LiteralPath $readyFile) {
    Remove-Item -LiteralPath $readyFile -Force
  }
}

Start-Sleep -Seconds 2
if ((Test-Path -LiteralPath $installDir) -and $null -eq $failure) {
  $failure = [System.Management.Automation.RuntimeException]::new(
    "Install directory remained after uninstall: $installDir"
  )
}
if ((Test-Path $uninstallRegistry) -and $null -eq $failure) {
  $failure = [System.Management.Automation.RuntimeException]::new(
    "Uninstall registry entry remained: $uninstallRegistry"
  )
}
if ($null -ne $failure) {
  throw $failure
}

[pscustomobject]@{
  installer = $installer
  installedBinarySha256 = $installedHash
  startupAlive = $startupAlive
  frontendReady = $frontendReady
  installDirectoryRemoved = -not (Test-Path -LiteralPath $installDir)
  uninstallRegistryRemoved = -not (Test-Path $uninstallRegistry)
} | ConvertTo-Json -Compress
