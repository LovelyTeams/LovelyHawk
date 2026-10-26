#!/usr/bin/env pwsh
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Build script for RDP DVC Simple Python implementation

.DESCRIPTION
    Builds all Simple Python projects (protocol, client, server)
    for the specified platform and configuration.
    By default, builds all projects for the current platform architecture in Debug configuration.

.PARAMETER Configuration
    Build configuration: Debug or Release. Default: Debug

.PARAMETER Platform
    Target platform: x64 or ARM64. Default: Current architecture

.PARAMETER Force
    Force rebuild all projects (clean before build)

.PARAMETER Clean
    Clean all build outputs (obj, bin folders) and exit

.PARAMETER Install
    Install Python dependencies and PyInstaller

.PARAMETER Project
    Specific project to build: all, protocol, client, server. Default: all

.EXAMPLE
    .\build.ps1
    # Builds all projects for current platform in Debug mode

.EXAMPLE
    .\build.ps1 -Configuration Release -Platform x64
    # Builds all projects for x64 in Release mode

.EXAMPLE
    .\build.ps1 -Force
    # Clean rebuild all projects

.EXAMPLE
    .\build.ps1 -Clean
    # Remove all build outputs

.EXAMPLE
    .\build.ps1 -Install
    # Install Python dependencies

.EXAMPLE
    .\build.ps1 -Project server -Configuration Release
    # Build only the server project in Release mode
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [Parameter()]
    [ValidateSet('x64', 'ARM64')]
    [string]$Platform,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$Clean,

    [Parameter()]
    [switch]$Install,

    [Parameter()]
    [ValidateSet('all', 'protocol', 'client', 'server')]
    [string]$Project = 'all'
)

$ErrorActionPreference = 'Stop'

# Clean function - removes all build artifacts
function Invoke-Clean {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "Cleaning all build outputs..." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow

    $foldersToClean = @(
        'bin'
        'obj'
        'build'
        'dist'
    )

    $totalRemoved = 0

    foreach ($folder in $foldersToClean) {
        $folderPath = Join-Path $PSScriptRoot $folder
        if (Test-Path $folderPath) {
            Write-Host "  Removing: $folderPath" -ForegroundColor Gray
            Remove-Item -Path $folderPath -Recurse -Force -ErrorAction SilentlyContinue
            $totalRemoved++
        }
    }

    # Clean __pycache__ folders recursively
    Get-ChildItem -Path $PSScriptRoot -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "  Removing: $($_.FullName)" -ForegroundColor Gray
        Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        $totalRemoved++
    }

    # Clean .pyc files
    Get-ChildItem -Path $PSScriptRoot -Recurse -Filter "*.pyc" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
    }

    if ($totalRemoved -eq 0) {
        Write-Host "`n[OK] Nothing to clean - already clean`n" -ForegroundColor Green
    } else {
        Write-Host "`n[OK] Clean completed ($totalRemoved folders removed)`n" -ForegroundColor Green
    }
}

# Handle Clean parameter first
if ($Clean) {
    Invoke-Clean
    exit 0
}

# Load prerequisites from JSON
$prereqJsonPath = Join-Path $PSScriptRoot "prerequisites.json"
$prereqJson = Get-Content $prereqJsonPath -Raw | ConvertFrom-Json
$Prerequisites = $prereqJson.prerequisites

function Test-WingetAvailable {
    try {
        $null = Get-Command winget -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Update-SessionEnvironment {
    <#
    .SYNOPSIS
        Updates environment variables in the current PowerShell session from registry
    .DESCRIPTION
        Refreshes PATH and other environment variables without requiring a shell restart.
        Useful after installing software via winget or other installers.
    #>
    Write-Verbose "Refreshing environment variables..."
    
    # Get system and user PATH from registry
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
    
    # Update PATH in current session
    $env:Path = "$machinePath;$userPath"
    
    # Also refresh other common environment variables
    foreach ($level in "Machine", "User") {
        [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
            if ($_.Key -ne "Path") {
                [Environment]::SetEnvironmentVariable($_.Key, $_.Value, "Process")
            }
        }
    }
    
    Write-Verbose "Environment refreshed successfully"
}

function Test-Prerequisite {
    <#
    .SYNOPSIS
        Tests if a prerequisite is installed using verification methods from JSON
    .PARAMETER Prerequisite
        The prerequisite object from prerequisites.json with verify section
    .RETURNS
        $true if installed and verified, $false otherwise
    #>
    param($Prerequisite)
    
    if (-not $Prerequisite.verify) {
        Write-Verbose "No verification method specified for $($Prerequisite.name), assuming not installed"
        return $false
    }
    
    $verify = $Prerequisite.verify
    
    # Check paths first (fastest check)
    if ($verify.paths) {
        $allPathsExist = $true
        foreach ($pathTemplate in $verify.paths) {
            $path = $ExecutionContext.InvokeCommand.ExpandString($pathTemplate)
            if (-not (Test-Path $path)) {
                Write-Verbose "Path not found: $path"
                $allPathsExist = $false
                break
            }
        }
        if (-not $allPathsExist) {
            return $false
        }
    }
    
    # Check registry keys
    if ($verify.registryKeys) {
        foreach ($regKeySpec in $verify.registryKeys) {
            $parts = $regKeySpec -split '\|'
            $regPath = $parts[0]
            $regValue = if ($parts.Count -gt 1) { $parts[1] } else { $null }
            
            try {
                if ($regValue) {
                    $value = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction Stop | Select-Object -ExpandProperty $regValue
                    if ($verify.registryPattern) {
                        if ($value -notmatch $verify.registryPattern) {
                            Write-Verbose "Registry value doesn't match pattern: $value"
                            return $false
                        }
                    }
                } else {
                    if (-not (Test-Path $regPath)) {
                        Write-Verbose "Registry path not found: $regPath"
                        return $false
                    }
                }
            } catch {
                Write-Verbose "Registry check failed: $_"
                return $false
            }
        }
    }
    
    # Check command execution
    if ($verify.command) {
        try {
            $commandExpanded = $ExecutionContext.InvokeCommand.ExpandString($verify.command)
            $output = Invoke-Expression $commandExpanded 2>&1 | Out-String
            
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
                Write-Verbose "Command failed with exit code $LASTEXITCODE"
                return $false
            }
            
            if ($verify.commandPattern -and $output -notmatch $verify.commandPattern) {
                Write-Verbose "Command output doesn't match pattern. Output: $output"
                return $false
            }
            
            return $true
        } catch {
            Write-Verbose "Command execution failed: $_"
            return $false
        }
    }
    
    # If we checked paths/registry without command, consider it verified
    if ($verify.paths -or $verify.registryKeys) {
        return $true
    }
    
    return $false
}

function Install-Prerequisites {
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "Installing Python Prerequisites" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow

    $wingetAvailable = Test-WingetAvailable
    $missingPrereqs = @()

    # Check what's missing
    foreach ($prereq in $Prerequisites) {
        Write-Host "Checking $($prereq.name)... " -NoNewline
        if (Test-Prerequisite $prereq) {
            Write-Host "[OK] Installed" -ForegroundColor Green
        } else {
            Write-Host "[X] Missing" -ForegroundColor Red
            $missingPrereqs += $prereq
        }
    }

    if ($missingPrereqs.Count -eq 0) {
        Write-Host "`n[OK] All prerequisites are installed!" -ForegroundColor Green
    } elseif (-not $wingetAvailable) {
        Write-Host "`n[!] winget is not available on this system." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please install the following prerequisites manually:" -ForegroundColor Cyan
        Write-Host ""
        foreach ($prereq in $missingPrereqs) {
            Write-Host "  $($prereq.name):" -ForegroundColor White
            Write-Host "    $($prereq.manualInstall)" -ForegroundColor Gray
            Write-Host ""
        }
        Write-Host "After installing, restart your terminal and run this script again." -ForegroundColor Yellow
        exit 1
    } else {
        # Install missing prerequisites via winget
        foreach ($prereq in $missingPrereqs) {
            Write-Host "`nInstalling $($prereq.name) via winget..." -ForegroundColor Cyan
            
            & winget install $prereq.wingetId --accept-package-agreements --accept-source-agreements

            if ($LASTEXITCODE -ne 0) {
                Write-Host "[!] winget install failed for $($prereq.name)." -ForegroundColor Yellow
                Write-Host "  Manual install: $($prereq.manualInstall)" -ForegroundColor Gray
            } else {
                Write-Host "[OK] $($prereq.name) installed successfully" -ForegroundColor Green
                Update-SessionEnvironment
            }
        }
        
        # Verify all prerequisites are now installed
        Write-Host "`nVerifying installation..." -ForegroundColor Cyan
        $allVerified = $true
        $failedPrereqs = @()
        
        foreach ($prereq in $Prerequisites) {
            Write-Host "  Checking $($prereq.name)... " -NoNewline
            if (Test-Prerequisite $prereq) {
                Write-Host "[OK]" -ForegroundColor Green
            } else {
                Write-Host "[FAILED]" -ForegroundColor Red
                $allVerified = $false
                $failedPrereqs += $prereq
            }
        }
        
        if (-not $allVerified) {
            Write-Host "`n========================================" -ForegroundColor Red
            Write-Host "Some prerequisites failed to install properly" -ForegroundColor Red
            Write-Host "========================================" -ForegroundColor Red
            Write-Host "`nPlease install manually:" -ForegroundColor Yellow
            foreach ($prereq in $failedPrereqs) {
                Write-Host "  - $($prereq.name)" -ForegroundColor White
                Write-Host "    $($prereq.manualInstall)" -ForegroundColor Gray
            }
            exit 1
        }
        
        Write-Host "`n[OK] All prerequisites verified successfully!" -ForegroundColor Green
    }

    # Now install Python packages
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Installing Python packages..." -ForegroundColor Cyan
    Write-Host "----------------------------------------`n" -ForegroundColor Cyan

    # Refresh Python path after potential install
    Update-SessionEnvironment
    $pythonPath = Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $pythonPath) {
        Write-Host "[!] Python not found in PATH. Please restart your terminal." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "Using Python: $pythonPath" -ForegroundColor Green

    # Upgrade pip
    Write-Host "  Upgrading pip..." -ForegroundColor Gray
    & python -m pip install --upgrade pip 2>$null

    # Install requirements
    $requirementsFile = Join-Path $PSScriptRoot "requirements.txt"
    if (Test-Path $requirementsFile) {
        Write-Host "  Installing requirements from requirements.txt..." -ForegroundColor Gray
        & python -m pip install -r $requirementsFile
        if ($LASTEXITCODE -ne 0) {
            Write-Host "`n[!] Failed to install requirements" -ForegroundColor Red
            exit 1
        }
    }

    # Install PyInstaller
    Write-Host "  Installing PyInstaller..." -ForegroundColor Gray
    & python -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[!] Failed to install PyInstaller" -ForegroundColor Red
        exit 1
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "[OK] All prerequisites installed!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now build with: .\build.ps1" -ForegroundColor Cyan
}

# Handle Install parameter
if ($Install) {
    Install-Prerequisites
    exit 0
}

# Determine current platform if not specified
if (-not $Platform) {
    $arch = $env:PROCESSOR_ARCHITECTURE
    $Platform = switch ($arch) {
        'AMD64' { 'x64' }
        'ARM64' { 'ARM64' }
        default { 
            Write-Host "`n[!] Unsupported architecture: $arch. Please specify -Platform x64 or ARM64" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "Auto-detected platform: $Platform" -ForegroundColor Cyan
}

# Verify all prerequisites before building
Write-Host "`nChecking prerequisites..." -ForegroundColor Cyan
$missingPrereqs = @()

foreach ($prereq in $Prerequisites) {
    Write-Host "  Checking $($prereq.name)... " -NoNewline
    if (Test-Prerequisite $prereq) {
        Write-Host "[OK]" -ForegroundColor Green
    } else {
        Write-Host "[MISSING]" -ForegroundColor Red
        $missingPrereqs += $prereq
    }
}

if ($missingPrereqs.Count -gt 0) {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "Missing Prerequisites" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "`nThe following prerequisites are not installed:" -ForegroundColor Yellow
    foreach ($prereq in $missingPrereqs) {
        Write-Host "  - $($prereq.name)" -ForegroundColor White
    }
    Write-Host "`nTo install automatically, run:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1 -Install" -ForegroundColor Cyan
    Write-Host "`nOr install manually:" -ForegroundColor Yellow
    foreach ($prereq in $missingPrereqs) {
        Write-Host "  - $($prereq.name): $($prereq.manualInstall)" -ForegroundColor Gray
    }
    Write-Host ""
    exit 1
}

Write-Host "[OK] All prerequisites verified.`n" -ForegroundColor Green

# Find Python
$pythonPath = Get-Command python -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if (-not $pythonPath) {
    Write-Host "`n[!] Python not found. Run: .\build.ps1 -Install" -ForegroundColor Red
    exit 1
}

# Check PyInstaller
$pyinstallerCheck = python -c "import PyInstaller" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[!] PyInstaller not found. Run: .\build.ps1 -Install" -ForegroundColor Red
    exit 1
}

Write-Host "Using Python: $pythonPath" -ForegroundColor Green

# Output directories
$binDir = Join-Path $PSScriptRoot "bin\$Platform\$Configuration"
$objDir = Join-Path $PSScriptRoot "obj\$Platform\$Configuration"

# Ensure directories exist
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
New-Item -ItemType Directory -Path $objDir -Force | Out-Null

# Build function
function Build-Project {
    param(
        [string]$ProjectName,
        [string]$EntryPoint,
        [string]$OutputName,
        [string[]]$HiddenImports
    )

    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Building: $ProjectName" -ForegroundColor Cyan
    Write-Host "  Platform: $Platform" -ForegroundColor Gray
    Write-Host "  Configuration: $Configuration" -ForegroundColor Gray
    Write-Host "----------------------------------------`n" -ForegroundColor Cyan

    if ($Force) {
        # Clean project-specific build artifacts
        $projectObjDir = Join-Path $objDir $ProjectName
        if (Test-Path $projectObjDir) {
            Write-Host "  Cleaning $ProjectName build artifacts (Force mode)..." -ForegroundColor Yellow
            Remove-Item -Path $projectObjDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Build arguments for PyInstaller
    $pyinstallerArgs = @(
        '--onefile'
        '--name', $OutputName
        '--console'
        '--noupx'
        '--distpath', $binDir
        '--workpath', (Join-Path $objDir $ProjectName)
        '--specpath', (Join-Path $objDir $ProjectName)
        '--paths', $PSScriptRoot
    )

    # Add module paths
    $moduleDirs = @(
        'rdp_simple_plugin_client'
        'rdp_simple_plugin_server'
        'rdp_simple_plugin_protocol'
    )
    foreach ($moduleDir in $moduleDirs) {
        $modulePath = Join-Path $PSScriptRoot $moduleDir
        if (Test-Path $modulePath) {
            $pyinstallerArgs += '--paths', $modulePath
        }
    }

    # Add hidden imports
    foreach ($import in $HiddenImports) {
        $pyinstallerArgs += '--hidden-import', $import
    }

    # Add entry point
    $pyinstallerArgs += $EntryPoint

    Push-Location $PSScriptRoot
    try {
        & python -m PyInstaller @pyinstallerArgs

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed for $ProjectName"
            exit $LASTEXITCODE
        }

        Write-Host "[OK] $ProjectName built successfully" -ForegroundColor Green
        Write-Host "  Output: $binDir\$OutputName.exe" -ForegroundColor Gray
    }
    finally {
        Pop-Location
    }
}

# Project definitions
$clientHiddenImports = @(
    'rdp_simple_plugin_protocol'
    'rdp_simple_plugin_protocol.ping_message'
    'rdp_simple_plugin_protocol.ping_message_codec'
    'rdp_simple_plugin_client'
    'rdp_simple_plugin_client.simple_plugin'
    'rdp_simple_plugin_client.registry_helper'
    'win32more'
    'win32more._win32api'
    'win32more._comclass'
    'win32more.Windows.Win32.System.Com'
    'win32more.Windows.Win32.System.RemoteDesktop'
)

$serverHiddenImports = @(
    'rdp_simple_plugin_protocol'
    'rdp_simple_plugin_protocol.ping_message'
    'rdp_simple_plugin_protocol.ping_message_codec'
    'rdp_simple_plugin_server'
    'rdp_simple_plugin_server.simple_server'
    'rdp_simple_plugin_server.dvc_reassembler'
)

# Main build logic
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "RDP DVC Simple Python Build" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  Configuration: $Configuration" -ForegroundColor Gray
Write-Host "  Platform: $Platform" -ForegroundColor Gray
Write-Host "  Project: $Project" -ForegroundColor Gray
Write-Host "  Output: $binDir" -ForegroundColor Gray

$startTime = Get-Date

try {
    if ($Project -eq 'all') {
        # Build client
        Build-Project `
            -ProjectName "rdp-simple-plugin-client" `
            -EntryPoint "rdp_simple_plugin_client/__main__.py" `
            -OutputName "rdp-simple-plugin-client-python" `
            -HiddenImports $clientHiddenImports

        # Build server
        Build-Project `
            -ProjectName "rdp-simple-plugin-server" `
            -EntryPoint "rdp_simple_plugin_server/__main__.py" `
            -OutputName "rdp-simple-plugin-server-python" `
            -HiddenImports $serverHiddenImports
    }
    elseif ($Project -eq 'client') {
        Build-Project `
            -ProjectName "rdp-simple-plugin-client" `
            -EntryPoint "rdp_simple_plugin_client/__main__.py" `
            -OutputName "rdp-simple-plugin-client-python" `
            -HiddenImports $clientHiddenImports
    }
    elseif ($Project -eq 'server') {
        Build-Project `
            -ProjectName "rdp-simple-plugin-server" `
            -EntryPoint "rdp_simple_plugin_server/__main__.py" `
            -OutputName "rdp-simple-plugin-server-python" `
            -HiddenImports $serverHiddenImports
    }
    elseif ($Project -eq 'protocol') {
        Write-Host "`nProtocol is a pure Python library - no executable to build." -ForegroundColor Cyan
        Write-Host "Protocol module: rdp_simple_plugin_protocol/" -ForegroundColor Gray
    }

    $elapsed = (Get-Date) - $startTime
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "[OK] Build completed successfully" -ForegroundColor Green
    Write-Host "Time elapsed: $($elapsed.ToString('mm\:ss'))" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    # Deployment instructions
    Write-Host "`nDEPLOYMENT INSTRUCTIONS:" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    
    Write-Host "`n[CLIENT] Register on local machine:" -ForegroundColor Yellow
    $clientExe = "$binDir\\rdp-simple-plugin-client-python.exe"
    if (Test-Path $clientExe) {
        Write-Host "  $clientExe /register" -ForegroundColor White
        Write-Host "  (Per-user registration, no admin required)" -ForegroundColor Gray
        Write-Host "`n  For machine-wide registration (requires admin):" -ForegroundColor Gray
        Write-Host "  $clientExe /register /machine" -ForegroundColor Gray
        Write-Host "`n  To unregister:" -ForegroundColor Gray
        Write-Host "  $clientExe /unregister" -ForegroundColor Gray
    }
    
    Write-Host "`n[SERVER] Copy to RDP server machine:" -ForegroundColor Yellow
    $serverExe = "$binDir\\rdp-simple-plugin-server-python.exe"
    if (Test-Path $serverExe) {
        Write-Host "  $serverExe" -ForegroundColor White
        Write-Host "  (Run inside RDP session)" -ForegroundColor Gray
    }
}
catch {
    Write-Error "Build failed: $_"
    exit 1
}
