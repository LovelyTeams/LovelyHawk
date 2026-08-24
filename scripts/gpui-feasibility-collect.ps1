#requires -Version 7.2

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$ScenarioId,
    [Parameter(Mandatory = $true)]
    [ValidateSet('Windows10-22H2', 'Windows11')]
    [string]$ExpectedOperatingSystem,
    [Parameter(Mandatory = $true)]
    [ValidateSet(100, 150, 200)]
    [int]$ExpectedDpiPercent,
    [switch]$RequireMixedDpi,
    [switch]$RequireRdp,
    [switch]$RequireVm,
    [switch]$RequireIntegratedGpu,
    [switch]$RequireOffline,
    [ValidateRange(1, 536870912)]
    [uint64]$TerminalStressBytes = 16777216,
    [ValidateRange(0.01, 1000000.0)]
    [double]$MinimumTerminalMiBPerSecond = 10.0,
    [ValidateRange(5, 1800)]
    [int]$StartupTimeoutSeconds = 120,
    [ValidateRange(1, 60)]
    [int]$PostReadyStabilitySeconds = 3,
    [string]$ManualEvidencePath,
    [switch]$InteractiveManual,
    [switch]$Headless,
    [switch]$ReportOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$automaticIds = @(
    'root_window',
    'portable_store',
    'page_registry',
    'theme_registry',
    'embedded_assets',
    'font_assets',
    'terminal_no_loss'
)
$manualIds = @(
    'd3d11_gpu_driver',
    'custom_titlebar',
    'native_multi_window',
    'chinese_ime',
    'clipboard',
    'file_dialog',
    'folder_dialog',
    'theme_switch',
    'virtual_large_table',
    'mixed_dpi',
    'rdp',
    'virtual_machine',
    'integrated_gpu',
    'offline_startup'
)
$commonManualIds = @(
    'd3d11_gpu_driver',
    'custom_titlebar',
    'native_multi_window',
    'chinese_ime',
    'clipboard',
    'file_dialog',
    'folder_dialog',
    'theme_switch',
    'virtual_large_table'
)

function Test-HasProperty {
    param($Object, [string]$Name)
    return $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

function New-CollectedCheck {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'NOT_RUN')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][bool]$Required
    )
    if ([string]::IsNullOrWhiteSpace($Evidence)) {
        $Evidence = 'No evidence was recorded.'
    }
    return [pscustomobject][ordered]@{
        id = $Id
        category = $Category
        status = $Status
        evidence = $Evidence
        source = $Source
        required_for_scenario = $Required
    }
}

function Set-CollectedCheck {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Map,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'NOT_RUN')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Evidence,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][bool]$Required
    )
    $Map[$Id] = New-CollectedCheck -Id $Id -Category $Category -Status $Status -Evidence $Evidence -Source $Source -Required $Required
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            return 'not-pe'
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            return 'invalid-pe-offset'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            return 'invalid-pe-signature'
        }
        switch ($reader.ReadUInt16()) {
            0x8664 { return 'x86_64' }
            0x014C { return 'x86' }
            0xAA64 { return 'arm64' }
            default { return 'unknown' }
        }
    } finally {
        $stream.Dispose()
    }
}

function Initialize-DisplayProbe {
    if ('LovelyRes.Feasibility.DisplayProbe' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace LovelyRes.Feasibility {
    public sealed class DisplayInfo {
        public string DeviceName { get; set; }
        public bool Primary { get; set; }
        public int Left { get; set; }
        public int Top { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int? DpiPercent { get; set; }
    }

    public static class DisplayProbe {
        private delegate bool MonitorEnumProc(IntPtr monitor, IntPtr hdc, IntPtr rect, IntPtr data);

        [StructLayout(LayoutKind.Sequential)]
        private struct Rect {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct MonitorInfoEx {
            public int Size;
            public Rect Monitor;
            public Rect Work;
            public uint Flags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string DeviceName;
        }

        [DllImport("user32.dll")]
        private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MonitorEnumProc callback, IntPtr data);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfoEx info);

        [DllImport("shcore.dll")]
        private static extern int GetDpiForMonitor(IntPtr monitor, int dpiType, out uint dpiX, out uint dpiY);

        public static DisplayInfo[] GetDisplays() {
            var displays = new List<DisplayInfo>();
            MonitorEnumProc callback = delegate(IntPtr monitor, IntPtr hdc, IntPtr rect, IntPtr data) {
                var info = new MonitorInfoEx();
                info.Size = Marshal.SizeOf(typeof(MonitorInfoEx));
                if (!GetMonitorInfo(monitor, ref info)) {
                    return true;
                }
                int? dpiPercent = null;
                try {
                    uint dpiX;
                    uint dpiY;
                    if (GetDpiForMonitor(monitor, 0, out dpiX, out dpiY) == 0 && dpiX > 0) {
                        dpiPercent = (int)Math.Round(dpiX * 100.0 / 96.0, MidpointRounding.AwayFromZero);
                    }
                } catch (DllNotFoundException) {
                } catch (EntryPointNotFoundException) {
                }
                displays.Add(new DisplayInfo {
                    DeviceName = info.DeviceName ?? String.Empty,
                    Primary = (info.Flags & 1U) != 0,
                    Left = info.Monitor.Left,
                    Top = info.Monitor.Top,
                    Width = info.Monitor.Right - info.Monitor.Left,
                    Height = info.Monitor.Bottom - info.Monitor.Top,
                    DpiPercent = dpiPercent
                });
                return true;
            };
            if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, callback, IntPtr.Zero)) {
                throw new InvalidOperationException("EnumDisplayMonitors failed");
            }
            GC.KeepAlive(callback);
            return displays.ToArray();
        }
    }
}
'@
}

function Get-GpuClassification {
    param([AllowNull()][string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'unknown' }
    if ($Name -match '(?i)(Microsoft Basic|Remote Display|VMware|VirtualBox|Hyper-V|Parallels|QXL|VirtIO)') { return 'virtual' }
    if ($Name -match '(?i)Intel.*(HD|UHD|Iris)' -or $Name -match '(?i)AMD.*(Vega|Radeon\s+Graphics)') { return 'integrated' }
    if ($Name -match '(?i)(NVIDIA|GeForce|Quadro|Radeon\s+(RX|Pro|VII))') { return 'discrete' }
    return 'unknown'
}

function Test-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = 1200
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    $connected = $false
    $errorText = $null
    try {
        $task = $client.ConnectAsync($HostName, $Port)
        if (-not $task.Wait($TimeoutMilliseconds)) {
            $errorText = "timeout after $TimeoutMilliseconds ms"
        } elseif ($client.Connected) {
            $connected = $true
        } else {
            $errorText = 'connection did not become established'
        }
    } catch {
        $errorText = $_.Exception.GetBaseException().Message
    } finally {
        $client.Dispose()
    }
    return [pscustomobject][ordered]@{
        endpoint = "${HostName}:$Port"
        connected = $connected
        error = $errorText
    }
}

function Get-EnvironmentSnapshot {
    $collectionErrors = [System.Collections.Generic.List[string]]::new()
    $caption = $null
    $version = $null
    $buildNumber = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        $version = [string]$os.Version
        $buildNumber = [int]$os.BuildNumber
    } catch {
        $collectionErrors.Add("Win32_OperatingSystem: $($_.Exception.Message)")
    }

    $displayVersion = $null
    try {
        $displayVersionValue = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion -ErrorAction Stop).DisplayVersion
        if ($null -ne $displayVersionValue) { $displayVersion = [string]$displayVersionValue }
    } catch {
        $collectionErrors.Add("Windows DisplayVersion: $($_.Exception.Message)")
    }

    $manufacturer = $null
    $model = $null
    $isVirtualMachine = $null
    $computerEvidence = ''
    try {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $manufacturer = [string]$computer.Manufacturer
        $model = [string]$computer.Model
        $computerEvidence = "$manufacturer / $model"
        $vmText = "$manufacturer $model"
        $isVirtualMachine = [bool]($vmText -match '(?i)(Microsoft Corporation.*Virtual|VMware|VirtualBox|KVM|QEMU|Xen|Parallels|HVM domU|Bochs|OpenStack|Google Compute Engine|Amazon EC2)')
    } catch {
        $computerEvidence = "collection failed: $($_.Exception.Message)"
        $collectionErrors.Add("Win32_ComputerSystem: $($_.Exception.Message)")
    }

    $displays = @()
    try {
        Initialize-DisplayProbe
        $displays = @([LovelyRes.Feasibility.DisplayProbe]::GetDisplays() | ForEach-Object {
            [pscustomobject][ordered]@{
                device_name = [string]$_.DeviceName
                primary = [bool]$_.Primary
                left = [int]$_.Left
                top = [int]$_.Top
                width = [int]$_.Width
                height = [int]$_.Height
                dpi_percent = if ($null -eq $_.DpiPercent) { $null } else { [int]$_.DpiPercent }
            }
        })
    } catch {
        $collectionErrors.Add("display probe: $($_.Exception.Message)")
    }

    $gpus = @()
    try {
        $gpus = @(Get-CimInstance -ClassName Win32_VideoController -ErrorAction Stop | ForEach-Object {
            $name = if ($null -eq $_.Name) { $null } else { [string]$_.Name }
            [pscustomobject][ordered]@{
                name = $name
                driver_version = if ($null -eq $_.DriverVersion) { $null } else { [string]$_.DriverVersion }
                adapter_compatibility = if ($null -eq $_.AdapterCompatibility) { $null } else { [string]$_.AdapterCompatibility }
                pnp_device_id = if ($null -eq $_.PNPDeviceID) { $null } else { [string]$_.PNPDeviceID }
                classification = Get-GpuClassification -Name $name
            }
        })
    } catch {
        $collectionErrors.Add("Win32_VideoController: $($_.Exception.Message)")
    }

    $probes = @(
        Test-TcpEndpoint -HostName '1.1.1.1' -Port 443
        Test-TcpEndpoint -HostName '8.8.8.8' -Port 53
    )
    $isOffline = @($probes | Where-Object { $_.connected }).Count -eq 0
    $sessionName = [Environment]::GetEnvironmentVariable('SESSIONNAME', 'Process')
    $clientName = [Environment]::GetEnvironmentVariable('CLIENTNAME', 'Process')
    $isRdp = (-not [string]::IsNullOrWhiteSpace($sessionName) -and $sessionName.StartsWith('RDP-', [System.StringComparison]::OrdinalIgnoreCase)) -or
        (-not [string]::IsNullOrWhiteSpace($clientName) -and $clientName -ne 'Console')

    return [pscustomobject][ordered]@{
        collected_at_utc = [DateTime]::UtcNow.ToString('o')
        os = [pscustomobject][ordered]@{
            caption = $caption
            version = $version
            build_number = $buildNumber
            display_version = $displayVersion
        }
        powershell = [pscustomobject][ordered]@{
            version = $PSVersionTable.PSVersion.ToString()
            architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        }
        session = [pscustomobject][ordered]@{
            name = $sessionName
            client_name = $clientName
            is_rdp = [bool]$isRdp
        }
        computer = [pscustomobject][ordered]@{
            manufacturer = $manufacturer
            model = $model
            is_virtual_machine = $isVirtualMachine
            evidence = $computerEvidence
        }
        displays = @($displays)
        gpus = @($gpus)
        network = [pscustomobject][ordered]@{
            is_offline = [bool]$isOffline
            probes = @($probes)
        }
        collection_errors = @($collectionErrors)
    }
}

function Test-ExpectedEnvironment {
    param(
        [Parameter(Mandatory = $true)]$Environment,
        [Parameter(Mandatory = $true)][string]$PeMachine
    )
    $failures = [System.Collections.Generic.List[string]]::new()
    $unknowns = [System.Collections.Generic.List[string]]::new()

    if ($PeMachine -ne 'x86_64') {
        $failures.Add("binary PE machine is '$PeMachine', expected x86_64")
    }
    if ($null -eq $Environment.os.build_number -or [string]::IsNullOrWhiteSpace([string]$Environment.os.caption)) {
        $unknowns.Add('Windows version/build could not be collected')
    } elseif ($ExpectedOperatingSystem -eq 'Windows10-22H2') {
        if ([int]$Environment.os.build_number -ne 19045 -or [string]$Environment.os.display_version -ne '22H2' -or [string]$Environment.os.caption -notmatch 'Windows 10') {
            $failures.Add("observed '$($Environment.os.caption)' build $($Environment.os.build_number) DisplayVersion $($Environment.os.display_version), expected Windows 10 22H2 build 19045")
        }
    } elseif ([int]$Environment.os.build_number -lt 22000 -or [string]$Environment.os.caption -notmatch 'Windows 11') {
        $failures.Add("observed '$($Environment.os.caption)' build $($Environment.os.build_number), expected Windows 11 build >= 22000")
    }

    $primaryDisplay = @($Environment.displays | Where-Object { $_.primary }) | Select-Object -First 1
    if ($null -eq $primaryDisplay) {
        $primaryDisplay = @($Environment.displays) | Select-Object -First 1
    }
    if ($null -eq $primaryDisplay -or $null -eq $primaryDisplay.dpi_percent) {
        $unknowns.Add('primary display DPI could not be collected')
    } elseif ([int]$primaryDisplay.dpi_percent -ne $ExpectedDpiPercent) {
        $failures.Add("primary display is $($primaryDisplay.dpi_percent)%, expected $ExpectedDpiPercent%")
    }

    if ($RequireMixedDpi) {
        $distinctDpi = @($Environment.displays | Where-Object { $null -ne $_.dpi_percent } | ForEach-Object { [int]$_.dpi_percent } | Sort-Object -Unique)
        if ($distinctDpi.Count -lt 2) { $failures.Add('mixed DPI was required but fewer than two distinct display DPI values were observed') }
    }
    if ($RequireRdp -and -not [bool]$Environment.session.is_rdp) {
        $failures.Add('RDP was required but the current session is not identified as RDP')
    }
    if ($RequireVm) {
        if ($null -eq $Environment.computer.is_virtual_machine) {
            $unknowns.Add('virtual-machine state could not be collected')
        } elseif (-not [bool]$Environment.computer.is_virtual_machine) {
            $failures.Add('a virtual machine was required but hardware identity did not match the conservative VM detector')
        }
    }
    if ($RequireIntegratedGpu -and @($Environment.gpus | Where-Object { $_.classification -eq 'integrated' }).Count -eq 0) {
        $failures.Add('an integrated GPU was required but none was conservatively classified as integrated')
    }
    if ($RequireOffline -and -not [bool]$Environment.network.is_offline) {
        $failures.Add('offline mode was required but at least one read-only TCP probe connected')
    }

    $facts = "OS='$($Environment.os.caption)' build=$($Environment.os.build_number) displayVersion=$($Environment.os.display_version); primaryDpi=$(if ($null -eq $primaryDisplay) { 'unknown' } else { $primaryDisplay.dpi_percent }); displays=$(@($Environment.displays).Count); rdp=$($Environment.session.is_rdp); vm=$($Environment.computer.is_virtual_machine); integratedGpu=$(@($Environment.gpus | Where-Object { $_.classification -eq 'integrated' }).Count -gt 0); offline=$($Environment.network.is_offline); pe=$PeMachine"
    if ($failures.Count -gt 0) {
        return [pscustomobject]@{ Status = 'FAIL'; Evidence = "$facts. Failures: $($failures -join '; ')." }
    }
    if ($unknowns.Count -gt 0) {
        return [pscustomobject]@{ Status = 'NOT_RUN'; Evidence = "$facts. Unknown: $($unknowns -join '; ')." }
    }
    return [pscustomobject]@{ Status = 'PASS'; Evidence = $facts }
}

function Convert-AppCheckMap {
    param(
        $Items,
        [string[]]$ExpectedIds,
        [string]$Label,
        [System.Collections.Generic.List[string]]$Errors
    )
    $map = [ordered]@{}
    foreach ($item in @($Items)) {
        if (-not (Test-HasProperty -Object $item -Name 'id') -or -not (Test-HasProperty -Object $item -Name 'status') -or -not (Test-HasProperty -Object $item -Name 'evidence')) {
            $Errors.Add("$Label contains an item without id/status/evidence")
            continue
        }
        $id = [string]$item.id
        if ($id -notin $ExpectedIds) {
            $Errors.Add("$Label contains unexpected id '$id'")
            continue
        }
        if ($map.Contains($id)) {
            $Errors.Add("$Label contains duplicate id '$id'")
            continue
        }
        if ([string]$item.status -notin @('PASS', 'FAIL', 'NOT_RUN')) {
            $Errors.Add("$Label '$id' has invalid status '$($item.status)'")
        }
        if ([string]::IsNullOrWhiteSpace([string]$item.evidence)) {
            $Errors.Add("$Label '$id' has empty evidence")
        }
        $map[$id] = $item
    }
    foreach ($id in $ExpectedIds) {
        if (-not $map.Contains($id)) { $Errors.Add("$Label is missing '$id'") }
    }
    return $map
}

function Test-AppDiagnostics {
    param(
        [Parameter(Mandatory = $true)]$Raw,
        [Parameter(Mandatory = $true)][string]$ExpectedDataRoot
    )
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($property in @('schema', 'status', 'generated_unix_ms', 'app_version', 'gpui_version', 'operating_system', 'architecture', 'portable_data_root', 'automatic_checks', 'terminal_stress', 'manual_checks')) {
        if (-not (Test-HasProperty -Object $Raw -Name $property)) { $errors.Add("missing top-level property '$property'") }
    }
    if ($errors.Count -gt 0) {
        return [pscustomobject]@{ Errors = @($errors); Automatic = [ordered]@{}; Manual = [ordered]@{} }
    }
    if ([string]$Raw.schema -ne 'lovelyres-gpui-feasibility/v1') { $errors.Add("schema is '$($Raw.schema)'") }
    if ([string]$Raw.status -ne 'READY') { $errors.Add("app status is '$($Raw.status)'") }
    if ([string]$Raw.gpui_version -ne '0.2.2') { $errors.Add("GPUI version is '$($Raw.gpui_version)', expected 0.2.2") }
    if ([string]$Raw.operating_system -ne 'windows') { $errors.Add("operating_system is '$($Raw.operating_system)', expected windows") }
    if ([string]$Raw.architecture -ne 'x86_64') { $errors.Add("architecture is '$($Raw.architecture)', expected x86_64") }
    try {
        $actualRoot = [System.IO.Path]::GetFullPath([string]$Raw.portable_data_root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        $wantedRoot = [System.IO.Path]::GetFullPath($ExpectedDataRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
        if (-not $actualRoot.Equals($wantedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            $errors.Add("portable_data_root is '$actualRoot', expected '$wantedRoot'")
        }
    } catch {
        $errors.Add("portable_data_root is invalid: $($_.Exception.Message)")
    }

    $automatic = Convert-AppCheckMap -Items $Raw.automatic_checks -ExpectedIds $automaticIds -Label 'automatic_checks' -Errors $errors
    $manual = Convert-AppCheckMap -Items $Raw.manual_checks -ExpectedIds $manualIds -Label 'manual_checks' -Errors $errors
    foreach ($id in $manualIds) {
        if ($manual.Contains($id) -and [string]$manual[$id].status -ne 'NOT_RUN') {
            $errors.Add("manual_checks '$id' must be NOT_RUN in app diagnostics; only operator evidence may set a manual result")
        }
    }
    $stressErrors = [System.Collections.Generic.List[string]]::new()
    foreach ($property in @('requested_bytes', 'processed_bytes', 'elapsed_ms', 'throughput_mib_per_second', 'no_loss')) {
        if (-not (Test-HasProperty -Object $Raw.terminal_stress -Name $property)) { $stressErrors.Add("terminal_stress missing '$property'") }
    }
    if ($stressErrors.Count -eq 0) {
        if ([uint64]$Raw.terminal_stress.requested_bytes -ne $TerminalStressBytes) { $stressErrors.Add("requested_bytes=$($Raw.terminal_stress.requested_bytes), expected $TerminalStressBytes") }
        if ([uint64]$Raw.terminal_stress.processed_bytes -ne [uint64]$Raw.terminal_stress.requested_bytes) { $stressErrors.Add('processed_bytes does not equal requested_bytes') }
        if ([uint64]$Raw.terminal_stress.elapsed_ms -lt 1) { $stressErrors.Add('elapsed_ms must be at least 1') }
        if (-not [bool]$Raw.terminal_stress.no_loss) { $stressErrors.Add('no_loss is false') }
        if ([double]$Raw.terminal_stress.throughput_mib_per_second -lt $MinimumTerminalMiBPerSecond) { $stressErrors.Add("throughput is $($Raw.terminal_stress.throughput_mib_per_second) MiB/s, required >= $MinimumTerminalMiBPerSecond MiB/s") }
    }
    foreach ($stressError in $stressErrors) { $errors.Add($stressError) }
    if ($automatic.Contains('terminal_no_loss') -and $stressErrors.Count -gt 0) {
        $automatic['terminal_no_loss'] = [pscustomobject][ordered]@{
            id = 'terminal_no_loss'
            status = 'FAIL'
            evidence = "Harness metric validation failed: $($stressErrors -join '; ')."
        }
    }
    return [pscustomobject]@{ Errors = @($errors); Automatic = $automatic; Manual = $manual }
}

function Read-ManualEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedScenarioId,
        [Parameter(Mandatory = $true)][string]$ExpectedBinarySha256
    )
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    try {
        $json = Get-Content -LiteralPath $resolved -Raw
        $schemaPath = Join-Path $PSScriptRoot 'gpui-feasibility-manual.schema.json'
        if (-not ($json | Test-Json -SchemaFile $schemaPath -ErrorAction Stop)) {
            throw 'JSON does not match gpui-feasibility-manual.schema.json'
        }
        $raw = $json | ConvertFrom-Json -Depth 30
    } catch {
        throw "Cannot parse manual evidence '$resolved': $($_.Exception.Message)"
    }
    foreach ($property in @('schema', 'scenario_id', 'binary_sha256', 'operator', 'recorded_at_utc', 'checks')) {
        if (-not (Test-HasProperty -Object $raw -Name $property)) { throw "Manual evidence '$resolved' is missing '$property'." }
    }
    if ([string]$raw.schema -ne 'lovelyres-feasibility-manual/v1') { throw "Manual evidence '$resolved' has unsupported schema '$($raw.schema)'." }
    if ([string]$raw.scenario_id -ne $ExpectedScenarioId) { throw "Manual evidence scenario '$($raw.scenario_id)' does not match '$ExpectedScenarioId'." }
    if (-not ([string]$raw.binary_sha256).Equals($ExpectedBinarySha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Manual evidence binary SHA-256 '$($raw.binary_sha256)' does not match '$ExpectedBinarySha256'."
    }
    if ([string]::IsNullOrWhiteSpace([string]$raw.operator)) { throw "Manual evidence '$resolved' has an empty operator." }
    $recorded = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$raw.recorded_at_utc, [ref]$recorded)) { throw "Manual evidence '$resolved' has an invalid recorded_at_utc." }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($check in @($raw.checks)) {
        foreach ($property in @('id', 'status', 'evidence')) {
            if (-not (Test-HasProperty -Object $check -Name $property)) { throw "Manual evidence '$resolved' has a check missing '$property'." }
        }
        $id = [string]$check.id
        if ($id -notin $manualIds) { throw "Manual evidence '$resolved' contains unexpected check '$id'." }
        if (-not $seen.Add($id)) { throw "Manual evidence '$resolved' contains duplicate check '$id'." }
        if ([string]$check.status -notin @('PASS', 'FAIL', 'NOT_RUN')) { throw "Manual evidence '$resolved' check '$id' has invalid status '$($check.status)'." }
        if ([string]::IsNullOrWhiteSpace([string]$check.evidence)) { throw "Manual evidence '$resolved' check '$id' has empty evidence." }
        $checks.Add([pscustomobject][ordered]@{ id = $id; status = [string]$check.status; evidence = [string]$check.evidence })
    }
    return [pscustomobject][ordered]@{
        schema = 'lovelyres-feasibility-manual/v1'
        scenario_id = $ExpectedScenarioId
        binary_sha256 = $ExpectedBinarySha256.ToUpperInvariant()
        operator = [string]$raw.operator
        recorded_at_utc = $recorded.ToUniversalTime().ToString('o')
        checks = @($checks)
    }
}

function Read-InteractiveManualEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedScenarioId,
        [Parameter(Mandatory = $true)][string]$ExpectedBinarySha256,
        [Parameter(Mandatory = $true)][string[]]$RequiredIds
    )
    Write-Host ''
    Write-Host 'The GPUI diagnostic process is ready. Leave it open while completing each requested interaction.'
    Write-Host 'Enter PASS only after observing the behavior. Use FAIL for a defect and NOT_RUN when this machine/session cannot cover it.'
    $operator = Read-Host 'Operator name or lab identifier'
    while ([string]::IsNullOrWhiteSpace($operator)) { $operator = Read-Host 'Operator cannot be empty; enter operator name or lab identifier' }
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $RequiredIds) {
        $status = $null
        while ($status -notin @('PASS', 'FAIL', 'NOT_RUN')) {
            $choice = (Read-Host "$id [P]ASS / [F]AIL / [N]OT_RUN").Trim().ToUpperInvariant()
            $status = switch ($choice) { 'P' { 'PASS' } 'PASS' { 'PASS' } 'F' { 'FAIL' } 'FAIL' { 'FAIL' } 'N' { 'NOT_RUN' } 'NOT_RUN' { 'NOT_RUN' } default { $null } }
        }
        $evidence = Read-Host "$id evidence (observation, screenshot/hash path, or NOT_RUN reason)"
        while ([string]::IsNullOrWhiteSpace($evidence)) { $evidence = Read-Host "$id evidence cannot be empty" }
        $checks.Add([pscustomobject][ordered]@{ id = $id; status = $status; evidence = $evidence })
    }
    return [pscustomobject][ordered]@{
        schema = 'lovelyres-feasibility-manual/v1'
        scenario_id = $ExpectedScenarioId
        binary_sha256 = $ExpectedBinarySha256.ToUpperInvariant()
        operator = $operator
        recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        checks = @($checks)
    }
}

function Write-AtomicJson {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $parent = Split-Path -Parent $Path
    $temporary = Join-Path $parent ('.' + [System.IO.Path]::GetFileName($Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($temporary, (($Value | ConvertTo-Json -Depth 100) + "`n"), $utf8NoBom)
        [System.IO.File]::Move($temporary, $Path, $false)
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Get-TreeSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)
    $snapshot = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not (Test-Path -LiteralPath $Root)) { return $snapshot }
    foreach ($entry in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        $relative = [System.IO.Path]::GetRelativePath($Root, $entry.FullName)
        if ($entry.PSIsContainer) {
            $snapshot[$relative] = 'directory'
            continue
        }
        try {
            $hash = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
            $snapshot[$relative] = "file:$($entry.Length):$hash"
        } catch {
            $snapshot[$relative] = "unreadable:$($entry.Length):$($entry.LastWriteTimeUtc.Ticks)"
        }
    }
    return $snapshot
}

function Get-TreeViolations {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string, string]]$Before,
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string, string]]$After,
        [Parameter(Mandatory = $true)][string]$Label,
        [switch]$AllowDataSubtree
    )
    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $After.GetEnumerator()) {
        $relative = $entry.Key
        $inData = $AllowDataSubtree -and ($relative -eq 'data' -or $relative.StartsWith("data$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase))
        if ($inData) { continue }
        if (-not $Before.ContainsKey($relative)) {
            $violations.Add("${Label}:created:$relative")
        } elseif ($Before[$relative] -ne $entry.Value) {
            $violations.Add("${Label}:modified:$relative")
        }
    }
    foreach ($entry in $Before.GetEnumerator()) {
        $relative = $entry.Key
        $inData = $AllowDataSubtree -and ($relative -eq 'data' -or $relative.StartsWith("data$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase))
        if (-not $inData -and -not $After.ContainsKey($relative)) {
            $violations.Add("${Label}:deleted:$relative")
        }
    }
    return $violations
}

if (-not $IsWindows) { throw 'gpui-feasibility-collect.ps1 must run on Windows.' }
if ($InteractiveManual -and -not [string]::IsNullOrWhiteSpace($ManualEvidencePath)) { throw '-InteractiveManual and -ManualEvidencePath are mutually exclusive.' }
if ($Headless -and $InteractiveManual) { throw '-Headless cannot be combined with -InteractiveManual.' }

$sourceBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) { throw "BinaryPath '$BinaryPath' is not a file." }
$output = [System.IO.Path]::GetFullPath($OutputPath)
if ([System.IO.Path]::GetExtension($output) -ne '.json') { throw 'OutputPath must end in .json.' }
$outputParent = Split-Path -Parent $output
if ([string]::IsNullOrWhiteSpace($outputParent)) { throw 'OutputPath must include a parent directory.' }
[System.IO.Directory]::CreateDirectory($outputParent) | Out-Null
if (Test-Path -LiteralPath $output) { throw "Output '$output' already exists; evidence is append-only." }

$stem = [System.IO.Path]::GetFileNameWithoutExtension($output)
$runDirectory = Join-Path $outputParent "$stem-run"
$appResultPath = Join-Path $outputParent "$stem.app-result.json"
$smokeMarkerPath = Join-Path $outputParent "$stem.smoke-ready.json"
$stdoutLogPath = Join-Path $outputParent "$stem.stdout.log"
$stderrLogPath = Join-Path $outputParent "$stem.stderr.log"
$profileDirectory = Join-Path $outputParent "$stem-profile"
foreach ($path in @($runDirectory, $profileDirectory, $appResultPath, $smokeMarkerPath, $stdoutLogPath, $stderrLogPath)) {
    if (Test-Path -LiteralPath $path) { throw "Harness artifact '$path' already exists; choose a new OutputPath." }
}
[System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
$launchBinary = Join-Path $runDirectory 'LovelyRes.exe'
Copy-Item -LiteralPath $sourceBinary -Destination $launchBinary
[System.IO.Directory]::CreateDirectory((Join-Path $profileDirectory 'Roaming')) | Out-Null
[System.IO.Directory]::CreateDirectory((Join-Path $profileDirectory 'Local')) | Out-Null
$runDirectoryBefore = Get-TreeSnapshot -Root $runDirectory
$previousAppData = [Environment]::GetEnvironmentVariable('APPDATA', 'Process')
$previousLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
$externalRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
[void]$externalRoots.Add($profileDirectory)
foreach ($base in @($previousAppData, $previousLocalAppData)) {
    if ([string]::IsNullOrWhiteSpace($base)) { continue }
    foreach ($name in @('LovelyRes', 'lovelyres', 'com.lovelyres.app')) {
        [void]$externalRoots.Add((Join-Path $base $name))
    }
}
$externalBefore = [ordered]@{}
foreach ($root in $externalRoots) { $externalBefore[$root] = Get-TreeSnapshot -Root $root }

$sourceInfo = Get-Item -LiteralPath $sourceBinary
$fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($sourceBinary).FileVersion
if ([string]::IsNullOrWhiteSpace($fileVersion)) { $fileVersion = $null }
$peMachine = Get-PeMachine -Path $sourceBinary
$build = [pscustomobject][ordered]@{
    source_path = $sourceBinary
    launch_path = $launchBinary
    sha256 = (Get-FileHash -LiteralPath $sourceBinary -Algorithm SHA256).Hash.ToUpperInvariant()
    size_bytes = [int64]$sourceInfo.Length
    file_version = $fileVersion
    pe_machine = $peMachine
}

$manualEvidence = $null
if (-not [string]::IsNullOrWhiteSpace($ManualEvidencePath)) {
    $manualEvidence = Read-ManualEvidence -Path $ManualEvidencePath -ExpectedScenarioId $ScenarioId -ExpectedBinarySha256 $build.sha256
}

$environment = Get-EnvironmentSnapshot
$checkMap = [ordered]@{}
Set-CollectedCheck -Map $checkMap -Id 'smoke_marker' -Category 'harness' -Status 'NOT_RUN' -Evidence 'Application has not been launched.' -Source 'harness' -Required $true
Set-CollectedCheck -Map $checkMap -Id 'process_alive' -Category 'harness' -Status 'NOT_RUN' -Evidence 'Application has not been launched.' -Source 'harness' -Required $true
Set-CollectedCheck -Map $checkMap -Id 'portable_persistence' -Category 'harness' -Status 'NOT_RUN' -Evidence 'Application has not been stopped and inspected.' -Source 'harness' -Required $true
Set-CollectedCheck -Map $checkMap -Id 'app_result' -Category 'harness' -Status 'NOT_RUN' -Evidence 'Application result has not been read.' -Source 'harness' -Required $true
$environmentMatch = Test-ExpectedEnvironment -Environment $environment -PeMachine $peMachine
Set-CollectedCheck -Map $checkMap -Id 'environment_match' -Category 'environment' -Status $environmentMatch.Status -Evidence $environmentMatch.Evidence -Source 'read-only Windows probes' -Required $true
foreach ($id in $automaticIds) {
    Set-CollectedCheck -Map $checkMap -Id $id -Category 'app-automatic' -Status 'NOT_RUN' -Evidence 'Application diagnostics were not available.' -Source 'app-result' -Required $true
}

$requiredManualIds = [System.Collections.Generic.List[string]]::new()
foreach ($id in $commonManualIds) { $requiredManualIds.Add($id) }
if ($RequireMixedDpi) { $requiredManualIds.Add('mixed_dpi') }
if ($RequireRdp) { $requiredManualIds.Add('rdp') }
if ($RequireVm) { $requiredManualIds.Add('virtual_machine') }
if ($RequireIntegratedGpu) { $requiredManualIds.Add('integrated_gpu') }
if ($RequireOffline) { $requiredManualIds.Add('offline_startup') }
foreach ($id in $manualIds) {
    Set-CollectedCheck -Map $checkMap -Id $id -Category 'manual' -Status 'NOT_RUN' -Evidence 'No operator evidence was supplied for this check.' -Source 'app-default' -Required ($requiredManualIds.Contains($id))
}

$appDiagnostics = $null
$process = $null
$readyFilesObserved = $false
$launchError = $null
$environmentNames = @('LOVELYRES_FEASIBILITY_MODE', 'LOVELYRES_FEASIBILITY_RESULT_FILE', 'LOVELYRES_TERMINAL_STRESS_BYTES', 'LOVELYRES_SMOKE_READY_FILE', 'APPDATA', 'LOCALAPPDATA')
$savedEnvironment = [ordered]@{}
foreach ($name in $environmentNames) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    [Environment]::SetEnvironmentVariable('LOVELYRES_FEASIBILITY_MODE', 'windows-v1', 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_FEASIBILITY_RESULT_FILE', $appResultPath, 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_TERMINAL_STRESS_BYTES', $TerminalStressBytes.ToString([System.Globalization.CultureInfo]::InvariantCulture), 'Process')
    [Environment]::SetEnvironmentVariable('LOVELYRES_SMOKE_READY_FILE', $smokeMarkerPath, 'Process')
    [Environment]::SetEnvironmentVariable('APPDATA', (Join-Path $profileDirectory 'Roaming'), 'Process')
    [Environment]::SetEnvironmentVariable('LOCALAPPDATA', (Join-Path $profileDirectory 'Local'), 'Process')
    $startParameters = @{
        FilePath = $launchBinary
        WorkingDirectory = $runDirectory
        PassThru = $true
        RedirectStandardOutput = $stdoutLogPath
        RedirectStandardError = $stderrLogPath
    }
    # GPUI 0.2.2 does not deliver the first-frame callback to a Win32 window
    # created hidden. `-Headless` means unattended evidence collection here;
    # the window must still present one real frame before readiness is trusted.
    $process = Start-Process @startParameters
} catch {
    $launchError = $_.Exception.Message
} finally {
    foreach ($name in $environmentNames) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}

if ($null -ne $process) {
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ((Test-Path -LiteralPath $smokeMarkerPath -PathType Leaf) -and (Test-Path -LiteralPath $appResultPath -PathType Leaf)) {
            $readyFilesObserved = $true
            break
        }
        if ($process.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }
}

if ($readyFilesObserved -and $null -ne $process) {
    $stabilityDeadline = [DateTime]::UtcNow.AddSeconds($PostReadyStabilitySeconds)
    while ([DateTime]::UtcNow -lt $stabilityDeadline) {
        $process.Refresh()
        if ($process.HasExited) { break }
        Start-Sleep -Milliseconds 100
    }
}

if (Test-Path -LiteralPath $smokeMarkerPath -PathType Leaf) {
    try {
        $marker = Get-Content -LiteralPath $smokeMarkerPath -Raw | ConvertFrom-Json
        if ((Test-HasProperty -Object $marker -Name 'schema') -and (Test-HasProperty -Object $marker -Name 'status') -and [string]$marker.schema -eq 'lovelyres-smoke-ready/v1' -and [string]$marker.status -eq 'ready') {
            Set-CollectedCheck -Map $checkMap -Id 'smoke_marker' -Category 'harness' -Status 'PASS' -Evidence "Validated lovelyres-smoke-ready/v1 marker at '$smokeMarkerPath'." -Source 'harness' -Required $true
        } else {
            Set-CollectedCheck -Map $checkMap -Id 'smoke_marker' -Category 'harness' -Status 'FAIL' -Evidence "Marker at '$smokeMarkerPath' did not contain the required schema/status." -Source 'harness' -Required $true
        }
    } catch {
        Set-CollectedCheck -Map $checkMap -Id 'smoke_marker' -Category 'harness' -Status 'FAIL' -Evidence "Cannot parse marker '$smokeMarkerPath': $($_.Exception.Message)" -Source 'harness' -Required $true
    }
} else {
    $reason = if ($null -ne $launchError) { "launch failed: $launchError" } else { "marker was not written within $StartupTimeoutSeconds seconds or before process exit" }
    Set-CollectedCheck -Map $checkMap -Id 'smoke_marker' -Category 'harness' -Status 'FAIL' -Evidence $reason -Source 'harness' -Required $true
}

if (Test-Path -LiteralPath $appResultPath -PathType Leaf) {
    try {
        $appDiagnostics = Get-Content -LiteralPath $appResultPath -Raw | ConvertFrom-Json -Depth 50
        $validation = Test-AppDiagnostics -Raw $appDiagnostics -ExpectedDataRoot (Join-Path $runDirectory 'data')
        $appResultStatus = if (@($validation.Errors).Count -eq 0) { 'PASS' } else { 'FAIL' }
        $appResultEvidence = if (@($validation.Errors).Count -eq 0) { "Validated lovelyres-gpui-feasibility/v1 at '$appResultPath'." } else { "Contract errors: $(@($validation.Errors) -join '; ')." }
        Set-CollectedCheck -Map $checkMap -Id 'app_result' -Category 'harness' -Status $appResultStatus -Evidence $appResultEvidence -Source 'harness' -Required $true
        foreach ($id in $automaticIds) {
            if ($validation.Automatic.Contains($id)) {
                $check = $validation.Automatic[$id]
                Set-CollectedCheck -Map $checkMap -Id $id -Category 'app-automatic' -Status ([string]$check.status) -Evidence ([string]$check.evidence) -Source 'app-result' -Required $true
            }
        }
        foreach ($id in $manualIds) {
            if ($validation.Manual.Contains($id)) {
                $check = $validation.Manual[$id]
                Set-CollectedCheck -Map $checkMap -Id $id -Category 'manual' -Status ([string]$check.status) -Evidence ([string]$check.evidence) -Source 'app-default' -Required ($requiredManualIds.Contains($id))
            }
        }
    } catch {
        Set-CollectedCheck -Map $checkMap -Id 'app_result' -Category 'harness' -Status 'FAIL' -Evidence "Cannot parse or validate '$appResultPath': $($_.Exception.Message)" -Source 'harness' -Required $true
    }
} else {
    $reason = if ($null -ne $launchError) { "launch failed: $launchError" } else { "app result was not written within $StartupTimeoutSeconds seconds or before process exit" }
    Set-CollectedCheck -Map $checkMap -Id 'app_result' -Category 'harness' -Status 'FAIL' -Evidence $reason -Source 'harness' -Required $true
}

$aliveForOperator = $false
if ($null -ne $process) {
    $process.Refresh()
    $aliveForOperator = -not $process.HasExited
}
if ($InteractiveManual -and $readyFilesObserved -and $aliveForOperator) {
    $manualEvidence = Read-InteractiveManualEvidence -ExpectedScenarioId $ScenarioId -ExpectedBinarySha256 $build.sha256 -RequiredIds @($requiredManualIds)
}
if ($null -ne $manualEvidence) {
    foreach ($check in @($manualEvidence.checks)) {
        $existing = $checkMap[[string]$check.id]
        if ([string]$existing.status -eq 'FAIL' -and [string]$check.status -eq 'PASS') {
            continue
        }
        Set-CollectedCheck -Map $checkMap -Id ([string]$check.id) -Category 'manual' -Status ([string]$check.status) -Evidence ([string]$check.evidence) -Source "operator:$($manualEvidence.operator)" -Required ($requiredManualIds.Contains([string]$check.id))
    }
}

if ($null -ne $process) {
    $process.Refresh()
    if ($readyFilesObserved -and -not $process.HasExited) {
        Set-CollectedCheck -Map $checkMap -Id 'process_alive' -Category 'harness' -Status 'PASS' -Evidence "Process $($process.Id) remained alive from readiness through evidence collection." -Source 'harness' -Required $true
    } else {
        $exitEvidence = if ($process.HasExited) { "Process $($process.Id) exited with code $($process.ExitCode) before evidence collection completed." } else { "Process $($process.Id) did not reach both readiness files." }
        Set-CollectedCheck -Map $checkMap -Id 'process_alive' -Category 'harness' -Status 'FAIL' -Evidence $exitEvidence -Source 'harness' -Required $true
    }
} else {
    Set-CollectedCheck -Map $checkMap -Id 'process_alive' -Category 'harness' -Status 'FAIL' -Evidence "Start-Process failed: $launchError" -Source 'harness' -Required $true
}

if ($null -ne $process) {
    try {
        $process.Refresh()
        if (-not $process.HasExited) {
            [void]$process.CloseMainWindow()
            if (-not $process.WaitForExit(5000)) {
                Stop-Process -Id $process.Id -Force
                [void]$process.WaitForExit(5000)
            }
        }
    } catch {
        Set-CollectedCheck -Map $checkMap -Id 'process_alive' -Category 'harness' -Status 'FAIL' -Evidence "The spawned process could not be stopped safely by exact PID $($process.Id): $($_.Exception.Message)" -Source 'harness' -Required $true
    }
}

$dataDirectory = Join-Path $runDirectory 'data'
$persistenceViolations = [System.Collections.Generic.List[string]]::new()
$runDirectoryAfter = Get-TreeSnapshot -Root $runDirectory
foreach ($violation in (Get-TreeViolations -Before $runDirectoryBefore -After $runDirectoryAfter -Label 'portable-root' -AllowDataSubtree)) {
    $persistenceViolations.Add($violation)
}
foreach ($root in $externalRoots) {
    $after = Get-TreeSnapshot -Root $root
    foreach ($violation in (Get-TreeViolations -Before $externalBefore[$root] -After $after -Label $root)) {
        $persistenceViolations.Add($violation)
    }
}
if ($persistenceViolations.Count -eq 0 -and (Test-Path -LiteralPath $dataDirectory -PathType Container)) {
    Set-CollectedCheck -Map $checkMap -Id 'portable_persistence' -Category 'harness' -Status 'PASS' -Evidence "After process exit, recursive snapshots found no change outside data/ in the portable root, redirected profile, or known LovelyRes AppData roots." -Source 'harness' -Required $true
} else {
    $violationSummary = @($persistenceViolations | Select-Object -First 20) -join '; '
    Set-CollectedCheck -Map $checkMap -Id 'portable_persistence' -Category 'harness' -Status 'FAIL' -Evidence "Portable persistence mismatch. dataExists=$(Test-Path -LiteralPath $dataDirectory -PathType Container); violations='$violationSummary'." -Source 'harness' -Required $true
}

$checks = @($checkMap.Values)
$failedChecks = @($checks | Where-Object { $_.status -eq 'FAIL' } | ForEach-Object { $_.id })
$requiredNotRun = @($checks | Where-Object { $_.required_for_scenario -and $_.status -eq 'NOT_RUN' } | ForEach-Object { $_.id })
$optionalNotRun = @($checks | Where-Object { -not $_.required_for_scenario -and $_.status -eq 'NOT_RUN' } | ForEach-Object { $_.id })
$outcomeStatus = if ($failedChecks.Count -gt 0) { 'FAIL' } elseif ($requiredNotRun.Count -gt 0) { 'NOT_RUN' } else { 'PASS' }

$result = [pscustomobject][ordered]@{
    schema = 'lovelyres-feasibility-result/v1'
    fixture = $false
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    scenario = [pscustomobject][ordered]@{
        id = $ScenarioId
        expected = [pscustomobject][ordered]@{
            operating_system = $ExpectedOperatingSystem
            dpi_percent = $ExpectedDpiPercent
            mixed_dpi = [bool]$RequireMixedDpi
            rdp = [bool]$RequireRdp
            virtual_machine = [bool]$RequireVm
            integrated_gpu = [bool]$RequireIntegratedGpu
            offline = [bool]$RequireOffline
        }
    }
    build = $build
    environment = $environment
    artifacts = [pscustomobject][ordered]@{
        run_directory = $runDirectory
        smoke_marker = $smokeMarkerPath
        app_result = $appResultPath
        stdout_log = $stdoutLogPath
        stderr_log = $stderrLogPath
        profile_root = $profileDirectory
    }
    app_diagnostics = $appDiagnostics
    operator_evidence = $manualEvidence
    checks = $checks
    outcome = [pscustomobject][ordered]@{
        status = $outcomeStatus
        failed_checks = $failedChecks
        required_not_run_checks = $requiredNotRun
        optional_not_run_checks = $optionalNotRun
    }
}

Write-AtomicJson -Path $output -Value $result
Write-Host "Wrote feasibility result '$output' with outcome $outcomeStatus."
Write-Host "Run directory '$runDirectory' is retained as evidence; the harness does not recursively delete it."
if ($outcomeStatus -ne 'PASS' -and -not $ReportOnly) {
    throw "GPUI feasibility scenario '$ScenarioId' ended $outcomeStatus. See '$output'."
}
