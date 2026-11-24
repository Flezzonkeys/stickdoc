<#
StickDoc: portable health check for RMA work.

Runs from a USB stick without installation, only reads the system and
writes an HTML/JSON/TXT report into the Reports folder next to it.
Works with the built-in Windows PowerShell 5.1 (Windows 10 and 11).

Optional: put smartctl.exe (smartmontools) into the tools folder for
full SMART data. Without it, the Windows storage counters are used.

License: MIT
#>
[CmdletBinding()]
param(
    [string]$Rma,
    [string]$OutDir,
    [int]$Days = 30,
    [switch]$NoPrompt,
    [switch]$NoOpen,
    [switch]$NoDumps
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5.1 otherwise writes some arrays as {"value": [...], "Count": n} into JSON
Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue
$VERSION = '1.0.0'
$AppDir = $PSScriptRoot
$Root = Split-Path -Parent $AppDir
$Inv = [Globalization.CultureInfo]::InvariantCulture
$Now = Get-Date
$Since = $Now.AddDays(-$Days)
$Deg = [string][char]0x00B0 + 'C'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

$RANK = @{ ok = 0; info = 0; warn = 1; fail = 2 }
$Script:Flags = New-Object System.Collections.ArrayList
$Script:Identity = @{}
$Script:DriveTemps = New-Object System.Collections.ArrayList
$Script:Bitlocker = New-Object System.Collections.ArrayList
$Script:ReportBase = $null   # path + file name without extension, set before the checks run

# ------------------------------------------------------------------ helpers
function Get-Worst {
    $w = 'ok'
    foreach ($a in $args) { foreach ($s in @($a)) { if ($s -and $RANK[[string]$s] -gt $RANK[$w]) { $w = [string]$s } } }
    return $w
}

function New-Result {
    param([string]$Id, [string]$Title, [string]$Status, [string]$Summary, $Details, $Gauges, $Links, [switch]$Info)
    $r = [ordered]@{ id = $Id; title = $Title; status = $Status; summary = $Summary; details = @(); gauges = @(); links = @() }
    if ($Details) { $r.details = [string[]]@($Details) }
    if ($Gauges) { $r.gauges = @($Gauges) }
    if ($Links) { $r.links = @($Links) }
    if ($Info) { $r.info = $true }
    return $r
}

function New-Gauge([string]$Label, [double]$Value, $Warn = $null, $Fail = $null) {
    $v = [math]::Round([math]::Max(0, [math]::Min(100, $Value)), 1)
    $g = [ordered]@{ label = $Label; value = $v }
    if ($null -ne $Warn) { $g.warn = $Warn }
    if ($null -ne $Fail) { $g.fail = $Fail }
    return $g
}

# Findings for the customer report: a code plus values, the German text is in report.html
$Script:Customer = New-Object System.Collections.ArrayList
function Add-Cust([string]$Area, [string]$Level, [string]$Code, [hashtable]$P) {
    $o = [ordered]@{ area = $Area; level = $Level; code = $Code }
    if ($P) { foreach ($k in $P.Keys) { $o[$k] = $P[$k] } }
    [void]$Script:Customer.Add($o)
}

function Add-Flag([string]$Level, [string]$Text) {
    [void]$Script:Flags.Add([ordered]@{ level = $Level; text = $Text })
}

function N($Value, [string]$Format = '0') { return ([double]$Value).ToString($Format, $Inv) }

function Format-Bytes($Bytes) {
    $n = [double]$Bytes
    $units = 'B', 'KB', 'MB', 'GB', 'TB'
    $i = 0
    while ($n -ge 1024 -and $i -lt 4) { $n /= 1024; $i++ }
    if ($i -lt 2) { return (N $n '0') + ' ' + $units[$i] }
    return (N $n '0.0') + ' ' + $units[$i]
}

function Format-Date($Date, [switch]$Time) {
    if (-not $Date) { return '' }
    try {
        $d = [datetime]$Date
        if ($Time) { return $d.ToString('yyyy-MM-dd HH:mm', $Inv) }
        return $d.ToString('yyyy-MM-dd', $Inv)
    } catch { return [string]$Date }
}

function Format-Ago($Date) {
    $s = ($Now - [datetime]$Date).TotalSeconds
    if ($s -lt 3600) { return "$([int][math]::Floor($s / 60)) min ago" }
    if ($s -lt 86400) { return "$([int][math]::Floor($s / 3600)) h ago" }
    return "$([int][math]::Floor($s / 86400)) days ago"
}

function Format-Duration([double]$Seconds) {
    $m = [int][math]::Floor($Seconds / 60)
    $d = [int][math]::Floor($m / 1440); $h = [int][math]::Floor($m / 60) % 24; $m = $m % 60
    if ($d) { return "$d day$(if ($d -ne 1) { 's' }) $h h" }
    if ($h) { return "$h h $m min" }
    return "$m min"
}

function Get-Cim([string]$Class, [string]$Namespace = 'root/cimv2', [string]$Filter) {
    try {
        $p = @{ ClassName = $Class; Namespace = $Namespace; ErrorAction = 'Stop'; OperationTimeoutSec = 60 }
        if ($Filter) { $p.Filter = $Filter }
        return @(Get-CimInstance @p)
    } catch { return @() }
}

function Get-Reg([string]$Path, [string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Get-Events([hashtable]$Filter, [int]$Max = 5000) {
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) } catch { return @() }
}

function Get-EventData($Event) {
    $h = @{}
    try {
        $x = [xml]$Event.ToXml()
        foreach ($n in @($x.Event.EventData.Data)) {
            if ($n -and $n.GetAttribute('Name')) { $h[$n.GetAttribute('Name')] = $n.InnerText }
        }
    } catch {}
    return $h
}

function First-Line($Text, [int]$Max = 200) {
    if (-not $Text) { return '' }
    $t = (([string]$Text -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $t) { return '' }
    $t = ($t -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    return $t
}

# Placeholder strings that vendors leave in the firmware
function Clean($Value) {
    if ($null -eq $Value) { return '' }
    $s = (([string]$Value) -replace '\s+', ' ').Trim()
    if ($s -match '^(To Be Filled By O\.E\.M\.|Default string|System (Product Name|Serial Number|Manufacturer|Version|SKU)|None|Not Applicable|Not Specified|N/A|O\.E\.M\.|OEM|0+|Invalid|INVALID|Chassis Serial Number|Base Board (Serial Number|Product Name)|123456789|0123456789|x+|SKU|Type1ProductConfigId)$') { return '' }
    return $s
}

function Map($Table, $Value) {
    if ($null -eq $Value) { return '' }
    $i = 0
    if ([int]::TryParse([string]$Value, [ref]$i)) {
        if ($Table.ContainsKey($i)) { return $Table[$i] }
        return "code $i"
    }
    return [string]$Value
}

function Norm($s) { return (([string]$s) -replace '[^A-Za-z0-9]', '').ToUpperInvariant() }

$BusMap = @{ 0 = 'Unknown'; 1 = 'SCSI'; 2 = 'ATAPI'; 3 = 'ATA'; 4 = '1394'; 5 = 'SSA'; 6 = 'Fibre Channel'; 7 = 'USB'; 8 = 'RAID';
    9 = 'iSCSI'; 10 = 'SAS'; 11 = 'SATA'; 12 = 'SD'; 13 = 'MMC'; 14 = 'Virtual'; 15 = 'File Backed Virtual'; 16 = 'Storage Spaces';
    17 = 'NVMe'; 18 = 'SCM'; 19 = 'UFS' }
$MediaMap = @{ 0 = ''; 3 = 'HDD'; 4 = 'SSD'; 5 = 'SCM' }
$HealthMap = @{ 0 = 'Healthy'; 1 = 'Warning'; 2 = 'Unhealthy'; 5 = 'Unknown' }
$OpStatusMap = @{ 1 = 'Other'; 2 = 'OK'; 3 = 'Degraded'; 4 = 'Stressed'; 5 = 'Predictive Failure'; 6 = 'Error'; 7 = 'Non-Recoverable Error';
    8 = 'Starting'; 9 = 'Stopping'; 10 = 'Stopped'; 11 = 'In Service'; 12 = 'No Contact'; 13 = 'Lost Communication'; 14 = 'Aborted';
    15 = 'Dormant'; 16 = 'Supporting Entity in Error'; 17 = 'Completed'; 18 = 'Power Mode' }

# ------------------------------------------------------------------ identity / stick
function Get-StickInfo {
    if (-not ($Root -match '^([A-Za-z]):')) { return $null }
    $letter = $Matches[1].ToUpper()
    try { $n = (Get-Partition -DriveLetter $letter -ErrorAction Stop).DiskNumber } catch { return $null }
    $pd = @(Get-Cim MSFT_PhysicalDisk 'root/Microsoft/Windows/Storage') | Where-Object { [string]$_.DeviceId -eq [string]$n } | Select-Object -First 1
    $bus = Map $BusMap $pd.BusType
    # Only skip the drive if it really is a removable stick, never the system disk
    if ($bus -in 'USB', 'SD', 'MMC') { return @{ Disk = [string]$n; Letter = $letter } }
    return $null
}

function Get-BootInfo {
    $mode = 'Unknown'; $sb = $null
    try {
        $sb = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $mode = 'UEFI'
    } catch {
        if ($_.Exception -is [System.PlatformNotSupportedException]) { $mode = 'Legacy BIOS (CSM)' }
        else {
            $v = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
            if ($null -ne $v) { $mode = 'UEFI'; $sb = ($v -eq 1) }
        }
    }
    if ($mode -eq 'Unknown') {
        $ft = (cmd.exe /c 'echo %firmware_type%' 2>$null | Out-String).Trim()
        if ($ft -eq 'UEFI') { $mode = 'UEFI' } elseif ($ft -eq 'Legacy') { $mode = 'Legacy BIOS (CSM)' }
    }
    return @{ Mode = $mode; SecureBoot = $sb }
}

$ChassisMap = @{ 3 = 'Desktop'; 4 = 'Low profile desktop'; 5 = 'Pizza box'; 6 = 'Mini tower'; 7 = 'Tower'; 8 = 'Portable'; 9 = 'Laptop';
    10 = 'Notebook'; 11 = 'Handheld'; 12 = 'Docking station'; 13 = 'All-in-one'; 14 = 'Sub notebook'; 15 = 'Space-saving';
    16 = 'Lunch box'; 17 = 'Main server chassis'; 23 = 'Rack mount'; 24 = 'Sealed-case PC'; 30 = 'Tablet'; 31 = 'Convertible';
    32 = 'Detachable'; 33 = 'IoT gateway'; 34 = 'Embedded PC'; 35 = 'Mini PC'; 36 = 'Stick PC' }

# SMBIOS memory type codes (Win32_PhysicalMemory.SMBIOSMemoryType)
$MemTypeMap = @{ 18 = 'DDR'; 19 = 'DDR2'; 20 = 'DDR2 FB-DIMM'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2';
    29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
$FormFactorMap = @{ 8 = 'DIMM'; 12 = 'SO-DIMM'; 13 = 'SO-DIMM'; 0 = '' }
# JEDEC IDs that some boards report instead of the maker name
$JedecMap = @{ '80CE' = 'Samsung'; '80AD' = 'SK Hynix'; '802C' = 'Micron'; '859B' = 'Crucial'; '04CD' = 'G.Skill'; '0198' = 'Kingston';
    '029E' = 'Corsair'; '0443' = 'Ramaxel'; '04F1' = 'Toshiba' }

function Get-RamMaker($m) {
    $s = Clean $m
    if (-not $s) { return '' }
    foreach ($k in $JedecMap.Keys) { if ($s.ToUpper().StartsWith($k)) { return $JedecMap[$k] } }
    return $s
}

function Get-GpuMemory([string]$Name) {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
        if ($k.PSChildName -notmatch '^\d{4}$') { continue }
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p -or $p.DriverDesc -ne $Name) { continue }
        $q = $p.'HardwareInformation.qwMemorySize'
        if ($q) { return [double]$q }
        $m = $p.'HardwareInformation.MemorySize'
        if ($m -is [byte[]] -and $m.Length -ge 4) { return [double][BitConverter]::ToUInt32($m, 0) }
        if ($m) { return [double]$m }
    }
    return 0
}

function Get-Gpus {
    $list = @()
    foreach ($g in Get-Cim Win32_VideoController) {
        if ($g.Name -match 'Remote Display|Mirage|Virtual Display|Parsec|Citrix|DisplayLink|Spacedesk|IddCx|Meta Virtual|Hyper-V') { continue }
        $vram = Get-GpuMemory $g.Name
        if (-not $vram -and $g.AdapterRAM -gt 0) { $vram = [double]$g.AdapterRAM }
        $list += [pscustomobject]@{ Name = ($g.Name -replace '\s+', ' ').Trim(); Vram = $vram; Driver = $g.DriverVersion; DriverDate = $g.DriverDate
            Width = $g.CurrentHorizontalResolution; Height = $g.CurrentVerticalResolution; Hz = $g.CurrentRefreshRate; Status = $g.Status
            Code = $g.ConfigManagerErrorCode }
    }
    return @($list | Sort-Object Vram -Descending)
}

# ------------------------------------------------------------------ system info
function Check-SysInfo {
    $d = New-Object System.Collections.Generic.List[string]
    $cs = @(Get-Cim Win32_ComputerSystem)[0]
    $csp = @(Get-Cim Win32_ComputerSystemProduct)[0]
    $bios = @(Get-Cim Win32_BIOS)[0]
    $os = @(Get-Cim Win32_OperatingSystem)[0]
    $enc = @(Get-Cim Win32_SystemEnclosure)[0]
    $bb = @(Get-Cim Win32_BaseBoard)[0]

    $maker = Clean $cs.Manufacturer
    if (-not $maker) { $maker = Clean $bb.Manufacturer }
    $model = Clean $cs.Model
    $friendly = Clean $csp.Version
    # Lenovo puts the friendly name (ThinkPad T14 ...) into the product version and a type number into the model
    if ($friendly -and $maker -match 'LENOVO' -and $friendly -notmatch '^\d') { $model = "$friendly ($model)" }
    if (-not $model) { $model = Clean $bb.Product }
    $serial = Clean $bios.SerialNumber
    if (-not $serial) { $serial = Clean $csp.IdentifyingNumber }
    if (-not $serial) { $serial = Clean $enc.SerialNumber }
    $sku = Clean $cs.SystemSKUNumber
    $chassis = @($enc.ChassisTypes | ForEach-Object { Map $ChassisMap $_ }) -join ', '

    $Script:Identity = @{ Name = $env:COMPUTERNAME; Maker = $maker; Model = $model; Serial = $serial; Sku = $sku; Chassis = $chassis }

    $d.Add("Device: $(($maker, $model | Where-Object { $_ }) -join ' ')")
    if ($serial) { $d.Add("Serial number: $serial") }
    if ($sku) { $d.Add("Product / SKU: $sku") }
    if ($chassis) { $d.Add("Type: $chassis") }
    $asset = Clean $enc.SMBIOSAssetTag
    if ($asset -and $asset -ne 'Asset-1234567890') { $d.Add("Asset tag: $asset") }
    if ($csp.UUID) { $d.Add("UUID: $($csp.UUID)") }
    $d.Add("Computer name: $env:COMPUTERNAME")

    # Windows
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $disp = Get-Reg $cv 'DisplayVersion'
    $build = Get-Reg $cv 'CurrentBuild'
    $ubr = Get-Reg $cv 'UBR'
    $caption = ([string]$os.Caption -replace '^Microsoft ', '').Trim()
    # Windows 11 still reports itself as Windows 10 in some places; the build number decides
    if ($caption -match 'Windows 10' -and [int]$build -ge 22000) { $caption = $caption -replace 'Windows 10', 'Windows 11' }
    $osLine = "Windows: $caption"
    if ($disp) { $osLine += " $disp" }
    $osLine += " (build $build$(if ($ubr) { ".$ubr" }), $($os.OSArchitecture))"
    $d.Add($osLine)
    $Script:Identity.Os = "$caption $disp".Trim()
    if ($os.InstallDate) { $d.Add("Installed: $(Format-Date $os.InstallDate)") }
    $langs = @($os.MUILanguages) -join ', '
    if ($langs) { $d.Add("Language: $langs") }

    # Activation
    $lic = @(Get-Cim SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL") |
        Sort-Object { if ([int]$_.LicenseStatus -eq 1) { 0 } else { 1 } } | Select-Object -First 1
    if ($lic) {
        $states = @{ 0 = 'not activated'; 1 = 'activated'; 2 = 'grace period'; 3 = 'grace period (hardware changed)'; 4 = 'grace period (not genuine)';
            5 = 'not activated (notification mode)'; 6 = 'extended grace period' }
        $chan = ''
        if ($lic.Description -match '(\w+)\s+channel') { $chan = $Matches[1] }
        $d.Add("Activation: $(Map $states $lic.LicenseStatus)$(if ($chan) { ", $chan" })")
        if ([int]$lic.LicenseStatus -ne 1) { Add-Flag 'warn' 'Windows is not activated'; Add-Cust 'sysinfo' 'warn' 'not_activated' }
    } elseif ($IsAdmin) { $d.Add('Activation: no Windows license found') }
    $oa3 = @(Get-Cim SoftwareLicensingService)[0]
    if ($oa3 -and $oa3.OA3xOriginalProductKey) {
        $k = [string]$oa3.OA3xOriginalProductKey
        $desc = [string]$oa3.OA3xOriginalProductKeyDescription
        $d.Add("Product key in firmware: yes (ends in $($k.Substring([math]::Max(0, $k.Length - 5)))$(if ($desc) { ", $desc" }))")
    } else { $d.Add('Product key in firmware: none') }

    # CPU
    $cpus = @(Get-Cim Win32_Processor)
    $cpuName = 'Unknown CPU'
    if ($cpus.Count) {
        $cpu = $cpus[0]
        $cpuName = ($cpu.Name -replace '\s+', ' ').Trim()
        $cores = ($cpus | Measure-Object NumberOfCores -Sum).Sum
        $threads = ($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        $line = "CPU: $cpuName, $cores cores / $threads threads"
        if ($cpu.MaxClockSpeed) { $line += ", base $(N ($cpu.MaxClockSpeed / 1000) '0.00') GHz" }
        if ($cpus.Count -gt 1) { $line += ", $($cpus.Count) sockets" }
        $d.Add($line)
        $extra = @()
        if ($cpu.SocketDesignation) { $extra += "socket $($cpu.SocketDesignation)" }
        if ($cpu.L3CacheSize) { $extra += "L3 $(N ($cpu.L3CacheSize / 1024) '0.#') MB" }
        if ($null -ne $cpu.VirtualizationFirmwareEnabled) { $extra += "virtualization $(if ($cpu.VirtualizationFirmwareEnabled) { 'on' } else { 'off' })" }
        if ($extra) { $d.Add('    ' + ($extra -join ', ')) }
    }

    # GPU
    $gpus = @(Get-Gpus)
    foreach ($g in $gpus) {
        $extra = @()
        if ($g.Vram -ge 1GB) { $extra += "$(N ($g.Vram / 1GB) '0') GB VRAM" } elseif ($g.Vram -gt 0) { $extra += "$(N ($g.Vram / 1MB) '0') MB VRAM" }
        if ($g.Driver) { $extra += "driver $($g.Driver)$(if ($g.DriverDate) { ' from ' + (Format-Date $g.DriverDate) })" }
        $d.Add("GPU: $($g.Name)$(if ($extra) { ' (' + ($extra -join ', ') + ')' })")
        if ($g.Name -match 'Microsoft Basic Display') {
            Add-Flag 'warn' 'No graphics driver installed (Microsoft Basic Display Adapter)'
            Add-Cust 'sysinfo' 'warn' 'no_gpu_driver'
        }
    }

    # RAM
    $total = [double]$cs.TotalPhysicalMemory
    $mods = @(Get-Cim Win32_PhysicalMemory)
    $installed = ($mods | Measure-Object Capacity -Sum).Sum
    $groups = [ordered]@{}
    $modLines = @()
    foreach ($m in $mods) {
        $size = "$(N ($m.Capacity / 1GB) '0') GB"
        $type = Map $MemTypeMap $m.SMBIOSMemoryType
        if ($type -like 'code *') { $type = '' }
        $speed = if ($m.ConfiguredClockSpeed) { $m.ConfiguredClockSpeed } else { $m.Speed }
        $key = "$size $type" + $(if ($speed) { "-$speed" } else { '' })
        $groups[$key] = 1 + [int]$groups[$key]
        $slot = Clean $m.DeviceLocator
        $bank = Clean $m.BankLabel
        if ($bank -and $slot -notmatch [regex]::Escape($bank)) { $slot = "$slot ($bank)" }
        $ff = Map $FormFactorMap $m.FormFactor
        if ($ff -like 'code *') { $ff = '' }
        $parts = @("$size $type $ff".Trim() -replace '\s+', ' ')
        if ($speed) { $parts += "$speed MT/s" }
        $mk = Get-RamMaker $m.Manufacturer
        $pn = Clean $m.PartNumber
        if ($mk -or $pn) { $parts += "$mk $pn".Trim() }
        $sn = Clean $m.SerialNumber
        if ($sn) { $parts += "S/N $sn" }
        $modLines += "    ${slot}: $($parts -join ', ')"
    }
    $slots = (@(Get-Cim Win32_PhysicalMemoryArray) | Where-Object { $_.Use -eq 3 } | Measure-Object MemoryDevices -Sum).Sum
    $ramLine = "RAM: $(Format-Bytes $total) usable"
    if ($groups.Count) { $ramLine += ' (' + (($groups.Keys | ForEach-Object { "$($groups[$_])x $_" }) -join ', ') + ')' }
    if ($slots) { $ramLine += ", $($mods.Count) of $slots slots used" }
    $d.Add($ramLine)
    foreach ($l in $modLines) { $d.Add($l) }

    # Mainboard and firmware
    $board = (Clean $bb.Manufacturer), (Clean $bb.Product), (Clean $bb.Version) | Where-Object { $_ }
    if ($board) {
        $line = "Mainboard: $($board -join ' ')"
        $bsn = Clean $bb.SerialNumber
        if ($bsn) { $line += " (S/N $bsn)" }
        $d.Add($line)
    }
    $Script:Boot = Get-BootInfo
    $biosVer = Clean $bios.SMBIOSBIOSVersion
    $d.Add("BIOS: $(Clean $bios.Manufacturer) $biosVer$(if ($bios.ReleaseDate) { ' (' + (Format-Date $bios.ReleaseDate) + ')' }), boot mode $($Script:Boot.Mode)".Trim())

    # Uptime and boot
    if ($os.LastBootUpTime) {
        $up = ($Now - $os.LastBootUpTime).TotalSeconds
        $d.Add("Running for: $(Format-Duration $up) (since $(Format-Date $os.LastBootUpTime -Time))")
    }
    $fast = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled'
    if ($fast -eq 1) { $d.Add('Fast startup: on (shutting down does not fully restart Windows, use Restart for tests)') }
    elseif ($null -ne $fast) { $d.Add('Fast startup: off') }
    $bootEv = @(Get-Events @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 } 1)
    if ($bootEv.Count) {
        $bt = (Get-EventData $bootEv[0])['BootTime']
        if ($bt) { $d.Add("Last boot took: $(N ($bt / 1000) '0.0') s ($(Format-Date $bootEv[0].TimeCreated))") }
    }

    $cpuShort = $cpuName -replace '\((R|TM)\)', '' -replace '\s+CPU\s+@.*$', '' -replace '\s+\d+-Core Processor$', '' -replace '\s+with Radeon.*$', '' -replace '^(AMD|Intel)\s+', '' -replace '\s+', ' '
    $gpuShort = ''
    if ($gpus.Count) { $gpuShort = ($gpus[0].Name -replace '^(NVIDIA|AMD|Intel\(R\)|Intel)\s+', '' -replace '\(R\)|\(TM\)', '').Trim() }
    $ramShort = if ($installed) { "$(N ($installed / 1GB) '0') GB" } else { Format-Bytes $total }
    $devName = ($maker, $model | Where-Object { $_ }) -join ' '
    $summary = @($devName, $cpuShort.Trim(), $gpuShort, "$ramShort RAM") | Where-Object { $_ }
    $Script:Identity.Short = "$($cpuShort.Trim()), $(if ($gpuShort) { "$gpuShort, " })$ramShort RAM"
    return New-Result 'sysinfo' 'System info' 'info' ($summary -join ', ') $d -Info
}

# ------------------------------------------------------------------ usage
function Check-Usage {
    $threads = [Environment]::ProcessorCount
    $t0 = @{}
    foreach ($p in Get-Process) { $tp = $p.TotalProcessorTime; if ($tp) { $t0[$p.Id] = $tp.TotalMilliseconds } }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $load = @(Get-Cim Win32_Processor | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
    Start-Sleep -Milliseconds 1200
    $load += @(Get-Cim Win32_Processor | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
    $elapsed = [math]::Max(1, $sw.Elapsed.TotalMilliseconds)
    $cpuBy = @{}; $memBy = @{}; $count = 0
    foreach ($p in Get-Process) {
        $count++
        $name = $p.ProcessName
        if ($name -eq 'Idle') { continue }
        $tp = $p.TotalProcessorTime
        if ($tp -and $t0.ContainsKey($p.Id)) { $cpuBy[$name] = [double]$cpuBy[$name] + 100 * ($tp.TotalMilliseconds - $t0[$p.Id]) / ($elapsed * $threads) }
        $memBy[$name] = [double]$memBy[$name] + $p.WorkingSet64
    }
    $cpuPct = if ($load.Count) { ($load | Measure-Object -Average).Average } else { ($cpuBy.Values | Measure-Object -Sum).Sum }

    $os = @(Get-Cim Win32_OperatingSystem)[0]
    $total = [double]$os.TotalVisibleMemorySize * 1KB
    $avail = [double]$os.FreePhysicalMemory * 1KB
    $used = $total - $avail
    $availPct = if ($total) { $avail * 100 / $total } else { 100 }
    $st = if ($availPct -lt 5) { 'fail' } elseif ($availPct -lt 10) { 'warn' } else { 'ok' }
    if ($st -ne 'ok') { Add-Cust 'usage' $st 'ram_low' @{ pct = [int](100 - $availPct) } }

    $d = New-Object System.Collections.Generic.List[string]
    $d.Add("RAM: $(Format-Bytes $used) of $(Format-Bytes $total) used ($(N (100 - $availPct))%), $(Format-Bytes $avail) available")
    $pf = @(Get-Cim Win32_PageFileUsage)
    $pfSize = ($pf | Measure-Object AllocatedBaseSize -Sum).Sum
    $pfUsed = ($pf | Measure-Object CurrentUsage -Sum).Sum
    if ($pfSize) { $d.Add("Page file: $(Format-Bytes ($pfUsed * 1MB)) of $(Format-Bytes ($pfSize * 1MB)) used ($(($pf | ForEach-Object { $_.Name }) -join ', '))") }
    else { $d.Add('Page file: none') }
    if ($os.TotalVirtualMemorySize) {
        $commit = ($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) * 1KB
        $d.Add("Committed memory: $(Format-Bytes $commit) of $(Format-Bytes ($os.TotalVirtualMemorySize * 1KB)) limit")
    }
    $d.Add("CPU usage: $(N $cpuPct)% on $threads threads, $count processes running")
    $d.Add('Using the most memory:')
    foreach ($e in ($memBy.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6)) { $d.Add("    $($e.Key): $(Format-Bytes $e.Value)") }
    $busy = @($cpuBy.GetEnumerator() | Where-Object { $_.Value -ge 0.5 } | Sort-Object Value -Descending | Select-Object -First 6)
    if ($busy.Count) {
        $d.Add('Using the most CPU:')
        foreach ($e in $busy) { $d.Add("    $($e.Key): $(N $e.Value '0.0')%") }
    } else { $d.Add('Using the most CPU: nothing busy') }
    $d.Add('Measured at check time')

    $g = @((New-Gauge 'RAM' (100 - $availPct) 90 95), (New-Gauge 'CPU' $cpuPct))
    if ($pfSize) { $g += New-Gauge 'Page file' ($pfUsed * 100 / $pfSize) 80 }
    return New-Result 'usage' 'Usage' $st "RAM $(Format-Bytes $used) / $(Format-Bytes $total) ($(N (100 - $availPct))%), CPU $(N $cpuPct)%" $d $g
}

# ------------------------------------------------------------------ drives
function Get-SmartctlData {
    $exe = Join-Path $Root 'tools\smartctl.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return @() }
    $list = @()
    try { $scan = (& $exe --scan-open -j 2>$null | Out-String) | ConvertFrom-Json } catch { return @() }
    foreach ($dev in @($scan.devices)) {
        if (-not $dev -or -not $dev.name) { continue }
        $a = @('-a', '-j')
        if ($dev.type) { $a += @('-d', [string]$dev.type) }
        $a += [string]$dev.name
        try {
            $j = (& $exe @a 2>$null | Out-String) | ConvertFrom-Json
            if ($j -and -not ([int]$j.smartctl.exit_status -band 3)) { $list += $j }
        } catch {}
    }
    return $list
}

# SMART evaluation, the same rules as the Linux version
function Test-Smart($s) {
    $st = 'ok'; $notes = @(); $extra = @(); $temp = $null; $why = @()
    if ($s.smart_status -and $s.smart_status.passed -eq $false) { $st = 'fail'; $notes += 'SMART self-assessment FAILED'; $why += 'smart_failed' }
    if ($s.temperature) { $temp = $s.temperature.current }
    $nv = $s.nvme_smart_health_information_log
    if ($nv) {
        if ($null -ne $nv.percentage_used) {
            $notes += "$($nv.percentage_used)% worn"
            if ($nv.percentage_used -ge 75) { $why += "worn:$($nv.percentage_used)" }
            if ($nv.percentage_used -ge 90) { $st = Get-Worst $st 'fail' } elseif ($nv.percentage_used -ge 75) { $st = Get-Worst $st 'warn' }
        }
        if ($nv.critical_warning) { $st = Get-Worst $st 'fail'; $notes += "critical warning flag $($nv.critical_warning)"; $why += 'critical' }
        if ($nv.media_errors) { $st = Get-Worst $st 'warn'; $notes += "$($nv.media_errors) media errors"; $why += 'errors' }
        if ($null -ne $nv.available_spare -and $null -ne $nv.available_spare_threshold -and $nv.available_spare -le $nv.available_spare_threshold) {
            $st = Get-Worst $st 'fail'; $notes += "spare blocks low ($($nv.available_spare)%)"; $why += 'spare_low'
        }
        if ($null -eq $temp) { $temp = $nv.temperature }
        if ($null -ne $nv.power_on_hours) { $extra += "$(N $nv.power_on_hours '#,0') h powered on" }
        if ($nv.data_units_written) { $extra += "$(N ($nv.data_units_written * 512000 / 1e12) '0.0') TB written" }
        if ($null -ne $nv.power_cycles) { $extra += "$(N $nv.power_cycles '#,0') power cycles" }
        if ($nv.unsafe_shutdowns) { $extra += "$(N $nv.unsafe_shutdowns '#,0') unsafe shutdowns" }
    } else {
        $attrs = @{}
        foreach ($a in @($s.ata_smart_attributes.table)) { if ($a) { $attrs[[int]$a.id] = $a } }
        foreach ($pair in @(@(5, 'reallocated sectors'), @(197, 'pending sectors'), @(198, 'uncorrectable sectors'))) {
            $a = $attrs[$pair[0]]
            if ($a -and $a.raw -and $a.raw.value) { $st = Get-Worst $st 'warn'; $notes += "$($a.raw.value) $($pair[1])"; $why += 'sectors' }
        }
        $wear = $null
        foreach ($id in 177, 231, 233) { if (-not $wear -and $attrs[$id]) { $wear = $attrs[$id] } }
        if ($wear -and $null -ne $wear.value) {
            $left = [int]$wear.value
            $notes += "$(100 - $left)% worn"
            if ($left -le 25) { $why += "worn:$(100 - $left)" }
            if ($left -le 10) { $st = Get-Worst $st 'fail' } elseif ($left -le 25) { $st = Get-Worst $st 'warn' }
        }
        if ($s.power_on_time -and $null -ne $s.power_on_time.hours) { $extra += "$(N $s.power_on_time.hours '#,0') h powered on" }
        $lbas = $attrs[241]
        if ($lbas -and $lbas.name -eq 'Total_LBAs_Written' -and $lbas.raw.value) { $extra += "$(N ($lbas.raw.value * 512 / 1e12) '0.0') TB written" }
        if ($null -ne $s.power_cycle_count) { $extra += "$(N $s.power_cycle_count '#,0') power cycles" }
    }
    return @{ Status = $st; Notes = $notes; Extra = $extra; Temp = $temp; Why = @($why | Select-Object -Unique) }
}

function Check-Drives {
    $ns = 'root/Microsoft/Windows/Storage'
    $pds = @(Get-Cim MSFT_PhysicalDisk $ns | Sort-Object { [int]$_.DeviceId })
    $disks = @(Get-Cim MSFT_Disk $ns)
    Write-Log '  drives: smartctl'
    $smart = @(Get-SmartctlData)
    Write-Log "  drives: $($pds.Count) disk(s), $($smart.Count) from smartctl"
    $usedSmart = @{}
    $states = @(); $d = New-Object System.Collections.Generic.List[string]
    $n = 0

    foreach ($pd in $pds) {
        if ($Script:Stick -and [string]$pd.DeviceId -eq $Script:Stick.Disk) { continue }
        $n++
        $model = (($pd.FriendlyName, $pd.Model | Where-Object { $_ }) | Select-Object -First 1)
        $model = ([string]$model).Trim()
        $bus = Map $BusMap $pd.BusType
        $media = Map $MediaMap $pd.MediaType
        if ($media -like 'code *') { $media = '' }
        if (-not $media -and $bus -eq 'NVMe') { $media = 'SSD' }
        $kind = (($bus, $media) | Where-Object { $_ -and $_ -ne 'Unknown' }) -join ' '
        $st = 'ok'; $notes = @(); $extra = @(); $temp = $null; $why = @()

        $health = Map $HealthMap $pd.HealthStatus
        if ($health -eq 'Warning') { $st = 'warn'; $notes += 'Windows health: Warning'; $why += 'health' }
        elseif ($health -eq 'Unhealthy') { $st = 'fail'; $notes += 'Windows health: Unhealthy'; $why += 'health' }
        foreach ($o in @($pd.OperationalStatus)) {
            $os = Map $OpStatusMap $o
            if ($os -in 'Predictive Failure', 'Error', 'Non-Recoverable Error', 'Lost Communication', 'No Contact') { $st = Get-Worst $st 'fail'; $notes += "status: $os"; $why += 'health' }
            elseif ($os -in 'Degraded', 'Stressed') { $st = Get-Worst $st 'warn'; $notes += "status: $os"; $why += 'health' }
        }

        # Prefer smartctl data (complete SMART), fall back to the Windows storage counters
        $sm = $null
        for ($i = 0; $i -lt $smart.Count; $i++) {
            if ($usedSmart[$i]) { continue }
            $s = $smart[$i]
            $sn = Norm $s.serial_number
            if (($sn -and $sn -eq (Norm $pd.SerialNumber)) -or ((Norm $s.model_name) -and (Norm $s.model_name) -eq (Norm $model))) {
                $sm = $s; $usedSmart[$i] = $true; break
            }
        }
        if ($sm) {
            $r = Test-Smart $sm
            $st = Get-Worst $st $r.Status
            $notes += $r.Notes; $extra += $r.Extra; $temp = $r.Temp; $why += $r.Why
        } else {
            $rel = $null
            Write-Log "  drives: reliability counters disk $($pd.DeviceId) ($model)"
            try { $rel = Get-CimAssociatedInstance -InputObject $pd -ResultClassName MSFT_StorageReliabilityCounter -ErrorAction Stop | Select-Object -First 1 } catch {}
            if ($rel) {
                if ($null -ne $rel.Wear) {
                    $notes += "$($rel.Wear)% worn"
                    if ($rel.Wear -ge 75) { $why += "worn:$($rel.Wear)" }
                    if ($rel.Wear -ge 90) { $st = Get-Worst $st 'fail' } elseif ($rel.Wear -ge 75) { $st = Get-Worst $st 'warn' }
                }
                $unc = [double]$rel.ReadErrorsUncorrected + [double]$rel.WriteErrorsUncorrected
                if ($unc -gt 0) { $st = Get-Worst $st 'warn'; $notes += "$(N $unc) uncorrected read/write errors"; $why += 'errors' }
                if ($rel.Temperature) { $temp = $rel.Temperature }
                if ($rel.TemperatureMax -and $rel.TemperatureMax -lt 200) { $extra += "max $($rel.TemperatureMax) $Deg" }
                if ($null -ne $rel.PowerOnHours) { $extra += "$(N $rel.PowerOnHours '#,0') h powered on" }
                if ($null -ne $rel.StartStopCycleCount) { $extra += "$(N $rel.StartStopCycleCount '#,0') start/stop cycles" }
            } else { $notes += 'detailed SMART data not available' }
        }
        if ($null -ne $temp -and $temp -gt 0) {
            $notes += "$temp $Deg"
            if ($temp -ge 75) { $st = Get-Worst $st 'warn'; $why += "temp:$temp" }
            [void]$Script:DriveTemps.Add("$model $temp $Deg")
        }
        if (-not $notes) { $notes += $health }

        $disk = $disks | Where-Object { [string]$_.Number -eq [string]$pd.DeviceId } | Select-Object -First 1
        $info = @()
        if ($pd.SerialNumber) { $info += "S/N $(([string]$pd.SerialNumber).Trim())" }
        if ($pd.FirmwareVersion) { $info += "firmware $(([string]$pd.FirmwareVersion).Trim())" }
        if ($disk) {
            $ps = @{ 1 = 'MBR'; 2 = 'GPT' }[[int]$disk.PartitionStyle]
            if ($ps) { $info += $ps }
            if ($disk.IsBoot -or $disk.IsSystem) { $info += 'Windows disk' }
        }
        $states += $st
        if ($st -ne 'ok') { Add-Cust 'drives' $st 'drive' @{ name = $model; size = [int]($pd.Size / 1e9); why = @($why | Select-Object -Unique) } }
        $d.Add("$model ($(($kind, "$(N ($pd.Size / 1e9)) GB", "disk $($pd.DeviceId)") | Where-Object { $_ }) -join ', ')): $($notes -join ', ')")
        if ($extra) { $d.Add('    ' + ($extra -join ', ')) }
        if ($info) { $d.Add('    ' + ($info -join ', ')) }
    }

    # Drives that only smartctl sees (e.g. behind a RAID controller)
    for ($i = 0; $i -lt $smart.Count; $i++) {
        if ($usedSmart[$i]) { continue }
        $s = $smart[$i]
        if ($s.device -and $s.device.protocol -eq 'SCSI' -and $Script:Stick) { continue }
        $r = Test-Smart $s
        $states += $r.Status; $n++
        if ($r.Status -ne 'ok') { Add-Cust 'drives' $r.Status 'drive' @{ name = [string]$s.model_name; size = [int]($s.user_capacity.bytes / 1e9); why = $r.Why } }
        $notes = $r.Notes
        if ($null -ne $r.Temp) { $notes += "$($r.Temp) $Deg" }
        $d.Add("$($s.model_name) ($($s.device.name)): $($notes -join ', ')")
        if ($r.Extra) { $d.Add('    ' + ($r.Extra -join ', ')) }
    }

    # Old-style SMART prediction from the storage driver
    Write-Log '  drives: failure prediction'
    $pred = @(Get-Cim MSStorageDriver_FailurePredictStatus 'root/wmi' | Where-Object { $_.PredictFailure })
    if ($pred.Count) { $states += 'fail'; Add-Cust 'drives' 'fail' 'drive_predict'; $d.Add("SMART predicts a drive failure ($($pred.Count) drive(s))") }

    if ($smart.Count) { $d.Add('SMART data from smartctl') }
    elseif ($n) { $d.Add('SMART data from Windows (for full SMART values put smartctl.exe into the tools folder)') }
    if ($Script:Stick) { $d.Add("The StickDoc stick (disk $($Script:Stick.Disk)) is not checked") }
    if (-not $n) { return New-Result 'drives' 'Drives' 'warn' 'No drives found' $d }
    $status = Get-Worst $states
    $summary = @{ ok = "$n drive(s) healthy"; warn = 'A drive needs attention'; fail = 'A drive is failing' }[$status]
    return New-Result 'drives' 'Drives' $status $summary $d
}

# ------------------------------------------------------------------ volumes
function Check-Volumes {
    $states = @(); $parts = @(); $g = @()
    $d = New-Object System.Collections.Generic.List[string]
    $vols = @(Get-Cim MSFT_Volume 'root/Microsoft/Windows/Storage')
    $bl = @{}
    foreach ($e in Get-Cim Win32_EncryptableVolume 'root/cimv2/Security/MicrosoftVolumeEncryption') { if ($e.DriveLetter) { $bl[$e.DriveLetter.TrimEnd(':').ToUpper()] = $e } }
    $sysLetter = $env:SystemDrive.TrimEnd(':').ToUpper()

    foreach ($ld in (Get-Cim Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object DeviceID)) {
        $L = $ld.DeviceID.TrimEnd(':').ToUpper()
        if ($Script:Stick -and $L -eq $Script:Stick.Letter) { continue }
        if (-not $ld.Size) { continue }
        $pct = ($ld.Size - $ld.FreeSpace) * 100 / $ld.Size
        $warnAt, $failAt = 85, 95
        $st = if ($pct -ge $failAt) { 'fail' } elseif ($pct -ge $warnAt) { 'warn' } else { 'ok' }
        if ($L -eq $sysLetter -and $ld.FreeSpace -lt 10GB) { $st = Get-Worst $st 'warn' }
        $name = if ($L -eq $sysLetter) { "${L}: (Windows)" } else { "${L}:" }
        $label = Clean $ld.VolumeName
        $line = "${name}: $(N $pct)% used, $(Format-Bytes $ld.FreeSpace) free of $(Format-Bytes $ld.Size), $($ld.FileSystem)$(if ($label) { ", '$label'" })"

        $v = $vols | Where-Object { [string]$_.DriveLetter -eq $L } | Select-Object -First 1
        $h = Map $HealthMap $v.HealthStatus
        if ($h -eq 'Warning') { $st = Get-Worst $st 'warn'; $line += ', file system health: Warning (run chkdsk)' }
        elseif ($h -eq 'Unhealthy') { $st = Get-Worst $st 'fail'; $line += ', file system health: Unhealthy' }

        $e = $bl[$L]
        if ($e) {
            $conv = [int]$e.ConversionStatus; $prot = [int]$e.ProtectionStatus
            if ($conv -ne 0) {
                $what = switch ($conv) { 1 { 'encrypted' } 2 { 'encrypting' } 3 { 'decrypting' } 4 { 'encryption paused' } 5 { 'decryption paused' } default { "state $conv" } }
                if ($prot -eq 1) {
                    $line += ", BitLocker ON ($what)"
                    [void]$Script:Bitlocker.Add($L)
                } else { $line += ", BitLocker $what but protection suspended" }
            }
        }
        $states += $st
        if ($h -in 'Warning', 'Unhealthy') { Add-Cust 'volumes' $st 'fs_health' @{ drive = $L } }
        elseif ($st -ne 'ok') { Add-Cust 'volumes' $st 'space' @{ drive = $L; pct = [int]$pct; free = [math]::Round($ld.FreeSpace / 1GB, 1) } }
        $d.Add($line)
        $parts += "$name $(N $pct)%"
        $g += New-Gauge $name $pct $warnAt $failAt
    }
    if ($Script:Bitlocker.Count) {
        $list = ($Script:Bitlocker | ForEach-Object { "${_}:" }) -join ', '
        $d.Add("BitLocker is active on $list. Get the recovery key before BIOS updates, board or TPM swaps.")
        Add-Flag 'warn' "BitLocker active on $list (recovery key needed before BIOS/board/TPM work)"
    } elseif (-not $IsAdmin) { $d.Add('BitLocker state needs administrator rights') }
    if (-not $states) { return New-Result 'volumes' 'Disk space' 'warn' 'No drives with a drive letter found' $d }
    return New-Result 'volumes' 'Disk space' (Get-Worst $states) ($parts -join ', ') $d $g
}

# ------------------------------------------------------------------ temperatures
function Check-Temps {
    $st = 'ok'; $parts = @()
    $d = New-Object System.Collections.Generic.List[string]

    $zones = @()
    foreach ($z in Get-Cim Win32_PerfFormattedData_Counters_ThermalZoneInformation) {
        $k = if ($z.HighPrecisionTemperature) { $z.HighPrecisionTemperature / 10 } else { [double]$z.Temperature }
        $c = $k - 273.15
        if ($c -gt 0 -and $c -lt 150) { $zones += @{ Name = ($z.Name -replace '^.*\\', ''); C = $c } }
    }
    if (-not $zones) {
        foreach ($z in Get-Cim MSAcpi_ThermalZoneTemperature 'root/wmi') {
            $c = $z.CurrentTemperature / 10 - 273.15
            if ($c -gt 0 -and $c -lt 150) { $zones += @{ Name = ($z.InstanceName -replace '^.*\\', '' -replace '_\d+$', ''); C = $c } }
        }
    }
    if ($zones) {
        $hot = ($zones | ForEach-Object { $_.C } | Measure-Object -Maximum).Maximum
        $d.Add("Mainboard / CPU (ACPI): " + (($zones | ForEach-Object { "$($_.Name) $(N $_.C) $Deg" }) -join ', '))
        $parts += "ACPI $(N $hot) $Deg"
        $zs = if ($hot -ge 95) { 'fail' } elseif ($hot -ge 85) { 'warn' } else { 'ok' }
        $st = Get-Worst $st $zs
        if ($zs -ne 'ok') { Add-Cust 'temps' $zs 'temp_acpi' @{ t = [int]$hot } }
    }

    # NVIDIA cards bring nvidia-smi with the driver
    $smi = (Get-Command nvidia-smi.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $smi) {
        $p = Join-Path $env:ProgramFiles 'NVIDIA Corporation\NVSMI\nvidia-smi.exe'
        if (Test-Path -LiteralPath $p) { $smi = $p }
    }
    if ($smi) {
        $out = & $smi '--query-gpu=name,temperature.gpu,fan.speed,power.draw,clocks.gr,utilization.gpu,memory.used,memory.total' '--format=csv,noheader,nounits' 2>$null
        foreach ($line in @($out)) {
            $f = @(([string]$line).Split(',') | ForEach-Object { $_.Trim() })
            if ($f.Count -lt 8) { continue }
            $t = 0.0
            if (-not [double]::TryParse($f[1], [Globalization.NumberStyles]::Float, $Inv, [ref]$t)) { continue }
            $l = "GPU ($($f[0])): $(N $t) $Deg"
            if ($f[2] -match '^\d') { $l += ", fan $($f[2])%" }
            if ($f[3] -match '^\d') { $l += ", $(N ([double]::Parse($f[3], $Inv))) W" }
            if ($f[4] -match '^\d') { $l += ", $($f[4]) MHz" }
            if ($f[5] -match '^\d') { $l += ", load $($f[5])%" }
            if ($f[6] -match '^\d') { $l += ", VRAM $($f[6]) / $($f[7]) MB" }
            $d.Add($l)
            $parts += "GPU $(N $t) $Deg"
            $gs = if ($t -ge 100) { 'fail' } elseif ($t -ge 90) { 'warn' } else { 'ok' }
            $st = Get-Worst $st $gs
            if ($gs -ne 'ok') { Add-Cust 'temps' $gs 'temp_gpu' @{ t = [int]$t } }
        }
    }
    if ($Script:DriveTemps.Count) { $d.Add("Drives: $($Script:DriveTemps -join ', ')") }

    $thr = @(Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = $Since } 500)
    if ($thr.Count) {
        $st = Get-Worst $st 'warn'
        Add-Cust 'temps' 'warn' 'throttle' @{ n = $thr.Count; days = $Days }
        $d.Add("CPU slowed down by firmware (heat or power limit): $($thr.Count)x in $Days days, last $(Format-Date $thr[0].TimeCreated -Time)")
        $parts += 'CPU throttling'
    }
    $d.Add('Windows has no CPU core sensor; for full sensor data use HWiNFO or LibreHardwareMonitor')
    $d.Add('Measured at check time')
    if (-not $parts) { return New-Result 'temps' 'Temperatures' 'info' 'No readable temperature sensors' $d -Info }
    return New-Result 'temps' 'Temperatures' $st ($parts -join ', ') $d
}

# ------------------------------------------------------------------ battery
function Check-Battery {
    $bats = @(Get-Cim Win32_Battery)
    if (-not $bats.Count) { return New-Result 'battery' 'Battery' 'info' 'No battery (desktop PC)' @('No battery found') -Info }
    $d = New-Object System.Collections.Generic.List[string]
    $st = 'ok'; $parts = @(); $g = @(); $links = @()
    $static = @(Get-Cim BatteryStaticData 'root/wmi')
    $full = @(Get-Cim BatteryFullChargedCapacity 'root/wmi')
    $cycles = @(Get-Cim BatteryCycleCount 'root/wmi')
    $status = @(Get-Cim BatteryStatus 'root/wmi')

    $i = 0
    foreach ($s in $(if ($static.Count) { $static } else { $bats })) {
        $i++
        $inst = $s.InstanceName
        $f = $full | Where-Object { $_.InstanceName -eq $inst } | Select-Object -First 1
        $c = $cycles | Where-Object { $_.InstanceName -eq $inst } | Select-Object -First 1
        $bs = $status | Where-Object { $_.InstanceName -eq $inst } | Select-Object -First 1
        $label = "Battery $i"
        $name = (Clean $s.ManufactureName), (Clean $s.DeviceName) | Where-Object { $_ }
        if ($name) { $d.Add("${label}: $($name -join ' ')$(if (Clean $s.SerialNumber) { ', S/N ' + (Clean $s.SerialNumber) })") }
        if ($s.DesignedCapacity -and $f -and $f.FullChargedCapacity) {
            $health = $f.FullChargedCapacity * 100 / $s.DesignedCapacity
            $d.Add("Health: $(N $health)% ($(N $f.FullChargedCapacity '#,0') of $(N $s.DesignedCapacity '#,0') mWh design capacity)")
            $parts += "health $(N $health)%"
            $hs = if ($health -lt 50) { 'fail' } elseif ($health -lt 70) { 'warn' } else { 'ok' }
            $hg = New-Gauge "Health $i" $health
            $hg.state = $hs   # here a full bar is good, so the colour comes from the status
            $g += $hg
            $st = Get-Worst $st $hs
            if ($hs -ne 'ok') {
                Add-Flag $hs "Battery health only $(N $health)%"
                Add-Cust 'battery' $hs 'battery_health' @{ pct = [int]$health; cycles = $(if ($c) { [int]$c.CycleCount } else { 0 }) }
            }
        }
        if ($c -and $c.CycleCount) { $d.Add("Charge cycles: $($c.CycleCount)"); $parts += "$($c.CycleCount) cycles" }
        if ($bs) {
            $state = if ($bs.Charging) { 'charging' } elseif ($bs.Discharging) { 'on battery' } elseif ($bs.PowerOnline) { 'plugged in, not charging' } else { 'unknown' }
            $l = "Now: $state"
            if ($bs.Voltage) { $l += ", $(N ($bs.Voltage / 1000) '0.00') V" }
            if ($bs.Charging -and $bs.ChargeRate) { $l += ", charging at $(N ($bs.ChargeRate / 1000) '0.0') W" }
            if ($bs.Discharging -and $bs.DischargeRate) { $l += ", using $(N ($bs.DischargeRate / 1000) '0.0') W" }
            if ($bs.Critical) { $l += ', CRITICAL'; $st = Get-Worst $st 'fail'; Add-Cust 'battery' 'fail' 'battery_critical' }
            $d.Add($l)
        }
    }
    foreach ($b in $bats) {
        $d.Add("Charge level: $($b.EstimatedChargeRemaining)%$(if ($b.Status -and $b.Status -ne 'OK') { ", Windows status: $($b.Status)" })")
        if ($b.Status -and $b.Status -notin 'OK', 'Unknown') { $st = Get-Worst $st 'warn'; Add-Cust 'battery' 'warn' 'battery_status' }
    }
    if (-not $static.Count) { $d.Add('Capacity data not readable (needs administrator rights)') }

    # Windows' own battery report with the full history
    if ($Script:ReportBase) {
        $file = "$($Script:ReportBase)_battery.html"
        & powercfg.exe /batteryreport /output "$file" 2>$null | Out-Null
        if (Test-Path -LiteralPath $file) { $links += [ordered]@{ label = 'Windows battery report (history, capacity over time)'; href = (Split-Path -Leaf $file) } }
    }
    if (-not $parts) { $parts += 'Battery found' }
    return New-Result 'battery' 'Battery' $st ($parts -join ', ') $d $g $links
}

# ------------------------------------------------------------------ devices
$PnpCodes = @{ 1 = 'not configured correctly'; 3 = 'driver corrupted or out of memory'; 10 = 'device cannot start'; 12 = 'not enough free resources';
    14 = 'needs a restart'; 18 = 'drivers need to be reinstalled'; 19 = 'registry entry damaged'; 21 = 'being removed';
    22 = 'disabled'; 24 = 'not present or not working'; 28 = 'no driver installed'; 29 = 'disabled by firmware'; 31 = 'not working properly';
    32 = 'driver disabled'; 33 = 'resource translation failed'; 37 = 'driver failed to load'; 38 = 'previous driver still loaded';
    39 = 'driver corrupted or missing'; 40 = 'driver registry entry damaged'; 41 = 'driver loaded but device not found';
    43 = 'device reported a problem (often hardware)'; 45 = 'not connected'; 47 = 'prepared for safe removal'; 48 = 'driver blocked';
    49 = 'registry too large'; 52 = 'driver signature cannot be verified' }

function Check-Devices {
    $d = New-Object System.Collections.Generic.List[string]
    $all = @(Get-Cim Win32_PnPEntity)
    $bad = @($all | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -notin 0, 22, 45 })
    $disabled = @($all | Where-Object { $_.ConfigManagerErrorCode -eq 22 })
    $st = 'ok'
    if ($bad.Count) {
        $st = 'warn'
        $d.Add("Devices with problems: $($bad.Count)")
        foreach ($b in ($bad | Sort-Object ConfigManagerErrorCode)) {
            $name = if ($b.Name) { $b.Name } else { $b.DeviceID }
            $d.Add("    $name$(if ($b.PNPClass) { " ($($b.PNPClass))" }): code $($b.ConfigManagerErrorCode), $(Map $PnpCodes $b.ConfigManagerErrorCode)")
            $cmc = [int]$b.ConfigManagerErrorCode
            if ($cmc -eq 43) { $st = 'fail' }
            $kind = if ($cmc -eq 43) { 'hw' } elseif ($cmc -in 1, 3, 18, 19, 28, 31, 32, 37, 38, 39, 40, 41, 48, 52) { 'driver' } else { 'other' }
            Add-Cust 'devices' $(if ($cmc -eq 43) { 'fail' } else { 'warn' }) 'device' @{ name = [string]$name; kind = $kind }
        }
    } else { $d.Add('Devices with problems: none') }
    if ($disabled.Count) {
        $d.Add("Disabled devices: $($disabled.Count)")
        foreach ($b in $disabled) { $d.Add("    $($b.Name)") }
    }

    # Which components Windows sees, to check against the device's spec sheet
    $d.Add('Components found:')
    $groups = [ordered]@{
        'Audio'        = @(Get-Cim Win32_SoundDevice | ForEach-Object { $_.Name })
        'Camera'       = @($all | Where-Object { $_.PNPClass -in 'Camera', 'Image' } | ForEach-Object { $_.Name })
        'Bluetooth'    = @($all | Where-Object { $_.PNPClass -eq 'Bluetooth' -and $_.DeviceID -match '^(USB|PCI)\\' } | ForEach-Object { $_.Name })
        'Fingerprint'  = @($all | Where-Object { $_.PNPClass -eq 'Biometric' } | ForEach-Object { $_.Name })
        'Touch'        = @($all | Where-Object { $_.PNPClass -in 'Mouse', 'HIDClass' -and $_.Name -match 'touch ?pad|touch ?screen|precision|I2C HID|touch' } | ForEach-Object { $_.Name })
        'Card reader'  = @($all | Where-Object { $_.PNPClass -eq 'SDHost' -or $_.Name -match 'card reader' } | ForEach-Object { $_.Name })
        'Smart card'   = @($all | Where-Object { $_.PNPClass -eq 'SmartCardReader' } | ForEach-Object { $_.Name })
        'Mobile broadband' = @($all | Where-Object { $_.PNPClass -eq 'Net' -and $_.Name -match 'Mobile Broadband|LTE|5G|WWAN|Snapdragon X' } | ForEach-Object { $_.Name })
        'Thunderbolt / USB4' = @($all | Where-Object { $_.Name -match 'Thunderbolt|USB4' -and $_.PNPClass -eq 'System' } | ForEach-Object { $_.Name })
    }
    foreach ($k in $groups.Keys) {
        $names = @($groups[$k] | Where-Object { $_ } | Sort-Object -Unique)
        $d.Add("    ${k}: $(if ($names) { $names -join '; ' } else { 'none' })")
    }
    $d.Add("$($all.Count) devices in total")
    $summary = if ($bad.Count) { "$($bad.Count) device(s) with problems" } else { 'All devices working' }
    if ($disabled.Count) { $summary += ", $($disabled.Count) disabled" }
    return New-Result 'devices' 'Devices' $st $summary $d
}

# ------------------------------------------------------------------ bluescreens
$BugChecks = @{ 0x0A = 'IRQL_NOT_LESS_OR_EQUAL'; 0x19 = 'BAD_POOL_HEADER'; 0x1A = 'MEMORY_MANAGEMENT'; 0x1E = 'KMODE_EXCEPTION_NOT_HANDLED';
    0x24 = 'NTFS_FILE_SYSTEM'; 0x3B = 'SYSTEM_SERVICE_EXCEPTION'; 0x4E = 'PFN_LIST_CORRUPT'; 0x50 = 'PAGE_FAULT_IN_NONPAGED_AREA';
    0x77 = 'KERNEL_STACK_INPAGE_ERROR'; 0x7A = 'KERNEL_DATA_INPAGE_ERROR'; 0x7B = 'INACCESSIBLE_BOOT_DEVICE'; 0x7E = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED';
    0x7F = 'UNEXPECTED_KERNEL_MODE_TRAP'; 0x9F = 'DRIVER_POWER_STATE_FAILURE'; 0xA0 = 'INTERNAL_POWER_ERROR'; 0xC2 = 'BAD_POOL_CALLER';
    0xD1 = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'; 0xEA = 'THREAD_STUCK_IN_DEVICE_DRIVER'; 0xED = 'UNMOUNTABLE_BOOT_VOLUME'; 0xEF = 'CRITICAL_PROCESS_DIED';
    0xF4 = 'CRITICAL_OBJECT_TERMINATION'; 0xFC = 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY'; 0x101 = 'CLOCK_WATCHDOG_TIMEOUT';
    0x109 = 'CRITICAL_STRUCTURE_CORRUPTION'; 0x113 = 'VIDEO_DXGKRNL_FATAL_ERROR'; 0x116 = 'VIDEO_TDR_FAILURE'; 0x117 = 'VIDEO_TDR_TIMEOUT_DETECTED';
    0x119 = 'VIDEO_SCHEDULER_INTERNAL_ERROR'; 0x124 = 'WHEA_UNCORRECTABLE_ERROR'; 0x133 = 'DPC_WATCHDOG_VIOLATION';
    0x139 = 'KERNEL_SECURITY_CHECK_FAILURE'; 0x13A = 'KERNEL_MODE_HEAP_CORRUPTION'; 0x154 = 'UNEXPECTED_STORE_EXCEPTION';
    0x1C8 = 'MANUALLY_INITIATED_POWER_BUTTON_HOLD'; 0x1000007E = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M'; 0x1000008E = 'KERNEL_MODE_EXCEPTION_NOT_HANDLED_M';
    0x100000EA = 'THREAD_STUCK_IN_DEVICE_DRIVER_M' }
$BugHints = @{ 0x124 = 'hardware error: CPU, RAM, mainboard or power supply'; 0x101 = 'often CPU or mainboard';
    0x1A = 'often RAM'; 0x4E = 'often RAM'; 0x50 = 'RAM or driver'; 0x19 = 'RAM or driver'; 0xC2 = 'driver or RAM';
    0x7A = 'drive or cable'; 0x77 = 'drive or cable'; 0xF4 = 'often drive'; 0x154 = 'often drive'; 0x24 = 'drive or file system';
    0x7B = 'boot drive not reachable'; 0xED = 'boot drive'; 0x116 = 'graphics card or driver'; 0x117 = 'graphics card or driver';
    0x113 = 'graphics driver'; 0x119 = 'graphics driver'; 0x9F = 'driver / power management'; 0xA0 = 'power management';
    0x133 = 'driver or storage firmware'; 0x1C8 = 'power button held by the user' }
# Likely cause for the customer report
$BugCat = @{ 0x124 = 'hw'; 0x101 = 'cpu'; 0x1A = 'ram'; 0x4E = 'ram'; 0x50 = 'ram'; 0x19 = 'ram'; 0xC2 = 'ram';
    0x7A = 'drive'; 0x77 = 'drive'; 0xF4 = 'drive'; 0x154 = 'drive'; 0x24 = 'drive'; 0x7B = 'drive'; 0xED = 'drive';
    0x116 = 'gpu'; 0x117 = 'gpu'; 0x113 = 'gpu'; 0x119 = 'gpu'; 0x9F = 'driver'; 0xA0 = 'driver'; 0x133 = 'driver';
    0xD1 = 'driver'; 0x3B = 'driver'; 0x7E = 'driver'; 0x1E = 'driver'; 0xEA = 'gpu' }
$HardwareBugChecks = @(0x124, 0x101, 0x7A, 0x77, 0xF4, 0x154)

function Check-Bluescreens {
    $d = New-Object System.Collections.Generic.List[string]
    $st = 'ok'; $links = @()
    $bc = @(Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $Since } 200)
    $counts = [ordered]@{}; $cats = [ordered]@{}
    foreach ($e in $bc) {
        $text = ((@($e.Properties | ForEach-Object { $_.Value }) -join ' ') + ' ' + $e.Message)
        $code = $null; $name = 'unknown'; $hint = ''
        if ($text -match '0x([0-9a-fA-F]{1,8})\b') {
            $code = [Convert]::ToInt64($Matches[1], 16)
            if ($code -le [int]::MaxValue) {
                if ($BugChecks.ContainsKey([int]$code)) { $name = $BugChecks[[int]$code] }
                if ($BugHints.ContainsKey([int]$code)) { $hint = $BugHints[[int]$code] }
                if ($HardwareBugChecks -contains [int]$code) { $st = 'fail' }
                if ($BugCat.ContainsKey([int]$code)) { $cats[$BugCat[[int]$code]] = $true }
            }
        }
        $hex = if ($null -ne $code) { '0x{0:X}' -f $code } else { '?' }
        $key = "$name ($hex)"
        if (-not $counts.Contains($key)) { $counts[$key] = @{ N = 0; Last = $e.TimeCreated; Hint = $hint } }
        $counts[$key].N++
    }
    if ($bc.Count) {
        $st = Get-Worst $st $(if ($bc.Count -ge 3) { 'fail' } else { 'warn' })
        Add-Cust 'bluescreens' $st 'bsod' @{ n = $bc.Count; days = $Days; cats = @($cats.Keys) }
        $d.Add("Bluescreens in the last $Days days: $($bc.Count)")
        foreach ($k in $counts.Keys) {
            $c = $counts[$k]
            $d.Add("    $($c.N)x $k, last $(Format-Date $c.Last -Time)$(if ($c.Hint) { " - $($c.Hint)" })")
        }
    } else { $d.Add("Bluescreens in the last $Days days: none") }

    # Kernel-Power 41: Windows did not shut down cleanly (freeze, power loss, reset button)
    $kp = @(Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $Since } 200)
    $hard = 0; $btn = 0
    foreach ($e in $kp) {
        $ed = Get-EventData $e
        if ([string]$ed['BugcheckCode'] -notin '', '0') { continue }   # already counted as a bluescreen
        if ([string]$ed['PowerButtonTimestamp'] -notin '', '0') { $btn++ } else { $hard++ }
    }
    if ($hard + $btn) {
        $st = Get-Worst $st 'warn'
        Add-Cust 'bluescreens' 'warn' 'restarts' @{ n = $hard + $btn; btn = $btn; days = $Days }
        $d.Add("Unexpected restarts without a bluescreen: $($hard + $btn) (last $(Format-Date $kp[0].TimeCreated -Time))")
        if ($hard) { $d.Add("    $hard x power lost, reset or hard freeze") }
        if ($btn) { $d.Add("    $btn x power button held to switch off") }
    } else { $d.Add('Unexpected restarts without a bluescreen: none') }

    # Crash dump files
    $mini = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Minidump') -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($mini.Count) {
        $d.Add("Minidumps: $($mini.Count), newest $(Format-Date $mini[0].LastWriteTime -Time)")
        if ($Script:ReportBase -and -not $NoDumps) {
            $dest = "$($Script:ReportBase)_dumps"
            $copy = @($mini | Where-Object { $_.LastWriteTime -ge $Now.AddDays(-90) } | Select-Object -First 10)
            if ($copy.Count) {
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                foreach ($m in $copy) { Copy-Item -LiteralPath $m.FullName -Destination $dest -Force }
                $links += [ordered]@{ label = "Copied minidumps ($($copy.Count)) for WinDbg / BlueScreenView"; href = (Split-Path -Leaf $dest) }
            }
        }
    } elseif ($IsAdmin) { $d.Add('Minidumps: none') }
    else { $d.Add('Minidumps: need administrator rights') }
    $full = Get-Item -LiteralPath (Join-Path $env:SystemRoot 'MEMORY.DMP') -ErrorAction SilentlyContinue
    if ($full) { $d.Add("Full memory dump: MEMORY.DMP, $(Format-Bytes $full.Length), $(Format-Date $full.LastWriteTime -Time)") }

    # Live kernel reports: driver or hardware hangs that Windows recovered from (e.g. GPU resets)
    $lkr = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'LiveKernelReports') -Recurse -Filter *.dmp -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Since })
    if ($lkr.Count) {
        $grp = $lkr | Group-Object { $_.Directory.Name } | Sort-Object Count -Descending
        $d.Add("Recovered hangs (live kernel reports): " + (($grp | ForEach-Object { "$($_.Name) $($_.Count)x" }) -join ', '))
        if ($lkr | Where-Object { $_.Directory.Name -match 'WATCHDOG' }) { $d.Add('    WATCHDOG reports usually mean the graphics driver hung and was restarted') }
    }

    $sumParts = @()
    if ($bc.Count) { $sumParts += "$($bc.Count) bluescreen(s)" }
    if ($hard + $btn) { $sumParts += "$($hard + $btn) unexpected restart(s)" }
    $summary = if ($sumParts) { ($sumParts -join ', ') + " in $Days days" } else { "No bluescreens in $Days days" }
    if ($bc.Count) { $summary += " ($((@($counts.Keys) | Select-Object -First 2 | ForEach-Object { $_ -replace ' \(.*$', '' }) -join ', '))" }
    return New-Result 'bluescreens' 'Bluescreens' $st $summary $d $null $links
}

# ------------------------------------------------------------------ hardware events (system log)
$EventRules = @(
    @{ P = '^Microsoft-Windows-WHEA-Logger$'; Ids = @(1, 18, 20, 46); S = 'fail'; L = 'fatal hardware error (WHEA)'; K = 'whea_fatal' }
    @{ P = '^Microsoft-Windows-WHEA-Logger$'; Ids = @(17, 19, 47); S = 'warn'; L = 'corrected hardware error (WHEA)'; K = 'whea_corr' }
    @{ P = '^disk$'; Ids = @(7, 52); S = 'fail'; L = 'bad block / predicted drive failure'; K = 'badblock' }
    @{ P = '^disk$'; Ids = @(11, 51, 153, 154); S = 'warn'; L = 'disk I/O error'; K = 'disk_io' }
    @{ P = '^(Microsoft-Windows-)?Ntfs$'; Ids = @(55, 137, 140); S = 'warn'; L = 'file system corruption'; K = 'ntfs' }
    @{ P = '^(stornvme|storahci|iaStor\w*|amd_sata|amdsata|nvme\w*|secnvme|stor\w*)$'; Ids = @(129, 11); S = 'warn'; L = 'storage controller reset / timeout'; K = 'storage_reset' }
    @{ P = '^Display$'; Ids = @(4101); S = 'warn'; L = 'graphics driver stopped responding (TDR)'; K = 'gpu_tdr' }
    @{ P = '^nvlddmkm$'; Ids = $null; S = 'warn'; L = 'NVIDIA driver error'; K = 'gpu_driver' }
    @{ P = '^(amdkmdag|amdwddmg|amdkmpfd)$'; Ids = $null; S = 'warn'; L = 'AMD graphics driver error'; K = 'gpu_driver' }
    @{ P = '^igfx\w*$'; Ids = $null; S = 'warn'; L = 'Intel graphics driver error'; K = 'gpu_driver' }
    @{ P = '^EventLog$'; Ids = @(6008); S = 'warn'; L = 'unexpected shutdown'; K = 'unexpected_shutdown' }
    @{ P = '^Microsoft-Windows-Resource-Exhaustion-Detector$'; Ids = @(2004); S = 'warn'; L = 'low virtual memory'; K = 'low_vm' }
    @{ P = '^(USBHUB3|Microsoft-Windows-USB-USBHUB3|usbhub)$'; Ids = $null; S = 'warn'; L = 'USB error'; K = 'usb' }
    @{ P = '^Microsoft-Windows-Kernel-Boot$'; Ids = @(29); S = 'warn'; L = 'Windows failed to boot'; K = 'boot_fail' }
)

function Check-HwEvents {
    $d = New-Object System.Collections.Generic.List[string]
    $ev = @(Get-Events @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $Since } 20000)
    $st = 'ok'; $hits = [ordered]@{}; $matched = @{}
    foreach ($e in $ev) {
        foreach ($r in $EventRules) {
            if ($e.ProviderName -notmatch $r.P) { continue }
            if ($r.Ids) { if ($r.Ids -notcontains $e.Id) { continue } }
            elseif ($e.Level -gt 2) { continue }   # whole-provider rules count only errors
            if (-not $hits.Contains($r.L)) { $hits[$r.L] = @{ S = $r.S; K = $r.K; E = New-Object System.Collections.ArrayList } }
            [void]$hits[$r.L].E.Add($e)
            $matched[$e.RecordId] = $true
            break
        }
    }
    foreach ($k in $hits.Keys) {
        $h = $hits[$k]
        $st = Get-Worst $st $h.S
        Add-Cust 'hwevents' $h.S $h.K @{ n = $h.E.Count; days = $Days }
        $d.Add("$($h.E.Count)x ${k}, last $(Format-Date $h.E[0].TimeCreated -Time)")
        foreach ($e in ($h.E | Select-Object -First 3)) {
            $msg = First-Line $e.Message 180
            $d.Add("    $(Format-Date $e.TimeCreated -Time) $($e.ProviderName) $($e.Id): $msg")
        }
    }
    if (-not $hits.Count) { $d.Add("No hardware-related errors in the last $Days days") }

    $other = @($ev | Where-Object { $_.Level -le 2 -and -not $matched[$_.RecordId] -and $_.ProviderName -notmatch 'WER-SystemErrorReporting|Kernel-Power|WindowsUpdateClient' })
    $top = $other | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8
    $d.Add("Other system errors: $($other.Count)$(if ($top) { ' (' + (($top | ForEach-Object { "$($_.Name) $($_.Count)x" }) -join ', ') + ')' })")
    $d.Add("Windows system log, last $Days days")
    $summary = if ($hits.Count) { (($hits.Keys | Select-Object -First 3 | ForEach-Object { "$($hits[$_].E.Count)x $_" }) -join ', ') } else { "No hardware errors in $Days days" }
    return New-Result 'hwevents' 'Hardware events' $st $summary $d
}

# ------------------------------------------------------------------ app crashes
function Check-AppCrashes {
    $d = New-Object System.Collections.Generic.List[string]
    $ev = @(Get-Events @{ LogName = 'Application'; ProviderName = 'Application Error', 'Application Hang'; Id = 1000, 1002; StartTime = $Since } 3000)
    $crash = @{}; $hang = @{}
    foreach ($e in $ev) {
        $app = [string]$e.Properties[0].Value
        if (-not $app) { $app = 'unknown' }
        if ($e.Id -eq 1000) {
            $mod = [string]$e.Properties[3].Value
            if (-not $crash.ContainsKey($app)) { $crash[$app] = @{ N = 0; Mods = @{} } }
            $crash[$app].N++
            if ($mod) { $crash[$app].Mods[$mod] = 1 + [int]$crash[$app].Mods[$mod] }
        } else { $hang[$app] = 1 + [int]$hang[$app] }
    }
    $nCrash = ($crash.Values | ForEach-Object { $_.N } | Measure-Object -Sum).Sum
    $nHang = ($hang.Values | Measure-Object -Sum).Sum
    $st = 'ok'
    if ($nCrash -ge 5 -or ($crash.Values | Where-Object { $_.N -ge 3 })) {
        $st = 'warn'
        $topApp = $crash.Keys | Sort-Object { -$crash[$_].N } | Select-Object -First 1
        Add-Cust 'apps' 'warn' 'apps' @{ n = [int]$nCrash; top = [string]$topApp; days = $Days }
    }
    if ($crash.Count) {
        $d.Add("Program crashes: $nCrash")
        foreach ($k in ($crash.Keys | Sort-Object { -$crash[$_].N } | Select-Object -First 10)) {
            $mods = ($crash[$k].Mods.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 2 | ForEach-Object { $_.Key }) -join ', '
            $d.Add("    ${k}: $($crash[$k].N)x$(if ($mods) { " (in $mods)" })")
        }
    } else { $d.Add('Program crashes: none') }
    if ($hang.Count) {
        $d.Add("Programs that stopped responding: $nHang")
        foreach ($k in ($hang.Keys | Sort-Object { -$hang[$_] } | Select-Object -First 8)) { $d.Add("    ${k}: $($hang[$k])x") }
    }
    $rel = @(Get-Cim Win32_ReliabilityStabilityMetrics) | Sort-Object TimeGenerated -Descending | Select-Object -First 1
    if ($rel) { $d.Add("Windows stability index: $(N $rel.SystemStabilityIndex '0.0') of 10") }
    $d.Add("Last $Days days")
    $top = ($crash.Keys | Sort-Object { -$crash[$_].N } | Select-Object -First 3) -join ', '
    $summary = if ($nCrash -or $nHang) { "$([int]$nCrash) crash(es), $([int]$nHang) hang(s) in $Days days$(if ($top) { " ($top)" })" } else { "No program crashes in $Days days" }
    return New-Result 'apps' 'Program crashes' $st $summary $d
}

# ------------------------------------------------------------------ services
$ImportantServices = 'RpcSs', 'DcomLaunch', 'Winmgmt', 'EventLog', 'PlugPlay', 'Power', 'ProfSvc', 'Schedule', 'SamSs', 'UserManager',
    'BrokerInfrastructure', 'Dhcp', 'Dnscache', 'nsi', 'BFE', 'mpssvc', 'Wcmsvc', 'LanmanWorkstation', 'CryptSvc', 'AudioSrv',
    'AudioEndpointBuilder', 'Themes', 'WlanSvc', 'BthServ', 'wuauserv'
$IgnoreStopped = 'gupdate', 'gupdatem', 'edgeupdate', 'edgeupdatem', 'MapsBroker', 'sppsvc', 'RemoteRegistry', 'tiledatamodelsvc',
    'WbioSrvc', 'GoogleUpdaterService*', 'GoogleUpdaterInternalService*', 'MozillaMaintenance', 'clr_optimization*', 'ShellHWDetection',
    'Intel(R) TPM Provisioning Service', 'TrustedInstaller', 'wuauserv', 'BITS', 'UsoSvc', 'WaaSMedicSvc'

function Check-Services {
    $d = New-Object System.Collections.Generic.List[string]
    $svc = @(Get-Cim Win32_Service)
    $st = 'ok'; $problems = @()
    foreach ($name in $ImportantServices) {
        $s = $svc | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $s) { continue }
        if ($s.StartMode -eq 'Disabled' -and $name -ne 'wuauserv') { $problems += "$($s.DisplayName) ($name): disabled" }
        elseif ($s.StartMode -eq 'Auto' -and $s.State -ne 'Running') { $problems += "$($s.DisplayName) ($name): $($s.State)" }
    }
    if ($problems) { $st = 'warn'; $d.Add('Important services not running:'); foreach ($p in $problems) { $d.Add("    $p") } }
    else { $d.Add('Important Windows services: all running') }

    $stopped = @($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | Where-Object {
            $n = $_.Name
            -not ($IgnoreStopped | Where-Object { $n -like $_ }) -and
            -not (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$n\TriggerInfo") -and
            ($ImportantServices -notcontains $n)
        })
    if ($stopped.Count) {
        if ($stopped | Where-Object { $_.ExitCode -and $_.ExitCode -ne 0 }) { $st = Get-Worst $st 'warn' }
        $d.Add("Other automatic services not running: $($stopped.Count)")
        foreach ($s in $stopped | Select-Object -First 15) {
            $d.Add("    $($s.DisplayName) ($($s.Name))$(if ($s.ExitCode) { ", exit code $($s.ExitCode)" })")
        }
    }
    $third = @($svc | Where-Object { $_.State -eq 'Running' -and $_.PathName -and $_.PathName -notmatch '\\Windows\\|\\Microsoft\\|\\Windows Defender\\' })
    if ($third.Count) {
        $d.Add("Third-party services running: $($third.Count)")
        $d.Add('    ' + (($third | Sort-Object DisplayName | Select-Object -First 25 | ForEach-Object { $_.DisplayName }) -join ', '))
    }
    if ($problems) { Add-Cust 'services' 'warn' 'services' @{ n = @($problems).Count } }
    elseif ($st -eq 'warn') { Add-Cust 'services' 'warn' 'services_failed' @{ n = $stopped.Count } }
    $summary = if ($problems) { "$($problems.Count) important service(s) not running" } elseif ($st -eq 'warn') { "$($stopped.Count) service(s) failed to start" } else { 'All important services running' }
    return New-Result 'services' 'Services' $st $summary $d
}

# ------------------------------------------------------------------ updates
function Check-Updates {
    $d = New-Object System.Collections.Generic.List[string]
    $st = 'ok'
    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    $last = $null
    if ($hf.Count) {
        $last = $hf[0].InstalledOn
        $d.Add("Last Windows update installed: $(Format-Date $last) ($(Format-Ago $last))")
        $d.Add('    ' + (($hf | Select-Object -First 6 | ForEach-Object { "$($_.HotFixID) $(Format-Date $_.InstalledOn)" }) -join ', '))
        if (($Now - $last).TotalDays -gt 60) { $st = 'warn'; Add-Cust 'updates' 'warn' 'updates_old' @{ days = [int]($Now - $last).TotalDays } }
    }

    $failed = @()
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $hist = @($searcher.QueryHistory(0, [math]::Min($total, 200)))
            $failed = @($hist | Where-Object { $_.ResultCode -in 4, 5 -and $_.Date -ge $Since.ToUniversalTime() })
            $okDrv = @($hist | Where-Object { $_.ResultCode -eq 2 -and $_.Title -notmatch 'KB2267602|Defender|Security Intelligence' } | Select-Object -First 1)
            if (-not $last -and $okDrv.Count) { $d.Add("Last update installed: $(Format-Date $okDrv[0].Date) $($okDrv[0].Title)") }
        }
    } catch {}
    if ($failed.Count) {
        $st = 'warn'
        Add-Cust 'updates' 'warn' 'updates_failed' @{ n = $failed.Count; days = $Days }
        $d.Add("Failed updates in the last $Days days: $($failed.Count)")
        foreach ($f in ($failed | Select-Object -First 6)) { $d.Add("    $(Format-Date $f.Date) $($f.Title)") }
    } else { $d.Add("Failed updates in the last $Days days: none") }

    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
              (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    if ($reboot) { $d.Add('Restart pending to finish installing updates'); Add-Flag 'info' 'A restart is pending to finish Windows updates' }
    $wu = @(Get-Cim Win32_Service -Filter "Name='wuauserv'")[0]
    if ($wu -and $wu.StartMode -eq 'Disabled') { $st = 'warn'; $d.Add('Windows Update service is disabled'); Add-Cust 'updates' 'warn' 'wu_disabled' }
    if ($Script:Identity.Os -match 'Windows 10') { $d.Add('Windows 10 reached end of support on 2025-10-14') }

    $summary = if ($last) { "Last update $(Format-Ago $last)" } else { 'Update history not readable' }
    if ($failed.Count) { $summary += ", $($failed.Count) failed" }
    if ($reboot) { $summary += ', restart pending' }
    return New-Result 'updates' 'Updates' $st $summary $d
}

# ------------------------------------------------------------------ security
function Check-Security {
    $d = New-Object System.Collections.Generic.List[string]
    $st = 'ok'; $parts = @()

    $avs = @(Get-Cim AntiVirusProduct 'root/SecurityCenter2')
    $active = @()
    foreach ($a in $avs) {
        $hex = ([int]$a.productState).ToString('X6')
        $on = $hex.Substring(2, 2) -in '10', '11'
        $current = $hex.Substring(4, 2) -eq '00'
        if ($on) { $active += $a.displayName }
        $d.Add("Antivirus: $($a.displayName), $(if ($on) { 'active' } else { 'off' }), $(if ($current) { 'up to date' } else { 'out of date' })")
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $l = "Defender: mode $($mp.AMRunningMode), real-time protection $(if ($mp.RealTimeProtectionEnabled) { 'on' } else { 'off' })"
        if ($mp.AntivirusSignatureLastUpdated) { $l += ", signatures from $(Format-Date $mp.AntivirusSignatureLastUpdated)" }
        $d.Add($l)
        if ($mp.QuickScanEndTime) { $d.Add("    last quick scan $(Format-Date $mp.QuickScanEndTime -Time)") }
        $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $Since })
        if ($threats.Count) { $st = 'warn'; $d.Add("Threats detected in the last $Days days: $($threats.Count)"); Add-Cust 'security' 'warn' 'threats' @{ n = $threats.Count; days = $Days } }
    } catch {}
    if ($avs.Count -and -not $active) { $st = 'warn'; $parts += 'no active antivirus'; Add-Cust 'security' 'warn' 'no_av' }
    elseif ($active) { $parts += ($active -join ', ') }

    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop)
        $off = @($fw | Where-Object { [string]$_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
        $d.Add("Firewall: " + (($fw | ForEach-Object { "$($_.Name) $(if ([string]$_.Enabled -eq 'True') { 'on' } else { 'off' })" }) -join ', '))
        if ($off.Count -eq $fw.Count -and $fw.Count) { $st = 'warn'; $parts += 'firewall off'; Add-Cust 'security' 'warn' 'fw_off' }
    } catch {}

    $b = $Script:Boot
    if (-not $b) { $b = Get-BootInfo; $Script:Boot = $b }
    $sb = if ($null -eq $b.SecureBoot) { 'unknown' } elseif ($b.SecureBoot) { 'on' } else { 'off' }
    $d.Add("Boot mode: $($b.Mode), Secure Boot $sb")
    $parts += "Secure Boot $sb"

    $tpm = @(Get-Cim Win32_Tpm 'root/cimv2/Security/MicrosoftTpm')[0]
    if ($tpm) {
        $spec = ([string]$tpm.SpecVersion -split ',')[0].Trim()
        $d.Add("TPM: version $spec, $(Clean $tpm.ManufacturerIdTxt) firmware $($tpm.ManufacturerVersion), $(if ($tpm.IsEnabled_InitialValue) { 'enabled' } else { 'disabled' })")
        $parts += "TPM $spec"
    } elseif ($IsAdmin) { $d.Add('TPM: none found (Windows 11 needs TPM 2.0)'); $parts += 'no TPM' }

    if ($Script:Bitlocker.Count) { $d.Add("BitLocker: on ($(($Script:Bitlocker | ForEach-Object { "${_}:" }) -join ', '))"); $parts += 'BitLocker on' }
    else { $d.Add('BitLocker: off') }
    $uac = Get-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    if ($uac -eq 0) { $d.Add('User Account Control: off') }

    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch {}
    if ($admins) { $d.Add("Administrators: $($admins -join ', ')") }
    $users = @(Get-Cim Win32_UserAccount -Filter 'LocalAccount=True AND Disabled=False' | ForEach-Object { $_.Name })
    if ($users) { $d.Add("Local accounts: $($users -join ', ')") }
    $cs = @(Get-Cim Win32_ComputerSystem)[0]
    if ($cs.PartOfDomain) { $d.Add("Domain: $($cs.Domain)") } else { $d.Add("Workgroup: $($cs.Workgroup)") }

    return New-Result 'security' 'Security' $st ($parts -join ', ') $d
}

# ------------------------------------------------------------------ network
function Check-Network {
    $d = New-Object System.Collections.Generic.List[string]
    $adapters = @()
    try { $adapters = @(Get-NetAdapter -Physical -ErrorAction Stop | Sort-Object Name) } catch {}
    foreach ($a in $adapters) {
        $ip = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.IPAddress }) -join ', '
        $l = "$($a.Name): $($a.InterfaceDescription), $($a.Status)"
        if ($a.Status -eq 'Up' -and $a.LinkSpeed) { $l += ", $($a.LinkSpeed)" }
        if ($ip) { $l += ", $ip" }
        $d.Add($l)
        $d.Add("    MAC $($a.MacAddress)$(if ($a.DriverVersion) { ", driver $($a.DriverVersion)" })")
    }
    if (-not $adapters) {
        foreach ($a in Get-Cim Win32_NetworkAdapter -Filter 'PhysicalAdapter=True') { $d.Add("$($a.NetConnectionID): $($a.Name), MAC $($a.MACAddress)") }
    }
    $wifi = netsh.exe wlan show interfaces 2>$null | Out-String
    if ($wifi -match '(?m)^\s*SSID\s*:\s*(.+)$') {
        $ssid = $Matches[1].Trim()
        $sig = if ($wifi -match '(?m)^\s*\S+\s*:\s*(\d+)\s*%\s*$') { " $($Matches[1])%" } else { '' }
        $d.Add("Wi-Fi connected to: $ssid$(if ($sig) { ", signal$sig" })")
    }
    $online = $false
    try {
        $w = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        $online = ([string]$w.Content) -match 'Microsoft Connect Test'
    } catch {}
    $d.Add("Internet: $(if ($online) { 'reachable' } else { 'not reachable' })")
    $up = @($adapters | Where-Object { $_.Status -eq 'Up' })
    $summary = "$($adapters.Count) adapter(s), $($up.Count) connected, internet $(if ($online) { 'OK' } else { 'offline' })"
    return New-Result 'network' 'Network' 'info' $summary $d -Info
}

# ------------------------------------------------------------------ displays
function Convert-WmiString($Arr) {
    if (-not $Arr) { return '' }
    return (-join (@($Arr) | Where-Object { $_ -ne 0 } | ForEach-Object { [char][int]$_ })).Trim()
}

function Check-Displays {
    $d = New-Object System.Collections.Generic.List[string]
    $ids = @(Get-Cim WmiMonitorID 'root/wmi')
    $params = @(Get-Cim WmiMonitorBasicDisplayParams 'root/wmi')
    $conns = @(Get-Cim WmiMonitorConnectionParams 'root/wmi')
    $tech = @{ 0 = 'VGA'; 1 = 'S-Video'; 2 = 'Composite'; 3 = 'Component'; 4 = 'DVI'; 5 = 'HDMI'; 6 = 'LVDS'; 8 = 'D-Jpn';
        9 = 'SDI'; 10 = 'DisplayPort'; 11 = 'internal DisplayPort'; 12 = 'UDI'; 13 = 'internal UDI'; 14 = 'SDTV'; 15 = 'Miracast' }
    $names = @()
    foreach ($m in $ids) {
        $mk = Convert-WmiString $m.ManufacturerName
        $nm = Convert-WmiString $m.UserFriendlyName
        $sn = Convert-WmiString $m.SerialNumberID
        $p = $params | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        $c = $conns | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1
        $parts = @()
        if ($p -and $p.MaxHorizontalImageSize -and $p.MaxVerticalImageSize) {
            $inch = [math]::Sqrt([math]::Pow($p.MaxHorizontalImageSize, 2) + [math]::Pow($p.MaxVerticalImageSize, 2)) / 2.54
            $parts += "$(N $inch '0.0') inch"
        }
        if ($c) {
            $v = [long]$c.VideoOutputTechnology
            $parts += $(if ($v -eq 2147483648) { 'built-in panel' } else { Map $tech $v })
        }
        if ($sn -and $sn -ne '0') { $parts += "S/N $sn" }
        if ($m.YearOfManufacture) { $parts += "made $($m.YearOfManufacture)$(if ($m.WeekOfManufacture) { " week $($m.WeekOfManufacture)" })" }
        $label = (($mk, $nm) | Where-Object { $_ }) -join ' '
        if (-not $label) { $label = ($m.InstanceName -split '\\')[1] }
        $names += $label
        $d.Add("Screen: $label$(if ($parts) { ' (' + ($parts -join ', ') + ')' })")
    }
    foreach ($g in Get-Gpus) {
        if ($g.Width) { $d.Add("$($g.Name): $($g.Width) x $($g.Height) at $($g.Hz) Hz") }
    }
    if (-not $ids.Count) { $d.Add('No screen information found') }
    $summary = if ($names) { "$($names.Count) screen(s): $($names -join ', ')" } else { 'No screens detected' }
    return New-Result 'displays' 'Screens' 'info' $summary $d -Info
}

# ------------------------------------------------------------------ main
function Write-CheckLine($r) {
    $c = @{ ok = 'Green'; info = 'Cyan'; warn = 'Yellow'; fail = 'Red' }[$r.status]
    $t = @{ ok = '  OK  '; info = ' INFO '; warn = ' WARN '; fail = ' FAIL ' }[$r.status]
    Write-Host "`r  [" -NoNewline
    Write-Host $t -ForegroundColor $c -NoNewline
    Write-Host ('] {0,-17}' -f $r.title) -NoNewline
    $s = [string]$r.summary
    if ($s.Length -gt 90) { $s = $s.Substring(0, 87) + '...' }
    Write-Host $s
}

function Safe-Name([string]$s) {
    $s = ($s -replace '[\\/:*?"<>|]', '' -replace '\s+', '-').Trim('-')
    if ($s.Length -gt 40) { $s = $s.Substring(0, 40) }
    return $s
}

try { $Host.UI.RawUI.WindowTitle = "StickDoc $VERSION" } catch {}
Write-Host ''
Write-Host "  StickDoc $VERSION" -ForegroundColor Cyan
Write-Host '  Read-only health check. Nothing on this PC is changed.' -ForegroundColor DarkGray
if (-not $IsAdmin) { Write-Host '  Not running as administrator: some checks will be incomplete.' -ForegroundColor Yellow }
Write-Host ''
if (-not $Rma -and -not $NoPrompt) {
    $Rma = (Read-Host '  RMA / ticket number (Enter to skip)').Trim()
    Write-Host ''
}

# Where the report goes: Reports folder on the stick, desktop as fallback
if (-not $OutDir) { $OutDir = Join-Path $Root 'Reports' }
try {
    New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop | Out-Null
    $probe = Join-Path $OutDir '.write-test'
    [IO.File]::WriteAllText($probe, 'x')
    Remove-Item -LiteralPath $probe -Force
} catch {
    $OutDir = [Environment]::GetFolderPath('Desktop')
    Write-Host "  Cannot write to the stick, saving the report to $OutDir" -ForegroundColor Yellow
}

# Progress log: written line by line, so it shows where a run stopped even after a freeze
$Script:LogFile = Join-Path $OutDir 'last-run.log'
function Write-Log([string]$Text) {
    try { [IO.File]::AppendAllText($Script:LogFile, "$((Get-Date).ToString('HH:mm:ss.fff', $Inv))  $Text`r`n") } catch {}
}
try { [IO.File]::WriteAllText($Script:LogFile, '') } catch {}
$osv = @(Get-Cim Win32_OperatingSystem)[0]
Write-Log "StickDoc $VERSION, PowerShell $($PSVersionTable.PSVersion), $($osv.Caption) $($osv.Version), admin=$IsAdmin"
Write-Log "Folder: $Root"
Write-Log 'Looking for the stick drive'
$Script:Stick = Get-StickInfo
Write-Log "Stick: $(if ($Script:Stick) { "disk $($Script:Stick.Disk), drive $($Script:Stick.Letter):" } else { 'not detected' })"
# Preliminary file name; the device serial is added after the system info check
$stamp = $Now.ToString('yyyy-MM-dd_HHmm', $Inv)
$Script:ReportBase = Join-Path $OutDir "$stamp$(if ($Rma) { '_' + (Safe-Name $Rma) })_$(Safe-Name $env:COMPUTERNAME)"

Write-Host "  Checking, this takes about a minute..." -ForegroundColor DarkGray
$plan = @(
    @{ Id = 'usage'; Title = 'Usage'; Fn = { Check-Usage } }
    @{ Id = 'sysinfo'; Title = 'System info'; Fn = { Check-SysInfo } }
    @{ Id = 'drives'; Title = 'Drives'; Fn = { Check-Drives } }
    @{ Id = 'volumes'; Title = 'Disk space'; Fn = { Check-Volumes } }
    @{ Id = 'temps'; Title = 'Temperatures'; Fn = { Check-Temps } }
    @{ Id = 'battery'; Title = 'Battery'; Fn = { Check-Battery } }
    @{ Id = 'devices'; Title = 'Devices'; Fn = { Check-Devices } }
    @{ Id = 'bluescreens'; Title = 'Bluescreens'; Fn = { Check-Bluescreens } }
    @{ Id = 'hwevents'; Title = 'Hardware events'; Fn = { Check-HwEvents } }
    @{ Id = 'apps'; Title = 'Program crashes'; Fn = { Check-AppCrashes } }
    @{ Id = 'services'; Title = 'Services'; Fn = { Check-Services } }
    @{ Id = 'updates'; Title = 'Updates'; Fn = { Check-Updates } }
    @{ Id = 'security'; Title = 'Security'; Fn = { Check-Security } }
    @{ Id = 'network'; Title = 'Network'; Fn = { Check-Network } }
    @{ Id = 'displays'; Title = 'Screens'; Fn = { Check-Displays } }
)
$order = 'sysinfo', 'usage', 'drives', 'volumes', 'temps', 'battery', 'devices', 'bluescreens', 'hwevents', 'apps', 'services', 'updates', 'security', 'network', 'displays'

$results = @{}
foreach ($c in $plan) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = $null; $err = $null
    Write-Host ('  [ .... ] {0,-17}' -f $c.Title) -NoNewline -ForegroundColor DarkGray
    Write-Log "START $($c.Id)"
    try { $r = & $c.Fn } catch { $r = $null; $err = $_.Exception.Message }
    Write-Log "END   $($c.Id) $([int]$sw.Elapsed.TotalMilliseconds) ms$(if ($err) { " ERROR: $err" })"
    if (-not $r -or -not $r.status) {
        $r = New-Result $c.Id $c.Title 'warn' "Check could not run$(if ($err) { ": $err" })" @("Error: $err")
    }
    $r.ms = [int]$sw.Elapsed.TotalMilliseconds
    $results[$c.Id] = $r
    Write-CheckLine $r
    if ($c.Id -eq 'sysinfo' -and $Script:Identity.Serial) {
        $Script:ReportBase = Join-Path $OutDir "$stamp$(if ($Rma) { '_' + (Safe-Name $Rma) })_$(Safe-Name $Script:Identity.Serial)"
    }
}
$checks = @($order | ForEach-Object { $results[$_] } | Where-Object { $_ })
if (-not $IsAdmin) { Add-Flag 'warn' 'Not run as administrator: drive, battery, BitLocker and crash data may be missing' }
$overall = Get-Worst @($checks | ForEach-Object { $_.status })

# Plain-text summary for tickets and e-mails
$id = $Script:Identity
$device = (($id.Maker, $id.Model) | Where-Object { $_ }) -join ' '
$headline = @{ ok = 'Everything looks fine'; warn = 'Some things need a look'; fail = 'Problems found' }[$overall]
$txt = New-Object System.Collections.Generic.List[string]
$txt.Add("StickDoc report - $($Now.ToString('yyyy-MM-dd HH:mm', $Inv))")
if ($Rma) { $txt.Add("RMA / ticket: $Rma") }
$txt.Add("Device: $device$(if ($id.Serial) { ", S/N $($id.Serial)" })")
if ($id.Short) { $txt.Add("Hardware: $($id.Short)") }
if ($id.Os) { $txt.Add("Windows: $($id.Os)") }
$txt.Add("Result: $headline")
$txt.Add('')
foreach ($c in $checks) { $txt.Add(('[{0}] {1}: {2}' -f $c.status.ToUpper(), $c.title, $c.summary)) }
if ($Script:Flags.Count) {
    $txt.Add('')
    $txt.Add('Notes:')
    foreach ($f in $Script:Flags) { $txt.Add("- $($f.text)") }
}
$summaryText = $txt -join "`r`n"

$report = [ordered]@{
    tool = 'StickDoc'; version = $VERSION
    time = $Now.ToString('yyyy-MM-dd HH:mm', $Inv); days = $Days; admin = $IsAdmin
    rma = $Rma; overall = $overall; headline = $headline
    device = [ordered]@{ name = $id.Name; maker = $id.Maker; model = $id.Model; serial = $id.Serial; sku = $id.Sku; chassis = $id.Chassis; os = $id.Os; short = $id.Short }
    flags = @($Script:Flags); checks = $checks; customer = @($Script:Customer); summaryText = $summaryText
}

$json = $report | ConvertTo-Json -Depth 8
$utf8 = New-Object System.Text.UTF8Encoding $false
$base = $Script:ReportBase
[IO.File]::WriteAllText("$base.json", $json, $utf8)
[IO.File]::WriteAllText("$base.txt", $summaryText, $utf8)
$template = [IO.File]::ReadAllText((Join-Path $AppDir 'report.html'), [Text.Encoding]::UTF8)
$embedded = ($report | ConvertTo-Json -Depth 8 -Compress).Replace('</', '<\/')
$html = $template.Replace('/*__REPORT_JSON__*/null', $embedded)
[IO.File]::WriteAllText("$base.html", $html, $utf8)
Write-Log "Report written: $base.html"

Write-Host ''
$col = @{ ok = 'Green'; warn = 'Yellow'; fail = 'Red' }[$overall]
Write-Host "  $headline" -ForegroundColor $col
foreach ($f in $Script:Flags) { Write-Host "  - $($f.text)" -ForegroundColor $(if ($f.level -eq 'info') { 'Cyan' } else { 'Yellow' }) }
Write-Host ''
Write-Host "  Report saved: $base.html" -ForegroundColor DarkGray
if (-not $NoOpen) {
    # Through Explorer so the browser does not start with administrator rights
    Start-Process -FilePath explorer.exe -ArgumentList ('"' + "$base.html" + '"')
}
