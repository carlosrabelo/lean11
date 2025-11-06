<#
.SYNOPSIS
    Lean11 - Modular Windows 11 Image Optimizer and System Debloator

.DESCRIPTION
    PowerShell-based optimizer for Windows 11 with dual operation modes:
    
    1. Image Mode: Optimizes Windows 11 installation ISO images
    2. Debloat Mode: Removes bloat from live Windows 11 installations

    Key capabilities:
    - Dual-mode operation (Image/Debloat)
    - Hashtable-driven configuration
    - Multi-level structured logging
    - Selective package preservation via -KeepPackages
    - Hardware requirement bypass (Image mode)
    - Privacy and telemetry neutralization
    - OneDrive removal option
    - Registry optimizations
    - Scheduled task management

.PARAMETER Mode
    Operation mode: 'Image' (default) or 'Debloat'
    Image: Optimizes ISO installation media
    Debloat: Cleans live Windows 11 system

.PARAMETER ISO
    Drive letter of mounted Windows 11 ISO (e.g., E) or path to ISO file (Image mode only)
    If a file path is provided, the ISO will be mounted automatically

.PARAMETER SCRATCH
    Optional drive letter for temporary workspace (Image mode only)

.PARAMETER KeepPackages
    String array of package name patterns to preserve
    Example: "WindowsTerminal","Calculator"

.PARAMETER SkipOneDrive
    Skip OneDrive removal (Debloat mode only)

.PARAMETER SkipRegistryOptimizations
    Skip registry optimizations (Debloat mode only)

.PARAMETER SkipScheduledTasks
    Skip telemetry task disablement (Debloat mode only)

.EXAMPLE
    # Image mode: Create optimized ISO with mounted drive
    .\lean11.ps1 -Mode Image -ISO E -SCRATCH D

.EXAMPLE
    # Image mode: Auto-mount ISO from file path
    .\lean11.ps1 -Mode Image -ISO "C:\ISOs\Win11.iso" -SCRATCH D

.EXAMPLE
    # Image mode: Keep specific packages
    .\lean11.ps1 -ISO E -KeepPackages "Paint","Calculator"

.EXAMPLE
    # Debloat mode: Clean live system
    .\lean11.ps1 -Mode Debloat

.EXAMPLE
    # Debloat mode: Keep packages, skip OneDrive removal
    .\lean11.ps1 -Mode Debloat -KeepPackages "WindowsTerminal","Paint" -SkipOneDrive

.NOTES
    Project: Lean11
    Version: 1.1.0
    Date: 2025-11-04
    Runtime: PowerShell 5.1+
    Privileges: Administrator required

    Implementation: Modular architecture with declarative configuration
    Based on official Microsoft DISM and Windows ADK documentation
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [ValidateSet('Image', 'Debloat')]
    [string]$Mode = 'Image',

    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[c-zC-Z]:?$')]
    [string]$ISO,

    [Parameter(Mandatory=$false)]
    [ValidatePattern('^[c-zC-Z]:?$')]
    [string]$SCRATCH,

    [Parameter(Mandatory=$false)]
    [string[]]$KeepPackages = @(),

    [Parameter(Mandatory=$false)]
    [switch]$SkipOneDrive,

    [Parameter(Mandatory=$false)]
    [switch]$SkipRegistryOptimizations,

    [Parameter(Mandatory=$false)]
    [switch]$SkipScheduledTasks
)

# Import required modules (only if running locally)
if ($PSScriptRoot) {
    Import-Module DISM -ErrorAction SilentlyContinue
    Import-Module ServerManager -ErrorAction SilentlyContinue
}

$Script:Config = @{
    ProjectName = 'Lean11'
    Version = '1.1'
    LogPrefix = 'lean11'
    IsoName = 'lean11.iso'
    WorkDir = 'lean11_work'
    MountDir = 'lean11_mount'
    OscdimgUrl = 'https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe'
    # AutoUnattend will be generated if not present
}

$Script:Paths = @{
    ScriptRoot = $PSScriptRoot
    WorkDir = $null
    MountDir = $null
    IsoOutput = $null
    AutoUnattend = $null
    Oscdimg = $null
    TranscriptPath = $null
}

# ISO mounting tracking
$Script:IsoMountedByScript = $false
$Script:SourceDriveLetter = $null

# DUPLICATE PACKAGE DECISIONS:
# -------------------------------------------------------------------------
# Office: REMOVE ALL - These are only launchers/Office 365 promotion, including OneNote
# Teams: REMOVE ALL - Heavy application, non-essential for lean systems
# LinkedIn: REMOVE ALL - Social network, non-essential
# Paint: KEEP ONLY Microsoft.Paint - Modern version is superior
# Communication: REMOVE ALL - Unless user specifies otherwise
#
# This approach removes all duplicate versions to avoid conflicts
# and maintain system consistency.

$Script:PackageCategories = @{
    Hardware = @(
        'AppUp.IntelManagementandSecurityStatus'
        'DolbyLaboratories.DolbyAccess'
        'DolbyLaboratories.DolbyDigitalPlusDecoderOEM'
    )

    MediaEntertainment = @(
        'Clipchamp.Clipchamp'
        'Microsoft.ZuneMusic'
        'Microsoft.ZuneVideo'
        'Microsoft.MixedReality.Portal'
        'Microsoft.Microsoft3DViewer'
    )

    NewsSearch = @(
        'Microsoft.BingNews'
        'Microsoft.BingSearch'
        'Microsoft.BingWeather'
    )

    Gaming = @(
        'Microsoft.GamingApp'
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxApp'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
        'Microsoft.MicrosoftSolitaireCollection'
    )

    Office = @(
        # REMOVED: All Office packages are launchers, not full applications
        # Removing all versions to avoid conflicts
    )

    Communication = @(
        # REMOVED: All corporate communication packages are heavy and non-essential
        # Removing all versions to avoid conflicts
    )

    Utilities = @(
        # ESSENTIAL PACKAGES KEPT:
        'Microsoft.WindowsTerminal'                  # Terminal - KEEP (essential for developers)
        'Microsoft.Paint'                            # Modern Paint - KEEP (useful)
        'Microsoft.MicrosoftStickyNotes'             # Sticky Notes - KEEP (useful)

        # REMOVED PACKAGES (non-essential for lean system):
        # 'Microsoft.GetHelp'                         # Help - REMOVE
        # 'Microsoft.Getstarted'                       # Get Started - REMOVE
        # 'Microsoft.StartExperiencesApp'              # Start experiences - REMOVE
        # 'Microsoft.WindowsFeedbackHub'               # Feedback Hub - REMOVE
        # 'Microsoft.WindowsMaps'                      # Maps - REMOVE
        # 'Microsoft.WindowsAlarms'                    # Alarms - REMOVE
        # 'Microsoft.WindowsCamera'                    # Camera - REMOVE
        # 'Microsoft.WindowsSoundRecorder'             # Sound Recorder - REMOVE
        # 'Microsoft.MSPaint'                          # Classic Paint - REMOVE (obsolete)
        # 'MicrosoftCorporationII.QuickAssist'         # Quick Assist - REMOVE
    )

    Other = @(
        'Microsoft.People'
        'Microsoft.Wallet'
        'Microsoft.Windows.DevHome'
        'Microsoft.Windows.CrossDevice'
        'MicrosoftCorporationII.MicrosoftFamily'
        'Microsoft.549981C3F5F10'
    )
}

$Script:RegistryOptimizations = @{
    SystemRequirementsBypass = @(
        @{Hive='zDEFAULT'; Path='Control Panel\UnsupportedHardwareNotificationCache'; Name='SV1'; Type='REG_DWORD'; Value='0'}
        @{Hive='zDEFAULT'; Path='Control Panel\UnsupportedHardwareNotificationCache'; Name='SV2'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Control Panel\UnsupportedHardwareNotificationCache'; Name='SV1'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Control Panel\UnsupportedHardwareNotificationCache'; Name='SV2'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSYSTEM'; Path='Setup\LabConfig'; Name='BypassCPUCheck'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSYSTEM'; Path='Setup\LabConfig'; Name='BypassRAMCheck'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSYSTEM'; Path='Setup\LabConfig'; Name='BypassSecureBootCheck'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSYSTEM'; Path='Setup\LabConfig'; Name='BypassStorageCheck'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSYSTEM'; Path='Setup\LabConfig'; Name='BypassTPMCheck'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSYSTEM'; Path='Setup\MoSetup'; Name='AllowUpgradesWithUnsupportedTPMOrCPU'; Type='REG_DWORD'; Value='1'}
    )

    TelemetryDisable = @(
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name='Enabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\Privacy'; Name='TailoredExperiencesWithDiagnosticDataEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'; Name='HasAccepted'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Input\TIPC'; Name='Enabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\InputPersonalization'; Name='RestrictImplicitInkCollection'; Type='REG_DWORD'; Value='1'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\InputPersonalization'; Name='RestrictImplicitTextCollection'; Type='REG_DWORD'; Value='1'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\InputPersonalization\TrainedDataStore'; Name='HarvestContacts'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Personalization\Settings'; Name='AcceptedPrivacyPolicy'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSYSTEM'; Path='ControlSet001\Services\dmwappushservice'; Name='Start'; Type='REG_DWORD'; Value='4'}
    )

    SponsoredAppsDisable = @(
        @{Hive='zNTUSER'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='OemPreInstalledAppsEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='PreInstalledAppsEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SilentInstalledAppsEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsConsumerFeatures'; Type='REG_DWORD'; Value='1'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='ContentDeliveryAllowed'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Microsoft\PolicyManager\current\device\Start'; Name='ConfigureStartPins'; Type='REG_SZ'; Value='{"pinnedList": [{}]}'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='FeatureManagementEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='PreInstalledAppsEverEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SoftLandingEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zNTUSER'; Path='Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name='SubscribedContentEnabled'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\PushToInstall'; Name='DisablePushToInstall'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\MRT'; Name='DontOfferThroughWUAU'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\CloudContent'; Name='DisableConsumerAccountStateContent'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\CloudContent'; Name='DisableCloudOptimizedContent'; Type='REG_DWORD'; Value='1'}
    )

    OOBELocalAccount = @(
        @{Hive='zSOFTWARE'; Path='Microsoft\Windows\CurrentVersion\OOBE'; Name='BypassNRO'; Type='REG_DWORD'; Value='1'}
    )

    MiscOptimizations = @(
        @{Hive='zSOFTWARE'; Path='Microsoft\Windows\CurrentVersion\ReserveManager'; Name='ShippedWithReserves'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSYSTEM'; Path='ControlSet001\Control\BitLocker'; Name='PreventDeviceEncryption'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\Windows Chat'; Name='ChatIcon'; Type='REG_DWORD'; Value='3'}
        @{Hive='zNTUSER'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='TaskbarMn'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\OneDrive'; Name='DisableFileSyncNGSC'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Teams'; Name='DisableInstallation'; Type='REG_DWORD'; Value='1'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\Windows Mail'; Name='PreventRun'; Type='REG_DWORD'; Value='1'}
    )
}

$Script:ScheduledTasksToRemove = @(
    'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
    'Microsoft\Windows\Application Experience\ProgramDataUpdater'
    'Microsoft\Windows\Chkdsk\Proxy'
    'Microsoft\Windows\Windows Error Reporting\QueueReporting'
)

$Script:StartMenuShortcutPatterns = @(
    'LinkedIn*'
    'Instagram*'
    'TikTok*'
    'Facebook*'
    'Prime*Video*'
    'Disney*'
    'WhatsApp*'
    'Messenger*'
    'Spotify*'
    'Netflix*'
    'Amazon*'
    'Hulu*'
    'Twitter*'
    'Pinterest*'
)

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        default   { Write-Host $logMessage }
    }

    # Don't use Write-Output as it pollutes the pipeline and can contaminate function returns
    # Write-Host is sufficient for logging to console
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AdministratorsGroup {
    try {
        $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminGroup = $adminSID.Translate([System.Security.Principal.NTAccount])
        return $adminGroup.Value
    } catch {
        # Fallback for systems where translation fails
        return "Administrators"
    }
}

function Initialize-Environment {
    Write-Log "Initializing environment..." -Level Info

    if (-not (Test-AdminPrivileges)) {
        Write-Log "Administrator privileges required. Restarting with elevation..." -Level Warning
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Definition)`""
        if ($Mode) { $arguments += " -Mode $Mode" }
        if ($ISO) { $arguments += " -ISO $ISO" }
        if ($SCRATCH) { $arguments += " -SCRATCH $SCRATCH" }
        if ($KeepPackages.Count -gt 0) {
            $escaped = $KeepPackages | ForEach-Object { 
                $escapedValue = $_ -replace '"', '""'  # Escape quotes
                "`"$escapedValue`"" 
            }
            $arguments += " -KeepPackages $($escaped -join ',')"
        }
        if ($SkipOneDrive) { $arguments += " -SkipOneDrive" }
        if ($SkipRegistryOptimizations) { $arguments += " -SkipRegistryOptimizations" }
        if ($SkipScheduledTasks) { $arguments += " -SkipScheduledTasks" }
        Start-Process -FilePath powershell.exe -ArgumentList $arguments -Verb RunAs
        exit
    }

    if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        throw "PowerShell 5.1 or later is required."
    }

        if ($Mode -eq 'Image') {
            if ((Get-ExecutionPolicy) -eq 'Restricted') {
                Write-Log "Execution policy is Restricted. Please run: Set-ExecutionPolicy Bypass -Scope Process" -Level Error
                exit 1
            }

            # Handle remote execution where $PSScriptRoot might be null
            $scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { $pwd.Path }

            if ($SCRATCH) {
                $Script:Paths.WorkDir = "${SCRATCH}:\$($Config.WorkDir)"
                $Script:Paths.MountDir = "${SCRATCH}:\$($Config.MountDir)"
            } else {
                $Script:Paths.WorkDir = Join-Path $scriptRoot $Config.WorkDir
                $Script:Paths.MountDir = Join-Path $scriptRoot $Config.MountDir
            }

            $Script:Paths.IsoOutput = Join-Path $scriptRoot $Config.IsoName
            $Script:Paths.AutoUnattend = Join-Path $scriptRoot 'autounattend.xml'
            $Script:Paths.Oscdimg = Join-Path $scriptRoot 'oscdimg.exe'

            New-Item -ItemType Directory -Force -Path $Script:Paths.WorkDir -ErrorAction SilentlyContinue | Out-Null
            New-Item -ItemType Directory -Force -Path "$($Script:Paths.WorkDir)\sources" -ErrorAction SilentlyContinue | Out-Null
            New-Item -ItemType Directory -Force -Path $Script:Paths.MountDir -ErrorAction SilentlyContinue | Out-Null
        }

    # Ensure temp directory exists
    $tempPath = if ($env:TEMP) { $env:TEMP } else { "$PSScriptRoot\temp" }
    if (-not (Test-Path $tempPath)) {
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
    }
    
    $Script:Paths.TranscriptPath = Join-Path $tempPath "$($Config.LogPrefix)_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    try {
        Start-Transcript -Path $Script:Paths.TranscriptPath -Append
    } catch {
        Write-Log "Failed to start transcript: $_" -Level Warning
    }

    $modeDescription = if ($Mode -eq 'Debloat') { "Debloat Mode" } else { "Image Optimizer Mode" }
    Write-Log "$($Config.ProjectName) v$($Config.Version) - Windows 11 $modeDescription" -Level Success
    
    if ($Mode -eq 'Image') {
        Write-Log "Working Directory: $($Script:Paths.WorkDir)" -Level Info
        Write-Log "Mount Directory: $($Script:Paths.MountDir)" -Level Info
    } else {
        Write-Log "Transcript: $($Script:Paths.TranscriptPath)" -Level Info
    }
}

function Get-SourceIso {
    Write-Log "Configuring source ISO..." -Level Info

    do {
        if (-not $ISO) {
            $isoInput = Read-Host "Enter the drive letter of mounted Windows 11 ISO (e.g., E) or path to ISO file"
        } else {
            $isoInput = $ISO
        }

        # Check if input is a file path (ISO file)
        if ($isoInput -match '\.(iso|ISO)$' -or (Test-Path $isoInput -PathType Leaf)) {
            Write-Log "Mounting ISO file: $isoInput" -Level Info
            try {
                $mountResult = Mount-DiskImage -ImagePath $isoInput -PassThru -ErrorAction Stop
                $driveLetter = ($mountResult | Get-Volume).DriveLetter
                if (-not $driveLetter) {
                    Write-Log "Failed to get drive letter after mounting ISO" -Level Error
                    $ISO = $null
                    continue
                }
                Write-Log "ISO mounted successfully at drive $driveLetter" -Level Success
                $Script:IsoMountedByScript = $true
            } catch {
                Write-Log "Failed to mount ISO: $_" -Level Error
                $ISO = $null
                continue
            }
        } else {
            # Accept both "E" and "E:" formats
            if ($isoInput -notmatch '^[c-zC-Z]:?$') {
                Write-Log "Invalid input. Enter a drive letter (C-Z) or path to ISO file" -Level Warning
                $ISO = $null
                continue
            }
            $driveLetter = $isoInput
            $Script:IsoMountedByScript = $false
        }

        # Normalize to drive letter with colon and backslash
        $driveLetterOnly = $driveLetter.TrimEnd(':')
        $driveLetter = "${driveLetterOnly}:"
        $driveRoot = "${driveLetterOnly}:\"
        $Script:SourceDriveLetter = $driveLetter

        Write-Log "Validating ISO at drive $driveLetter..." -Level Info

        # First check if drive exists
        if (-not (Test-Path $driveRoot)) {
            Write-Log "Drive $driveLetter does not exist or is not accessible" -Level Error
            Write-Log "Available drives:" -Level Info
            Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Z]$' } | ForEach-Object {
                Write-Log "  $($_.Name): - $($_.Description)" -Level Info
            }
            $ISO = $null
            continue
        }

        # Check for sources directory
        $sourcesPath = Join-Path $driveRoot "sources"
        if (-not (Test-Path $sourcesPath)) {
            Write-Log "Sources directory not found at $sourcesPath" -Level Error
            Write-Log "This does not appear to be a valid Windows installation media" -Level Error
            Write-Log "Root directory contents:" -Level Info
            try {
                Get-ChildItem -Path $driveRoot -ErrorAction Stop | ForEach-Object {
                    Write-Log "  - $($_.Name)" -Level Info
                }
            } catch {
                Write-Log "Could not list directory contents: $_" -Level Warning
            }
            $ISO = $null
            continue
        }

        # Check for required WIM files
        $bootWimPath = Join-Path $sourcesPath "boot.wim"
        $installWimPath = Join-Path $sourcesPath "install.wim"
        $installEsdPath = Join-Path $sourcesPath "install.esd"

        $validationErrors = @()

        if (-not (Test-Path $bootWimPath)) {
            $validationErrors += "boot.wim not found"
        }

        if (-not (Test-Path $installWimPath) -and -not (Test-Path $installEsdPath)) {
            $validationErrors += "Neither install.wim nor install.esd found"
        }

        if ($validationErrors.Count -gt 0) {
            Write-Log "ISO validation failed:" -Level Error
            foreach ($error in $validationErrors) {
                Write-Log "  - $error" -Level Error
            }
            Write-Log "Contents of sources directory:" -Level Info
            try {
                Get-ChildItem -Path $sourcesPath -ErrorAction Stop | Select-Object -First 10 | ForEach-Object {
                    Write-Log "  - $($_.Name) ($([math]::Round($_.Length/1MB, 2)) MB)" -Level Info
                }
            } catch {
                Write-Log "Could not list sources directory: $_" -Level Warning
            }
            $ISO = $null
            continue
        }

        # Try to verify it's actually Windows 11
        try {
            $imageInfo = Get-WindowsImage -ImagePath $bootWimPath -Index 1 -ErrorAction Stop
            $osVersion = $imageInfo.Version
            Write-Log "Detected Windows version: $osVersion" -Level Info

            # Windows 11 has build 22000 or higher
            if ($imageInfo.Build -lt 22000) {
                Write-Log "Warning: This appears to be Windows 10 (Build $($imageInfo.Build))" -Level Warning
                Write-Log "Lean11 is designed for Windows 11 (Build 22000+)" -Level Warning
                $response = Read-Host "Continue anyway? (y/N)"
                if ($response -notmatch '^[Yy]') {
                    $ISO = $null
                    continue
                }
            } else {
                Write-Log "Windows 11 detected (Build $($imageInfo.Build))" -Level Success
            }
        } catch {
            Write-Log "Could not verify Windows version from boot.wim: $_" -Level Warning
            Write-Log "Proceeding with validation..." -Level Info
        }

        Write-Log "Source ISO validated successfully: $driveLetter" -Level Success
        return $driveLetter

    } while ($true)
}

function Copy-WindowsSource {
    param([string]$SourcePath)

    # Normalize source path - ensure it has : and \ for root access
    $SourcePath = $SourcePath.Trim().TrimEnd(':').TrimEnd('\')
    $driveRoot = "${SourcePath}:\"

    Write-Log "Copying Windows installation files from $driveRoot..." -Level Info
    Write-Log "DEBUG: Normalized path components - Letter: '$SourcePath', Root: '$driveRoot'" -Level Info

    # Give Windows a moment to settle if ISO was just mounted
    Start-Sleep -Milliseconds 500

    # Try multiple verification methods
    $pathExists = $false

    # Method 1: Test-Path
    if (Test-Path $driveRoot) {
        $pathExists = $true
        Write-Log "DEBUG: Test-Path verification succeeded" -Level Info
    }

    # Method 2: Get-PSDrive
    if (-not $pathExists) {
        $drive = Get-PSDrive -Name $SourcePath -PSProvider FileSystem -ErrorAction SilentlyContinue
        if ($drive) {
            $pathExists = $true
            Write-Log "DEBUG: Get-PSDrive verification succeeded" -Level Info
        }
    }

    # Method 3: Get-Volume
    if (-not $pathExists) {
        $volume = Get-Volume -DriveLetter $SourcePath -ErrorAction SilentlyContinue
        if ($volume) {
            $pathExists = $true
            Write-Log "DEBUG: Get-Volume verification succeeded" -Level Info
        }
    }

    if (-not $pathExists) {
        Write-Log "Source path not accessible: $driveRoot" -Level Error
        Write-Log "Attempted path: '$driveRoot' (Length: $($driveRoot.Length))" -Level Error
        Write-Log "Verifying drives..." -Level Info
        try {
            Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -match '^[A-Z]$' } | ForEach-Object {
                Write-Log "  Available drive: $($_.Name): $($_.Root)" -Level Info
            }
        } catch {
            Write-Log "Could not enumerate drives: $_" -Level Warning
        }
        throw "Source path validation failed"
    }

    $SourcePath = $driveRoot

    # Check available disk space - more reasonable requirement
    try {
        Write-Log "Calculating source size, this may take a moment..." -Level Info
        $sourceSize = (Get-ChildItem -Path $SourcePath -Recurse -Force -ErrorAction Stop | Measure-Object -Property Length -Sum).Sum / 1GB
        Write-Log "Source size: $([math]::Round($sourceSize, 2))GB" -Level Info
        $availableSpace = (Get-PSDrive -Name ($Script:Paths.WorkDir -split ':')[0] -ErrorAction Stop).Free / 1GB

        # More reasonable space requirement - 1.2x instead of 1.5x
        $requiredSpace = $sourceSize * 1.2
        if ($availableSpace -lt $requiredSpace) {
            Write-Log "Insufficient disk space. Required: $([math]::Round($requiredSpace, 2))GB, Available: $([math]::Round($availableSpace, 2))GB" -Level Error
            throw "Insufficient disk space for operation"
        }
        Write-Log "Disk space check passed. Required: $([math]::Round($requiredSpace, 2))GB, Available: $([math]::Round($availableSpace, 2))GB" -Level Info
    } catch [System.Management.Automation.DriveNotFoundException] {
        Write-Log "Could not access target drive for space verification" -Level Error
        throw "Target drive not accessible. Please verify the SCRATCH parameter."
    } catch {
        Write-Log "Disk space verification failed: $_" -Level Error
        Write-Log "This may indicate insufficient permissions or disk access issues" -Level Warning
        $response = Read-Host "Continue anyway? (y/N)"
        if ($response -notmatch '^[Yy]') {
            throw "Operation cancelled by user"
        }
        Write-Log "User chose to continue despite disk space verification failure" -Level Warning
    }

    # Handle install.esd conversion
    $sourcesPath = Join-Path $SourcePath "sources"
    $esdPath = Join-Path $sourcesPath "install.esd"
    $wimPath = Join-Path $sourcesPath "install.wim"

    if ((Test-Path $esdPath) -and -not (Test-Path $wimPath)) {
        Write-Log "Found install.esd, conversion required" -Level Warning
        try {
            $images = Get-WindowsImage -ImagePath $esdPath -ErrorAction Stop
            Write-Log "Available editions:" -Level Info
            foreach ($img in $images) {
                Write-Host "  [$($img.ImageIndex)] $($img.ImageName)"
            }

            do {
                $index = Read-Host "Enter the image index to convert"
                if ($images.ImageIndex -notcontains $index) {
                    Write-Log "Invalid index. Please select from the list above." -Level Warning
                    continue
                }
                break
            } while ($true)

            Write-Log "Converting install.esd to install.wim (this may take 15-30 minutes)..." -Level Info
            Write-Log "Please be patient, do not interrupt this process..." -Level Warning

            $destWimPath = Join-Path $Script:Paths.WorkDir "sources\install.wim"
            Export-WindowsImage -SourceImagePath $esdPath `
                               -SourceIndex $index `
                               -DestinationImagePath $destWimPath `
                               -CompressionType Maximum `
                               -CheckIntegrity -ErrorAction Stop

            Write-Log "ESD to WIM conversion completed successfully" -Level Success
        } catch [System.IO.FileNotFoundException] {
            Write-Log "Source ESD file not found or became inaccessible" -Level Error
            throw "ESD conversion failed: Source file not accessible"
        } catch [System.UnauthorizedAccessException] {
            Write-Log "Access denied during ESD conversion" -Level Error
            throw "ESD conversion failed: Insufficient permissions"
        } catch {
            Write-Log "Failed to convert install.esd: $_" -Level Error
            Write-Log "Possible causes:" -Level Warning
            Write-Log "  - Corrupted ESD file" -Level Warning
            Write-Log "  - Insufficient disk space (needs ~2x source size)" -Level Warning
            Write-Log "  - Source media disconnected during conversion" -Level Warning
            throw "ESD conversion failed"
        }
    }

    try {
        Write-Log "Copying files from $SourcePath to $($Script:Paths.WorkDir)" -Level Info
        Write-Log "This may take several minutes depending on your disk speed..." -Level Info
        Copy-Item -Path "$SourcePath\*" -Destination $Script:Paths.WorkDir -Recurse -Force -ErrorAction Stop
        Write-Log "File copy completed successfully" -Level Success
    } catch [System.UnauthorizedAccessException] {
        Write-Log "Access denied while copying files. Ensure you have administrator privileges." -Level Error
        throw "File copy failed due to insufficient permissions"
    } catch [System.IO.IOException] {
        Write-Log "I/O error during file copy: $_" -Level Error
        Write-Log "This may indicate:" -Level Warning
        Write-Log "  - Insufficient disk space" -Level Warning
        Write-Log "  - Source media is damaged or disconnected" -Level Warning
        Write-Log "  - Target drive is having issues" -Level Warning
        throw "File copy failed due to I/O error"
    } catch {
        Write-Log "Failed to copy Windows source files: $_" -Level Error
        Write-Log "Source path: $SourcePath" -Level Info
        Write-Log "Destination: $($Script:Paths.WorkDir)" -Level Info
        throw
    }

    # Clean up install.esd if it exists in work directory
    $workEsdPath = Join-Path (Join-Path $Script:Paths.WorkDir "sources") "install.esd"
    if (Test-Path $workEsdPath) {
        Write-Log "Removing install.esd from work directory" -Level Info
        Remove-Item $workEsdPath -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Windows source files copied successfully" -Level Success
}

function Select-WindowsImage {
    Write-Log "Detecting available Windows editions..." -Level Info

    $wimPath = "$($Script:Paths.WorkDir)\sources\install.wim"
    $images = Get-WindowsImage -ImagePath $wimPath

    Write-Log "Available editions:" -Level Info
    foreach ($img in $images) {
        Write-Host "  [$($img.ImageIndex)] $($img.ImageName)"
    }

    do {
        $index = Read-Host "Select image index"
        if ($images.ImageIndex -contains $index) {
            Write-Log "Selected: $($images | Where-Object {$_.ImageIndex -eq $index} | Select-Object -ExpandProperty ImageName)" -Level Success
            return $index
        }
        Write-Log "Invalid index. Please try again." -Level Warning
    } while ($true)
}

function Mount-WindowsInstallImage {
    param([int]$Index)

    Write-Log "Mounting Windows image (Index: $Index)..." -Level Info

    $wimPath = "$($Script:Paths.WorkDir)\sources\install.wim"
    $adminGroup = Get-AdministratorsGroup

    # Check for existing mounts
    try {
        $existingMounts = Get-WindowsImage -Mounted -ErrorAction Stop
        if ($existingMounts) {
            $mountAtTargetPath = $existingMounts | Where-Object { $_.MountPath -eq $Script:Paths.MountDir }
            if ($mountAtTargetPath) {
                Write-Log "Dismounting existing mount at $($Script:Paths.MountDir)" -Level Warning
                try {
                    Dismount-WindowsImage -Path $Script:Paths.MountDir -Discard -ErrorAction Stop
                    Write-Log "Successfully dismounted previous image" -Level Success
                } catch {
                    Write-Log "Failed to dismount gracefully, attempting cleanup..." -Level Warning
                    & dism /Cleanup-Wim
                    Start-Sleep -Seconds 2
                }
            }
        }
    } catch {
        Write-Log "Could not check for existing mounts: $_" -Level Warning
        Write-Log "Attempting DISM cleanup to clear any orphaned mounts..." -Level Info
        & dism /Cleanup-Wim >$null 2>&1
    }

    # Take ownership and set permissions with proper error handling
    try {
        Write-Log "Setting permissions for WIM file..." -Level Info
        & takeown /F $wimPath >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: takeown failed with exit code $LASTEXITCODE" -Level Warning
        }
        
        & icacls $wimPath /grant "$($adminGroup):(F)" >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Warning: icacls failed with exit code $LASTEXITCODE" -Level Warning
        }
        
        Set-ItemProperty -Path $wimPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Failed to set permissions on WIM file: $_" -Level Warning
    }

    try {
        Mount-WindowsImage -ImagePath $wimPath -Index $Index -Path $Script:Paths.MountDir -ErrorAction Stop
        Write-Log "Image mounted successfully" -Level Success
    } catch {
        Write-Log "Failed to mount Windows image: $_" -Level Error

        # Provide helpful troubleshooting information
        Write-Log "Troubleshooting steps:" -Level Info
        Write-Log "  1. Ensure no other applications are accessing the mount directory" -Level Info
        Write-Log "  2. Try running: dism /Cleanup-Wim" -Level Info
        Write-Log "  3. Check available disk space on mount drive" -Level Info
        Write-Log "  4. Verify WIM file is not corrupted: dism /Get-WimInfo /WimFile:`"$wimPath`"" -Level Info

        # Check if mount directory is accessible
        if (Test-Path $Script:Paths.MountDir) {
            $mountItems = Get-ChildItem -Path $Script:Paths.MountDir -ErrorAction SilentlyContinue
            if ($mountItems) {
                Write-Log "  Mount directory is not empty - may need manual cleanup" -Level Warning
            }
        }

        throw "Image mounting failed. Please review troubleshooting steps above."
    }

    try {
        # Detect architecture dynamically
        $imageInfo = & dism /English /Get-WimInfo /wimFile:$wimPath /index:$Index
        $architectureMatch = $imageInfo | Select-String -Pattern 'Architecture : (.*)'
        if ($architectureMatch) {
            $architecture = $architectureMatch.Matches.Groups[1].Value
            if ($architecture -eq 'x64') { $architecture = 'amd64' }
        } else {
            $architecture = 'amd64'  # Default assumption
        }

        # Detect language dynamically
        $imageIntl = & dism /English /Get-Intl /Image:$($Script:Paths.MountDir)
        $languageMatch = $imageIntl | Select-String -Pattern 'Default system UI language : ([a-zA-Z]{2}-[a-zA-Z]{2})'
        if ($languageMatch) {
            $language = $languageMatch.Matches.Groups[1].Value
        } else {
            $language = 'en-US'  # Default assumption
        }

        Write-Log "Architecture: $architecture | Language: $language" -Level Info
    } catch {
        Write-Log "Failed to get image information: $_" -Level Warning
        $architecture = 'amd64'  # Default assumption
        $language = 'en-US'      # Default assumption
    }

    return @{
        Architecture = $architecture
        Language = $language
    }
}

function Remove-BloatwarePackages {
    Write-Log "Analyzing installed provisioned packages..." -Level Info

    $installedPackages = & dism /English /image:$($Script:Paths.MountDir) /Get-ProvisionedAppxPackages |
        ForEach-Object { if ($_ -match 'PackageName : (.*)') { $matches[1] } }

    $removalList = @()
    foreach ($category in $Script:PackageCategories.Keys) {
        foreach ($packagePrefix in $Script:PackageCategories[$category]) {
            $matchingPackages = $installedPackages | Where-Object { $_ -like "*$packagePrefix*" }
            $removalList += $matchingPackages
        }
    }

    if ($KeepPackages.Count -gt 0) {
        Write-Log "Keeping user-specified packages: $($KeepPackages -join ', ')" -Level Info
        $removalList = $removalList | Where-Object {
            $pkg = $_
            -not ($KeepPackages | Where-Object { $pkg -like "*$_*" })
        }
    }

    Write-Log "Removing $($removalList.Count) bloatware packages..." -Level Info

    foreach ($package in $removalList) {
        Write-Log "  Removing: $package" -Level Info
        & dism /English /image:$($Script:Paths.MountDir) /Remove-ProvisionedAppxPackage /PackageName:$package >$null 2>&1
    }

    Write-Log "Bloatware removal completed" -Level Success
}

function Remove-OneDrive {
    Write-Log "Removing OneDrive..." -Level Info
    $adminGroup = Get-AdministratorsGroup

    $onedriveSetup = "$($Script:Paths.MountDir)\Windows\System32\OneDriveSetup.exe"
    if (Test-Path $onedriveSetup) {
        try {
            & takeown /f $onedriveSetup >$null 2>&1
            & icacls $onedriveSetup /grant "$($adminGroup):(F)" /T /C >$null 2>&1
            Remove-Item -Path $onedriveSetup -Force -ErrorAction Stop
            Write-Log "OneDrive removed successfully" -Level Success
        } catch {
            Write-Log "Failed to remove OneDrive: $_" -Level Warning
        }
    } else {
        Write-Log "OneDrive not found in image" -Level Info
    }
}

function Mount-RegistryHives {
    Write-Log "Loading registry hives..." -Level Info

    $hivesPath = "$($Script:Paths.MountDir)\Windows\System32\config"

    # Load hives with error handling
    $hives = @{
        'HKLM\zCOMPONENTS' = "$hivesPath\COMPONENTS"
        'HKLM\zDEFAULT' = "$hivesPath\default"
        'HKLM\zNTUSER' = "$($Script:Paths.MountDir)\Users\Default\ntuser.dat"
        'HKLM\zSOFTWARE' = "$hivesPath\SOFTWARE"
        'HKLM\zSYSTEM' = "$hivesPath\SYSTEM"
    }

    foreach ($hive in $hives.GetEnumerator()) {
        if (Test-Path $hive.Value) {
            try {
                & reg load $hive.Key $hive.Value >$null 2>&1
                Write-Log "  Loaded: $($hive.Key)" -Level Info
            } catch {
                Write-Log "  Failed to load $($hive.Key): $_" -Level Warning
            }
        } else {
            Write-Log "  Hive file not found: $($hive.Value)" -Level Warning
        }
    }

    Write-Log "Registry hives loading completed" -Level Success
}

function Dismount-RegistryHives {
    Write-Log "Unloading registry hives..." -Level Info

    & reg unload HKLM\zCOMPONENTS >$null 2>&1
    & reg unload HKLM\zDEFAULT >$null 2>&1
    & reg unload HKLM\zNTUSER >$null 2>&1
    & reg unload HKLM\zSOFTWARE >$null 2>&1
    & reg unload HKLM\zSYSTEM >$null 2>&1

    Write-Log "Registry hives unloaded" -Level Success
}

function Set-RegistryOptimization {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Optimization,

        [Parameter(Mandatory=$true)]
        [string]$Description
    )

    $path = "HKLM\$($Optimization.Hive)\$($Optimization.Path)"

    try {
        & reg add $path /v $Optimization.Name /t $Optimization.Type /d $Optimization.Value /f >$null 2>&1
    } catch {
        Write-Log "  Failed to set $path\$($Optimization.Name)" -Level Warning
    }
}

function Apply-RegistryOptimizations {
    Write-Log "Applying registry optimizations..." -Level Info

    Write-Log "  - System requirements bypass" -Level Info
    foreach ($opt in $Script:RegistryOptimizations.SystemRequirementsBypass) {
        Set-RegistryOptimization -Optimization $opt -Description "Hardware bypass"
    }

    Write-Log "  - Telemetry disable" -Level Info
    foreach ($opt in $Script:RegistryOptimizations.TelemetryDisable) {
        Set-RegistryOptimization -Optimization $opt -Description "Telemetry"
    }

    Write-Log "  - Sponsored apps disable" -Level Info
    foreach ($opt in $Script:RegistryOptimizations.SponsoredAppsDisable) {
        Set-RegistryOptimization -Optimization $opt -Description "Sponsored content"
    }

    Write-Log "  - OOBE local account enable" -Level Info
    foreach ($opt in $Script:RegistryOptimizations.OOBELocalAccount) {
        Set-RegistryOptimization -Optimization $opt -Description "Local account"
    }

    Write-Log "  - Miscellaneous optimizations" -Level Info
    foreach ($opt in $Script:RegistryOptimizations.MiscOptimizations) {
        Set-RegistryOptimization -Optimization $opt -Description "Misc"
    }

    $keysToRemove = @(
        'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions'
        'HKLM\zNTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps'
        'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate'
        'HKLM\zSOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate'
    )

    foreach ($key in $keysToRemove) {
        & reg delete $key /f >$null 2>&1
    }

    Write-Log "Registry optimizations applied successfully" -Level Success
}

function Remove-TelemetryTasks {
    Write-Log "Removing telemetry scheduled tasks..." -Level Info

    $tasksPath = "$($Script:Paths.MountDir)\Windows\System32\Tasks"

    foreach ($task in $Script:ScheduledTasksToRemove) {
        $taskPath = Join-Path $tasksPath $task
        if (Test-Path $taskPath) {
            Remove-Item -Path $taskPath -Force -Recurse -ErrorAction SilentlyContinue
            Write-Log "  Removed: $task" -Level Info
        }
    }

    $ceipPath = "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program"
    if (Test-Path $ceipPath) {
        Remove-Item -Path $ceipPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "  Removed: Customer Experience Improvement Program folder" -Level Info
    }

    Write-Log "Telemetry tasks removed" -Level Success
}

function Optimize-WindowsImage {
    Write-Log "Running DISM cleanup and optimization..." -Level Info
    & dism /English /Image:$($Script:Paths.MountDir) /Cleanup-Image /StartComponentCleanup /ResetBase
    Write-Log "Image optimization completed" -Level Success
}

function Dismount-AndExport-Image {
    param([int]$Index)

    Write-Log "Saving and unmounting Windows image..." -Level Info
    Dismount-WindowsImage -Path $Script:Paths.MountDir -Save

    Write-Log "Exporting optimized image with maximum compression..." -Level Info
    $wimPath = "$($Script:Paths.WorkDir)\sources\install.wim"
    $wimPathTemp = "$($Script:Paths.WorkDir)\sources\install2.wim"

    & dism /English /Export-Image /SourceImageFile:$wimPath /SourceIndex:$Index /DestinationImageFile:$wimPathTemp /Compress:recovery

    Remove-Item -Path $wimPath -Force
    Rename-Item -Path $wimPathTemp -NewName 'install.wim'

    Write-Log "Image export completed" -Level Success
}

function Process-BootImage {
    Write-Log "Processing boot image..." -Level Info

    $bootWimPath = "$($Script:Paths.WorkDir)\sources\boot.wim"
    $adminGroup = Get-AdministratorsGroup

    & takeown /F $bootWimPath >$null 2>&1
    & icacls $bootWimPath /grant "$($adminGroup):(F)" >$null 2>&1
    Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

    Mount-WindowsImage -ImagePath $bootWimPath -Index 2 -Path $Script:Paths.MountDir

    Mount-RegistryHives

    Write-Log "Applying system requirement bypasses to boot image..." -Level Info
    foreach ($opt in $Script:RegistryOptimizations.SystemRequirementsBypass) {
        Set-RegistryOptimization -Optimization $opt -Description "Boot image bypass"
    }

    Dismount-RegistryHives

    Write-Log "Unmounting boot image..." -Level Info
    Dismount-WindowsImage -Path $Script:Paths.MountDir -Save

    Write-Log "Boot image processing completed" -Level Success
}

function Get-OscdimgTool {
    Write-Log "Locating oscdimg.exe..." -Level Info

    # Check ADK path
    $hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
    if ($hostArchitecture -eq 'AMD64') { $hostArchitecture = 'amd64' }
    
    $adkDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostArchitecture\Oscdimg"
    $adkPath = Join-Path $adkDepTools "oscdimg.exe"

    if (Test-Path $adkPath) {
        Write-Log "Using oscdimg.exe from system ADK" -Level Success
        return $adkPath
    }

    # Download if not available locally
    if (-not (Test-Path $Script:Paths.Oscdimg)) {
        try {
            Write-Log "ADK folder not found. Will be using bundled oscdimg.exe." -Level Info
            Write-Log "Downloading oscdimg.exe..." -Level Info
            Invoke-WebRequest -Uri $Config.OscdimgUrl -OutFile $Script:Paths.Oscdimg -ErrorAction Stop
            
            # Verify download
            if (-not (Test-Path $Script:Paths.Oscdimg) -or (Get-Item $Script:Paths.Oscdimg).Length -eq 0) {
                throw "Download failed or file is empty"
            }
            Write-Log "oscdimg.exe downloaded successfully" -Level Success
        } catch {
            Write-Log "Failed to download oscdimg.exe: $_" -Level Error
            Write-Log "Please install Windows ADK or download oscdimg.exe manually" -Level Error
            throw
        }
    } else {
        Write-Log "oscdimg.exe already exists locally" -Level Info
    }

    Write-Log "Using local oscdimg.exe" -Level Success
    return $Script:Paths.Oscdimg
}

function New-AutoUnattendFile {
    Write-Log "Generating autounattend.xml for OOBE bypass..." -Level Info

    $autounattendContent = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Password>
                            <Value></Value>
                            <PlainText>true</PlainText>
                        </Password>
                        <DisplayName>User</DisplayName>
                        <Group>Administrators</Group>
                        <Name>User</Name>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>DISM /Online /Set-Edition:Professional /ProductKey:VK7JG-NPHTM-C97JM-9MPGT-3V66T /AcceptEula</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
</unattend>
'@

    Set-Content -Path $Script:Paths.AutoUnattend -Value $autounattendContent -Encoding UTF8
    Write-Log "AutoUnattend file created successfully" -Level Success
}

function New-BootableIso {
    param([string]$Architecture)

    Write-Log "Creating bootable ISO..." -Level Info

    if (-not (Test-Path $Script:Paths.AutoUnattend)) {
        New-AutoUnattendFile
    }

    Copy-Item -Path $Script:Paths.AutoUnattend -Destination "$($Script:Paths.WorkDir)\autounattend.xml" -Force
    Copy-Item -Path $Script:Paths.AutoUnattend -Destination "$($Script:Paths.MountDir)\Windows\System32\Sysprep\autounattend.xml" -Force -ErrorAction SilentlyContinue

    $oscdimg = Get-OscdimgTool

    # Verify boot files exist before creating ISO
    $etfsboot = "$($Script:Paths.WorkDir)\boot\etfsboot.com"
    $efisys = "$($Script:Paths.WorkDir)\efi\microsoft\boot\efisys.bin"
    
    if (-not (Test-Path $etfsboot)) {
        Write-Log "Warning: etfsboot.com not found at $etfsboot" -Level Warning
    }
    if (-not (Test-Path $efisys)) {
        Write-Log "Warning: efisys.bin not found at $efisys" -Level Warning
    }

    # Create bootdata string
    $bootData = "2#p0,e,b$($Script:Paths.WorkDir)\boot\etfsboot.com#pEF,e,b$($Script:Paths.WorkDir)\efi\microsoft\boot\efisys.bin"

    Write-Log "Creating ISO with boot data: $bootData" -Level Info
    
    try {
        & $oscdimg -m -o -u2 -udfver102 "-bootdata:$bootData" $Script:Paths.WorkDir $Script:Paths.IsoOutput
        if ($LASTEXITCODE -eq 0) {
            Write-Log "ISO created successfully: $($Script:Paths.IsoOutput)" -Level Success
            
            # Verify ISO was created
            if (Test-Path $Script:Paths.IsoOutput) {
                $isoSize = (Get-Item $Script:Paths.IsoOutput).Length / 1GB
                Write-Log "ISO size: $([math]::Round($isoSize, 2))GB" -Level Info
            } else {
                throw "ISO file was not created"
            }
        } else {
            throw "oscdimg failed with exit code $LASTEXITCODE"
        }
    } catch {
        Write-Log "Failed to create ISO: $_" -Level Error
        throw
    }
}

function Clear-WorkingDirectories {
    Write-Log "Cleaning up working directories..." -Level Info

    # Only dismount if we mounted it
    if ($Script:IsoMountedByScript -and $Script:SourceDriveLetter) {
        try {
            Write-Log "Dismounting ISO from drive $Script:SourceDriveLetter..." -Level Info
            Get-Volume -DriveLetter $Script:SourceDriveLetter[0] -ErrorAction SilentlyContinue |
                Get-DiskImage |
                Dismount-DiskImage -ErrorAction SilentlyContinue
            Write-Log "ISO dismounted successfully" -Level Success
        } catch {
            Write-Log "Could not dismount ISO: $_" -Level Warning
        }
    }

    $itemsToRemove = @(
        @{Path=$Script:Paths.WorkDir; Desc="Working directory"}
        @{Path=$Script:Paths.MountDir; Desc="Mount directory"}
        @{Path=$Script:Paths.Oscdimg; Desc="oscdimg.exe"}
        @{Path=$Script:Paths.AutoUnattend; Desc="autounattend.xml"}
    )

    foreach ($item in $itemsToRemove) {
        if ($item.Path -and (Test-Path $item.Path)) {
            try {
                Remove-Item -Path $item.Path -Recurse -Force -ErrorAction Stop
                Write-Log "  Removed: $($item.Desc)" -Level Info
            } catch {
                Write-Log "  Initial removal failed for $($item.Desc), attempting forced removal..." -Level Warning

                # Try to force removal with takeown/icacls
                try {
                    if (-not $item.Path) { throw "Path is null" }
                    $adminGroup = Get-AdministratorsGroup
                    & takeown /F $item.Path /R /D Y >$null 2>&1
                    & icacls $item.Path /grant "$($adminGroup):(F)" /T /C >$null 2>&1
                    Remove-Item -Path $item.Path -Recurse -Force -ErrorAction Stop
                    Write-Log "  Removed: $($item.Desc) (forced)" -Level Info
                } catch {
                    Write-Log "  Failed to remove: $($item.Desc) - $_" -Level Warning
                    Write-Log "  You may need to manually delete: $($item.Path)" -Level Warning
                }
            }
        }
    }

    Write-Log "Cleanup completed" -Level Success
}

function Resolve-RegPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hive,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $root = switch ($Hive.ToUpper()) {
        'HKCU' { 'HKCU:' }
        'HKLM' { 'HKLM:' }
        'HKU' { 'Registry::HKEY_USERS' }
        'HKU\.DEFAULT' { 'Registry::HKEY_USERS\.DEFAULT' }
        { $_ -match '^HKLM\\Z[A-Z]+' } { "Registry::$Hive" }  # Support for image mode hives
        default { throw "Unsupported hive: $Hive" }
    }

    return Join-Path -Path $root -ChildPath $Path
}

function Should-KeepPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    foreach ($keep in $KeepPackages) {
        if ($PackageName -like "*$keep*") {
            return $true
        }
    }
    return $false
}

# Function to handle package duplicates
function Resolve-PackageDuplicates {
    param(
        [Parameter(Mandatory = $true)]
        [array]$PackageCandidates
    )
    
    $resolved = @()
    $duplicateGroups = @{
        'Office' = @('Microsoft.MicrosoftOfficeHub', 'MicrosoftCorporationII.MicrosoftOfficeHub', 'MicrosoftCorporationII.OfficeHub', 'Microsoft.Office.OneNote')
        'Teams' = @('MicrosoftTeams', 'MSTeams', 'Microsoft.Windows.Teams')
        'LinkedIn' = @('Microsoft.LinkedIn', 'MicrosoftCorporationII.LinkedInForWindows', 'LinkedInForWindows')
        'Paint' = @('Microsoft.MSPaint')  # Only remove old version, keep modern one
    }
    
    foreach ($group in $duplicateGroups.Keys) {
        $duplicates = $PackageCandidates | Where-Object { 
            if ($null -eq $_.DisplayName) { 
                if ($null -eq $_.PackageName) { 
                    $pkg = $_ 
                } else { 
                    $pkg = $_.PackageName 
                } 
            } else { 
                $pkg = $_.DisplayName 
            }
            $duplicateGroups[$group] | Where-Object { $pkg -like "*$_*" }
        }
        
        if ($duplicates.Count -gt 1) {
            Write-Log "Found $($duplicates.Count) duplicate packages for $group - removing all duplicates" -Level Info

            # For Paint: keep only modern version
            if ($group -eq 'Paint') {
                $modernPaint = $duplicates | Where-Object { 
                    if ($null -eq $_.DisplayName) { 
                        if ($null -eq $_.PackageName) { 
                            $pkg = $_ 
                        } else { 
                            $pkg = $_.PackageName 
                        } 
                    } else { 
                        $pkg = $_.DisplayName 
                    }
                    $pkg -like "*Microsoft.Paint*" 
                }
                if ($modernPaint) {
                    $resolved += $modernPaint
                    if ($null -eq $modernPaint.DisplayName) { 
                        if ($null -eq $modernPaint.PackageName) { 
                            $pkgName = $modernPaint 
                        } else { 
                            $pkgName = $modernPaint.PackageName 
                        } 
                    } else { 
                        $pkgName = $modernPaint.DisplayName 
                    }
                    Write-Log "Keeping modern Paint: $pkgName" -Level Info
                }
            }
            # For other groups: remove all
            else {
                Write-Log "Removing all $group packages" -Level Info
            }
        }
    }

    # Add non-duplicate packages
    $nonDuplicates = $PackageCandidates | Where-Object { 
        if ($null -eq $_.DisplayName) { 
            if ($null -eq $_.PackageName) { 
                $pkg = $_ 
            } else { 
                $pkg = $_.PackageName 
            } 
        } else { 
            $pkg = $_.DisplayName 
        }
        $isDuplicate = $false
        foreach ($group in $duplicateGroups.Keys) {
            if ($duplicateGroups[$group] | Where-Object { $pkg -like "*$_*" }) {
                $isDuplicate = $true
                break
            }
        }
        -not $isDuplicate
    }
    
    $resolved += $nonDuplicates
    return $resolved
}

$Script:SupportsAppxPackageFamilyLookup = $null

function Supports-AppxPackageFamilyLookup {
    if ($null -ne $Script:SupportsAppxPackageFamilyLookup) {
        return $Script:SupportsAppxPackageFamilyLookup
    }

    try {
        $params = (Get-Command -Name Get-AppxPackage -ErrorAction Stop).Parameters
        $Script:SupportsAppxPackageFamilyLookup = $params.ContainsKey('PackageFamilyName')
    } catch {
        $Script:SupportsAppxPackageFamilyLookup = $false
    }

    return $Script:SupportsAppxPackageFamilyLookup
}

function Get-RemovalCandidates {
    [CmdletBinding()]
    param()

    Write-Log "Cataloging installed AppX packages..." -Level Info

    $provisioned = @()
    $installed = @()

    try {
        $provisioned = Get-AppxProvisionedPackage -Online -ErrorAction Stop
    } catch {
        Write-Log "Failed to query provisioned packages: $_" -Level Warning
    }

    try {
        $installed = Get-AppxPackage -AllUsers -ErrorAction Stop
    } catch {
        Write-Log "Failed to query installed AppX packages: $_" -Level Warning
    }

    $unique = [System.Collections.Generic.HashSet[string]]::new()
    $candidates = @()

    foreach ($category in $Script:PackageCategories.Keys) {
        foreach ($prefix in $Script:PackageCategories[$category]) {
            $provMatches = $provisioned | Where-Object { $_.DisplayName -like "*$prefix*" }
            foreach ($pkg in $provMatches) {
                if (Should-KeepPackage -PackageName $pkg.DisplayName) { continue }
                $key = "Provisioned|$($pkg.PackageName)"
                if ($unique.Add($key)) {
                    $candidates += [PSCustomObject]@{
                        Kind          = 'Provisioned'
                        Category      = $category
                        DisplayName   = $pkg.DisplayName
                        PackageName   = $pkg.PackageName
                        PackageFamily = $pkg.PackageFamilyName
                    }
                }
            }

            $appxMatches = $installed | Where-Object { $_.Name -like "*$prefix*" }
            foreach ($pkg in $appxMatches) {
                if (Should-KeepPackage -PackageName $pkg.Name) { continue }
                $key = "Installed|$($pkg.PackageFullName)"
                if ($unique.Add($key)) {
                    $candidates += [PSCustomObject]@{
                        Kind            = 'Installed'
                        Category        = $category
                        DisplayName     = $pkg.Name
                        PackageName     = $pkg.PackageFullName
                        PackageFamily   = $pkg.PackageFamilyName
                        InstallLocation = $pkg.InstallLocation
                    }
                }
            }
        }
    }

    $total = $candidates.Count
    $categories = ($candidates | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', '
    Write-Log "Identified $total removable package entries. Breakdown: $categories" -Level Info

    return $candidates
}

function Remove-ProvisionedPackages {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Candidates
    )

    $targets = $Candidates | Where-Object { $_.Kind -eq 'Provisioned' }
    if ($targets.Count -eq 0) {
        Write-Log "No provisioned packages to remove." -Level Info
        return
    }

    Write-Log "Removing provisioned packages..." -Level Info

    foreach ($entry in $targets) {
        if (-not $PSCmdlet.ShouldProcess($entry.DisplayName, 'Remove-AppxProvisionedPackage')) { continue }
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $entry.PackageName -ErrorAction Stop | Out-Null
            Write-Log "  Removed provisioned: $($entry.DisplayName) [$($entry.Category)]" -Level Success
        } catch {
            Write-Log "  Failed to remove provisioned $($entry.DisplayName): $_" -Level Warning
        }
    }
}

function Remove-InstalledPackages {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Candidates
    )

    $targets = $Candidates | Where-Object { $_.Kind -eq 'Installed' }
    if ($targets.Count -eq 0) {
        Write-Log "No installed AppX packages to remove." -Level Info
        return
    }

    Write-Log "Removing installed AppX packages for all users..." -Level Info

    $supportsPackageFamily = Supports-AppxPackageFamilyLookup
    if (-not $supportsPackageFamily) {
        Write-Log "Get-AppxPackage does not support PackageFamilyName parameter; using inventory fallback." -Level Info
    }

    $cachedInventory = $null

    foreach ($entry in $targets) {
        if (-not $PSCmdlet.ShouldProcess($entry.DisplayName, 'Remove-AppxPackage')) { continue }
        $instances = @()

        if ($supportsPackageFamily -and $entry.PackageFamily) {
            $instances = Get-AppxPackage -AllUsers -PackageFamilyName $entry.PackageFamily -ErrorAction SilentlyContinue
        }

        if (-not $instances -and $entry.PackageName) {
            if ($null -eq $cachedInventory) {
                try {
                    $cachedInventory = Get-AppxPackage -AllUsers -ErrorAction Stop
                } catch {
                    Write-Log ("  Failed to build installed AppX inventory: {0}" -f $_) -Level Warning
                    $cachedInventory = @()
                }
            }
            $instances = $cachedInventory | Where-Object {
                $_.PackageFullName -eq $entry.PackageName -or $_.Name -eq $entry.DisplayName
            }
        }

        if (-not $instances -or $instances.Count -eq 0) {
            Write-Log "  Package not found: $($entry.DisplayName)" -Level Warning
            continue
        }

        foreach ($instance in $instances) {
            try {
                Remove-AppxPackage -Package $instance.PackageFullName -AllUsers -ErrorAction Stop
                Write-Log "  Removed installed: $($instance.Name)" -Level Success
            } catch {
                Write-Log ("  Failed to remove {0}: {1}" -f $instance.Name, $_) -Level Warning
            }
        }
    }
}

function Remove-OneDriveDebloat {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    $oneDrivePaths = @(
        "$env:SystemRoot\System32\OneDriveSetup.exe",
        "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    )

    $found = $false

    foreach ($path in $oneDrivePaths) {
        if (-not (Test-Path $path)) { continue }
        $found = $true
        if (-not $PSCmdlet.ShouldProcess($path, 'Uninstall OneDrive')) { continue }
        try {
            Start-Process -FilePath $path -ArgumentList '/uninstall' -Wait -ErrorAction Stop
            Write-Log "  Invoked OneDrive uninstaller: $path" -Level Success
        } catch {
            Write-Log ("  Failed to uninstall OneDrive via {0}: {1}" -f $path, $_) -Level Warning
        }
    }

    if (-not $found) {
        Write-Log "OneDrive installer not found; assuming already removed." -Level Info
    }

    $leftovers = @(
        "$env:UserProfile\OneDrive",
        "$env:LocalAppData\Microsoft\OneDrive",
        "$env:ProgramData\Microsoft OneDrive"
    )

    foreach ($item in $leftovers) {
        if (-not (Test-Path $item)) { continue }
        if (-not $PSCmdlet.ShouldProcess($item, 'Remove OneDrive residual files')) { continue }
        try {
            Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
            Write-Log "  Deleted leftover: $item" -Level Info
        } catch {
            Write-Log ("  Failed to delete leftover {0}: {1}" -f $item, $_) -Level Warning
        }
    }
}

function Remove-StartMenuShortcuts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string[]]$Patterns = $Script:StartMenuShortcutPatterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) {
        Write-Log "No Start menu shortcut patterns configured; skipping cleanup." -Level Info
        return
    }

    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $candidatePaths = [System.Collections.Generic.HashSet[string]]::new()

    $programDataPath = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    if (Test-Path $programDataPath) {
        [void]$candidatePaths.Add((Get-Item -LiteralPath $programDataPath).FullName)
    }

    $defaultProfilePath = Join-Path $systemDrive 'Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
    if (Test-Path $defaultProfilePath) {
        [void]$candidatePaths.Add((Get-Item -LiteralPath $defaultProfilePath).FullName)
    }

    try {
        $userProfiles = Get-ChildItem -Path (Join-Path $systemDrive 'Users') -Directory -ErrorAction Stop |
            Where-Object { $_.Name -notmatch '^(Default|Default User|All Users|Public)$' }

        foreach ($profile in $userProfiles) {
            $userStartMenu = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
            if (Test-Path $userStartMenu) {
                [void]$candidatePaths.Add((Get-Item -LiteralPath $userStartMenu).FullName)
            }
        }
    } catch {
        Write-Log ("Failed to enumerate user profiles for Start menu cleanup: {0}" -f $_) -Level Warning
    }

    if ($candidatePaths.Count -eq 0) {
        Write-Log "Start menu shortcut locations not found; skipping cleanup." -Level Info
        return
    }

    Write-Log "Removing promotional Start menu shortcuts..." -Level Info
    $removed = 0
    $visited = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($path in $candidatePaths) {
        $shortcuts = Get-ChildItem -Path $path -Include *.lnk,*.url -File -Recurse -ErrorAction SilentlyContinue
        foreach ($shortcut in $shortcuts) {
            $shortcutKey = $shortcut.FullName.ToLowerInvariant()
            if (-not $visited.Add($shortcutKey)) { continue }

            $matchedPattern = $null
            foreach ($pattern in $Patterns) {
                if ($shortcut.BaseName -like $pattern -or $shortcut.Name -like "$pattern.*") {
                    $matchedPattern = $pattern
                    break
                }
            }

            if (-not $matchedPattern) { continue }

            if (-not $PSCmdlet.ShouldProcess($shortcut.FullName, 'Remove Start menu shortcut')) { continue }

            try {
                Remove-Item -Path $shortcut.FullName -Force -ErrorAction Stop
                Write-Log ("  Removed shortcut: {0} (pattern: {1})" -f $shortcut.FullName, $matchedPattern) -Level Success
                $removed++
            } catch {
                Write-Log ("  Failed to remove shortcut {0}: {1}" -f $shortcut.FullName, $_) -Level Warning
            }
        }
    }

    if ($removed -eq 0) {
        Write-Log "No promotional Start menu shortcuts found." -Level Info
    } else {
        Write-Log "Removed $removed Start menu shortcuts." -Level Success
    }
}

function Convert-RegistryValue {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Definition
    )

    switch ($Definition.Type.ToUpper()) {
        'REG_DWORD' { return [int]$Definition.Value }
        'REG_QWORD' { return [long]$Definition.Value }
        'REG_BINARY' { return ([byte[]][System.ComponentModel.TypeDescriptor]::GetConverter([byte[]]).ConvertFromString($Definition.Value)) }
        'REG_MULTI_SZ' { return [string[]]$Definition.Value }
        default { return [string]$Definition.Value }
    }
}

function Set-RegistryValueDebloat {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Definition
    )

    $targetPath = Resolve-RegPath -Hive $Definition.Hive -Path $Definition.Path
    $propertyType = switch ($Definition.Type.ToUpper()) {
        'REG_DWORD' { 'DWord' }
        'REG_QWORD' { 'QWord' }
        'REG_BINARY' { 'Binary' }
        'REG_MULTI_SZ' { 'MultiString' }
        default { 'String' }
    }

    if (-not (Test-Path $targetPath)) {
        try {
            New-Item -Path $targetPath -Force | Out-Null
        } catch {
            Write-Log ("  Failed to create registry path {0}: {1}" -f $targetPath, $_) -Level Warning
            return
        }
    }

    $value = Convert-RegistryValue -Definition $Definition

    $identifier = "$($Definition.Hive)\$($Definition.Path)\$($Definition.Name)"
    if (-not $PSCmdlet.ShouldProcess($identifier, 'Set registry value')) { return }

    try {
        New-ItemProperty -Path $targetPath -Name $Definition.Name -Value $value -PropertyType $propertyType -Force | Out-Null
        Write-Log "  Set registry: $identifier = $($Definition.Value)" -Level Success
    } catch {
        Write-Log ("  Failed to set {0}: {1}" -f $identifier, $_) -Level Warning
    }
}

function Apply-RegistryOptimizationsDebloat {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log "Applying registry optimizations..." -Level Info

    $debloatRegistryOptimizations = @{
        TelemetryDisable = @(
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Name = 'Enabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\Privacy'; Name = 'TailoredExperiencesWithDiagnosticDataEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'; Name = 'HasAccepted'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Input\TIPC'; Name = 'Enabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\InputPersonalization'; Name = 'RestrictImplicitInkCollection'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\InputPersonalization'; Name = 'RestrictImplicitTextCollection'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\InputPersonalization\TrainedDataStore'; Name = 'HarvestContacts'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Personalization\Settings'; Name = 'AcceptedPrivacyPolicy'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SYSTEM\CurrentControlSet\Services\dmwappushservice'; Name = 'Start'; Type = 'REG_DWORD'; Value = 4}
        )

        SponsoredAppsDisable = @(
            @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'OemPreInstalledAppsEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'PreInstalledAppsEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SilentInstalledAppsEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsConsumerFeatures'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'ContentDeliveryAllowed'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\PolicyManager\current\device\Start'; Name = 'ConfigureStartPins'; Type = 'REG_SZ'; Value = '{"pinnedList": [{}]}'}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'FeatureManagementEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'PreInstalledAppsEverEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SoftLandingEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKCU'; Path = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Name = 'SubscribedContentEnabled'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\PushToInstall'; Name = 'DisablePushToInstall'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\MRT'; Name = 'DontOfferThroughWUAU'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableConsumerAccountStateContent'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableCloudOptimizedContent'; Type = 'REG_DWORD'; Value = 1}
        )

        MiscOptimizations = @(
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager'; Name = 'ShippedWithReserves'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SYSTEM\CurrentControlSet\Control\BitLocker'; Name = 'PreventDeviceEncryption'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\Windows Chat'; Name = 'ChatIcon'; Type = 'REG_DWORD'; Value = 3}
            @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'TaskbarMn'; Type = 'REG_DWORD'; Value = 0}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\OneDrive'; Name = 'DisableFileSyncNGSC'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Teams'; Name = 'DisableInstallation'; Type = 'REG_DWORD'; Value = 1}
            @{Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\Windows Mail'; Name = 'PreventRun'; Type = 'REG_DWORD'; Value = 1}
        )
    }

    foreach ($category in $debloatRegistryOptimizations.Keys) {
        Write-Log "  - $category" -Level Info
        foreach ($definition in $debloatRegistryOptimizations[$category]) {
            Set-RegistryValueDebloat -Definition $definition
        }
    }
}

function Disable-TelemetryTasksDebloat {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log "Disabling telemetry-related scheduled tasks..." -Level Info

    $debloatScheduledTasks = @(
        '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
        '\Microsoft\Windows\Application Experience\ProgramDataUpdater'
        '\Microsoft\Windows\Windows Error Reporting\QueueReporting'
        '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
    )

    foreach ($task in $debloatScheduledTasks) {
        if (-not $PSCmdlet.ShouldProcess($task, 'Disable scheduled task')) { continue }
        try {
            schtasks.exe /Change /TN $task /Disable | Out-Null
            Write-Log "  Disabled: $task" -Level Success
        } catch {
            Write-Log ("  Failed to disable {0}: {1}" -f $task, $_) -Level Warning
        }
    }
}

function Start-DebloatMode {
    Write-Log "Starting Debloat mode for live Windows 11 system..." -Level Info

    $candidates = Get-RemovalCandidates
    Remove-ProvisionedPackages -Candidates $candidates
    Remove-InstalledPackages -Candidates $candidates

    if (-not $SkipOneDrive) {
        Remove-OneDriveDebloat
    } else {
        Write-Log "Skipping OneDrive removal as requested." -Level Info
    }

    Remove-StartMenuShortcuts

    if (-not $SkipRegistryOptimizations) {
        Apply-RegistryOptimizationsDebloat
    } else {
        Write-Log "Skipping registry optimizations as requested." -Level Info
    }

    if (-not $SkipScheduledTasks) {
        Disable-TelemetryTasksDebloat
    } else {
        Write-Log "Skipping scheduled task changes as requested." -Level Info
    }

    Write-Log "Debloat routine completed successfully." -Level Success
}

function Start-ImageMode {
    Write-Log "Starting Image mode for Windows 11 ISO optimization..." -Level Info

    $driveLetter = Get-SourceIso
    Write-Log "DEBUG: Get-SourceIso returned: '$driveLetter'" -Level Info

    # Verify drive is still accessible before proceeding
    $driveRoot = $driveLetter.Trim().TrimEnd(':') + ':\'
    Write-Log "DEBUG: Pre-copy verification for: '$driveRoot'" -Level Info

    if (-not (Test-Path $driveRoot)) {
        Write-Log "Critical: Drive $driveLetter was dismounted after validation!" -Level Error
        Write-Log "The ISO may have been auto-dismounted by Windows." -Level Error
        Write-Log "Please mount the ISO programmatically or keep it mounted." -Level Error
        throw "Source drive was unexpectedly dismounted"
    }
    Write-Log "DEBUG: Pre-copy verification succeeded" -Level Info

    Copy-WindowsSource -SourcePath $driveLetter

    $imageIndex = Select-WindowsImage
    $imageInfo = Mount-WindowsInstallImage -Index $imageIndex

    Remove-BloatwarePackages
    Remove-OneDrive

    Mount-RegistryHives
    Apply-RegistryOptimizations
    Remove-TelemetryTasks
    Dismount-RegistryHives

    Optimize-WindowsImage
    Dismount-AndExport-Image -Index $imageIndex

    Process-BootImage
    New-BootableIso -Architecture $imageInfo.Architecture

    Write-Log "" -Level Info
    Write-Log "========================================" -Level Success
    Write-Log "$($Config.ProjectName) image creation completed!" -Level Success
    Write-Log "Output: $($Script:Paths.IsoOutput)" -Level Success
    Write-Log "========================================" -Level Success
}

try {
    Clear-Host
    Initialize-Environment

    if ($Mode -eq 'Debloat') {
        Start-DebloatMode
    } else {
        Start-ImageMode
    }

} catch {
    Write-Log "Critical error: $_" -Level Error
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Log $_.InvocationInfo.PositionMessage -Level Error
    }
    exit 1

} finally {
    if ($Script:Paths.TranscriptPath -and (Test-Path $Script:Paths.TranscriptPath)) {
        try {
            Stop-Transcript | Out-Null
        } catch {}
    }
    
    if ($Mode -eq 'Image') {
        Clear-WorkingDirectories
    }

    Write-Host "`nPress Enter to exit..."
    Read-Host
}
