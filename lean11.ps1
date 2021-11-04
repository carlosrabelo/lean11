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

.PARAMETER ProductKey
    Optional product key for Windows activation
    If provided, will be included in autounattend.xml via Microsoft-Windows-Shell-Setup
    WARNING: Use your own legitimate product key

.PARAMETER NonInteractive
    Skip interactive prompts (e.g. Press Enter to exit). Fail closed on ambiguous errors.

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

.EXAMPLE
    # Image mode: With product key for automatic activation
    .\lean11.ps1 -Mode Image -ISO E -SCRATCH D -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

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
    [ValidateScript({
        if ($_ -match '^[c-zC-Z]:?$') { return $true }
        if ($_ -match '\.iso$') { return $true }
        throw "ISO must be a drive letter (E or E:) or a path to an .iso file."
    })]
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
    [switch]$SkipScheduledTasks,

    [Parameter(Mandatory=$false)]
    [string]$ProductKey,

    [Parameter(Mandatory=$false)]
    [switch]$NonInteractive
)

# Import required modules (only if running locally)
if ($PSScriptRoot) {
    Import-Module DISM -ErrorAction SilentlyContinue
    Import-Module ServerManager -ErrorAction SilentlyContinue
}

$Script:Config = @{
    ProjectName = 'Lean11'
    Version = '1.1.0'
    LogPrefix = 'lean11'
    IsoName = 'lean11.iso'
    WorkDir = 'lean11_work'
    MountDir = 'lean11_mount'
    OscdimgUrl = 'https://msdl.microsoft.com/download/symbols/oscdimg.exe/3D44737265000/oscdimg.exe'
    # PE TimeDateStamp|SizeOfImage identity from the Microsoft symbol-server path above
    OscdimgSymbolId = '3D44737265000'
    # Used when re-elevating after irm/iex (no local -File path)
    RemoteScriptUrl = 'https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1'
}

$Script:Paths = @{
    ScriptRoot = $PSScriptRoot
    WorkDir = $null
    MountDir = $null
    IsoOutput = $null
    AutoUnattend = $null
    AutoUnattendTemplate = $null
    Oscdimg = $null
    TranscriptPath = $null
}

# ISO mounting tracking
$Script:IsoMountedByScript = $false
$Script:SourceDriveLetter = $null
$Script:OscdimgDownloaded = $false

# PACKAGE POLICY:
# -------------------------------------------------------------------------
# Entries in PackageCategories are REMOVAL targets.
# DefaultKeepPackages are never removed (merged with -KeepPackages).
# Also kept by omission (not listed): Microsoft.WindowsTerminal,
# Microsoft.MicrosoftStickyNotes, Microsoft.WindowsCamera, Calculator, etc.
# Use -KeepPackages to preserve removal-list packages (e.g. "Xbox", "Teams").

# Always preserved: Paint (classic + Store) and Snipping Tool (Screen Sketch)
$Script:DefaultKeepPackages = @(
    'Microsoft.Paint'
    'Microsoft.MSPaint'
    'Microsoft.ScreenSketch'
)

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
        # Microsoft 365 Copilot app ships as MicrosoftOfficeHub (Store 9WZDNCRD29V9)
        'Microsoft.MicrosoftOfficeHub'
        'MicrosoftCorporationII.MicrosoftOfficeHub'
        'MicrosoftCorporationII.OfficeHub'
        'Microsoft.Office.OneNote'
        'Microsoft.OutlookForWindows'
        'Microsoft.OfficePushNotificationUtility'
    )

    Communication = @(
        'MicrosoftTeams'
        'MSTeams'
        'Microsoft.Windows.Teams'
        'Microsoft.LinkedIn'
        'MicrosoftCorporationII.LinkedInForWindows'
        'LinkedInForWindows'
        '7EE7776C.LinkedInforWindows'
        '5319275A.WhatsAppDesktop'
        'WhatsAppDesktop'
        'WhatsApp.WhatsApp'
        'Microsoft.YourPhone'
    )

    Utilities = @(
        'Microsoft.GetHelp'
        'Microsoft.Getstarted'
        'Microsoft.StartExperiencesApp'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.WindowsMaps'
        'Microsoft.WindowsAlarms'
        'Microsoft.WindowsSoundRecorder'
        'MicrosoftCorporationII.QuickAssist'
        'Microsoft.Todos'
        'Microsoft.PowerAutomateDesktop'
    )

    Other = @(
        'Microsoft.People'
        'Microsoft.Wallet'
        'Microsoft.Windows.DevHome'
        'Microsoft.Windows.CrossDevice'
        'MicrosoftWindows.CrossDevice'
        'MicrosoftWindows.Client.WebExperience'
        'Microsoft.WidgetsPlatformRuntime'
        'MicrosoftCorporationII.MicrosoftFamily'
        'Microsoft.549981C3F5F10'
        'Microsoft.Copilot'
        'Microsoft.Windows.Ai.Copilot.Provider'
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
        @{Hive='zNTUSER'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name='ShowCopilotButton'; Type='REG_DWORD'; Value='0'}
        @{Hive='zSOFTWARE'; Path='Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Type='REG_DWORD'; Value='1'}
        @{Hive='zNTUSER'; Path='Software\Policies\Microsoft\Windows\WindowsCopilot'; Name='TurnOffWindowsCopilot'; Type='REG_DWORD'; Value='1'}
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
    'Microsoft 365*'
    'Microsoft 365 Copilot*'
    'Copilot*'
    'Office*'
    'Outlook*'
    'OneNote*'
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
        $scriptPath = $PSCommandPath
        if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) {
            # irm|iex / scriptblock invoke — materialize so -File elevation works
            $scriptPath = Join-Path $env:TEMP 'lean11.ps1'
            try {
                Invoke-WebRequest -Uri $Script:Config.RemoteScriptUrl -OutFile $scriptPath -UseBasicParsing
            } catch {
                throw "Cannot elevate from remote invocation: failed to download script to TEMP. Run an elevated PowerShell first. $_"
            }
        }
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        if ($Mode) { $arguments += " -Mode $Mode" }
        if ($ISO) { $arguments += " -ISO `"$ISO`"" }
        if ($SCRATCH) { $arguments += " -SCRATCH $SCRATCH" }
        if ($KeepPackages.Count -gt 0) {
            $escaped = $KeepPackages | ForEach-Object {
                $escapedValue = $_ -replace '"', '""'
                "`"$escapedValue`""
            }
            $arguments += " -KeepPackages $($escaped -join ',')"
        }
        if ($SkipOneDrive) { $arguments += " -SkipOneDrive" }
        if ($SkipRegistryOptimizations) { $arguments += " -SkipRegistryOptimizations" }
        if ($SkipScheduledTasks) { $arguments += " -SkipScheduledTasks" }
        if ($ProductKey) { $arguments += " -ProductKey `"$ProductKey`"" }
        if ($NonInteractive) { $arguments += " -NonInteractive" }
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
        $Script:Paths.ScriptRoot = $scriptRoot

        if ($SCRATCH) {
            $scratchLetter = $SCRATCH.TrimEnd(':')
            $Script:Paths.WorkDir = "${scratchLetter}:\$($Config.WorkDir)"
            $Script:Paths.MountDir = "${scratchLetter}:\$($Config.MountDir)"
        } else {
            $Script:Paths.WorkDir = Join-Path $scriptRoot $Config.WorkDir
            $Script:Paths.MountDir = Join-Path $scriptRoot $Config.MountDir
        }

        $Script:Paths.IsoOutput = Join-Path $scriptRoot $Config.IsoName
        $Script:Paths.AutoUnattendTemplate = Join-Path $scriptRoot 'autounattend.xml'
        # Generated unattend lives in the work dir; never overwrite/delete the repo template
        $Script:Paths.AutoUnattend = Join-Path $Script:Paths.WorkDir 'autounattend.xml'
        $Script:Paths.Oscdimg = Join-Path $scriptRoot 'oscdimg.exe'

        New-Item -ItemType Directory -Force -Path $Script:Paths.WorkDir -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Force -Path "$($Script:Paths.WorkDir)\sources" -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Force -Path $Script:Paths.MountDir -ErrorAction SilentlyContinue | Out-Null
    }

    # Ensure temp directory exists
    $tempPath = if ($env:TEMP) { $env:TEMP } else { Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { $pwd.Path }) 'temp' }
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
        Write-Log "Transcript: $($Script:Paths.TranscriptPath)" -Level Info
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
    # Give Windows a moment to settle if ISO was just mounted
    Start-Sleep -Milliseconds 500

    # Try multiple verification methods
    $pathExists = $false

    # Method 1: Test-Path
    if (Test-Path $driveRoot) {
        $pathExists = $true
    }

    # Method 2: Get-PSDrive
    if (-not $pathExists) {
        $drive = Get-PSDrive -Name $SourcePath -PSProvider FileSystem -ErrorAction SilentlyContinue
        if ($drive) {
            $pathExists = $true
        }
    }

    # Method 3: Get-Volume
    if (-not $pathExists) {
        $volume = Get-Volume -DriveLetter $SourcePath -ErrorAction SilentlyContinue
        if ($volume) {
            $pathExists = $true
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
        if ("$_" -match 'Insufficient disk space') { throw }
        Write-Log "Disk space verification failed: $_" -Level Error
        Write-Log "This may indicate insufficient permissions or disk access issues" -Level Warning
        if ($NonInteractive) {
            throw "Disk space verification failed in non-interactive mode: $_"
        }
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

function Test-PackageNameMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Pattern)) { return $false }

    # Prefer anchored / family-style matches over broad substring wildcards.
    # Use ${Pattern} so "_*" is not parsed as a variable name ($Pattern_).
    return (
        ($PackageName -eq $Pattern) -or
        ($PackageName -like "${Pattern}_*") -or
        ($PackageName -like "${Pattern}.*") -or
        ($PackageName.StartsWith($Pattern + '_', [System.StringComparison]::OrdinalIgnoreCase)) -or
        ($PackageName.StartsWith($Pattern + '.', [System.StringComparison]::OrdinalIgnoreCase))
    )
}

function Remove-BloatwarePackages {
    Write-Log "Analyzing installed provisioned packages..." -Level Info

    $installedPackages = & dism /English /image:$($Script:Paths.MountDir) /Get-ProvisionedAppxPackages |
        ForEach-Object { if ($_ -match 'PackageName : (.*)') { $matches[1] } }
    if ($LASTEXITCODE -ne 0) {
        Write-Log "DISM Get-ProvisionedAppxPackages failed with exit code $LASTEXITCODE" -Level Warning
    }

    $removalList = @()
    foreach ($category in $Script:PackageCategories.Keys) {
        foreach ($packagePrefix in $Script:PackageCategories[$category]) {
            $matchingPackages = $installedPackages | Where-Object { Test-PackageNameMatch -PackageName $_ -Pattern $packagePrefix }
            $removalList += $matchingPackages
        }
    }

    $removalList = $removalList | Select-Object -Unique

    if ($KeepPackages.Count -gt 0) {
        Write-Log "Keeping user-specified packages: $($KeepPackages -join ', ')" -Level Info
    }
    $removalList = @($removalList | Where-Object { -not (Should-KeepPackage -PackageName $_) })

    Write-Log "Removing $($removalList.Count) bloatware packages..." -Level Info

    foreach ($package in $removalList) {
        Write-Log "  Removing: $package" -Level Info
        & dism /English /image:$($Script:Paths.MountDir) /Remove-ProvisionedAppxPackage /PackageName:$package >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "  DISM failed removing $package (exit $LASTEXITCODE)" -Level Warning
        }
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
            & reg load $hive.Key $hive.Value >$null 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "  Loaded: $($hive.Key)" -Level Info
            } else {
                Write-Log "  Failed to load $($hive.Key) (exit $LASTEXITCODE)" -Level Warning
            }
        } else {
            Write-Log "  Hive file not found: $($hive.Value)" -Level Warning
        }
    }

    Write-Log "Registry hives loading completed" -Level Success
}

function Dismount-RegistryHives {
    Write-Log "Unloading registry hives..." -Level Info

    foreach ($hive in @('HKLM\zCOMPONENTS', 'HKLM\zDEFAULT', 'HKLM\zNTUSER', 'HKLM\zSOFTWARE', 'HKLM\zSYSTEM')) {
        & reg unload $hive >$null 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Log "  Failed to unload $hive (exit $LASTEXITCODE)" -Level Warning
        }
    }

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

    & reg add $path /v $Optimization.Name /t $Optimization.Type /d $Optimization.Value /f >$null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "  Failed to set $path\$($Optimization.Name) (exit $LASTEXITCODE)" -Level Warning
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
    if ($LASTEXITCODE -ne 0) {
        throw "DISM Cleanup-Image failed with exit code $LASTEXITCODE"
    }
    Write-Log "Image optimization completed" -Level Success
}

function Dismount-AndExport-Image {
    param([int]$Index)

    Write-Log "Saving and unmounting Windows image..." -Level Info
    Dismount-WindowsImage -Path $Script:Paths.MountDir -Save

    Write-Log "Exporting optimized image with maximum compression..." -Level Info
    $wimPath = "$($Script:Paths.WorkDir)\sources\install.wim"
    $wimPathTemp = "$($Script:Paths.WorkDir)\sources\install2.wim"

    if (Test-Path $wimPathTemp) {
        Remove-Item -Path $wimPathTemp -Force -ErrorAction SilentlyContinue
    }

    & dism /English /Export-Image /SourceImageFile:$wimPath /SourceIndex:$Index /DestinationImageFile:$wimPathTemp /Compress:recovery
    if ($LASTEXITCODE -ne 0) {
        throw "DISM Export-Image failed with exit code $LASTEXITCODE. Original install.wim was preserved."
    }
    if (-not (Test-Path $wimPathTemp) -or (Get-Item $wimPathTemp).Length -eq 0) {
        throw "DISM Export-Image reported success but install2.wim is missing or empty. Original install.wim was preserved."
    }

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

    $bootMounted = $false
    $hivesMounted = $false
    try {
        Mount-WindowsImage -ImagePath $bootWimPath -Index 2 -Path $Script:Paths.MountDir
        $bootMounted = $true

        Mount-RegistryHives
        $hivesMounted = $true

        Write-Log "Applying system requirement bypasses to boot image..." -Level Info
        foreach ($opt in $Script:RegistryOptimizations.SystemRequirementsBypass) {
            Set-RegistryOptimization -Optimization $opt -Description "Boot image bypass"
        }
    } finally {
        if ($hivesMounted) {
            Dismount-RegistryHives
        }
        if ($bootMounted) {
            Write-Log "Unmounting boot image..." -Level Info
            try {
                Dismount-WindowsImage -Path $Script:Paths.MountDir -Save -ErrorAction Stop
            } catch {
                Write-Log "Save dismount failed, discarding boot mount: $_" -Level Warning
                Dismount-WindowsImage -Path $Script:Paths.MountDir -Discard -ErrorAction SilentlyContinue
                throw
            }
        }
    }

    Write-Log "Boot image processing completed" -Level Success
}

function Test-OscdimgIntegrity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path) -or (Get-Item $Path).Length -eq 0) {
        throw "oscdimg.exe is missing or empty: $Path"
    }

    # Verify PE TimeDateStamp + SizeOfImage match the Microsoft symbol-server identity
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "oscdimg.exe is not a valid PE executable"
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if (($peOffset + 24 + 56) -gt $bytes.Length) {
        throw "oscdimg.exe PE headers are truncated"
    }
    $peSig = [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4)
    if ($peSig -ne "PE`0`0") {
        throw "oscdimg.exe is missing a PE signature"
    }
    $timeDateStamp = [BitConverter]::ToUInt32($bytes, $peOffset + 8)
    $sizeOfImage = [BitConverter]::ToUInt32($bytes, $peOffset + 24 + 56)
    $fullId = "{0:X8}{1:X}" -f $timeDateStamp, $sizeOfImage
    if ($fullId -ne $Config.OscdimgSymbolId) {
        throw "oscdimg.exe PE identity '$fullId' does not match expected '$($Config.OscdimgSymbolId)'"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') {
        throw "oscdimg.exe Authenticode status is '$($signature.Status)' (expected Valid)"
    }
    $subject = $signature.SignerCertificate.Subject
    if ($subject -notmatch 'Microsoft') {
        throw "oscdimg.exe is not signed by Microsoft (subject: $subject)"
    }

    Write-Log "oscdimg.exe integrity verified (PE id + Microsoft Authenticode)" -Level Success
}

function Get-OscdimgTool {
    Write-Log "Locating oscdimg.exe..." -Level Info

    # Prefer Windows ADK
    $hostArchitecture = $Env:PROCESSOR_ARCHITECTURE
    if ($hostArchitecture -eq 'AMD64') { $hostArchitecture = 'amd64' }

    $adkDepTools = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\$hostArchitecture\Oscdimg"
    $adkPath = Join-Path $adkDepTools "oscdimg.exe"

    if (Test-Path $adkPath) {
        Write-Log "Using oscdimg.exe from system ADK" -Level Success
        return $adkPath
    }

    # Download from Microsoft symbol server only if not already present locally
    if (-not (Test-Path $Script:Paths.Oscdimg)) {
        try {
            Write-Log "ADK not found. Downloading oscdimg.exe from Microsoft symbol server..." -Level Info
            Invoke-WebRequest -Uri $Config.OscdimgUrl -OutFile $Script:Paths.Oscdimg -ErrorAction Stop
            $Script:OscdimgDownloaded = $true
        } catch {
            Write-Log "Failed to download oscdimg.exe: $_" -Level Error
            Write-Log "Please install Windows ADK or place a verified oscdimg.exe next to the script" -Level Error
            throw
        }
    } else {
        Write-Log "oscdimg.exe already exists locally" -Level Info
    }

    try {
        Test-OscdimgIntegrity -Path $Script:Paths.Oscdimg
    } catch {
        if ($Script:OscdimgDownloaded -and (Test-Path $Script:Paths.Oscdimg)) {
            Remove-Item -Path $Script:Paths.Oscdimg -Force -ErrorAction SilentlyContinue
            $Script:OscdimgDownloaded = $false
        }
        Write-Log "oscdimg.exe failed integrity checks: $_" -Level Error
        throw
    }

    Write-Log "Using verified local oscdimg.exe" -Level Success
    return $Script:Paths.Oscdimg
}

function Build-AutoUnattendContent {
    param(
        [string]$Architecture = 'amd64',
        [string]$Language = 'en-US',
        [string]$ProductKey
    )

    $arch = if ($Architecture) { $Architecture } else { 'amd64' }
    $lang = if ($Language) { $Language } else { 'en-US' }

    $productKeyComponent = ''
    if ($ProductKey) {
        $escapedKey = [System.Security.SecurityElement]::Escape($ProductKey)
        $productKeyComponent = @"

        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <ProductKey>$escapedKey</ProductKey>
        </component>
"@
    }

    return @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <InputLocale>$lang</InputLocale>
            <SystemLocale>$lang</SystemLocale>
            <UILanguage>$lang</UILanguage>
            <UserLocale>$lang</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <ProtectYourPC>3</ProtectYourPC>
            </OOBE>
        </component>
    </settings>
    <settings pass="specialize">$productKeyComponent
        <component name="Microsoft-Windows-Deployment" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
    </settings>
</unattend>
"@
}

function New-AutoUnattendFile {
    param(
        [string]$Architecture = 'amd64',
        [string]$Language = 'en-US'
    )

    Write-Log "Generating autounattend.xml for OOBE bypass..." -Level Info

    if ($ProductKey) {
        Write-Log "Including product key in Microsoft-Windows-Shell-Setup" -Level Info
    }

    $autounattendContent = Build-AutoUnattendContent -Architecture $Architecture -Language $Language -ProductKey $ProductKey

    if (-not $Script:Paths.WorkDir) {
        throw "Work directory is not initialized; cannot write autounattend.xml"
    }

    $Script:Paths.AutoUnattend = Join-Path $Script:Paths.WorkDir 'autounattend.xml'
    Set-Content -Path $Script:Paths.AutoUnattend -Value $autounattendContent -Encoding UTF8
    Write-Log "AutoUnattend file created at $($Script:Paths.AutoUnattend)" -Level Success
}

function New-BootableIso {
    param(
        [string]$Architecture = 'amd64',
        [string]$Language = 'en-US'
    )

    Write-Log "Creating bootable ISO..." -Level Info

    # Always regenerate into the work directory so ProductKey/locale stay in sync
    New-AutoUnattendFile -Architecture $Architecture -Language $Language

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

    # Never delete the repo autounattend.xml template. Only remove scratch dirs
    # and oscdimg.exe when this run downloaded it.
    $itemsToRemove = @(
        @{Path=$Script:Paths.WorkDir; Desc="Working directory"}
        @{Path=$Script:Paths.MountDir; Desc="Mount directory"}
    )
    if ($Script:OscdimgDownloaded -and $Script:Paths.Oscdimg) {
        $itemsToRemove += @{Path=$Script:Paths.Oscdimg; Desc="downloaded oscdimg.exe"}
    }

    foreach ($item in $itemsToRemove) {
        if ($item.Path -and (Test-Path $item.Path)) {
            try {
                Remove-Item -Path $item.Path -Recurse -Force -ErrorAction Stop
                Write-Log "  Removed: $($item.Desc)" -Level Info
            } catch {
                Write-Log "  Initial removal failed for $($item.Desc), attempting forced removal..." -Level Warning

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

    $keepPatterns = @()
    if ($Script:DefaultKeepPackages) { $keepPatterns += $Script:DefaultKeepPackages }
    if ($KeepPackages) { $keepPatterns += $KeepPackages }

    foreach ($keep in $keepPatterns) {
        if ([string]::IsNullOrWhiteSpace($keep)) { continue }
        # Anchored match first; also allow short user tokens (e.g. "Xbox", "Teams")
        if ((Test-PackageNameMatch -PackageName $PackageName -Pattern $keep) -or
            ($PackageName -like "*$keep*")) {
            return $true
        }
    }
    return $false
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

function Start-DebloatMode {
    Write-Log "Debloat mode is not implemented yet." -Level Warning
}

function Start-ImageMode {
    Write-Log "Starting Image mode for Windows 11 ISO optimization..." -Level Info

    $driveLetter = Get-SourceIso

    # Verify drive is still accessible before proceeding
    $driveRoot = $driveLetter.Trim().TrimEnd(':') + ':\'

    if (-not (Test-Path $driveRoot)) {
        Write-Log "Critical: Drive $driveLetter was dismounted after validation!" -Level Error
        Write-Log "The ISO may have been auto-dismounted by Windows." -Level Error
        Write-Log "Please mount the ISO programmatically or keep it mounted." -Level Error
        throw "Source drive was unexpectedly dismounted"
    }

    Copy-WindowsSource -SourcePath $driveLetter

    $imageIndex = Select-WindowsImage
    $imageInfo = $null
    $imageMounted = $false
    $hivesMounted = $false

    try {
        $imageInfo = Mount-WindowsInstallImage -Index $imageIndex
        $imageMounted = $true

        Remove-BloatwarePackages
        Remove-OneDrive

        try {
            Mount-RegistryHives
            $hivesMounted = $true
            Apply-RegistryOptimizations
            Remove-TelemetryTasks
        } finally {
            if ($hivesMounted) {
                Dismount-RegistryHives
                $hivesMounted = $false
            }
        }

        Optimize-WindowsImage
        Dismount-AndExport-Image -Index $imageIndex
        $imageMounted = $false

        Process-BootImage
        New-BootableIso -Architecture $imageInfo.Architecture -Language $imageInfo.Language
    } catch {
        if ($hivesMounted) {
            try { Dismount-RegistryHives } catch {}
            $hivesMounted = $false
        }
        if ($imageMounted) {
            Write-Log "Discarding mounted install image after failure..." -Level Warning
            try { Dismount-WindowsImage -Path $Script:Paths.MountDir -Discard -ErrorAction SilentlyContinue } catch {}
            $imageMounted = $false
        }
        throw
    }

    Write-Host ""
    Write-Log "========================================" -Level Success
    Write-Log "$($Config.ProjectName) image creation completed!" -Level Success
    Write-Log "Output: $($Script:Paths.IsoOutput)" -Level Success
    Write-Log "========================================" -Level Success
}

# Skip auto-run when dot-sourced (e.g. Pester tests)
$script:Lean11IsDotSourced = ($MyInvocation.InvocationName -eq '.') -or ($MyInvocation.Line -match '^\s*\.\s+')

if (-not $script:Lean11IsDotSourced) {
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

        if (-not $NonInteractive) {
            Write-Host "`nPress Enter to exit..."
            Read-Host
        }
    }
}
