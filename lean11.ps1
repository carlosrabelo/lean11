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

function Clear-WorkingDirectories {
    Write-Log "Working-directory cleanup is not implemented yet." -Level Info
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

function Start-DebloatMode {
    Write-Log "Debloat mode is not implemented yet." -Level Warning
}

function Start-ImageMode {
    Write-Log "Image mode is not implemented yet." -Level Warning
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
