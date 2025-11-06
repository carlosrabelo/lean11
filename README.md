# Lean11 Image Optimizer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6.svg)](https://www.microsoft.com/windows/windows-11)
[![GitHub stars](https://img.shields.io/github/stars/carlosrabelo/lean11)](https://github.com/carlosrabelo/lean11/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/carlosrabelo/lean11)](https://github.com/carlosrabelo/lean11/issues)

**Dual-mode Windows 11 optimizer: Create debloated ISOs or clean installed systems**

---

## About

Lean11 is a PowerShell-based Windows 11 optimizer that operates in two distinct modes:

**Image Mode**: Creates debloated Windows 11 installation media
- Mounts original Windows 11 ISO
- Removes bloatware packages before installation
- Applies privacy and performance optimizations
- Exports optimized bootable ISO (~36% smaller)

**Debloat Mode**: Cleans up already-installed Windows 11 systems
- Removes bloatware from running systems
- Applies same optimizations as Image Mode
- No ISO required - runs directly on your machine
- Ideal for cleaning pre-installed or existing installations

Both modes share the same modular architecture using hashtables for configuration and multi-level logging system.

### Design Philosophy

The project adopts the following principles:

- **Separation of Concerns**: Each function has a single, well-defined purpose
- **Configuration over Code**: Behavior defined by data structures, not scattered logic
- **Observability**: Structured logging system with severity levels
- **Extensibility**: Add functionality without modifying the codebase
- **Resilience**: Robust error handling with try-catch-finally blocks

---

## Technical Differentiator

### Component-Based Architecture

```
┌─────────────────────────────────────────┐
│     Declarative Configuration           │
│  (Hashtables + Script Scope)            │
└──────────────┬──────────────────────────┘
               │
    ┌──────────▼──────────┐
    │  Core Functions     │
    │  - Validation       │
    │  - Transformation   │
    │  - Export           │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │  Orchestrator       │
    │  (Main Execution)   │
    └─────────────────────┘
```

### Configuration System

All operations are defined through data structures:

```powershell
# Example: Package categorization
$Script:PackageCategories = @{
    Gaming = @('Microsoft.XboxApp', 'Microsoft.XboxGameOverlay')
    Office = @('Microsoft.MicrosoftOfficeHub', 'Microsoft.Todos')
}

# Example: Registry optimizations
$Script:RegistryOptimizations = @{
    TelemetryDisable = @(
        @{Hive='zSYSTEM'; Path='...'; Name='...'; Type='REG_DWORD'; Value='0'}
    )
}
```

This approach allows modifications without altering logic.

---

## Installation

### System Requirements

| Component | Specification |
|-----------|---------------|
| Operating System | Windows 11 (host) |
| PowerShell | 5.1 or higher |
| Privileges | Administrator |
| Disk Space | Minimum 20GB free |
| Source Media | Official Windows 11 ISO |

### Environment Setup

**1. Get Windows 11 ISO**

Source: https://www.microsoft.com/software-download/windows11

**2. Mount ISO on the system**

Method: Windows Explorer → Right-click → Mount

**3. Configure execution policy (temporary session)**
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

**4. Run optimizer**
```powershell
.\lean11.ps1 -ISO <letter> -SCRATCH <letter>
```

---

## Usage

### `lean11.ps1` (Unified Dual-Mode Script)

#### Image Mode (ISO Optimization)

**Standard Mode**
```powershell
# ISO mounted at E:, workspace at D:
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

**Selective Preservation Mode**

Preserve Windows Terminal and Paint:
```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "WindowsTerminal","Paint"
```

Preserve multiple packages:
```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "Calculator","StickyNotes","ScreenSketch"
```

**Simplified Mode**
```powershell
# Uses script directory as workspace
.\lean11.ps1 -Mode Image -ISO E
```

#### Debloat Mode (Live System Optimization)

Run from an elevated PowerShell session on the machine you want to clean up.

Standard debloat:
```powershell
.\lean11.ps1 -Mode Debloat
```

Remove default bloat while keeping Windows Terminal and Paint:
```powershell
.\lean11.ps1 -Mode Debloat -KeepPackages "WindowsTerminal","Paint"
```

Skip OneDrive removal:
```powershell
.\lean11.ps1 -Mode Debloat -SkipOneDrive
```

Skip registry optimizations:
```powershell
.\lean11.ps1 -Mode Debloat -SkipRegistryOptimizations
```

Skip scheduled tasks:
```powershell
.\lean11.ps1 -Mode Debloat -SkipScheduledTasks
```

**Note**: Restart after removal if you remove provisioned apps or OneDrive.

---

## Remote Execution (IRM + IEX)

###    Security Warning + Technical Limitations

**NOT RECOMMENDED** - Remote execution has both security risks AND technical limitations:

**Security Risks:**
- Man-in-the-middle attacks
- Code modification without detection
- No integrity verification

**Technical Limitations:**
- PowerShell module imports fail remotely
- Parameter validation may not work correctly
- File path dependencies break
- Script metadata processing issues

### Working Remote Methods

**Method 1: Download then Execute**
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" -OutFile "lean11.ps1"
```
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Method 2: GitHub CLI (Recommended)**
```powershell
gh repo clone carlosrabelo/lean11
```
```powershell
cd lean11
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Method 3: PowerShell Gallery (if available)**
```powershell
Install-Script -Name Lean11 -Force
```
```powershell
Lean11.ps1 -Mode Debloat
```

### IRM + IEX Method

```powershell
# Alternative syntax
irm "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" | iex
```

### With Parameters

Image mode with parameters (Method 1: Direct execution):
```powershell
Invoke-Expression "& { $(irm 'https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1') } -Mode Image -ISO E"
```

Image mode with parameters (Method 2: Variable approach):
```powershell
$script = irm "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1"
$script | Save-String lean11.ps1
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

Debloat mode with parameters:
```powershell
Invoke-Expression "& { $(irm 'https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1') } -Mode Debloat -KeepPackages 'WindowsTerminal','Paint'"
```

### Safer Alternatives

**1. Download and Verify**

Download first:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1" -OutFile "lean11.ps1"
```

Verify content (optional):
```powershell
Get-Content lean11.ps1 | Select-Object -First 20
```

Execute after verification:
```powershell
.\lean11.ps1 -Mode Debloat
```

**2. Hash Verification**
```powershell
# Download and verify SHA256
$hash = Get-FileHash lean11.ps1 -Algorithm SHA256
# Replace with actual hash from GitHub releases page
$expectedHash = "ACTUAL_SHA256_HASH_HERE"  
if ($hash.Hash -eq $expectedHash) {
    .\lean11.ps1 -Mode Debloat
} else {
    Write-Error "Hash mismatch! Script may be compromised."
}
```

**3. GitHub CLI**
```powershell
gh repo clone carlosrabelo/lean11
```
```powershell
cd lean11
```
```powershell
.\lean11.ps1 -Mode Debloat
```

**Recommendation**: Always download and verify scripts before execution, especially when running with administrator privileges.

---

## Operations Performed

### Component Removal

The optimization process removes the following software categories:

**Hardware/OEM**: Manufacturer-specific tools
**Media**: Non-essential media applications
**Productivity**: Simplified Office suite
**Communication**: Alternative messaging and email clients
**Entertainment**: Games and Xbox services
**Utilities**: Redundant system tools

**Total**: 50+ AppX packages removed

### Preserved Components

The following essential Windows components remain **fully functional**:

- **Microsoft Store**: App installation and updates
- **Windows Defender**: Security and antivirus protection
- **Windows Update**: System updates and patches
- **Microsoft Edge**: Default browser
- **Windows Copilot**: AI assistant (can be removed via KeepPackages if desired)

### System Optimizations

**Hardware Bypass**
- TPM 2.0 not required
- Secure Boot not required
- Relaxed RAM/CPU requirements
- Legacy hardware installation enabled

**Privacy and Telemetry**
- Diagnostic data collection: Disabled
- Advertising ID: Disabled
- Personalized experiences: Disabled
- Telemetry services: Stopped

**Sponsored Content**
- Pre-installed OEM apps: Blocked
- Content suggestions: Disabled
- Automatic installations: Blocked
- Content Delivery Manager: Neutralized

**OOBE (Out of Box Experience)**
- Local account creation: Enabled
- Microsoft account requirements: Removed
- Offline setup: Possible

---

## Code Architecture

### Main Components

| Function | Responsibility | Input | Output |
|--------|-----------------|-------|--------|
| `Initialize-Environment` | Path and logging setup | Parameters | Paths hashtable |
| `Get-SourceIso` | Source media validation | Drive letter | Validated path |
| `Mount-WindowsInstallImage` | WIM mounting | Index | Image info |
| `Remove-BloatwarePackages` | Categorized removal | Categories | Removed count |
| `Apply-RegistryOptimizations` | Batch application | Optimization sets | Success status |
| `New-BootableIso` | Media generation | Work dir | ISO path |

### Execution Flow

```
[Initialization] → [Validation] → [Mount] → [Transform] → [Optimize] → [Export] → [Cleanup]
       ↓              ↓             ↓           ↓             ↓           ↓          ↓
   Paths Setup   ISO Check   Mount WIM   Remove Apps   Registry Tweaks Create ISO Cleanup
```

### Logging System

Structured logging implementation with levels:

```powershell
Write-Log "Message" -Level Info      # Informational
Write-Log "Message" -Level Success   # Operation success (green)
Write-Log "Message" -Level Warning   # Non-critical issue (yellow)
Write-Log "Message" -Level Error     # Critical failure (red)
```

**Output**: `lean11_YYYYMMDD_HHmmss.log`

---

## Customization

### Add Removal Category

Locate `$Script:PackageCategories` in the script:

```powershell
$Script:PackageCategories = @{
    # ... existing ...

    CustomCategory = @(
        'Vendor.PackageName'
        'Another.Package'
    )
}
```

### Add Registry Optimization

Locate `$Script:RegistryOptimizations`:

```powershell
$Script:RegistryOptimizations = @{
    # ... existing ...

    CustomOptimizations = @(
        @{
            Hive  = 'zSOFTWARE'
            Path  = 'Path\To\Key'
            Name  = 'ValueName'
            Type  = 'REG_DWORD'
            Value = '1'
        }
    )
}
```

### Modify Scheduled Tasks

Locate `$Script:ScheduledTasksToRemove`:

```powershell
$Script:ScheduledTasksToRemove = @(
    'Microsoft\Windows\Path\To\Task'
)
```

---

## Output and Artifacts

### Generated Files

**lean11.iso**
Optimized bootable image (~3-4GB)
Compression: Recovery (maximum)
Format: ISO 9660 + UDF

**lean11_TIMESTAMP.log**
Structured execution log
Format: `[timestamp] [level] message`
Encoding: UTF-8

### Optimization Metrics

| Metric | Before | After | Reduction |
|---------|-------|--------|---------|
| ISO Size | ~5.5GB | ~3.5GB | ~36% |
| AppX Packages | ~80 | ~30 | ~62% |
| Scheduled Tasks | 150+ | 145 | ~3% |
| Installation Time | ~25min | ~18min | ~28% |

---

## Performance

**Processing Time**: 35-90 minutes (varies with hardware)
**CPU Usage**: High during WIM compression
**Disk I/O**: Intensive during copy and export
**RAM Required**: Minimum 4GB, recommended 8GB+

---

## Troubleshooting

### Error: "Execution policy is Restricted"

**Solution**:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

### Error: "Access Denied" during operations

**Cause**: Insufficient privileges
**Solution**: Run PowerShell as Administrator

### Error: "Failed to mount image"

**Possible causes**:
- Corrupted WIM
- Insufficient disk space
- Previous mount not unmounted

**Solution**:
```powershell
# Clean pending mounts
Dism /Cleanup-Wim
```

### ISO doesn't boot after creation

**Check**:
- UEFI vs Legacy boot mode
- Secure Boot disabled
- Media burned correctly

---

## Technical FAQ

**Q: Is the generated image serviceable?**
A: Yes. Windows Update, driver installation, and language packs work normally.

**Q: What compression method is used?**
A: Recovery compression (maximum DISM compression).

**Q: Does it work with ESD instead of WIM?**
A: Yes, the script automatically detects and converts.

**Q: Can I use in production?**
A: Recommended for personal use and testing. For production, perform extensive testing.

**Q: Is there activation bypass?**
A: No. Windows activation works normally.

---

## Known Limitations

- Not compatible with Windows 11 ARM (x64/amd64 only)
- Requires official Microsoft ISO (doesn't work with modified builds)
- OneDrive permanently removed (not reinstallable via Store)
- Requires internet connection to download oscdimg.exe (if ADK not installed)

---

## Roadmap

- [ ] Support for configuration profile creation (.json)
- [ ] Interactive mode for package selection
- [ ] HTML report generation post-processing
- [ ] SHA256 integrity validation of generated ISO
- [ ] Support for multiple editions in batch

---

## Technical References

This project was developed using official Microsoft documentation:

**DISM (Deployment Image Servicing and Management)**
[Microsoft Learn - DISM Technical Reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism---deployment-image-servicing-and-management-technical-reference-for-windows)

**Windows Assessment and Deployment Kit (ADK)**
[Microsoft - Download Windows ADK](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install)

**Unattend Answer Files**
[Microsoft Learn - Answer Files Overview](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/update-windows-settings-and-scripts-create-your-own-answer-file-sxs)

**Windows Image Management**
[Microsoft Learn - Work with Windows Images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/mount-and-modify-a-windows-image-using-dism)

**PowerShell DISM Module**
[Microsoft Learn - DISM PowerShell Reference](https://learn.microsoft.com/en-us/powershell/module/dism/)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Open-source educational project developed based on Microsoft's public documentation.

**Legal Notice**: This software is provided "as is", without warranties of any kind.
Use at your own risk. No official support is provided.

---

**Lean11 Project** - Version 1.1 - November 2025
