# Lean11

Dual-mode PowerShell optimizer for Windows 11: clean a live install, or build a debloated install ISO.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows 11](https://img.shields.io/badge/Windows-11-0078D6.svg)](https://www.microsoft.com/windows/windows-11)

## Highlights

- Debloat mode cleans AppX bloat, Copilot, Office Hub, Teams, and privacy tweaks on a running PC
- Image mode builds `lean11.iso` from an official Windows 11 ISO with offline DISM tweaks
- Always keeps Paint and Snipping Tool; Terminal, Store, Edge, and Sticky Notes stay by omission
- One-liner Debloat via `irm`/`iex` (elevated PowerShell; review the URL first)
- Selective keep-list with `-KeepPackages` for anything you want to preserve
- Hardware bypasses and OOBE unattend only in Image mode (lab/unsupported hardware — not hardening)
- Transcript logs under `%TEMP%`; Pester tests for helpers without admin or ISO

## Overview

Lean11 is for personal or lab use. **Debloat** removes removable AppX packages and applies registry/task tweaks on the current Windows 11 install. **Image** rewrites installation media with DISM and exports a custom ISO. Prefer an official Microsoft ISO, always run elevated, and treat the result as a customized image — not a security-hardened one.

| Mode | When to use | Needs ISO |
|------|-------------|-----------|
| `Debloat` | Clean the PC you are using now | No |
| `Image` | Prepare lean install media | Yes |

## Prerequisites

- **Windows 11 host** — required to run the script
- **PowerShell 5.1+** — Windows PowerShell or compatible
- **Administrator privileges** — elevation is required (auto-elevates when possible)
- **Official Windows 11 ISO** — Image mode only; [download from Microsoft](https://www.microsoft.com/software-download/windows11)
- **~20GB free disk** — Image mode scratch space (use `-SCRATCH` on a large drive)
- **Windows ADK (optional)** — provides `oscdimg.exe`; otherwise Lean11 may download it and verify Authenticode

## Installation

### Clone (recommended for Image mode)

```powershell
gh repo clone carlosrabelo/lean11
cd lean11
Set-ExecutionPolicy Bypass -Scope Process
```

Keep `autounattend.xml` next to `lean11.ps1` when using Image mode.

### One-liner (Debloat only)

Elevated PowerShell (review the URL first):

```powershell
iex "& { $(irm https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1) } -Mode Debloat"
```

Plain `irm … | iex` is not enough — pass `-Mode Debloat` (default mode is `Image`).

## Quick Start

Clean the current machine (elevated PowerShell in the repo):

```powershell
.\lean11.ps1 -Mode Debloat
```

Skip OneDrive removal:

```powershell
.\lean11.ps1 -Mode Debloat -SkipOneDrive
```

Build an optimized ISO (mounted drive `E:`, scratch on `D:`):

```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
```

Restart after Debloat if AppX or OneDrive changed.

## Usage

Run from an **elevated** PowerShell session.

### Debloat mode

```powershell
.\lean11.ps1 -Mode Debloat
.\lean11.ps1 -Mode Debloat -SkipOneDrive
.\lean11.ps1 -Mode Debloat -KeepPackages "Xbox","Teams"
.\lean11.ps1 -Mode Debloat -SkipRegistryOptimizations -SkipScheduledTasks
```

Remote Debloat (same as Installation one-liner):

```powershell
iex "& { $(irm https://raw.githubusercontent.com/carlosrabelo/lean11/master/lean11.ps1) } -Mode Debloat -SkipOneDrive"
```

List removable AppX on the machine (useful before/after):

```powershell
Get-AppxPackage -AllUsers |
  Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } |
  Sort-Object Name |
  Select-Object -ExpandProperty Name
```

### Image mode

```powershell
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D
.\lean11.ps1 -Mode Image -ISO "C:\ISOs\Win11.iso" -SCRATCH D
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -KeepPackages "Xbox","Teams"
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -ProductKey "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
.\lean11.ps1 -Mode Image -ISO E -SCRATCH D -NonInteractive
```

Output: `lean11.iso` beside the script, plus a transcript under `%TEMP%`.

### What gets changed

| Area | Behavior |
|------|----------|
| AppX | Gaming, Office Hub, Outlook, Teams, Copilot, Phone Link, Widgets, OEM helpers, and more when present |
| Kept by default | Store, Defender, Update, Edge, Terminal, Paint, Snipping Tool, Sticky Notes, codecs, OEM GPU/audio |
| Copilot | App removal + `TurnOffWindowsCopilot`; M365 Copilot = Office Hub (also removed). Keep with `-KeepPackages "Copilot","OfficeHub"` |
| Telemetry / ads | Registry and scheduled-task tweaks in both modes |
| Hardware bypass | Image only (TPM / Secure Boot / RAM / CPU) |
| OOBE unattend | Image only — hide online-account screens; no blank-password admin |
| OneDrive | Debloat uninstalls unless `-SkipOneDrive`; user Documents are not deleted |

### Limitations

- x64/amd64 only (not ARM)
- Official Microsoft ISO required for Image mode
- OneDrive can be hard to restore after removal
- Network needed if ADK is missing and `oscdimg.exe` must be downloaded
- Start-menu *suggestions* (LinkedIn/WhatsApp ads) are not AppX — pin cleanup + consumer-features policy help; unpin manually if they remain

## Configuration

Defaults live in hashtables near the top of `lean11.ps1` (`PackageCategories`, `DefaultKeepPackages`, registry blocks). Edit those to change what is removed or kept.

```powershell
$Script:DefaultKeepPackages = @(
    'Microsoft.Paint'
    'Microsoft.MSPaint'
    'Microsoft.ScreenSketch'
)

$Script:PackageCategories = @{
    Office = @(
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.OutlookForWindows'
    )
}
```

| Parameter | Modes | Purpose |
|-----------|-------|---------|
| `-Mode` | both | `Image` (default) or `Debloat` |
| `-ISO` | Image | Drive letter (`E`) or path to `.iso` |
| `-SCRATCH` | Image | Drive letter for work/mount directories |
| `-KeepPackages` | both | Patterns to preserve from removal |
| `-SkipOneDrive` | Debloat | Skip OneDrive uninstall |
| `-SkipRegistryOptimizations` | Debloat | Skip live registry tweaks |
| `-SkipScheduledTasks` | Debloat | Skip disabling telemetry tasks |
| `-ProductKey` | Image | Inject into generated unattend |
| `-NonInteractive` | both | Skip interactive exit prompt |

## Project Layout

```
lean11.ps1           # Dual-mode optimizer (entry point)
autounattend.xml     # OOBE template reference (no blank admin password)
tests/               # Pester tests for pure helpers
README.md            # English documentation
README-PT.md         # Portuguese documentation
LICENSE              # MIT
```

## Development

Requires [Pester 5+](https://pester.dev/) on Windows:

```powershell
Install-Module Pester -Scope CurrentUser -Force
Invoke-Pester -Path .\tests
```

Tests cover package matching, unattend generation, registry helpers, and category policy. They do not need Administrator rights or a Windows 11 ISO.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/description`
3. Keep `README.md` and `README-PT.md` in sync when docs change
4. Run `Invoke-Pester -Path .\tests` before opening a PR
5. Open a pull request with a short summary of the change

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

Use at your own risk. Lean11 is an unofficial educational project based on public Microsoft DISM/ADK documentation; it is not affiliated with Microsoft.
