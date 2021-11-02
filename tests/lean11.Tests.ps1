#Requires -Version 5.1
# Pester 5+ tests for Lean11 pure helpers (no admin / no ISO required)

BeforeAll {
    $scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'lean11.ps1'
    # Dot-source defines functions without running the main pipeline
    . $scriptPath -Mode Debloat -NonInteractive
}

Describe 'Test-PackageNameMatch' {
    It 'matches exact package family names' {
        Test-PackageNameMatch -PackageName 'Microsoft.XboxApp' -Pattern 'Microsoft.XboxApp' | Should -BeTrue
    }

    It 'matches provisioned package full names with underscore suffix' {
        Test-PackageNameMatch -PackageName 'Microsoft.XboxApp_8wekyb3d8bbwe' -Pattern 'Microsoft.XboxApp' | Should -BeTrue
    }

    It 'does not over-match short substrings inside unrelated names' {
        Test-PackageNameMatch -PackageName 'Microsoft.Paint' -Pattern 'Paint' | Should -BeFalse
        Test-PackageNameMatch -PackageName 'Microsoft.MSPaint_8wekyb3d8bbwe' -Pattern 'Microsoft.MSPaint' | Should -BeTrue
    }

    It 'does not match Microsoft.Paint against Microsoft.MSPaint (Pattern_* expansion)' {
        # Regression: "$Pattern_*" was parsed as $Pattern_ + "*" (= "*"), matching every package
        Test-PackageNameMatch -PackageName 'Microsoft.Paint' -Pattern 'Microsoft.MSPaint' | Should -BeFalse
        Test-PackageNameMatch -PackageName 'Microsoft.MicrosoftStickyNotes' -Pattern 'Microsoft.MSPaint' | Should -BeFalse
        Test-PackageNameMatch -PackageName 'Microsoft.MSPaint_8wekyb3d8bbwe' -Pattern 'Microsoft.MSPaint' | Should -BeTrue
    }

    It 'matches Screen Sketch / Snipping Tool family names' {
        Test-PackageNameMatch -PackageName 'Microsoft.ScreenSketch' -Pattern 'Microsoft.ScreenSketch' | Should -BeTrue
        Test-PackageNameMatch -PackageName 'Microsoft.ScreenSketch_8wekyb3d8bbwe' -Pattern 'Microsoft.ScreenSketch' | Should -BeTrue
    }

    It 'returns false for empty patterns' {
        Test-PackageNameMatch -PackageName 'Microsoft.XboxApp' -Pattern '' | Should -BeFalse
    }
}

Describe 'Should-KeepPackage' {
    It 'keeps packages matching KeepPackages patterns including short tokens' {
        Set-Variable -Name KeepPackages -Scope Script -Value @('Xbox', 'Teams')
        try {
            Should-KeepPackage -PackageName 'Microsoft.XboxApp_8wekyb3d8bbwe' | Should -BeTrue
            Should-KeepPackage -PackageName 'MicrosoftTeams' | Should -BeTrue
            Should-KeepPackage -PackageName 'Microsoft.BingWeather' | Should -BeFalse
        } finally {
            Set-Variable -Name KeepPackages -Scope Script -Value @()
        }
    }
}

Describe 'Build-AutoUnattendContent' {
    It 'omits UserAccounts and empty passwords' {
        $xml = Build-AutoUnattendContent -Architecture 'amd64' -Language 'en-US'
        $xml | Should -Not -Match 'UserAccounts'
        $xml | Should -Not -Match '<Password>'
        $xml | Should -Match 'BypassNRO'
        $xml | Should -Match 'processorArchitecture="amd64"'
        $xml | Should -Match '<UILanguage>en-US</UILanguage>'
    }

    It 'includes ProductKey in Shell-Setup when provided' {
        $xml = Build-AutoUnattendContent -ProductKey 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'
        $xml | Should -Match '<ProductKey>AAAAA-BBBBB-CCCCC-DDDDD-EEEEE</ProductKey>'
        $xml | Should -Not -Match 'Set-Edition'
        $xml | Should -Not -Match 'DISM /Online'
    }

    It 'uses requested architecture and language' {
        $xml = Build-AutoUnattendContent -Architecture 'amd64' -Language 'pt-BR'
        $xml | Should -Match '<InputLocale>pt-BR</InputLocale>'
        $xml | Should -Match '<SystemLocale>pt-BR</SystemLocale>'
    }

    It 'escapes XML special characters in product key' {
        $xml = Build-AutoUnattendContent -ProductKey 'A&B<C>'
        $xml | Should -Match '<ProductKey>A&amp;B&lt;C&gt;</ProductKey>'
    }
}

Describe 'Resolve-RegPath' {
    It 'maps HKCU hive' {
        $path = Resolve-RegPath -Hive 'HKCU' -Path 'Software\Test'
        $path | Should -Be (Join-Path 'HKCU:' 'Software\Test')
    }

    It 'maps HKLM hive' {
        $path = Resolve-RegPath -Hive 'HKLM' -Path 'SOFTWARE\Test'
        $path | Should -Be (Join-Path 'HKLM:' 'SOFTWARE\Test')
    }

    It 'throws on unsupported hive' {
        { Resolve-RegPath -Hive 'HKCR' -Path 'Test' } | Should -Throw
    }
}

Describe 'Convert-RegistryValue' {
    It 'converts REG_DWORD' {
        Convert-RegistryValue -Definition @{ Type = 'REG_DWORD'; Value = '1' } | Should -Be 1
    }

    It 'converts REG_SZ as string' {
        Convert-RegistryValue -Definition @{ Type = 'REG_SZ'; Value = 'abc' } | Should -Be 'abc'
    }
}

Describe 'PackageCategories policy' {
    It 'does not list Terminal, Paint, Snipping Tool, or Sticky Notes as removal targets' {
        $all = @($Script:PackageCategories.Values | ForEach-Object { $_ })
        $all | Should -Not -Contain 'Microsoft.WindowsTerminal'
        $all | Should -Not -Contain 'Microsoft.Paint'
        $all | Should -Not -Contain 'Microsoft.MSPaint'
        $all | Should -Not -Contain 'Microsoft.ScreenSketch'
        $all | Should -Not -Contain 'Microsoft.MicrosoftStickyNotes'
    }

    It 'always keeps Paint and Snipping Tool via DefaultKeepPackages' {
        $Script:DefaultKeepPackages | Should -Contain 'Microsoft.Paint'
        $Script:DefaultKeepPackages | Should -Contain 'Microsoft.MSPaint'
        $Script:DefaultKeepPackages | Should -Contain 'Microsoft.ScreenSketch'
        Should-KeepPackage -PackageName 'Microsoft.Paint_8wekyb3d8bbwe' | Should -BeTrue
        Should-KeepPackage -PackageName 'Microsoft.ScreenSketch_8wekyb3d8bbwe' | Should -BeTrue
    }

    It 'includes Office Hub, Outlook, LinkedIn, WhatsApp, and Teams removal targets' {
        $Script:PackageCategories.Office | Should -Contain 'Microsoft.MicrosoftOfficeHub'
        $Script:PackageCategories.Office | Should -Contain 'Microsoft.OutlookForWindows'
        $Script:PackageCategories.Communication | Should -Contain 'MicrosoftTeams'
        $Script:PackageCategories.Communication | Should -Contain '7EE7776C.LinkedInforWindows'
        $Script:PackageCategories.Communication | Should -Contain '5319275A.WhatsAppDesktop'
    }

    It 'targets Phone Link, Todos, Power Automate, Widgets, CrossDevice, and Copilot' {
        $Script:PackageCategories.Communication | Should -Contain 'Microsoft.YourPhone'
        $Script:PackageCategories.Utilities | Should -Contain 'Microsoft.Todos'
        $Script:PackageCategories.Utilities | Should -Contain 'Microsoft.PowerAutomateDesktop'
        $Script:PackageCategories.Other | Should -Contain 'MicrosoftWindows.Client.WebExperience'
        $Script:PackageCategories.Other | Should -Contain 'Microsoft.WidgetsPlatformRuntime'
        $Script:PackageCategories.Other | Should -Contain 'MicrosoftWindows.CrossDevice'
        $Script:PackageCategories.Other | Should -Contain 'Microsoft.Copilot'
    }
}
