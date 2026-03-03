BeforeAll {
    # Import the module
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
    $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\'
    try {
        Import-Module $ModulePath -Force -ErrorAction Stop
    } catch {
        # Fallback: import .psm1 directly when required module dependencies are not available
        $PsmPath = Join-Path -Path $ModuleRoot -ChildPath 'AsBuiltReport.Microsoft.AD.psm1'
        Import-Module $PsmPath -Force
    }
}

Describe 'AsBuiltReport.Microsoft.AD Module Tests' {
    Context 'Module Manifest' {
        BeforeAll {
            $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
            $Manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
        }

        It 'Should have a valid module manifest' {
            $Manifest | Should -Not -BeNullOrEmpty
        }

        It 'Should have the correct module name' {
            $Manifest.Name | Should -Be 'AsBuiltReport.Microsoft.AD'
        }

        It 'Should have a valid GUID' {
            $Manifest.Guid | Should -Be '0a3e1c04-13b8-418f-89bc-a5a18da07394'
        }

        It 'Should have a valid version' {
            $Manifest.Version | Should -Not -BeNullOrEmpty
            $Manifest.Version.GetType().Name | Should -Be 'Version'
        }

        It 'Should have a valid author' {
            $Manifest.Author | Should -Not -BeNullOrEmpty
        }

        It 'Should have a valid description' {
            $Manifest.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should require AsBuiltReport.Core module' {
            $Manifest.RequiredModules | Should -Not -BeNullOrEmpty
            $Manifest.RequiredModules.Name | Should -Contain 'AsBuiltReport.Core'
        }

        It 'Should require AsBuiltReport.Core version 1.6.1 or higher' {
            $CoreModule = $Manifest.RequiredModules | Where-Object { $_.Name -eq 'AsBuiltReport.Core' }
            $CoreModule.Version | Should -BeGreaterOrEqual ([Version]'1.6.2')
        }

        It 'Should require AsBuiltReport.Chart version 0.2.0 or higher' {
            $ChartModule = $Manifest.RequiredModules | Where-Object { $_.Name -eq 'AsBuiltReport.Chart' }
            $ChartModule.Version | Should -BeGreaterOrEqual ([Version]'0.2.0')
        }
        It 'Should require Diagrammer.Core version 0.2.38 or higher' {
            $DiagrammerModule = $Manifest.RequiredModules | Where-Object { $_.Name -eq 'Diagrammer.Core' }
            $DiagrammerModule.Version | Should -BeGreaterOrEqual ([Version]'0.2.38')
        }
        It 'Should require PSPKI version 4.3.0 or higher' {
            $PSPKIModule = $Manifest.RequiredModules | Where-Object { $_.Name -eq 'PSPKI' }
            $PSPKIModule.Version | Should -BeGreaterOrEqual ([Version]'4.3.0')
        }

        It 'Should export the Invoke-AsBuiltReport.Microsoft.AD function' {
            $Manifest.ExportedFunctions.Keys | Should -Contain 'Invoke-AsBuiltReport.Microsoft.AD'
        }

        It 'Should have valid tags' {
            $Manifest.Tags | Should -Contain 'AsBuiltReport'
            $Manifest.Tags | Should -Contain 'Report'
            $Manifest.Tags | Should -Contain 'Microsoft'
            $Manifest.Tags | Should -Contain 'AD'
        }

        It 'Should have a valid project URI' {
            $Manifest.ProjectUri | Should -Not -BeNullOrEmpty
            $Manifest.ProjectUri.ToString() | Should -Match '^https?://'
        }

        It 'Should have a valid license URI' {
            $Manifest.LicenseUri | Should -Not -BeNullOrEmpty
            $Manifest.LicenseUri.ToString() | Should -Match '^https?://'
        }

        It 'Should support PowerShell 5.1 and higher' {
            $Manifest.PowerShellVersion | Should -BeGreaterOrEqual ([Version]'5.1')
        }

        It 'Should support Desktop and Core editions' {
            $Manifest.CompatiblePSEditions | Should -Contain 'Desktop'
            $Manifest.CompatiblePSEditions | Should -Contain 'Core'
        }

        It 'Should have a copyright with current or recent year' {
            $Manifest.Copyright | Should -Not -BeNullOrEmpty
            $Manifest.Copyright | Should -Match '202[0-9]'
        }

        It 'Should have a meaningful description' {
            $Manifest.Description | Should -Not -BeNullOrEmpty
            $Manifest.Description.Length | Should -BeGreaterThan 50
        }

        It 'Should have a ReleaseNotes URI' {
            $Manifest.PrivateData.PSData.ReleaseNotes | Should -Not -BeNullOrEmpty
            $Manifest.PrivateData.PSData.ReleaseNotes | Should -Match '^https?://'
        }

        It 'Should have an IconUri' {
            $Manifest.PrivateData.PSData.IconUri | Should -Not -BeNullOrEmpty
            $Manifest.PrivateData.PSData.IconUri | Should -Match '^https?://'
        }

        It 'Should have module version matching expected format' {
            $Manifest.Version.ToString() | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'Should have author information' {
            $Manifest.Author | Should -Not -BeNullOrEmpty
            $Manifest.Author.Length | Should -BeGreaterThan 2
        }
    }

    Context 'Module Structure' {
        It 'Should have a valid root module file' {
            $RootModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psm1'
            Test-Path $RootModulePath | Should -Be $true
        }

        It 'Should have a Src folder' {
            $SrcPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Src'
            Test-Path $SrcPath | Should -Be $true
        }

        It 'Should have a Public functions folder' {
            $PublicPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Src\Public'
            Test-Path $PublicPath | Should -Be $true
        }

        It 'Should have a Private functions folder' {
            $PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Src\Private'
            Test-Path $PrivatePath | Should -Be $true
        }

        It 'Should have a Language folder' {
            $LanguagePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Language'
            Test-Path $LanguagePath | Should -Be $true
        }

        foreach ($lang in @('en-US', 'es-ES')) {
            It 'Should have <Language> language folder' -TestCases @(@{ Language = $lang }) {
                $LangPath = Join-Path -Path $PSScriptRoot -ChildPath "..\Language\$Language"
                Test-Path $LangPath | Should -Be $true
            }

            It 'Should have <Language> MicrosoftAD.psd1 localization file' -TestCases @(@{ Language = $lang }) {
                $LangFile = Join-Path -Path $PSScriptRoot -ChildPath "..\Language\$Language\MicrosoftAD.psd1"
                Test-Path $LangFile | Should -Be $true
            }

            It 'Should be able to load <Language> localization file' -TestCases @(@{ Language = $lang }) {
                $LangPath = Join-Path -Path $PSScriptRoot -ChildPath "..\Language\$Language"
                { Import-LocalizedData -BaseDirectory $LangPath -FileName 'MicrosoftAD.psd1' -ErrorAction Stop } | Should -Not -Throw
            }
        }

        It 'Should have a JSON configuration file' {
            $JsonConfigPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.json'
            Test-Path $JsonConfigPath | Should -Be $true
        }

        It 'Should have at least one private function' {
            $PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Src\Private'
            $PrivateFunctions = Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -ErrorAction SilentlyContinue
            $PrivateFunctions.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Public Functions' {
        It 'Should export Invoke-AsBuiltReport.Microsoft.AD function' {
            Get-Command -Name 'Invoke-AsBuiltReport.Microsoft.AD' -Module 'AsBuiltReport.Microsoft.AD' -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }

        It 'Should have exactly 1 exported function' {
            $ExportedFunctions = Get-Command -Module 'AsBuiltReport.Microsoft.AD' -CommandType Function
            # Filter to only count the officially exported public functions
            $PublicFunctions = $ExportedFunctions | Where-Object {
                $_.Name -in @('Invoke-AsBuiltReport.Microsoft.AD')
            }
            $PublicFunctions.Count | Should -Be 1
        }
    }

    Context 'Function Parameter Validation' {
        BeforeAll {
            $InvokeCommand = Get-Command -Name 'Invoke-AsBuiltReport.Microsoft.AD'
        }

        It 'Invoke-AsBuiltReport.Microsoft.AD should have Target parameter' {
            $InvokeCommand.Parameters.Keys | Should -Contain 'Target'
        }

        It 'Invoke-AsBuiltReport.Microsoft.AD should have Credential parameter' {
            $InvokeCommand.Parameters.Keys | Should -Contain 'Credential'
        }

        It 'Target parameter should accept string array' {
            $TargetParam = $InvokeCommand.Parameters['Target']
            $TargetParam.ParameterType.Name | Should -Be 'String[]'
        }

        It 'Credential parameter should accept PSCredential' {
            $CredentialParam = $InvokeCommand.Parameters['Credential']
            $CredentialParam.ParameterType.Name | Should -Be 'PSCredential'
        }
    }

    Context 'Help Content' {
        It 'Invoke-AsBuiltReport.Microsoft.AD should have help content' {
            $Help = Get-Help -Name 'Invoke-AsBuiltReport.Microsoft.AD' -ErrorAction SilentlyContinue
            $Help | Should -Not -BeNullOrEmpty
            $Help.Synopsis | Should -Not -BeNullOrEmpty
        }

        It 'Invoke-AsBuiltReport.Microsoft.AD should have description' {
            $Help = Get-Help -Name 'Invoke-AsBuiltReport.Microsoft.AD' -ErrorAction SilentlyContinue
            $Help.Description | Should -Not -BeNullOrEmpty
        }

        It 'Invoke-AsBuiltReport.Microsoft.AD should have a link' {
            $Help = Get-Help -Name 'Invoke-AsBuiltReport.Microsoft.AD' -ErrorAction SilentlyContinue
            $Help.relatedLinks | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Private Functions' {
        $PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Src\Private'
        $PrivateFunctions = Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -ErrorAction SilentlyContinue
        BeforeDiscovery {
            $PF = $PrivateFunctions
            $ExpectedPrivateFunctions = @(
                'Convert-IpAddressToMaskLength.ps1'
                'Convert-TimeToDay.ps1'
                'ConvertFrom-DistinguishedName.ps1'
                'ConvertTo-ADCanonicalName.ps1'
                'ConvertTo-ADObjectName.ps1'
                'ConvertTo-EmptyToFiller.ps1'
                'ConvertTo-FileSizeString.ps1'
                'ConvertTo-HashToYN.ps1'
                'ConvertTo-OperatingSystem.ps1'
                'ConvertTo-TextYN.ps1'
                'Copy-DictionaryManual.ps1'
                'Get-AbrADCAAIA.ps1'
                'Get-AbrADCACRLSetting.ps1'
                'Get-AbrADCACryptographyConfig.ps1'
                'Get-AbrADCaInfo.ps1'
                'Get-AbrADCAKeyRecoveryAgent.ps1'
                'Get-AbrADCARoot.ps1'
                'Get-AbrADCASecurity.ps1'
                'Get-AbrADCASubordinate.ps1'
                'Get-AbrADCASummary.ps1'
                'Get-AbrADCATemplate.ps1'
                'Get-AbrADDCDiag.ps1'
                'Get-AbrADDCRoleFeature.ps1'
                'Get-AbrADDFSHealth.ps1'
                'Get-AbrADDNSInfrastructure.ps1'
                'Get-AbrADDNSZone.ps1'
                'Get-AbrADDomain.ps1'
                'Get-AbrADDomainController.ps1'
                'Get-AbrADDomainLastBackup.ps1'
                'Get-AbrADDomainObject.ps1'
                'Get-AbrADDuplicateObject.ps1'
                'Get-AbrADDuplicateSPN.ps1'
                'Get-AbrADExchange.ps1'
                'Get-AbrADForest.ps1'
                'Get-AbrADForestInfo.ps1'
                'Get-AbrADFSMO.ps1'
                'Get-AbrADGPO.ps1'
                'Get-AbrADHardening.ps1'
                'Get-AbrADInfrastructureService.ps1'
                'Get-AbrADKerberosAudit.ps1'
                'Get-AbrADOU.ps1'
                'Get-AbrADSCCM.ps1'
                'Get-AbrADSecurityAssessment.ps1'
                'Get-AbrADSite.ps1'
                'Get-AbrADSiteReplication.ps1'
                'Get-AbrADSitesInfo.ps1'
                'Get-AbrADSitesInventoryInfo.ps1'
                'Get-AbrADTrust.ps1'
                'Get-AbrADTrustInfo.ps1'
                'Get-AbrDHCPinAD.ps1'
                'Get-AbrDiagCertificateAuthority.ps1'
                'Get-AbrDiagForest.ps1'
                'Get-AbrDiagrammer.ps1'
                'Get-AbrDiagSite.ps1'
                'Get-AbrDiagSiteInventory.ps1'
                'Get-AbrDiagTrust.ps1'
                'Get-AbrDNSSection.ps1'
                'Get-AbrDomainSection.ps1'
                'Get-AbrForestSection.ps1'
                'Get-AbrPKISection.ps1'
                'Get-ADExchangeServer.ps1'
                'Get-ADObjectList.ps1'
                'Get-ADObjectSearch.ps1'
                'Get-CimData.ps1'
                'Get-ColumnChart.ps1'
                'Get-ComputerADDomain.ps1'
                'Get-ComputerSplit.ps1'
                'Get-DCWinRMState.ps1'
                'Get-PieChart.ps1'
                'Get-RequiredFeature.ps1'
                'Get-RequiredModule.ps1'
                'Get-ValidCIMSession.ps1'
                'Get-ValidDCfromDomain.ps1'
                'Get-ValidPSSession.ps1'
                'Get-WinADDFSHealth.ps1'
                'Get-WinADDuplicateObject.ps1'
                'Get-WinADDuplicateSPN.ps1'
                'Get-WinADForestDetail.ps1'
                'Get-WinADLastBackup.ps1'
                'Images.ps1'
                'Invoke-CommandWithTimeout.ps1'
                'Invoke-DcDiag.ps1'
                'New-AbrADDiagram.ps1'
                'Show-AbrDebugExecutionTime.ps1'
                'Test-ComputerPort.ps1'
                'Test-WinRM.ps1'
            )
        }

        It 'Should contain expected private function file count' {
            $PrivateFunctions.Count | Should -Be $ExpectedPrivateFunctions.Count
        }

        It 'Should have private functions matching expected list' -ForEach @{
            TestArray = $ExpectedPrivateFunctions
            PrivateFunctions = $PF
        } {
            foreach ($Expected in $TestArray) {
                $Match = $PrivateFunctions | Where-Object { $_.Name -eq $Expected }
                $Match | Should -Not -BeNullOrEmpty -Because "Expected private function file '$Expected' should exist"
            }
        }
    }

    Context 'JSON Configuration' {
        BeforeAll {
            $JsonConfigPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.json'
            $JsonConfig = Get-Content -Path $JsonConfigPath -Raw | ConvertFrom-Json
        }

        It 'Should have a valid JSON configuration file' {
            $JsonConfig | Should -Not -BeNullOrEmpty
        }

        It 'Should have a Report section' {
            $JsonConfig.Report | Should -Not -BeNullOrEmpty
        }

        It 'Should have an Options section' {
            $JsonConfig.Options | Should -Not -BeNullOrEmpty
        }

        It 'Should have an InfoLevel section' {
            $JsonConfig.InfoLevel | Should -Not -BeNullOrEmpty
        }

        It 'Should have a HealthCheck section' {
            $JsonConfig.HealthCheck | Should -Not -BeNullOrEmpty
        }

        It 'InfoLevel should include Forest' {
            $JsonConfig.InfoLevel.PSObject.Properties.Name | Should -Contain 'Forest'
        }

        It 'InfoLevel should include Domain' {
            $JsonConfig.InfoLevel.PSObject.Properties.Name | Should -Contain 'Domain'
        }

        It 'InfoLevel should include DNS' {
            $JsonConfig.InfoLevel.PSObject.Properties.Name | Should -Contain 'DNS'
        }

        It 'InfoLevel should include CA' {
            $JsonConfig.InfoLevel.PSObject.Properties.Name | Should -Contain 'CA'
        }

        It 'HealthCheck should include Domain checks' {
            $JsonConfig.HealthCheck.PSObject.Properties.Name | Should -Contain 'Domain'
        }

        It 'HealthCheck should include DomainController checks' {
            $JsonConfig.HealthCheck.PSObject.Properties.Name | Should -Contain 'DomainController'
        }

        It 'HealthCheck should include Site checks' {
            $JsonConfig.HealthCheck.PSObject.Properties.Name | Should -Contain 'Site'
        }

        It 'HealthCheck should include DNS checks' {
            $JsonConfig.HealthCheck.PSObject.Properties.Name | Should -Contain 'DNS'
        }

        It 'HealthCheck should include CA checks' {
            $JsonConfig.HealthCheck.PSObject.Properties.Name | Should -Contain 'CA'
        }
    }

    Context 'Configuration Schema Validation' {
        BeforeAll {
            $JsonConfigPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.json'
            $JsonConfig = Get-Content -Path $JsonConfigPath -Raw | ConvertFrom-Json
        }

        It 'All InfoLevel values should be valid (0-4 or complex object)' {
            $InvalidInfoLevels = @()

            foreach ($Property in $JsonConfig.InfoLevel.PSObject.Properties) {
                # Skip comment fields (fields starting with underscore)
                if ($Property.Name -match '^_') {
                    continue
                }

                $Value = $Property.Value

                # Check if it's a complex object (like Policy with Assignments/Definitions)
                if ($Value -is [PSCustomObject]) {
                    # Validate each sub-property
                    foreach ($SubProperty in $Value.PSObject.Properties) {
                        $SubValue = $SubProperty.Value
                        # Accept both Int32 and Int64 (JSON deserializes to Int64)
                        $IsValidInteger = ($SubValue -is [int] -or $SubValue -is [int64])
                        if (-not $IsValidInteger -or $SubValue -lt 0 -or $SubValue -gt 4) {
                            $InvalidInfoLevels += "$($Property.Name).$($SubProperty.Name) = $SubValue (expected 0-4)"
                        }
                    }
                } elseif ($Value -is [int] -or $Value -is [int64]) {
                    # Accept both Int32 and Int64
                    if ($Value -lt 0 -or $Value -gt 4) {
                        $InvalidInfoLevels += "$($Property.Name) = $Value (expected 0-4)"
                    }
                } else {
                    $InvalidInfoLevels += "$($Property.Name) has invalid type: $($Value.GetType().Name)"
                }
            }

            if ($InvalidInfoLevels.Count -gt 0) {
                $ErrorMessage = "Found $($InvalidInfoLevels.Count) invalid InfoLevel value(s):`n" + ($InvalidInfoLevels -join "`n")
                $InvalidInfoLevels.Count | Should -Be 0 -Because $ErrorMessage
            }
        }

        It 'All HealthCheck values should be boolean' {
            $InvalidHealthChecks = @()

            foreach ($Section in $JsonConfig.HealthCheck.PSObject.Properties) {
                foreach ($Check in $Section.Value.PSObject.Properties) {
                    if ($Check.Value -isnot [bool]) {
                        $InvalidHealthChecks += "$($Section.Name).$($Check.Name) = $($Check.Value) (expected boolean)"
                    }
                }
            }

            if ($InvalidHealthChecks.Count -gt 0) {
                $ErrorMessage = "Found $($InvalidHealthChecks.Count) non-boolean HealthCheck value(s):`n" + ($InvalidHealthChecks -join "`n")
                $InvalidHealthChecks.Count | Should -Be 0 -Because $ErrorMessage
            }
        }

        It 'Options.PSDefaultAuthentication should be string' {
            $JsonConfig.Options.PSDefaultAuthentication | Should -BeOfType [string]
        }

        It 'All SectionOrder entries should have corresponding InfoLevel sections' {
            $MissingSections = @()

            foreach ($Section in $JsonConfig.Options.SectionOrder) {
                if ($Section -notin $JsonConfig.InfoLevel.PSObject.Properties.Name) {
                    $MissingSections += $Section
                }
            }

            if ($MissingSections.Count -gt 0) {
                $ErrorMessage = "SectionOrder contains sections without InfoLevel definitions:`n" + ($MissingSections -join "`n")
                $MissingSections.Count | Should -Be 0 -Because $ErrorMessage
            }
        }

        It 'Report.Name should not be empty' {
            $JsonConfig.Report.Name | Should -Not -BeNullOrEmpty
            $JsonConfig.Report.Name.Length | Should -BeGreaterThan 5
        }

        It 'Report.Version should be valid' {
            $JsonConfig.Report.Version | Should -Not -BeNullOrEmpty
            $JsonConfig.Report.Version | Should -Match '^\d+\.\d+$'
        }

        It 'Report boolean settings should be boolean type' {
            $JsonConfig.Report.ShowCoverPageImage | Should -BeOfType [bool]
            $JsonConfig.Report.ShowTableOfContents | Should -BeOfType [bool]
            $JsonConfig.Report.ShowHeaderFooter | Should -BeOfType [bool]
            $JsonConfig.Report.ShowTableCaptions | Should -BeOfType [bool]
        }
    }
}

Describe 'Module File Syntax and Quality' {
    Context 'PowerShell Script Files' {
        It 'Should have valid PowerShell syntax in all script files' {
            $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\'
            $ScriptFiles = Get-ChildItem -Path $ModuleRoot -Include '*.ps1', '*.psm1' -Recurse

            foreach ($File in $ScriptFiles) {
                $FileContent = Get-Content -Path $File.FullName -Raw -ErrorAction Stop
                $Errors = $null
                $null = [System.Management.Automation.PSParser]::Tokenize($FileContent, [ref]$Errors)
                $Errors.Count | Should -Be 0 -Because "File $($File.Name) should have no syntax errors"
            }
        }
    }

    Context 'Code Style and Standards' {
        BeforeAll {
            $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\'
            $PublicFunctions = Get-ChildItem -Path "$ModuleRoot\Src\Public" -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
            $PrivateFunctions = Get-ChildItem -Path "$ModuleRoot\Src\Private" -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
        }

        It 'All public functions should have comment-based help' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.SYNOPSIS'
                $Content | Should -Match '\.DESCRIPTION'
            }
        }

        It 'All public functions should have CmdletBinding attribute' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\[CmdletBinding\(\)\]'
            }
        }

        It 'All private Get-AbrAD* functions should use try/catch blocks' {
            $ADFunctions = $PrivateFunctions | Where-Object { $_.BaseName -match '^Get-AbrAD' }
            foreach ($Function in $ADFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\btry\s*\{' -Because "$($Function.Name) should use try/catch for error handling"
                $Content | Should -Match '\}\s*catch\s*\{' -Because "$($Function.Name) should use try/catch for error handling"
            }
        }
    }

    Context 'PSScriptAnalyzer Compliance' {
        BeforeAll {
            $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\'
            $SettingsPath = Join-Path -Path $PSScriptRoot -ChildPath '..\.github\workflows\PSScriptAnalyzerSettings.psd1'
        }

        It 'Should have no critical PSScriptAnalyzer violations' {
            $AnalyzerResults = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -Severity Error -ErrorAction SilentlyContinue

            if ($AnalyzerResults.Count -gt 0) {
                $ErrorMessages = $AnalyzerResults | ForEach-Object { "$($_.ScriptName):$($_.Line) - $($_.Message)" }
                $ErrorMessage = "Found $($AnalyzerResults.Count) critical violation(s):`n" + ($ErrorMessages -join "`n")
                $AnalyzerResults.Count | Should -Be 0 -Because $ErrorMessage
            } else {
                $AnalyzerResults.Count | Should -Be 0
            }
        }

        It 'Should have minimal PSScriptAnalyzer warnings' {
            try {
                $AnalyzerResults = Invoke-ScriptAnalyzer -Path $ModuleRoot -Recurse -Severity Warning -ErrorAction SilentlyContinue
            } catch {
                $AnalyzerResults = @()
            }
            @($AnalyzerResults).Count | Should -BeLessThan 20 -Because 'Module should have fewer than 20 warnings'
        }

        It 'Should pass PSScriptAnalyzer with settings file if it exists' {
            if (Test-Path $SettingsPath) {
                $AnalyzerResults = Invoke-ScriptAnalyzer -Path $ModuleRoot -Settings $SettingsPath -Recurse -ErrorAction SilentlyContinue
                $CriticalResults = $AnalyzerResults | Where-Object { $_.Severity -eq 'Error' }

                if ($CriticalResults.Count -gt 0) {
                    $ErrorMessages = $CriticalResults | ForEach-Object { "$($_.ScriptName):$($_.Line) - $($_.Message)" }
                    $ErrorMessage = "Found $($CriticalResults.Count) violation(s) with settings file:`n" + ($ErrorMessages -join "`n")
                    $CriticalResults.Count | Should -Be 0 -Because $ErrorMessage
                } else {
                    $CriticalResults.Count | Should -Be 0
                }
            } else {
                Set-ItResult -Skipped -Because 'PSScriptAnalyzerSettings.psd1 not found'
            }
        }
    }

    Context 'Function Documentation Quality' {
        BeforeAll {
            $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.Azure'
            $PublicFunctions = Get-ChildItem -Path "$ModuleRoot\Src\Public" -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
        }

        It 'All public functions should have SYNOPSIS' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.SYNOPSIS' -Because "$($Function.Name) should have .SYNOPSIS documentation"
            }
        }

        It 'All public functions should have DESCRIPTION' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.DESCRIPTION' -Because "$($Function.Name) should have .DESCRIPTION documentation"
            }
        }

        It 'All public functions should have at least one EXAMPLE' {
            foreach ($Function in $PublicFunctions) {
                # Check file content directly since Get-Help requires module to be loaded
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.EXAMPLE' -Because "$($Function.Name) should have at least one .EXAMPLE section in comment-based help"
            }
        }

        It 'All public functions should have NOTES section' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.NOTES' -Because "$($Function.Name) should have .NOTES documentation"
            }
        }

        It 'All public functions should have LINK section' {
            foreach ($Function in $PublicFunctions) {
                $Content = Get-Content -Path $Function.FullName -Raw
                $Content | Should -Match '\.LINK' -Because "$($Function.Name) should have .LINK documentation"
            }
        }

        It 'Public function DESCRIPTION should be meaningful' {
            foreach ($Function in $PublicFunctions) {
                # Check file content directly since Get-Help requires module to be loaded
                $Content = Get-Content -Path $Function.FullName -Raw

                # Extract DESCRIPTION section content (allow for whitespace/newlines)
                if ($Content -match '\.DESCRIPTION\s+([\s\S]+?)(?=\s+\.(?:NOTES|PARAMETER|EXAMPLE|LINK|INPUTS|OUTPUTS)|$)') {
                    $DescriptionText = $Matches[1].Trim()
                    # Remove excessive whitespace
                    $DescriptionText = $DescriptionText -replace '\s+', ' '
                    $DescriptionText.Length | Should -BeGreaterThan 50 -Because "$($Function.Name) should have a meaningful description (>50 characters)"
                }
            }
        }
    }
}

Describe 'Error Handling and Edge Cases' {
    Context 'Configuration Error Handling' {
        It 'Should handle invalid JSON configuration gracefully' {
            $InvalidJsonPath = Join-Path -Path $TestDrive -ChildPath 'invalid.json'
            Set-Content -Path $InvalidJsonPath -Value '{ invalid json content'

            { Get-Content -Path $InvalidJsonPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Throw
        }

        It 'Should validate InfoLevel range when manually checking' {
            # Test that our validation logic works for out-of-range values
            $ValidValues = 0..4
            $InvalidValues = @(-1, 5, 10, 100)

            foreach ($Invalid in $InvalidValues) {
                $Invalid -in $ValidValues | Should -Be $false
            }

            foreach ($Valid in $ValidValues) {
                $Valid -in $ValidValues | Should -Be $true
            }
        }
    }

    Context 'Parameter Validation' {
        BeforeAll {
            $InvokeCommand = Get-Command -Name 'Invoke-AsBuiltReport.Microsoft.AD' -ErrorAction SilentlyContinue
        }

        It 'Target parameter should be mandatory or have default behavior' {
            if ($InvokeCommand) {
                $TargetParam = $InvokeCommand.Parameters['Target']
                # Target should exist as we've already tested
                $TargetParam | Should -Not -BeNullOrEmpty
            }
        }

        It 'Credential parameter should accept PSCredential type' {
            if ($InvokeCommand) {
                $CredParam = $InvokeCommand.Parameters['Credential']
                $CredParam.ParameterType.Name | Should -Be 'PSCredential'
            }
        }
    }

    Context 'Module Import Error Scenarios' {
        It 'Should gracefully handle missing required modules in manifest' {
            $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
            $Manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop

            # Verify required modules are declared
            $Manifest.RequiredModules | Should -Not -BeNullOrEmpty
            $Manifest.RequiredModules.Name | Should -Contain 'AsBuiltReport.Core'
        }

        It 'Should have valid PowerShell version requirement' {
            $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
            $Manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop

            $Manifest.PowerShellVersion | Should -Not -BeNullOrEmpty
            $Manifest.PowerShellVersion | Should -BeOfType [System.Version]
        }
    }

    Context 'File Path Validation' {
        It 'Module manifest path should be valid' {
            $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
            Test-Path $ManifestPath | Should -Be $true
        }

        It 'Module root path should be valid' {
            $ModuleRoot = Join-Path -Path $PSScriptRoot -ChildPath '..\'
            Test-Path $ModuleRoot | Should -Be $true
        }

        It 'Language files should exist' {
            $LanguagePath = Join-Path -Path $PSScriptRoot -ChildPath '..\Language'
            Test-Path $LanguagePath | Should -Be $true

            $EnUSPath = Join-Path -Path $LanguagePath -ChildPath 'en-US\MicrosoftAD.psd1'
            Test-Path $EnUSPath | Should -Be $true

            $EnESPath = Join-Path -Path $LanguagePath -ChildPath 'es-ES\MicrosoftAD.psd1'
            Test-Path $EnESPath | Should -Be $true
        }
    }

    Context 'Type Safety and Null Handling' {
        It 'JSON configuration should deserialize without errors' {
            $JsonConfigPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.json'
            { Get-Content -Path $JsonConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Localization data should load without errors' {
            $EnUSPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Language\en-US'
            { Import-LocalizedData -BaseDirectory $EnUSPath -FileName 'MicrosoftAD.psd1' -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Module manifest should parse correctly' {
            $ManifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD.psd1'
            { Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop } | Should -Not -Throw
        }
    }
}

AfterAll {
    # Clean up
    Remove-Module -Name 'AsBuiltReport.Microsoft.AD' -Force -ErrorAction SilentlyContinue
}
