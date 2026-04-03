BeforeAll {
    # Get the language folder path
    $LanguagePath = Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD\Language'

    # Helper function to extract nested localization keys in Section.Key format
    function Get-NestedLocalizationKeys {
        param([string]$FilePath)

        $keys = @()
        $content = Get-Content -Path $FilePath
        $currentSection = $null

        foreach ($line in $content) {
            # Match section headers like: GetAbrAzTenant = ConvertFrom-StringData @'
            if ($line -match '^\s*(\w+)\s*=\s*ConvertFrom-StringData') {
                $currentSection = $Matches[1]
            }
            # Match key-value pairs within sections
            elseif ($currentSection -and $line -match '^\s+(\w+)\s*=' -and $line -notmatch "^'@") {
                $keys += "$currentSection.$($Matches[1])"
            }
            # End of section
            elseif ($line -match "^'@") {
                $currentSection = $null
            }
        }
        return $keys | Sort-Object
    }
}

Describe 'Localization Data Consistency Tests' {
    Context 'MicrosoftAD.psd1 Localization Files' {
        BeforeAll {
            $TemplateFile = Join-Path -Path $LanguagePath -ChildPath 'en-US\MicrosoftAD.psd1'
            $TemplateKeys = Get-NestedLocalizationKeys -FilePath $TemplateFile
            $LanguageFolders = Get-ChildItem -Path $LanguagePath -Directory | Where-Object { $_.Name -ne 'en-US' }
        }

        It "Template 'en-US' should have localization keys" {
            $TemplateKeys.Count | Should -BeGreaterThan 0
        }

        foreach ($folder in (Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\AsBuiltReport.Microsoft.AD\Language') -Directory | Where-Object { $_.Name -ne 'en-US' })) {
            It "Language '<Name>' should have all keys from en-US template for MicrosoftAD.psd1" -TestCases @(@{ Name = $folder.Name; FolderPath = $folder.FullName }) {
                param($Name, $FolderPath)

                $LocalizedFile = Join-Path -Path $FolderPath -ChildPath 'MicrosoftAD.psd1'
                if (Test-Path $LocalizedFile) {
                    $LocalizedKeys = Get-NestedLocalizationKeys -FilePath $LocalizedFile
                    $TemplatePath = Join-Path -Path $LanguagePath -ChildPath 'en-US\MicrosoftAD.psd1'
                    $TemplateKeysForTest = Get-NestedLocalizationKeys -FilePath $TemplatePath

                    $MissingKeys = $TemplateKeysForTest | Where-Object { $_ -notin $LocalizedKeys }
                    $ExtraKeys = $LocalizedKeys | Where-Object { $_ -notin $TemplateKeysForTest }

                    if ($MissingKeys) {
                        $MissingKeys | Should -BeNullOrEmpty -Because "Language '$Name' is missing keys: $($MissingKeys -join ', ')"
                    }
                    if ($ExtraKeys) {
                        $ExtraKeys | Should -BeNullOrEmpty -Because "Language '$Name' has extra keys not in template: $($ExtraKeys -join ', ')"
                    }
                } else {
                    Set-ItResult -Skipped -Because "File not found: $LocalizedFile"
                }
            }
        }
    }
}
