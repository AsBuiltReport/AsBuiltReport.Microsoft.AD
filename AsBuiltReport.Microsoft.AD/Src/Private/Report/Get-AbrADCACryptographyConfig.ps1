function Get-AbrADCACryptographyConfig {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Cryptography Config information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
        $CA
    )

    begin {
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCACryptographyConfig.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Cryptography Configuration'
    }

    process {
        if ($CA) {
            $CryptoConfig = Get-CACryptographyConfig -CertificationAuthority $CA
            if ($CryptoConfig) {
                Section -Style Heading3 $reportTranslate.GetAbrADCACryptographyConfig.Heading {
                    Paragraph $reportTranslate.GetAbrADCACryptographyConfig.Paragraph
                    BlankLine
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    try {
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADCACryptographyConfig.CAName = $CryptoConfig.Name
                            $reportTranslate.GetAbrADCACryptographyConfig.ServerName = $CryptoConfig.ComputerName.ToString().ToUpper().Split('.')[0]
                            $reportTranslate.GetAbrADCACryptographyConfig.PublicKeyAlgorithm = $CryptoConfig.PublicKeyAlgorithm | Select-Object -ExpandProperty FriendlyName
                            $reportTranslate.GetAbrADCACryptographyConfig.HashingAlgorithm = ($CryptoConfig.HashingAlgorithm | Select-Object -ExpandProperty FriendlyName).ToUpper()
                            $reportTranslate.GetAbrADCACryptographyConfig.ProviderName = $CryptoConfig.ProviderName
                            $reportTranslate.GetAbrADCACryptographyConfig.AlternateSignatureAlgorithm = $CryptoConfig.AlternateSignatureAlgorithm
                            $reportTranslate.GetAbrADCACryptographyConfig.ProviderIsCNG = $CryptoConfig.ProviderIsCNG
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADCACryptographyConfig.TableName) - $($ForestInfo.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    } catch {
                        Write-PScriboMessage -IsWarning $_.Exception.Message
                    }
                }
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Cryptography Configuration'
    }

}
