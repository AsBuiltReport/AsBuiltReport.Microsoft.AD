function Get-AbrADCACryptographyConfig {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Cryptography Config information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.7
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
        Write-PScriboMessage -Message "Collecting CA Certification Authority Cryptography Config information."
        Show-AbrDebugExecutionTime -Start -TitleMessage "CA Cryptography Configuration"
    }

    process {
        if ($CA) {
            $CryptoConfig = Get-CACryptographyConfig -CertificationAuthority $CA
            if ($CryptoConfig) {
                Section -Style Heading3 "Cryptography Configuration" {
                    Paragraph "The following section provides detailed information about the cryptography configuration settings for the Certification Authority, including algorithms, providers, and key specifications."
                    BlankLine
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        $inObj = [ordered] @{
                            'CA Name' = $CryptoConfig.Name
                            'Server Name' = $CryptoConfig.ComputerName.ToString().ToUpper().Split(".")[0]
                            'PublicKey Algorithm' = $CryptoConfig.PublicKeyAlgorithm | Select-Object -ExpandProperty FriendlyName
                            'Hashing Algorithm' = ($CryptoConfig.HashingAlgorithm | Select-Object -ExpandProperty FriendlyName).ToUpper()
                            'Provider Name' = $CryptoConfig.ProviderName
                            'Alternate Signature Algorithm' = $CryptoConfig.AlternateSignatureAlgorithm
                            'Provider Is CNG' = $CryptoConfig.ProviderIsCNG
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                        $TableParams = @{
                            Name = "Cryptography Configuration - $($ForestInfo.ToString().ToUpper())"
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
        Show-AbrDebugExecutionTime -End -TitleMessage "CA Cryptography Configuration"
    }

}