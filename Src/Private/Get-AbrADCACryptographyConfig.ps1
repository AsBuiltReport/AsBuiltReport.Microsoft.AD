function Get-AbrADCACryptographyConfig {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Cryptography Config information.
    .DESCRIPTION

    .NOTES
        Version:        0.5.0
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PscriboMessage "Collecting AD Certification Authority Cryptography Config information."
    }

    process {
        try {
            Section -Style Heading4 "Cryptography Configuration" {
                Paragraph "The following section provides the Certification Authority Cryptography Configuration information."
                BlankLine
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                $CAs = Get-CertificationAuthority -Enterprise
                if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                foreach ($CA in $CAs) {
                    try {
                        Write-PscriboMessage "Collecting AD Certification Authority Summary information of $CA."
                        $CryptoConfig = Get-CACryptographyConfig -CertificationAuthority $CA
                        $inObj = [ordered] @{
                            'CA Name' = $CryptoConfig.Name
                            'Server Name' = $CryptoConfig.ComputerName.ToString().ToUpper().Split(".")[0]
                            'PublicKey Algorithm' = $CryptoConfig.PublicKeyAlgorithm | Select-Object -ExpandProperty FriendlyName
                            'Hashing Algorithm' = ($CryptoConfig.HashingAlgorithm | Select-Object -ExpandProperty FriendlyName).ToUpper()
                            'Provider Name' = $CryptoConfig.ProviderName
                            'Alternate Signature Algorithm' = ConvertTo-TextYN $CryptoConfig.AlternateSignatureAlgorithm
                            'Provider Is CNG' = ConvertTo-TextYN $CryptoConfig.ProviderIsCNG
                        }
                        $OutObj = [pscustomobject]$inobj

                        $TableParams = @{
                            Name = "Cryptography Configuration - $($ForestInfo.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}