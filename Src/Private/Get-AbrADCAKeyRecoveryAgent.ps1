function Get-AbrADCAKeyRecoveryAgent {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Key Recovery Agent information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
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
        Write-PScriboMessage -Message "Collecting AD Certification Authority Key Recovery Agent information."
        Show-AbrDebugExecutionTime -Start -TitleMessage "CA Key Recovery Agent"
    }

    process {
        $OutObj = [System.Collections.ArrayList]::new()
        try {
            $KRA = Get-CAKRACertificate -CertificationAuthority $CA
            if ($KRA.Certificate) {
                $inObj = [ordered] @{
                    'CA Name' = $KRA.DisplayName
                    'Server Name' = $KRA.ComputerName.ToString().ToUpper().Split(".")[0]
                    'Certificate' = $KRA.Certificate
                }
                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Key Recovery Agent Certificate Item)"
        }

        if ($OutObj) {
            Section -Style Heading3 "Key Recovery Agent Certificate" {
                Paragraph "This section provides details about the Key Recovery Agent certificate, which is used to encrypt users' certificate private keys for storage in the CA database. If a user loses access to their certificate private key, the Key Recovery Agent can recover it, provided that key archival was performed for the certificate."
                BlankLine
                foreach ($Item in $OutObj) {
                    $TableParams = @{
                        Name = "Key Recovery Agent Certificate - $($Item.'CA Name')"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $Item | Table @TableParams
                }
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "CA Key Recovery Agent"
    }

}