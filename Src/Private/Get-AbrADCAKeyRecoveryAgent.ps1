function Get-AbrADCAKeyRecoveryAgent {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Key Recovery Agent information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.1
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
        Write-PScriboMessage "Collecting AD Certification Authority Key Recovery Agent information."
    }

    process {
        $OutObj = @()
        try {
            $KRA = Get-CAKRACertificate -CertificationAuthority $CA
            if ($KRA.Certificate) {
                $inObj = [ordered] @{
                    'CA Name' = $KRA.DisplayName
                    'Server Name' = $KRA.ComputerName.ToString().ToUpper().Split(".")[0]
                    'Certificate' = $KRA.Certificate
                }
                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Key Recovery Agent Certificate Item)"
        }

        if ($OutObj) {
            Section -Style Heading3 "Key Recovery Agent Certificate" {
                Paragraph "The following section provides the Key Recovery Agent certificate used to encrypt user's certificate private key and store it in CA database. In the case when user cannot access his or her certificate private key it is possible to recover it by Key Recovery Agent if Key Archival procedure was taken against particular certificate."
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

    end {}

}