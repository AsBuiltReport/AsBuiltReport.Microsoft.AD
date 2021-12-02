function Get-AbrADCAKeyRecoveryAgent {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Key Recovery Agent information.
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
        Write-PscriboMessage "Collecting AD Certification Authority Key Recovery Agent information."
    }

    process {
        try {
            Section -Style Heading4 "Key Recovery Agent Certificate" {
                Paragraph "The following section provides the Key Recovery Agent certificate used to encrypt user's certificate private key and store it in CA database. In the case when user cannot access his or her certificate private key it is possible to recover it by Key Recovery Agent if Key Archival procedure was taken against particular certificate."
                BlankLine
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                $CAs = Get-CertificationAuthority -Enterprise
                if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                foreach ($CA in $CAs) {
                    Write-PscriboMessage "Collecting AD Certification Authority KRA Certificate information of $CA."
                    $KRAs = Get-CAKRACertificate -CertificationAuthority $CA
                    foreach ($KRA in $KRAs) {
                        if ($KRA.Certificate) {
                            $inObj = [ordered] @{
                                'CA Name' = $KRA.DisplayName
                                'Server Name' = $KRA.ComputerName.ToString().ToUpper().Split(".")[0]
                                'Certificate' = $KRA.Certificate
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                }

                $TableParams = @{
                    Name = "Key Recovery Agent Certificate - $($ForestInfo.ToString().ToUpper())"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Key Recovery Agent Certificate)"
        }
    }

    end {}

}