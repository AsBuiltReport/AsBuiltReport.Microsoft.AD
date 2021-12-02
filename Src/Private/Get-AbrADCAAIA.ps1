function Get-AbrADCAAIA {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Authority Information Access information.
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
        Write-PscriboMessage "Collecting AD Certification Authority Authority Information Access information."
    }

    process {
        try {
            Section -Style Heading4 "Authority Information Access (AIA) Summary" {
                Paragraph "The following section provides the Certification Authority Authority Information Access information."
                BlankLine
                Write-PscriboMessage "Discovering Active Directory Certification Authority information on $($ForestInfo.toUpper())."
                $CAs = Get-CertificationAuthority -Enterprise
                if ($CAs) {Write-PscriboMessage "Discovered '$(($CAs | Measure-Object).Count)' Active Directory Certification Authority in forest $ForestInfo."}
                foreach ($CA in $CAs) {
                    Section -Style Heading5 "$($CA.Name) AIA" {
                        Paragraph "The following section provides the Certification Authority Authority Information Access information."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Collecting AD CA Authority Information Access information on $CA."
                        $AIA = Get-AuthorityInformationAccess -CertificationAuthority $CA
                        foreach ($URI in $AIA.URI) {
                            $inObj = [ordered] @{
                                'Reg URI' = $URI.RegURI
                                'Config URI' = $URI.ConfigURI
                                'Flags' = ConvertTo-EmptyToFiller ($URI.Flags -join ", ")
                                'Server Publish' = ConvertTo-TextYN $URI.ServerPublish
                                'Include To Extension' = ConvertTo-TextYN $URI.IncludeToExtension
                                'OCSP' = ConvertTo-TextYN $URI.OCSP
                            }
                            $OutObj += [pscustomobject]$inobj
                        }

                        $TableParams = @{
                            Name = "Authority Information Access - $($CA.Name)"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Authority Information Access)"
        }
    }

    end {}

}