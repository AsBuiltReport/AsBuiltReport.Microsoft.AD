function Get-AbrADCAAIA {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory CA Authority Information Access information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.5
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
        Show-AbrDebugExecutionTime -Start -TitleMessage "CA Authority Information Access Objects"
    }

    process {
        if ($CA) {
            Section -Style Heading3 "Authority Information Access (AIA)" {
                Paragraph "The following section provides the Certification Authority Information Access details."
                BlankLine
                try {
                    $OutObj = @()
                    Write-PScriboMessage -Message "Collecting AD CA Authority Information Access information on $($CA.Name)."
                    $AIA = Get-AuthorityInformationAccess -CertificationAuthority $CA
                    foreach ($URI in $AIA.URI) {
                        try {
                            $inObj = [ordered] @{
                                'Reg URI' = $URI.RegURI
                                'Config URI' = $URI.ConfigURI
                                'Flags' = ($URI.Flags -join ", ")
                                'Server Publish' = $URI.ServerPublish
                                'Include To Extension' = $URI.IncludeToExtension
                                'OCSP' = $URI.OCSP
                            }
                            $OutObj = [pscustomobject](ConvertTo-HashToYN $inObj)

                            $TableParams = @{
                                Name = "Authority Information Access - $($CA.Name)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Authority Information Access Item $($URI.RegURI) Section: $($_.Exception.Message)"
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "Authority Information Access Section: $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        if ($Options.ShowExecutionTime) {
            $SectionEndTime = Get-Date
            Write-Host "Ending CA Authority Information Access Objects section: $($SectionEndTime)" -ForegroundColor Cyan
            $elapsedTime = New-TimeSpan -Start $SectionStartTime -End $SectionEndTime
            Write-Host "CA Authority Information Access Objects Section execution time: $($elapsedTime.tostring("hh")) Hours $($elapsedTime.tostring("mm")) Minutes $($elapsedTime.tostring("ss")) Seconds"
        }
        Show-AbrDebugExecutionTime -End -TitleMessage "CA Authority Information Access Objects"
    }

}