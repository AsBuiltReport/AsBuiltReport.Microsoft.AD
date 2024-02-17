function Get-AbrADDuplicateSPN {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate SPN information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
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
        [string]
        $Domain
    )

    begin {
        Write-PScriboMessage "Collecting duplicate SPN information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.SPN) {
            try {
                $SPNs = Get-WinADDuplicateSPN -Domain $Domain -Credential $Credential
                if ($SPNs) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Duplicate SPN' {
                        Paragraph "The following section details Duplicate SPN discovered on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($SPN in $SPNs) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $SPN.Name
                                    'Count' = $SPN.Count
                                    'Distinguished Name' = $SPN.List
                                }
                                $OutObj += [pscustomobject]$inobj

                                if ($HealthCheck.Domain.SPN) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (SPN Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Duplicate SPN - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 10, 50
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                        if ($HealthCheck.Domain.SPN) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Ensure there aren't any duplicate SPNs (other than krbtgt)."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No Duplicate SPN information found in $Domain, disabling the section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (SPN Table)"
            }
        }
    }

    end {}

}