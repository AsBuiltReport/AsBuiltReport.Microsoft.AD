function Get-AbrADDuplicateSPN {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate SPN information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.14
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
        Write-PscriboMessage "Discovering duplicate SPN information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.SPN) {
            try {
                $SPNs = Get-WinADDuplicateSPN -Domain $Domain -Credential $Credential
                Write-PscriboMessage "Discovered AD Duplicate SPN information from $Domain."
                if ($SPNs) {
                    Section -ExcludeFromTOC -Style NOTOCHeading5 'Duplicate SPN' {
                        Paragraph "The following section details Duplicate SPN discovered on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($SPN in $SPNs) {
                            try {
                                Write-PscriboMessage "Collecting $($SPN.Name) information from $($Domain)."
                                $inObj = [ordered] @{
                                    'Name' = $SPN.Name
                                    'Count' = $SPN.Count
                                    'Distinguished Name' = $SPN.List
                                }
                                $OutObj += [pscustomobject]$inobj

                                if ($HealthCheck.Domain.SPN) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (SPN Item)"
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
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (SPN Table)"
            }
        }
    }

    end {}

}