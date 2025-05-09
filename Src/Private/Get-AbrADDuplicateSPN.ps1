function Get-AbrADDuplicateSPN {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Duplicate SPN information.
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
        $Domain
    )

    begin {
        Write-PScriboMessage -Message "Collecting duplicate SPN information on $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Domain Duplicate SPN"
    }

    process {
        if ($HealthCheck.Domain.SPN) {
            try {
                $SPNs = Get-WinADDuplicateSPN -Domain $Domain.DNSRoot -Credential $Credential -ExcludeDomains $Options.Exclude.Domains
                if ($SPNs) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Duplicate SPN' {
                        Paragraph "The following section details Duplicate SPN discovered on Domain $($Domain.DNSRoot.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($SPN in $SPNs) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $SPN.Name
                                    'Count' = $SPN.Count
                                    'Distinguished Name' = $SPN.List
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.SPN) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SPN Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Duplicate SPN - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                Text "Ensure there aren't any duplicate SPNs (other than krbtgt). Duplicate SPNs can cause authentication issues and should be resolved promptly. Use the `setspn -X` command to identify duplicate SPNs. Remove or reassign duplicate SPNs as necessary to maintain a healthy AD environment."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message "No Duplicate SPN information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SPN Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain Duplicate SPN"
    }

}