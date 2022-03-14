function Get-AbrADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain DFS Health information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.0
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
        Write-PscriboMessage "Discovering AD Domain DFS Health information on $Domain."
    }

    process {
        if ($Domain -and $HealthCheck.Domain.DFS) {
            try {
                $DFS =  Get-WinADDFSHealth -Domain $Domain
                Write-PscriboMessage "Discovered AD Domain DFS Health information from $Domain."
                if ($DFS) {
                    Section -Style Heading4 'Health Check - DFS Health' {
                        Paragraph "The following section details Distributed File System health status for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($DCStatus in $DFS) {
                            try {
                                Write-PscriboMessage "Collecting DFS information from $($Domain)."
                                $inObj = [ordered] @{
                                    'DC Name' = $DCStatus.DomainController
                                    'Replication State' = $DCStatus.ReplicationState
                                    'GPO Count' = $DCStatus.GroupPolicyCount
                                    'Sysvol Count' = $DCStatus.SysvolCount
                                    'Identical Count' = ConvertTo-TextYN $DCStatus.IdenticalCount
                                    'Stop Replication On AutoRecovery' = ConvertTo-TextYN $DCStatus.StopReplicationOnAutoRecovery

                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DFS Health Item)"
                            }
                        }

                        if ($HealthCheck.Domain.DFS) {
                            $OutObj | Where-Object { $_.'Identical Count' -like 'No' } | Set-Style -Style Warning -Property 'Identical Count'
                        }

                        $TableParams = @{
                            Name = "Domain Last Backup - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Naming Context' | Table @TableParams
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Corrective Actions: Ensure an identical GPO/SYSVOL content for the domain controller in all Active Directory domains." -Italic -Bold
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DFS Health Table)"
            }
        }
    }

    end {}

}