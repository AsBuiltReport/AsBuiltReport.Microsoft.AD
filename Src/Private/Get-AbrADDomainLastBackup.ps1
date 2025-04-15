function Get-AbrADDomainLastBackup {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain last backup information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
        Write-PScriboMessage "Collecting AD Domain last backup information on $Domain."
    }

    process {
        if ($Domain -and $HealthCheck.Domain.Backup) {
            try {
                $LastBackups = Get-WinADLastBackup -Domain $Domain -Credential $Credential -DCStatus ([ref]$DCStatus)
                if ($LastBackups) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Naming Context Last Backup' {
                        Paragraph "The following section details naming context last backup time for Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($LastBackup in $LastBackups) {
                            try {
                                $inObj = [ordered] @{
                                    'Naming Context' = $LastBackup.NamingContext
                                    'Last Backup' = Switch ($LastBackup.LastBackup) {
                                        $Null { 'Unknown'; break }
                                        default { $LastBackup.LastBackup.ToString("yyyy:MM:dd") }
                                    }
                                    'Last Backup in Days' = $LastBackup.LastBackupDaysAgo
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.Backup) {
                                    $OutObj | Where-Object { $_.'Last Backup in Days' -gt 180 } | Set-Style -Style Warning -Property 'Last Backup in Days'
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Last Backup Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Naming Context Last Backup - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 60, 20, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property 'Naming Context' | Table @TableParams
                        if ($OutObj | Where-Object { $_.'Last Backup in Days' -gt 180 }) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Ensure there is a recent (<180 days) Active Directory backup."
                                Text "Regular backups are crucial for disaster recovery and maintaining the integrity of your Active Directory environment."
                                Text "Consider setting up automated backup schedules and regularly verifying the backup status to prevent data loss."
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage "No Naming context last backup information found in $Domain, Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Last Backup Table)"
            }
        }
    }

    end {}

}