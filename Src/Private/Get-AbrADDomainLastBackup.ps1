function Get-AbrADDomainLastBackup {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain last backup information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.7
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
        Write-PScriboMessage -Message "Collecting AD Domain last backup information on $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Domain Last Backup"
    }

    process {
        if ($Domain -and $HealthCheck.Domain.Backup) {
            try {
                $LastBackups = Get-WinADLastBackup -Domain $Domain.DNSRoot -Credential $Credential -DCStatus ([ref]$DCStatus)
                if ($LastBackups) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Naming Context Last Backup' {
                        Paragraph "The following section provides the last backup times for each naming context in the $($Domain.DNSRoot.ToString().ToUpper()) domain."
                        BlankLine
                        $OutObj = [System.Collections.ArrayList]::new()
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
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                if ($HealthCheck.Domain.Backup) {
                                    $OutObj | Where-Object { [int]$_.'Last Backup in Days' -gt 180 } | Set-Style -Style Warning -Property 'Last Backup in Days'
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Last Backup Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "Naming Context Last Backup - $($Domain.DNSRoot.ToString().ToUpper())"
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
                    Write-PScriboMessage -Message "No Naming context last backup information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Last Backup Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain Last Backup"
    }

}