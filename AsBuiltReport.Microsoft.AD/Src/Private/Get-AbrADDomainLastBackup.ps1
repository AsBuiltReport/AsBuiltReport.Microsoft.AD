function Get-AbrADDomainLastBackup {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain last backup information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
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
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDomainLastBackup.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Last Backup'
    }

    process {
        if ($Domain -and $HealthCheck.Domain.Backup) {
            try {
                $LastBackups = Get-WinADLastBackup -Domain $Domain.DNSRoot -Credential $Credential -DCStatus ([ref]$DCStatus)
                if ($LastBackups) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDomainLastBackup.SectionTitle {
                        Paragraph ($reportTranslate.GetAbrADDomainLastBackup.SectionParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($LastBackup in $LastBackups) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDomainLastBackup.NamingContext = $LastBackup.NamingContext
                                    $reportTranslate.GetAbrADDomainLastBackup.LastBackup = switch ($LastBackup.LastBackup) {
                                        $Null { $reportTranslate.GetAbrADDomainLastBackup.LastBackupUnknown; break }
                                        default { $LastBackup.LastBackup.ToString('yyyy:MM:dd') }
                                    }
                                    $reportTranslate.GetAbrADDomainLastBackup.LastBackupInDays = $LastBackup.LastBackupDaysAgo
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))

                                if ($HealthCheck.Domain.Backup) {
                                    $OutObj | Where-Object { [int]$_.$($reportTranslate.GetAbrADDomainLastBackup.LastBackupInDays) -gt 180 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainLastBackup.LastBackupInDays
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Last Backup Item)"
                            }
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainLastBackup.TableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 60, 20, 20
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainLastBackup.NamingContext | Table @TableParams
                        if ($OutObj | Where-Object { [int]$_.$($reportTranslate.GetAbrADDomainLastBackup.LastBackupInDays) -gt 180 }) {
                            Paragraph $reportTranslate.GetAbrADDomainLastBackup.HealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainLastBackup.CorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADDomainLastBackup.BackupBP1
                                Text $reportTranslate.GetAbrADDomainLastBackup.BackupBP2
                                Text $reportTranslate.GetAbrADDomainLastBackup.BackupBP3
                            }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADDomainLastBackup.NoData -f $Domain.DNSRoot)
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Last Backup Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Last Backup'
    }

}