function Get-AbrADCASubordinate {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Subordinate Certification Authority information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.11
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
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCASubordinate.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'CA Subordinate'
    }

    process {
        try {
            if ($CAs | Where-Object { $_.IsRoot -like 'False' }) {
                Section -Style Heading2 $reportTranslate.GetAbrADCASubordinate.Heading {
                    Paragraph $reportTranslate.GetAbrADCASubordinate.Paragraph
                    BlankLine
                    foreach ($CA in ($CAs | Where-Object { $_.IsRoot -like 'False' })) {
                        if (Get-DCWinRMState -ComputerName $CA.ComputerName -DCStatus ([ref]$DCStatus)) {
                            $DCPssSession = Get-ValidPSSession -ComputerName $CA.ComputerName -SessionName $($CA.ComputerName) -PSSTable ([ref]$PSSTable)
                            if ($DCPssSession) {
                                $OutObj = [System.Collections.ArrayList]::new()
                                try {
                                    $AuditingIssue = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
                                        Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($using:CA.DisplayName)\" -Name 'AuditFilter'
                                    }
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADCASubordinate.CAName = $CA.DisplayName
                                        $reportTranslate.GetAbrADCASubordinate.ServerName = $CA.ComputerName.ToString().ToUpper().Split('.')[0]
                                        $reportTranslate.GetAbrADCASubordinate.Type = $CA.Type
                                        $reportTranslate.GetAbrADCASubordinate.ConfigString = $CA.ConfigString
                                        $reportTranslate.GetAbrADCASubordinate.OperatingSystem = $CA.OperatingSystem
                                        $reportTranslate.GetAbrADCASubordinate.Certificate = $CA.Certificate
                                        $reportTranslate.GetAbrADCASubordinate.Auditing = switch ($AuditingIssue) {
                                            $Null { $reportTranslate.GetAbrADCASubordinate.AuditingNotConfigured }
                                            0 { $reportTranslate.GetAbrADCASubordinate.AuditingNotConfigured }
                                            1 { $reportTranslate.GetAbrADCASubordinate.Auditing1 }
                                            2 { $reportTranslate.GetAbrADCASubordinate.Auditing2 }
                                            4 { $reportTranslate.GetAbrADCASubordinate.Auditing4 }
                                            8 { $reportTranslate.GetAbrADCASubordinate.Auditing8 }
                                            16 { $reportTranslate.GetAbrADCASubordinate.Auditing16 }
                                            32 { $reportTranslate.GetAbrADCASubordinate.Auditing32 }
                                            64 { $reportTranslate.GetAbrADCASubordinate.Auditing64 }
                                            127 { $reportTranslate.GetAbrADCASubordinate.AuditingFull }
                                            default { $reportTranslate.GetAbrADCASubordinate.AuditingUnknown }
                                        }
                                        $reportTranslate.GetAbrADCASubordinate.Status = $CA.ServiceStatus
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                    if ($HealthCheck.CA.Status) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCASubordinate.Status) -notlike 'Running' } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCASubordinate.Status
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCASubordinate.Auditing) -notlike $reportTranslate.GetAbrADCASubordinate.AuditingFull } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCASubordinate.Auditing
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADCASubordinate.TableName) - $($CA.DisplayName)"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                    if ( $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCASubordinate.Auditing) -notlike $reportTranslate.GetAbrADCASubordinate.AuditingFull } ) {
                                        Paragraph $reportTranslate.GetAbrADCASubordinate.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADCASubordinate.SecurityBestPractice -Bold
                                            Text $reportTranslate.GetAbrADCASubordinate.AuditingBP
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'CA Subordinate'
    }

}
