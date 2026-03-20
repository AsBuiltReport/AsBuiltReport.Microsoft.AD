function Get-AbrADCARoot {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory Root Certification Authority information.
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
        Write-PScriboMessage -Message $reportTranslate.GetAbrADCARoot.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Certification Authority Per Domain'
    }

    process {
        try {
            if ($CAs | Where-Object { $_.IsRoot -like 'True' }) {
                Section -Style Heading2 $reportTranslate.GetAbrADCARoot.Heading {
                    Paragraph $reportTranslate.GetAbrADCARoot.Paragraph
                    BlankLine
                    foreach ($CA in ($CAs | Where-Object { $_.IsRoot -like 'True' })) {
                        if (Get-DCWinRMState -ComputerName $CA.ComputerName -DCStatus ([ref]$DCStatus)) {
                            $DCPssSession = Get-ValidPSSession -ComputerName $CA.ComputerName -SessionName $($CA.ComputerName) -PSSTable ([ref]$PSSTable)
                            if ($DCPssSession) {
                                $OutObj = [System.Collections.ArrayList]::new()
                                $AuditingIssue = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock {
                                    Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($using:CA.DisplayName)\" -Name 'AuditFilter'
                                }
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADCARoot.CAName = $CA.DisplayName
                                    $reportTranslate.GetAbrADCARoot.ServerName = $CA.ComputerName.ToString().ToUpper().Split('.')[0]
                                    $reportTranslate.GetAbrADCARoot.Type = $CA.Type
                                    $reportTranslate.GetAbrADCARoot.ConfigString = $CA.ConfigString
                                    $reportTranslate.GetAbrADCARoot.OperatingSystem = $CA.OperatingSystem
                                    $reportTranslate.GetAbrADCARoot.Certificate = $CA.Certificate
                                    $reportTranslate.GetAbrADCARoot.Auditing = switch ($AuditingIssue) {
                                        $Null { $reportTranslate.GetAbrADCARoot.AuditingNotConfigured }
                                        0 { $reportTranslate.GetAbrADCARoot.AuditingNotConfigured }
                                        1 { $reportTranslate.GetAbrADCARoot.Auditing1 }
                                        2 { $reportTranslate.GetAbrADCARoot.Auditing2 }
                                        4 { $reportTranslate.GetAbrADCARoot.Auditing4 }
                                        8 { $reportTranslate.GetAbrADCARoot.Auditing8 }
                                        16 { $reportTranslate.GetAbrADCARoot.Auditing16 }
                                        32 { $reportTranslate.GetAbrADCARoot.Auditing32 }
                                        64 { $reportTranslate.GetAbrADCARoot.Auditing64 }
                                        127 { $reportTranslate.GetAbrADCARoot.AuditingFull }
                                        default { $reportTranslate.GetAbrADCARoot.AuditingUnknown }
                                    }
                                    $reportTranslate.GetAbrADCARoot.Status = $CA.ServiceStatus
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                if ($HealthCheck.CA.Status) {
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCARoot.Status) -notlike 'Running' } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCARoot.Status
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCARoot.Auditing) -notlike $reportTranslate.GetAbrADCARoot.AuditingFull } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADCARoot.Auditing
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADCARoot.TableName) - $($ForestInfo.ToString().ToUpper())"
                                    List = $true
                                    ColumnWidths = 40, 60
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                                if ( $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADCARoot.Auditing) -notlike $reportTranslate.GetAbrADCARoot.AuditingFull } ) {
                                    Paragraph $reportTranslate.GetAbrADCARoot.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADCARoot.SecurityBestPractice -Bold
                                        Text $reportTranslate.GetAbrADCARoot.AuditingBP
                                    }
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
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Certification Authority Per Domain'
    }
}
