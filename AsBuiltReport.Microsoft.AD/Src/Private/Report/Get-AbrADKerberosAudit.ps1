function Get-AbrADKerberosAudit {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Kerberos Audit information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADKerberosAudit.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Kerberos Audit'
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $Unconstrained = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -and (PrimaryGroupID -ne '516') -and (PrimaryGroupID -ne '521') } -Server $using:ValidDCFromDomain -SearchBase $($using:Domain).distinguishedName }
                if ($Unconstrained) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADKerberosAudit.UnconstrainedTitle {
                        Paragraph ($reportTranslate.GetAbrADKerberosAudit.UnconstrainedParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $OutObj = [System.Collections.Generic.List[object]]::new()
                        foreach ($Item in $Unconstrained) {
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADKerberosAudit.Name = $Item.Name
                                    $reportTranslate.GetAbrADKerberosAudit.DistinguishedName = $Item.DistinguishedName
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorUnconstrainedKerberosItem))"
                            }
                        }

                        if ($HealthCheck.Domain.Security) {
                            $OutObj | Set-Style -Style Warning
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADKerberosAudit.UnconstrainedTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 60
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                        Paragraph $reportTranslate.GetAbrADKerberosAudit.UnconstrainedHealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADKerberosAudit.UnconstrainedCorrectiveActions -Bold
                            Text $reportTranslate.GetAbrADKerberosAudit.UnconstrainedBP
                        }
                    }
                } else {
                    Write-PScriboMessage -Message ($reportTranslate.GetAbrADKerberosAudit.UnconstrainedNoData -f $Domain.DNSRoot)
                }
                try {
                    $KRBTGT = $Users | Where-Object { $_.Name -eq 'krbtgt' }
                    if ($KRBTGT) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADKerberosAudit.KRBTGTTitle {
                            Paragraph ($reportTranslate.GetAbrADKerberosAudit.KRBTGTParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADKerberosAudit.Name = $KRBTGT.Name
                                    $reportTranslate.GetAbrADKerberosAudit.Created = $KRBTGT.Created
                                    $reportTranslate.GetAbrADKerberosAudit.PasswordLastSet = $KRBTGT.PasswordLastSet
                                    $reportTranslate.GetAbrADKerberosAudit.DistinguishedName = $KRBTGT.DistinguishedName
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorKRBTGTAccountItem))"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADKerberosAudit.PasswordLastSet
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADKerberosAudit.KRBTGTTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph $reportTranslate.GetAbrADKerberosAudit.KRBTGTHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADKerberosAudit.KRBTGTBestPractice -Bold
                                Text $reportTranslate.GetAbrADKerberosAudit.KRBTGTBP
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message ($reportTranslate.GetAbrADKerberosAudit.KRBTGTNoData -f $Domain.DNSRoot)
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorUnconstrainedKerberosItem))"
                }
                try {
                    $SID = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { "$($($using:Domain).domainsid.ToString())-500" }
                    $ADMIN = $Users | Where-Object { $_.SID -eq $SID }
                    if ($ADMIN) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADKerberosAudit.AdminTitle {
                            Paragraph ($reportTranslate.GetAbrADKerberosAudit.AdminParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADKerberosAudit.Name = $ADMIN.Name
                                    $reportTranslate.GetAbrADKerberosAudit.Created = $ADMIN.Created
                                    $reportTranslate.GetAbrADKerberosAudit.PasswordLastSet = $ADMIN.PasswordLastSet
                                    $reportTranslate.GetAbrADKerberosAudit.LastLogonDate = $ADMIN.LastLogonDate
                                    $reportTranslate.GetAbrADKerberosAudit.DistinguishedName = $ADMIN.DistinguishedName
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorAdminAccountItem))"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADKerberosAudit.PasswordLastSet
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADKerberosAudit.AdminTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph $reportTranslate.GetAbrADKerberosAudit.AdminHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADKerberosAudit.AdminBestPractice -Bold
                                Text $reportTranslate.GetAbrADKerberosAudit.AdminBP
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message ($reportTranslate.GetAbrADKerberosAudit.AdminNoData -f $Domain.DNSRoot)
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorUnconstrainedKerberosItem))"
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) ($($reportTranslate.GetAbrADKerberosAudit.ErrorUnconstrainedKerberosSection))"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Kerberos Audit'
    }

}