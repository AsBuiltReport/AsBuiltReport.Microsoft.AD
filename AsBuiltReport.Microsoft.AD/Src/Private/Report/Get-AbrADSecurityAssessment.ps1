function Get-AbrADSecurityAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Account Security Assessment information.
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
        $Domain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADSecurityAssessment.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Account Security Assessment'
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -Days 180)
                $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -Days 180)
                $DomainUsers = $Users
                $DomainEnabledUsers = $DomainUsers | Where-Object { $_.Enabled } | Measure-Object
                $DomainDisabledUsers = $DomainUsers | Where-Object { -not $_.Enabled } | Measure-Object
                $DomainEnabledInactiveUsers = $DomainEnabledUsers | Where-Object { ($_.LastLogonDate -le $LastLoggedOnDate) -and ($_.PasswordLastSet -le $PasswordStaleDate) } | Measure-Object
                $DomainUsersWithReversibleEncryptionPasswordArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x0080 } | Measure-Object
                $DomainUserPasswordNotRequiredArray = $DomainUsers | Where-Object { $_.PasswordNotRequired } | Measure-Object
                $DomainUserPasswordNeverExpiresArray = $DomainUsers | Where-Object { $_.PasswordNeverExpires } | Measure-Object
                $DomainKerberosDESUsersArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x200000 } | Measure-Object
                $DomainUserDoesNotRequirePreAuthArray = $DomainUsers | Where-Object { $_.DoesNotRequirePreAuth -eq $True } | Measure-Object
                $DomainUsersWithSIDHistoryArray = $DomainUsers | Where-Object { $_.SIDHistory -like '*' } | Measure-Object
                if ($DomainUsers) {
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    try {
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADSecurityAssessment.Total = $DomainUsers.Count
                            $reportTranslate.GetAbrADSecurityAssessment.Enabled = $DomainEnabledUsers.Count
                            $reportTranslate.GetAbrADSecurityAssessment.Disabled = $DomainDisabledUsers.Count
                            $reportTranslate.GetAbrADSecurityAssessment.EnabledInactive = $DomainEnabledInactiveUsers.Count
                            $reportTranslate.GetAbrADSecurityAssessment.ReversibleEncryptionPassword = $DomainUsersWithReversibleEncryptionPasswordArray.Count
                            $reportTranslate.GetAbrADSecurityAssessment.PasswordNotRequired = $DomainUserPasswordNotRequiredArray.Count
                            $reportTranslate.GetAbrADSecurityAssessment.PasswordNeverExpires = $DomainUserPasswordNeverExpiresArray.Count
                            $reportTranslate.GetAbrADSecurityAssessment.KerberosDES = $DomainKerberosDESUsersArray.Count
                            $reportTranslate.GetAbrADSecurityAssessment.DoesNotRequirePreAuth = $DomainUserDoesNotRequirePreAuthArray.Count
                            $reportTranslate.GetAbrADSecurityAssessment.SIDHistory = $DomainUsersWithSIDHistoryArray.Count
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Account Security Assessment Item)"
                    }

                    if ($HealthCheck.Domain.Security) {
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.EnabledInactive) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.EnabledInactive
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.ReversibleEncryptionPassword) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.ReversibleEncryptionPassword
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.PasswordNotRequired) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.PasswordNotRequired
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.PasswordNeverExpires) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.PasswordNeverExpires
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.KerberosDES) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.KerberosDES
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.DoesNotRequirePreAuth) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.DoesNotRequirePreAuth
                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.SIDHistory) -gt 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.SIDHistory
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADSecurityAssessment.UserAccountTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }

                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    try {
                        $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Category'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } }
                        $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Category -Title $reportTranslate.GetAbrADSecurityAssessment.UserAccountTitle -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 600 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (User Account Security Assessment Chart)"
                    }
                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSecurityAssessment.UserAccountTitle {
                            Paragraph ($reportTranslate.GetAbrADSecurityAssessment.UserAccountParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            if ($Chart) {
                                Image -Text $reportTranslate.GetAbrADSecurityAssessment.UserAccountDiagram -Align 'Center' -Percent 100 -Base64 $Chart
                            }
                            $OutObj | Table @TableParams
                            Paragraph $reportTranslate.GetAbrADSecurityAssessment.UserAccountHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADSecurityAssessment.UserAccountCorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADSecurityAssessment.UserAccountBP }
                        }
                    }
                } else {
                    Write-PScriboMessage -Message "No Domain users information found in $($Domain.DNSRoot), Disabling this section."
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Account Security Assessment Table)"
            }
            if ($InfoLevel.Domain -ge 2) {
                try {
                    if ($PrivilegedUsers) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersTitle {
                            Paragraph ($reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            $AccountNotDelegated = $PrivilegedUsers | Where-Object { -not $_.AccountNotDelegated -and $_.objectClass -eq 'user' }
                            foreach ($PrivilegedUser in $PrivilegedUsers) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADSecurityAssessment.Username = $PrivilegedUser.SamAccountName
                                        $reportTranslate.GetAbrADSecurityAssessment.PasswordLastSet = switch ($PrivilegedUser.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $PrivilegedUser.PasswordLastSet.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.LastLogonDate = switch ($PrivilegedUser.LastLogonDate) {
                                            $Null { '--' }
                                            default { $PrivilegedUser.LastLogonDate.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.EmailEnabled = switch ([string]::IsNullOrEmpty($PrivilegedUser.EmailAddress)) {
                                            $true { $reportTranslate.GetAbrADSecurityAssessment.EmailEnabledNo }
                                            $false { $reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes }
                                            default { $reportTranslate.GetAbrADSecurityAssessment.EmailEnabledUnknown }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation = switch ([string]::IsNullOrEmpty(($AccountNotDelegated | Where-Object { $_.SamAccountName -eq $PrivilegedUser.SamAccountName }))) {
                                            $true { $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationNo }
                                            $false { $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes }
                                            default { $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationUnknown }
                                        }
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Users Assessment Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.EmailEnabled) -eq $reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes })) {
                                    $OBJ.$($reportTranslate.GetAbrADSecurityAssessment.EmailEnabled) = "* $($reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes)"
                                }
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.EmailEnabled) -eq "* $($reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes)" } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.EmailEnabled

                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation) -eq $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes })) {
                                    $OBJ.$($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation) = "** $($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes)"
                                }
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation) -eq "** $($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes)" } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 15, 15, 15, 15
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation) -eq "** $($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes)" }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.EmailEnabled) -eq "* $($reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes)" })) {
                                Paragraph $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersHealthCheck -Bold -Underline
                                BlankLine
                                Paragraph $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersSecurityBP -Bold
                                BlankLine
                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.EmailEnabled) -eq "* $($reportTranslate.GetAbrADSecurityAssessment.EmailEnabledYes)" }) {
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersEmailNote
                                    }
                                    BlankLine
                                }
                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegation) -eq "** $($reportTranslate.GetAbrADSecurityAssessment.TrustedForDelegationYes)" }) {
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersDelegationNote
                                        Text $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersReference
                                        Text $reportTranslate.GetAbrADSecurityAssessment.PrivilegedUsersReferenceURL -Color blue
                                    }
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Privileged User Assessment information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Users Table)"
                }
                try {
                    $InactivePrivilegedUsers = $PrivilegedUsers | Where-Object { ($_.LastLogonDate -le (Get-Date).AddDays(-30)) -and ($_.PasswordLastSet -le (Get-Date).AddDays(-365)) -and ($_.SamAccountName -ne 'krbtgt') -and ($_.SamAccountName -ne 'Administrator') }
                    if ($InactivePrivilegedUsers) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedTitle {
                            Paragraph ($reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            foreach ($InactivePrivilegedUser in $InactivePrivilegedUsers) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADSecurityAssessment.Username = $InactivePrivilegedUser.SamAccountName
                                        $reportTranslate.GetAbrADSecurityAssessment.Created = switch ($InactivePrivilegedUser.Created) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.Created.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.PasswordLastSet = switch ($InactivePrivilegedUser.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.PasswordLastSet.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.LastLogonDate = switch ($InactivePrivilegedUser.LastLogonDate) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.LastLogonDate.ToShortDateString() }
                                        }
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Inactive Privileged Accounts Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 20, 20, 20
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph $reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedHealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedCorrectiveActions -Bold
                                Text $reportTranslate.GetAbrADSecurityAssessment.InactivePrivilegedBP
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Inactive Privileged Accounts information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Inactive Privileged Accounts Table)"
                }
                try {
                    $UserSPNs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADUser -ResultPageSize 1000 -Server ($using:Domain).DNSRoot -Filter { ServicePrincipalName -like '*' } -Properties AdminCount, PasswordLastSet, LastLogonDate, ServicePrincipalName, TrustedForDelegation, TrustedtoAuthForDelegation }
                    if ($UserSPNs) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsTitle {
                            Paragraph ($reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                            BlankLine
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            $AdminCount = ($UserSPNs | Where-Object { $_.AdminCount -eq 1 -and $_.SamAccountName -ne 'krbtgt' }).Name
                            foreach ($UserSPN in $UserSPNs) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADSecurityAssessment.Username = $UserSPN.SamAccountName
                                        $reportTranslate.GetAbrADSecurityAssessment.Enabled = $UserSPN.Enabled
                                        $reportTranslate.GetAbrADSecurityAssessment.PasswordLastSet = switch ($UserSPN.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $UserSPN.PasswordLastSet.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.LastLogonDate = switch ($UserSPN.LastLogonDate) {
                                            $Null { '--' }
                                            default { $UserSPN.LastLogonDate.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADSecurityAssessment.ServicePrincipalName = $UserSPN.ServicePrincipalName
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Service Accounts Assessment Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.Username) -in $AdminCount } | Set-Style -Style Critical

                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.Username) -in $AdminCount })) {
                                    $OBJ.$($reportTranslate.GetAbrADSecurityAssessment.Username) = "** $($OBJ.$($reportTranslate.GetAbrADSecurityAssessment.Username))"
                                }
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 30, 12, 14, 14, 30
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph $reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsHealthCheck -Bold -Underline
                            BlankLine
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSecurityAssessment.Username) -match '\*' }) {
                                Paragraph {
                                    Text $reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsSecurityBP -Bold
                                    Text $reportTranslate.GetAbrADSecurityAssessment.ServiceAccountsAdminCountNote
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Service Accounts Assessment information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Service Accounts Assessment Table)"
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Account Security Assessment'
    }
}
