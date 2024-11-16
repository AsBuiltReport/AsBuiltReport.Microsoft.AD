function Get-AbrADSecurityAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Account Security Assessment information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.1
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
        Write-PScriboMessage "Collecting Account Security Assessment information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -Days 180)
                $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -Days 180)
                $DomainUsers = $Users
                $DomainEnabledUsers = $DomainUsers | Where-Object { $_.Enabled -eq $True } | Measure-Object
                $DomainDisabledUsers = $DomainUsers | Where-Object { $_.Enabled -eq $false } | Measure-Object
                $DomainEnabledInactiveUsers = $DomainEnabledUsers | Where-Object { ($_.LastLogonDate -le $LastLoggedOnDate) -AND ($_.PasswordLastSet -le $PasswordStaleDate) } | Measure-Object
                $DomainUsersWithReversibleEncryptionPasswordArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x0080 } | Measure-Object
                $DomainUserPasswordNotRequiredArray = $DomainUsers | Where-Object { $_.PasswordNotRequired -eq $True } | Measure-Object
                $DomainUserPasswordNeverExpiresArray = $DomainUsers | Where-Object { $_.PasswordNeverExpires -eq $True } | Measure-Object
                $DomainKerberosDESUsersArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x200000 } | Measure-Object
                $DomainUserDoesNotRequirePreAuthArray = $DomainUsers | Where-Object { $_.DoesNotRequirePreAuth -eq $True } | Measure-Object
                $DomainUsersWithSIDHistoryArray = $DomainUsers | Where-Object { $_.SIDHistory -like "*" } | Measure-Object
                if ($DomainUsers) {
                    $OutObj = @()
                    try {
                        $inObj = [ordered] @{
                            'Total Users' = $DomainUsers.Count
                            'Enabled Users' = $DomainEnabledUsers.Count
                            'Disabled Users' = $DomainDisabledUsers.Count
                            'Enabled Inactive Users' = $DomainEnabledInactiveUsers.Count
                            'Users With Reversible Encryption Password' = $DomainUsersWithReversibleEncryptionPasswordArray.Count
                            'Password Not Required' = $DomainUserPasswordNotRequiredArray.Count
                            'Password Never Expires' = $DomainUserPasswordNeverExpiresArray.Count
                            'Kerberos DES Users' = $DomainKerberosDESUsersArray.Count
                            'Does Not Require Pre Auth' = $DomainUserDoesNotRequirePreAuthArray.Count
                            'Users With SID History' = $DomainUsersWithSIDHistoryArray.Count
                        }
                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Item)"
                    }

                    if ($HealthCheck.Domain.Security) {
                        $OutObj | Where-Object { $_.'Enabled Inactive Users' -gt 0 } | Set-Style -Style Warning -Property 'Enabled Inactive Users'
                        $OutObj | Where-Object { $_.'Users With Reversible Encryption Password' -gt 0 } | Set-Style -Style Warning -Property 'Users With Reversible Encryption Password'
                        $OutObj | Where-Object { $_.'User Password Not Required' -gt 0 } | Set-Style -Style Warning -Property 'User Password Not Required'
                        $OutObj | Where-Object { $_.'User Password Never Expires' -gt 0 } | Set-Style -Style Warning -Property 'User Password Never Expires'
                        $OutObj | Where-Object { $_.'Kerberos DES Users' -gt 0 } | Set-Style -Style Warning -Property 'Kerberos DES Users'
                        $OutObj | Where-Object { $_.'User Does Not Require Pre Auth' -gt 0 } | Set-Style -Style Warning -Property 'User Does Not Require Pre Auth'
                        $OutObj | Where-Object { $_.'Users With SID History' -gt 0 } | Set-Style -Style Warning -Property 'Users With SID History'
                    }

                    $TableParams = @{
                        Name = "Account Security Assessment - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }

                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    try {
                        # Chart Section
                        $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Category'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } }
                        $chartFileItem = Get-ColumnChart -SampleData $sampleData -ChartName 'AccountSecurityAssessment' -XField 'Category' -YField 'Value' -ChartAreaName 'Account Security Assessment' -AxisXTitle 'Categories' -AxisYTitle 'Number of Users' -ChartTitleName 'AccountSecurityAssessment' -ChartTitleText 'Assessment' -ReversePalette $True
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Chart)"
                    }
                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Account Security Assessment' {
                            Paragraph "The following section provide a summary of the Account Security Assessment on Domain $($Domain.ToString().ToUpper())."
                            BlankLine
                            if ($chartFileItem) {
                                Image -Text 'Account Security Assessment - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Ensure there aren't any account with weak security posture." }
                        }
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No Domain users information found in $Domain, disabling the section."
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
            }
            if ($InfoLevel.Domain -ge 2) {
                try {
                    if ($PrivilegedUsers) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Privileged Users Assessment' {
                            Paragraph "The following section details probable AD Admin accounts (user accounts with AdminCount set to 1) on Domain $($Domain.ToString().ToUpper())"
                            BlankLine
                            $OutObj = @()
                            $AccountNotDelegated = $PrivilegedUsers | Where-Object { -not $_.AccountNotDelegated -and $_.objectClass -eq "user" }
                            foreach ($PrivilegedUser in $PrivilegedUsers) {
                                try {
                                    $inObj = [ordered] @{
                                        'Username' = $PrivilegedUser.SamAccountName
                                        'Password Last Set' = Switch ($PrivilegedUser.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $PrivilegedUser.PasswordLastSet.ToShortDateString() }
                                        }
                                        'Last Logon Date' = Switch ($PrivilegedUser.LastLogonDate) {
                                            $Null { '--' }
                                            default { $PrivilegedUser.LastLogonDate.ToShortDateString() }
                                        }
                                        'Email Enabled?' = Switch ([string]::IsNullOrEmpty($PrivilegedUser.EmailAddress)) {
                                            $true { 'No' }
                                            $false { "Yes" }
                                            default { "Unknown" }
                                        }
                                        'Trusted for Delegation' = Switch ([string]::IsNullOrEmpty(($AccountNotDelegated | Where-Object { $_.SamAccountName -eq $PrivilegedUser.SamAccountName }))) {
                                            $true { "No" }
                                            $false { "Yes" }
                                            default { "Unknown" }
                                        }
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Privileged Users Assessment Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Email Enabled?' -eq "Yes" })) {
                                    $OBJ.'Email Enabled?' = "* $($OBJ.'Email Enabled?')"
                                }
                                $OutObj | Where-Object { $_.'Email Enabled?' -eq "* Yes" } | Set-Style -Style Warning -Property 'Email Enabled?'

                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Trusted for Delegation' -eq "Yes" })) {
                                    $OBJ.'Trusted for Delegation' = "** $($OBJ.'Trusted for Delegation')"
                                }
                                $OutObj | Where-Object { $_.'Trusted for Delegation' -eq "** Yes" } | Set-Style -Style Warning -Property 'Trusted for Delegation'
                            }

                            $TableParams = @{
                                Name = "Privileged User Assessment - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 15, 15, 15, 15
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            if (($OutObj | Where-Object { $_.'Trusted for Delegation' -eq "** Yes" }) -or ($OutObj | Where-Object { $_.'Email Enabled?' -eq "* Yes" })) {
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph "Security Best Practice:" -Bold
                                BlankLine
                                if ($OutObj | Where-Object { $_.'Email Enabled?' -eq "* Yes" }) {
                                    Paragraph {
                                        Text "* Privileged accounts such as those belonging to any of the administrator groups must not have configured email."
                                    }
                                    BlankLine
                                }
                                if ($OutObj | Where-Object { $_.'Trusted for Delegation' -eq "** Yes" }) {
                                    Paragraph {
                                        Text "** Privileged accounts such as those belonging to any of the administrator groups must not be trusted for delegation. Allowing privileged accounts to be trusted for delegation provides a means for privilege escalation from a compromised system. Delegation of privileged accounts must be prohibited."
                                        Text "Reference: "
                                        Text "https://www.stigviewer.com/stig/active_directory_domain/2017-12-15/finding/V-36435"  -Color blue
                                    }
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "No Privileged User Assessment information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Privileged Users Table)"
                }
                try {
                    $InactivePrivilegedUsers = $PrivilegedUsers | Where-Object { ($_.LastLogonDate -le (Get-Date).AddDays(-30)) -AND ($_.PasswordLastSet -le (Get-Date).AddDays(-365)) -and ($_.SamAccountName -ne 'krbtgt') -and ($_.SamAccountName -ne 'Administrator') }
                    if ($InactivePrivilegedUsers) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Inactive Privileged Accounts' {
                            Paragraph "The following section details privileged accounts with the following filter (LastLogonDate >=30 days and PasswordLastSet >= 365 days) on Domain $($Domain.ToString().ToUpper())"
                            BlankLine
                            $OutObj = @()
                            foreach ($InactivePrivilegedUser in $InactivePrivilegedUsers) {
                                try {
                                    $inObj = [ordered] @{
                                        'Username' = $InactivePrivilegedUser.SamAccountName
                                        'Created' = Switch ($InactivePrivilegedUser.Created) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.Created.ToShortDateString() }
                                        }
                                        'Password Last Set' = Switch ($InactivePrivilegedUser.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.PasswordLastSet.ToShortDateString() }
                                        }
                                        'Last Logon Date' = Switch ($InactivePrivilegedUser.LastLogonDate) {
                                            $Null { '--' }
                                            default { $InactivePrivilegedUser.LastLogonDate.ToShortDateString() }
                                        }
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Inactive Privileged Accounts Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning
                            }

                            $TableParams = @{
                                Name = "Inactive Privileged Accounts - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 20, 20, 20
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text  "Unused or underutilized accounts in highly privileged groups, outside of any break-glass emergency accounts like the default Administrator account, should have their AD Admin privileges removed."
                            }
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "No Inactive Privileged Accounts information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Inactive Privileged Accounts Table)"
                }
                try {
                    $UserSPNs = Invoke-Command -Session $TempPssSession { Get-ADUser -ResultPageSize 1000 -Server $using:Domain -Filter { ServicePrincipalName -like '*' } -Properties AdminCount, PasswordLastSet, LastLogonDate, ServicePrincipalName, TrustedForDelegation, TrustedtoAuthForDelegation }
                    if ($UserSPNs) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Service Accounts Assessment (Kerberoastable)' {
                            Paragraph "The following section details probable AD Service Accounts (user accounts with SPNs) on Domain $($Domain.ToString().ToUpper())"
                            BlankLine
                            $OutObj = @()
                            $AdminCount = ($UserSPNs | Where-Object { $_.AdminCount -eq 1 -and $_.SamAccountName -ne 'krbtgt' }).Name
                            foreach ($UserSPN in $UserSPNs) {
                                try {
                                    $inObj = [ordered] @{
                                        'Username' = $UserSPN.SamAccountName
                                        'Enabled' = $UserSPN.Enabled
                                        'Password Last Set' = Switch ($UserSPN.PasswordLastSet) {
                                            $Null { '--' }
                                            default { $UserSPN.PasswordLastSet.ToShortDateString() }
                                        }
                                        'Last Logon Date' = Switch ($UserSPN.LastLogonDate) {
                                            $Null { '--' }
                                            default { $UserSPN.LastLogonDate.ToShortDateString() }
                                        }
                                        'Service Principal Name' = $UserSPN.ServicePrincipalName
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Service Accounts Assessment Item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Username' -in $AdminCount })) {
                                    $OBJ.Username = "** $($OBJ.Username)"
                                }
                            }

                            $TableParams = @{
                                Name = "Service Accounts Assessment - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 30, 12, 14, 14, 30
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            if ($OutObj | Where-Object { $_.'Username' -match '\*' }) {
                                Paragraph {
                                    Text "Security Best Practice:" -Bold

                                    Text "**Attackers are most interested in Service Accounts that are members of highly privileged groups like Domain Admins. A quick way to check for this is to enumerate all user accounts with the attribute AdminCount equal to 1. This means an attacker may just ask AD for all user accounts with a SPN and with AdminCount=1. Ensure that there are no privileged accounts that have SPNs assigned to them."
                                }
                            }
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "No Service Accounts Assessment information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Service Accounts Assessment Table)"
                }
            }
        }
    }
    end {}
}