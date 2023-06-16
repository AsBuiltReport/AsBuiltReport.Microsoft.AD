function Get-AbrADSecurityAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Account Security Assessment information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.13
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
        Write-PscriboMessage "Discovering Account Security Assessment information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -days 180)
                $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -days 180)
                $DomainUsers = $Users
                $DomainEnabledUsers = $DomainUsers | Where-Object {$_.Enabled -eq $True } | Measure-Object
                $DomainDisabledUsers = $DomainUsers | Where-Object {$_.Enabled -eq $false } | Measure-Object
                $DomainEnabledInactiveUsers = $DomainEnabledUsers | Where-Object { ($_.LastLogonDate -le $LastLoggedOnDate) -AND ($_.PasswordLastSet -le $PasswordStaleDate) } | Measure-Object
                $DomainUsersWithReversibleEncryptionPasswordArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x0080 } | Measure-Object
                $DomainUserPasswordNotRequiredArray = $DomainUsers | Where-Object {$_.PasswordNotRequired -eq $True} | Measure-Object
                $DomainUserPasswordNeverExpiresArray = $DomainUsers | Where-Object {$_.PasswordNeverExpires -eq $True} | Measure-Object
                $DomainKerberosDESUsersArray = $DomainUsers | Where-Object { $_.UserAccountControl -band 0x200000 } | Measure-Object
                $DomainUserDoesNotRequirePreAuthArray = $DomainUsers | Where-Object {$_.DoesNotRequirePreAuth -eq $True} | Measure-Object
                $DomainUsersWithSIDHistoryArray = $DomainUsers | Where-Object {$_.SIDHistory -like "*"} | Measure-Object
                Write-PscriboMessage "Discovered AD Account Security Assessment information from $Domain."
                if ($DomainUsers) {
                    $OutObj = @()
                    Write-PscriboMessage "Collecting Account Security Assessment information from $($Domain)."
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
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Item)"
                    }

                    if ($HealthCheck.Domain.Security) {
                        $OutObj | Where-Object {$_.'Enabled Inactive Users' -gt 0} | Set-Style -Style Warning -Property 'Enabled Inactive Users'
                        $OutObj | Where-Object {$_.'Users With Reversible Encryption Password' -gt 0} | Set-Style -Style Warning -Property 'Users With Reversible Encryption Password'
                        $OutObj | Where-Object {$_.'User Password Not Required' -gt 0} | Set-Style -Style Warning -Property 'User Password Not Required'
                        $OutObj | Where-Object {$_.'User Password Never Expires' -gt 0} | Set-Style -Style Warning -Property 'User Password Never Expires'
                        $OutObj | Where-Object {$_.'Kerberos DES Users' -gt 0} | Set-Style -Style Warning -Property 'Kerberos DES Users'
                        $OutObj | Where-Object {$_.'User Does Not Require Pre Auth' -gt 0} | Set-Style -Style Warning -Property 'User Does Not Require Pre Auth'
                        $OutObj | Where-Object {$_.'Users With SID History' -gt 0} | Set-Style -Style Warning -Property 'Users With SID History'
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
                        $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Category';  Expression = {$_.key}},@{ Name = 'Value';  Expression = {$_.value}}
                        $exampleChart = New-Chart -Name AccountSecurityAssessment -Width 600 -Height 400

                        $addChartAreaParams = @{
                            Chart                 = $exampleChart
                            Name                  = 'Account Security Assessment'
                            AxisXTitle            = 'Categories'
                            AxisYTitle            = 'Number of Users'
                            NoAxisXMajorGridLines = $true
                            NoAxisYMajorGridLines = $true
                        }
                        $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                        $addChartSeriesParams = @{
                            Chart             = $exampleChart
                            ChartArea         = $exampleChartArea
                            Name              = 'exampleChartSeries'
                            XField            = 'Category'
                            YField            = 'Value'
                            Palette           = 'Blue'
                            ColorPerDataPoint = $true
                        }
                        $sampleData | Add-ColumnChartSeries @addChartSeriesParams

                        $addChartTitleParams = @{
                            Chart     = $exampleChart
                            ChartArea = $exampleChartArea
                            Name      = 'AccountSecurityAssessment'
                            Text      = 'Assessment'
                            Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                        }
                        Add-ChartTitle @addChartTitleParams

                        $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru

                        if ($PassThru)
                        {
                            Write-Output -InputObject $chartFileItem
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
                    }

                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading5 'Account Security Assessment' {
                            Paragraph "The following section provide a summary of the Account Security Assessment on Domain $($Domain.ToString().ToUpper())."
                            BlankLine
                            if ($chartFileItem) {
                                Image -Text 'Account Security Assessment - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            Paragraph "Corrective Actions: Ensure there aren't any account with weak security posture." -Italic -Bold
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
            }
            if ($InfoLevel.Domain -ge 2) {
                try {
                    Write-PscriboMessage "Discovered Privileged Users information from $Domain."
                    if ($PrivilegedUsers) {
                        Section -ExcludeFromTOC -Style NOTOCHeading5 'Privileged Users Assessment' {
                            Paragraph "The following section details probable AD Admin accounts (user accounts with AdminCount set to 1) on Domain $($Domain.ToString().ToUpper())"
                            BlankLine
                            $OutObj = @()
                            Write-PscriboMessage "Collecting Privileged Users Assessment information from $($Domain)."
                            foreach ($PrivilegedUser in $PrivilegedUsers) {
                                try {
                                    $inObj = [ordered] @{
                                        'Username' = $PrivilegedUser.SamAccountName
                                        'Created' = Switch ($PrivilegedUser.Created) {
                                            $Null {'--'}
                                            default {$PrivilegedUser.Created.ToShortDateString()}
                                        }
                                        'Password Last Set' = Switch ($PrivilegedUser.PasswordLastSet) {
                                            $Null {'--'}
                                            default {$PrivilegedUser.PasswordLastSet.ToShortDateString()}
                                        }
                                        'Last Logon Date' = Switch ($PrivilegedUser.LastLogonDate) {
                                            $Null {'--'}
                                            default {$PrivilegedUser.LastLogonDate.ToShortDateString()}
                                        }
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Privileged Users Assessment Item)"
                                }
                            }

                            $TableParams = @{
                                Name = "Privileged User Assessment - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 40, 20, 20, 20
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            Paragraph "Corrective Actions: Ensure there aren't any account with weak security posture." -Italic -Bold
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
                }
                try {
                    $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                    $UserSPNs = Invoke-Command -Session $TempPssSession {Get-ADUser -ResultPageSize 1000 -Server $using:Domain -filter {ServicePrincipalName -like '*'} -Properties PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation}
                    Write-PscriboMessage "Discovered Service Accounts information from $Domain."
                    if ($UserSPNs) {
                        Section -ExcludeFromTOC -Style NOTOCHeading5 'Service Accounts Assessment' {
                            Paragraph "The following section details probable AD Service Accounts (user accounts with SPNs) on Domain $($Domain.ToString().ToUpper())"
                            BlankLine
                            $OutObj = @()
                            Write-PscriboMessage "Collecting Service Accounts information from $($Domain)."
                            foreach ($UserSPN in $UserSPNs) {
                                try {
                                    $inObj = [ordered] @{
                                        'Username' = $UserSPN.SamAccountName
                                        'Enabled' = ConvertTo-TextYN $UserSPN.Enabled
                                        'Password Last Set' = Switch ($UserSPN.PasswordLastSet) {
                                            $Null {'--'}
                                            default {$UserSPN.PasswordLastSet.ToShortDateString()}
                                        }
                                        'Last Logon Date' = Switch ($UserSPN.LastLogonDate) {
                                            $Null {'--'}
                                            default {$UserSPN.LastLogonDate.ToShortDateString()}
                                        }
                                        'Service Principal Name' = $UserSPN.ServicePrincipalName
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Service Accounts Assessment Item)"
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
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            Paragraph "Corrective Actions: Service accounts are that gray area between regular user accounts and admin accounts that are often highly privileged. They are almost always over-privileged due to documented vendor requirements or because of operational challenges. Ensure there aren't any account with weak security posture." -Italic -Bold
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
                }
            }
        }
    }

    end {}

}