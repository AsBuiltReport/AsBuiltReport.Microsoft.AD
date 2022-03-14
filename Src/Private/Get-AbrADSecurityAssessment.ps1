function Get-AbrADSecurityAssessment {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Account Security Assessment information.
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
        Write-PscriboMessage "Discovering Account Security Assessment information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -days 180)
                $PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -days 180)
                $ADLimitedProperties = @("Name","Enabled","SAMAccountname","DisplayName","Enabled","LastLogonDate","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","SmartcardLogonRequired","AccountExpirationDate","AdminCount","Created","Modified","LastBadPasswordAttempt","badpwdcount","mail","CanonicalName","DistinguishedName","ServicePrincipalName","SIDHistory","PrimaryGroupID","UserAccountControl")
                $DomainUsers = Invoke-Command -Session $TempPssSession {Get-ADUser -Filter * -Property $using:ADLimitedProperties -Server $using:DC -Searchbase (Get-ADDomain -Identity $using:Domain)}
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
                    Section -Style Heading4 'Health Check - Account Security Assessment' {
                        Paragraph "The following section provide a summary of the Account Security Assessment on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Collecting Account Security Assessment information from $($Domain)."
                        try {
                            $inObj = [ordered] @{
                                'Total Users' = $DomainUsers.Count
                                'Enabled Users' = $DomainEnabledUsers.Count
                                'Disabled Users' = $DomainDisabledUsers.Count
                                'Enabled Inactive Users' = $DomainEnabledInactiveUsers.Count
                                'Users With Reversible Encryption Password' = $DomainUsersWithReversibleEncryptionPasswordArray.Count
                                'User Password Not Required' = $DomainUserPasswordNotRequiredArray.Count
                                'User Password Never Expires' = $DomainUserPasswordNeverExpiresArray.Count
                                'Kerberos DES Users' = $DomainKerberosDESUsersArray.Count
                                'User Does Not Require Pre Auth' = $DomainUserDoesNotRequirePreAuthArray.Count
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
                        $OutObj | Table @TableParams
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Corrective Actions: Ensure there aren't any account with weak security posture." -Italic -Bold
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Account Security Assessment Table)"
            }
        }
    }

    end {}

}