function Get-AbrADKerberosAudit {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Kerberos Audit information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
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
        Write-PScriboMessage "Collecting Kerberos Audit information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $DC = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers | Select-Object -First 1 }
                $Unconstrained = Invoke-Command -Session $TempPssSession { Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $using:DC -SearchBase (Get-ADDomain -Identity $using:Domain).distinguishedName }
                if ($Unconstrained) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Unconstrained Kerberos Delegation' {
                        Paragraph "The following section provide a summary of unconstrained kerberos delegation on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($Item in $Unconstrained) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'Distinguished Name' = $Item.DistinguishedName
                                }
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Item)"
                            }
                        }

                        if ($HealthCheck.Domain.Security) {
                            $OutObj | Set-Style -Style Warning
                        }

                        $TableParams = @{
                            Name = "Unconstrained Kerberos Delegation - $($Domain.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 40, 60
                        }

                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Corrective Actions:" -Bold
                            Text "Ensure there aren't any unconstrained kerberos delegation in Active Directory."
                        }
                    }
                } else {
                    Write-PScriboMessage -IsWarning "No Unconstrained Kerberos Delegation information found in $Domain, disabling the section."
                }
                try {
                    $KRBTGT = $Users | Where-Object { $_.Name -eq 'krbtgt' }
                    if ($KRBTGT) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'KRBTGT Account Audit' {
                            Paragraph "The following section provide a summary of KRBTGT account on Domain $($Domain.ToString().ToUpper())."
                            BlankLine
                            $OutObj = @()
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $KRBTGT.Name
                                    'Created' = $KRBTGT.Created
                                    'Password Last Set' = $KRBTGT.PasswordLastSet
                                    'Distinguished Name' = $KRBTGT.DistinguishedName
                                }
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (KRBTGT account Item)"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property 'Password Last Set'
                            }

                            $TableParams = @{
                                Name = "KRBTGT Account Audit - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Microsoft advises changing the krbtgt account password at regular intervals to keep the environment more secure."
                            }
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "No KRBTGT Account Audit information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
                }
                try {
                    $SID = Invoke-Command -Session $TempPssSession { ((Get-ADDomain -Identity $using:Domain).domainsid).ToString() + "-500" }
                    $ADMIN = $Users | Where-Object { $_.SID -eq $SID }
                    if ($ADMIN) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Administrator Account Audit' {
                            Paragraph "The following section provide a summary of Administrator account on Domain $($Domain.ToString().ToUpper())."
                            BlankLine
                            $OutObj = @()
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $ADMIN.Name
                                    'Created' = $ADMIN.Created
                                    'Password Last Set' = $ADMIN.PasswordLastSet
                                    'Last Logon Date' = $ADMIN.LastLogonDate
                                    'Distinguished Name' = $ADMIN.DistinguishedName
                                }
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (ADMIN account Item)"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property 'Password Last Set'
                            }

                            $TableParams = @{
                                Name = "Administrator Account Audit - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "Microsoft advises changing the administrator account password at regular intervals to keep the environment more secure."
                            }
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "No Administrator Account Audit information found in $Domain, disabling the section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
            }
        }
    }

    end {}

}