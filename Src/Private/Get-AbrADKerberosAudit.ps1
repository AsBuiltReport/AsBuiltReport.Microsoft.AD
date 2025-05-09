function Get-AbrADKerberosAudit {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Kerberos Audit information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
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
        Write-PScriboMessage -Message "Collecting Kerberos Audit information on $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage "AD Kerberos Audit"
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $Unconstrained = Invoke-Command -Session $TempPssSession { Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $using:ValidDCFromDomain -SearchBase $($using:Domain).distinguishedName }
                if ($Unconstrained) {
                    Section -ExcludeFromTOC -Style NOTOCHeading4 'Unconstrained Kerberos Delegation' {
                        Paragraph "The following section provide a summary of unconstrained kerberos delegation on Domain $($Domain.DNSRoot.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        foreach ($Item in $Unconstrained) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $Item.Name
                                    'Distinguished Name' = $Item.DistinguishedName
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Unconstrained Kerberos delegation Item)"
                            }
                        }

                        if ($HealthCheck.Domain.Security) {
                            $OutObj | Set-Style -Style Warning
                        }

                        $TableParams = @{
                            Name = "Unconstrained Kerberos Delegation - $($Domain.DNSRoot.ToString().ToUpper())"
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
                            Text "Ensure there are no instances of unconstrained Kerberos delegation in Active Directory, as it poses a security risk by allowing any service to impersonate users."
                        }
                    }
                } else {
                    Write-PScriboMessage -Message "No Unconstrained Kerberos Delegation information found in $($Domain.DNSRoot), Disabling this section."
                }
                try {
                    $KRBTGT = $Users | Where-Object { $_.Name -eq 'krbtgt' }
                    if ($KRBTGT) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'KRBTGT Account Audit' {
                            Paragraph "The following section provide a summary of KRBTGT account on Domain $($Domain.DNSRoot.ToString().ToUpper())."
                            BlankLine
                            $OutObj = @()
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $KRBTGT.Name
                                    'Created' = $KRBTGT.Created
                                    'Password Last Set' = $KRBTGT.PasswordLastSet
                                    'Distinguished Name' = $KRBTGT.DistinguishedName
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (KRBTGT account Item)"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property 'Password Last Set'
                            }

                            $TableParams = @{
                                Name = "KRBTGT Account Audit - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                Text "Microsoft recommends changing the krbtgt account password regularly to enhance security and protect the environment."
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No KRBTGT Account Audit information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
                }
                try {
                    $SID = Invoke-Command -Session $TempPssSession { $($using:Domain).domainsid.ToString() + "-500" }
                    $ADMIN = $Users | Where-Object { $_.SID -eq $SID }
                    if ($ADMIN) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Administrator Account Audit' {
                            Paragraph "The following section provide a summary of Administrator account on Domain $($Domain.DNSRoot.ToString().ToUpper())."
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
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (ADMIN account Item)"
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Set-Style -Style Warning -Property 'Password Last Set'
                            }

                            $TableParams = @{
                                Name = "Administrator Account Audit - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                Text "Microsoft recommends changing the Administrator account password regularly to enhance security and protect the environment."
                            }
                        }
                    } else {
                        Write-PScriboMessage -Message "No Administrator Account Audit information found in $($Domain.DNSRoot), Disabling this section."
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Kerberos Audit"
    }

}