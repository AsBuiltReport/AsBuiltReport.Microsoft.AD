function Get-AbrADKerberosAudit {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Kerberos Audit information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.1
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
        Write-PscriboMessage "Discovering Kerberos Audit information on $Domain."
    }

    process {
        if ($HealthCheck.Domain.Security) {
            try {
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $Unconstrained = Invoke-Command -Session $TempPssSession {Get-ADComputer -Filter { (TrustedForDelegation -eq $True) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') } -Server $using:DC -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName}
                Write-PscriboMessage "Discovered Unconstrained Kerberos Delegation information from $Domain."
                if ($Unconstrained) {
                    Section -Style Heading4 'Health Check - Unconstrained Kerberos Delegation' {
                        Paragraph "The following section provide a summary of unconstrained kerberos delegation on Domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $OutObj = @()
                        Write-PscriboMessage "Collecting Unconstrained Kerberos delegation information from $($Domain)."
                        try {
                            $inObj = [ordered] @{
                                'Name' = $Unconstrained.Name
                                'Distinguished Name' = $Unconstrained.DistinguishedName
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Item)"
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
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        Paragraph "Corrective Actions: Ensure there aren't any unconstrained kerberos delegation in Active Directory." -Italic -Bold
                        try {
                            $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            $KRBTGT = Invoke-Command -Session $TempPssSession { Get-ADUser -Properties 'msds-keyversionnumber',Created,PasswordLastSet -Server $using:DC -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName -Filter * | Where-Object {$_.Name  -eq 'krbtgt'}}
                            Write-PscriboMessage "Discovered Unconstrained Kerberos Delegation information from $Domain."
                            if ($KRBTGT) {
                                Section -Style Heading4 'Health Check - KRBTGT Account Audit' {
                                    Paragraph "The following section provide a summary of KRBTGT account on Domain $($Domain.ToString().ToUpper())."
                                    BlankLine
                                    $OutObj = @()
                                    Write-PscriboMessage "Collecting KRBTGT account information from $($Domain)."
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $KRBTGT.Name
                                            'Created' = $KRBTGT.Created
                                            'Password Last Set' = $KRBTGT.PasswordLastSet
                                            'Distinguished Name' = $KRBTGT.DistinguishedName
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (KRBTGT account Item)"
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
                                    Paragraph "Health Check:" -Italic -Bold -Underline
                                    Paragraph "Best Practice: Microsoft advises changing the krbtgt account password at regular intervals to keep the environment more secure." -Italic -Bold
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Unconstrained Kerberos delegation Table)"
            }
        }
    }

    end {}

}