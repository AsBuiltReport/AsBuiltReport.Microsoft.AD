function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.6.3
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
        Write-PscriboMessage "Discovering AD Domain Objects information on forest $Forestinfo."
    }

    process {
        if ($InfoLevel.Domain -ge 2) {
            try {
                Section -Style Heading5 'Domain Object Count' {
                    Paragraph "The following section provides a summary of the Active Directory Object Count on $($Domain.ToString().ToUpper())."
                    BlankLine
                    $OutObj = @()
                    if ($Domain) {
                        Write-PscriboMessage "Collecting the Active Directory Object Count of domain $Domain."
                        try {
                            $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            $Computers =  Invoke-Command -Session $TempPssSession {(Get-ADComputer -Server $using:DC -Filter * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                            $Servers = Invoke-Command -Session $TempPssSession {(Get-ADComputer -Server $using:DC -Filter { OperatingSystem -like "Windows Ser*"} -Property OperatingSystem -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                            $Users =  Invoke-Command -Session $TempPssSession {(Get-ADUser -Server $using:DC -filter * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                            $PrivilegedUsers =  Invoke-Command -Session $TempPssSession {(Get-ADUser -Server $using:DC -filter {AdminCount -eq "1"} -Properties AdminCount -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                            $Group =  Invoke-Command -Session $TempPssSession {(Get-ADGroup -Server $using:DC -filter * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                            $DomainController = Invoke-Command -Session $TempPssSession {(Get-ADDomainController -Server $using:DC -filter *) | Select-Object name | Measure-Object}
                            $GC = Invoke-Command -Session $TempPssSession {(Get-ADDomainController -Server $using:DC -filter {IsGlobalCatalog -eq "True"}) | Select-Object name | Measure-Object}
                            $inObj = [ordered] @{
                                'Computers' = $Computers.Count
                                'Servers' = $Servers.Count
                                'Domain Controller' = $DomainController.Count
                                'Global Catalog' = $GC.Count
                                'Users' = $Users.Count
                                'Privileged Users' = $PrivilegedUsers.Count
                                'Groups' = $Group.Count
                            }
                            $OutObj += [pscustomobject]$inobj

                            $TableParams = @{
                                Name = "Object Count - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Object Count)"
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Object Count)"
            }
        }
        try {
            Section -Style Heading5 'Default Domain Password Policy' {
                Paragraph "The following section provides a summary of the Default Domain Password Policy on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Default Domain Password Policy of domain $Item."
                    try {
                        $PasswordPolicy =  Invoke-Command -Session $TempPssSession {Get-ADDefaultDomainPasswordPolicy -Identity $using:Domain}
                        if ($PasswordPolicy) {
                            $inObj = [ordered] @{
                                'Domain Name' = $Item
                                'Complexity Enabled' = ConvertTo-TextYN $PasswordPolicy.ComplexityEnabled
                                'Path' = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Domain $Domain
                                'Lockout Duration' = $PasswordPolicy.LockoutDuration.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Lockout Threshold' = $PasswordPolicy.LockoutThreshold
                                'Lockout Observation Window' = $PasswordPolicy.LockoutObservationWindow.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Max Password Age' = $PasswordPolicy.MaxPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Min Password Age' = $PasswordPolicy.MinPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Min Password Length' = $PasswordPolicy.MinPasswordLength
                                'Password History Count' = $PasswordPolicy.PasswordHistoryCount
                                'Reversible Encryption Enabled' = ConvertTo-TextYN $PasswordPolicy.ReversibleEncryptionEnabled
                            }
                            $OutObj += [pscustomobject]$inobj

                            $TableParams = @{
                                Name = "Default Domain Password Policy - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Default Domain Password Policy)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        if ($InfoLevel.Domain -ge 2) {
            try {
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        Write-PscriboMessage "Collecting the Active Directory Fined Grained Password Policies of domain $Item."
                        $DC =  Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty PDCEmulator}
                        $PasswordPolicy =  Invoke-Command -Session $TempPssSession {Get-ADFineGrainedPasswordPolicy -Server $using:DC -Filter {Name -like "*"} -Properties * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName}
                        if ($PasswordPolicy) {
                            Section -Style Heading5 'Fined Grained Password Policies' {
                                Paragraph "The following section provides a summary of the Fined Grained Password Policies on $($Domain.ToString().ToUpper())."
                                BlankLine
                                $OutObj = @()
                                foreach ($FGPP in $PasswordPolicy) {
                                    try {
                                        $Accounts = @()
                                        foreach ($ADObject in $FGPP.AppliesTo) {
                                            $Accounts += Invoke-Command -Session $TempPssSession {Get-ADObject $using:ADObject -Server $using:DC -Properties * | Select-Object -ExpandProperty sAMAccountName }
                                        }
                                        $inObj = [ordered] @{
                                            'Password Setting Name' = $FGPP.Name
                                            'Domain Name' = $Item
                                            'Complexity Enabled' = ConvertTo-TextYN $FGPP.ComplexityEnabled
                                            'Path' = ConvertTo-ADCanonicalName -DN $FGPP.DistinguishedName -Domain $Domain
                                            'Lockout Duration' = $FGPP.LockoutDuration.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                            'Lockout Threshold' = $FGPP.LockoutThreshold
                                            'Lockout Observation Window' = $FGPP.LockoutObservationWindow.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                            'Max Password Age' = $FGPP.MaxPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                            'Min Password Age' = $FGPP.MinPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                            'Min Password Length' = $FGPP.MinPasswordLength
                                            'Password History Count' = $FGPP.PasswordHistoryCount
                                            'Reversible Encryption Enabled' = ConvertTo-TextYN $FGPP.ReversibleEncryptionEnabled
                                            'Precedence' = $FGPP.Precedence
                                            'Applies To' = $Accounts -join ", "
                                        }
                                        $OutObj = [pscustomobject]$inobj

                                        $TableParams = @{
                                            Name = "Fined Grained Password Policies - $($FGPP.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Fined Grained Password Policies)"
            }
        }
        if ($InfoLevel.Domain -ge 2) {
            try {
                if ($Domain) {
                    Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts for $Item."
                    try {
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts from DC $DC."
                        $GMSA = Invoke-Command -Session $TempPssSession {Get-ADServiceAccount -Server $using:DC -Filter * -Properties *}
                        if ($GMSA) {
                            Section -Style Heading5 'Group Managed Service Accounts (GMSA)' {
                                Paragraph "The following section provides a summary of the Group Managed Service Accounts on $($Domain.ToString().ToUpper())."
                                BlankLine
                                $OutObj = @()
                                foreach ($Account in $GMSA) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $Account.Name
                                            'SamAccountName' = $Account.SamAccountName
                                            'Created' = $Account.Created
                                            'Enabled' = ConvertTo-TextYN $Account.Enabled
                                            'DNS Host Name' = $Account.DNSHostName
                                            'Host Computers' = (ConvertTo-ADObjectName -DN $Account.HostComputers -Session $TempPssSession -DC $DC) -join ", "
                                            'Retrieve Managed Password' = (ConvertTo-ADObjectName $Account.PrincipalsAllowedToRetrieveManagedPassword -Session $TempPssSession -DC $DC) -join ", "
                                            'Primary Group' = (ConvertTo-ADObjectName $Account.PrimaryGroup -Session $TempPssSession -DC $DC) -join ", "
                                            'Last Logon Date' = $Account.LastLogonDate
                                            'Locked Out' = ConvertTo-TextYN $Account.LockedOut
                                            'Logon Count' = $Account.logonCount
                                            'Password Expired' = ConvertTo-TextYN $Account.PasswordExpired
                                            'Password Last Set' =  $Account.PasswordLastSet
                                        }
                                        $OutObj = [pscustomobject]$inobj

                                        if ($HealthCheck.Domain.GMSA) {
                                            $OutObj | Where-Object { $_.'Enabled' -notlike 'Yes'} | Set-Style -Style Warning -Property 'Enabled'
                                        }

                                        $TableParams = @{
                                            Name = "Group Managed Service Accounts - $($Account.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Managed Service Accounts)"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Managed Service Accounts)"
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning $($_.Exception.Message)
            }
        }#>
    }

    end {}

}