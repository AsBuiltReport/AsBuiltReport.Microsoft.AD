function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
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
            $Domain,
            $Session,
            [pscredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering AD Domain Objects information on forest $Forestinfo."
    }

    process {
        if ($InfoLevel.Domain -ge 2) {
            Section -Style Heading5 'Domain Object Count Summary' {
                Paragraph "The following section provides a summary of the Active Directory Object Count on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        Write-PscriboMessage "Collecting the Active Directory Object Count of domain $Item."
                        try {
                            $DC = Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            $Computers =  Invoke-Command -Session $DCPssSession {(Get-ADComputer -Filter * -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                            $Servers = Invoke-Command -Session $DCPssSession {(Get-ADComputer -Filter { OperatingSystem -like "Windows Ser*"} -Property OperatingSystem -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                            $Users =  Invoke-Command -Session $DCPssSession {(Get-ADUser -filter * -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                            $PrivilegedUsers =  Invoke-Command -Session $DCPssSession {(Get-ADUser -filter {AdminCount -eq "1"} -Properties AdminCount -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                            $Group =  Invoke-Command -Session $DCPssSession {(Get-ADGroup -filter * -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                            $DomainController = Invoke-Command -Session $DCPssSession {(Get-ADDomainController -filter *) | Select-Object name | Measure-Object}
                            $GC = Invoke-Command -Session $DCPssSession {(Get-ADDomainController -filter {IsGlobalCatalog -eq "True"}) | Select-Object name | Measure-Object}
                            Remove-PSSession -Session $DCPssSession
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
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "WARNING: Could not retrieve Object Count from domain $Item"
                            Write-PscriboMessage -IsDebug $_.Exception.Message
                        }
                    }

                    $TableParams = @{
                        Name = "Active Directory Object Count Information - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    if ($OutObj) {$OutObj | Table @TableParams}
                }
            }
        }
        Section -Style Heading5 'Default Domain Password Policy Summary' {
            Paragraph "The following section provides a summary of the Default Domain Password Policy on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Default Domain Password Policy of domain $Item."
                    try {
                        $PasswordPolicy =  Invoke-Command -Session $Session {Get-ADDefaultDomainPasswordPolicy -Identity $using:Item}
                        $inObj = [ordered] @{
                            'Domain Name' = $Item
                            'Complexity Enabled' = ConvertTo-TextYN $PasswordPolicy.ComplexityEnabled
                            'Path' = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Credential $Cred -Domain $Domain
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
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "WARNING: Could not retrieve Default Domain Password Policy from domain $Item"
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }
                }

                $TableParams = @{
                    Name = "Default Domain Password Policy Information - $($Domain.ToString().ToUpper())"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                if ($OutObj) {$OutObj | Table @TableParams}
            }
        }
        if ($InfoLevel.Domain -ge 2) {
            try {
                Section -Style Heading5 'Fined Grained Password Policies Summary' {
                    Paragraph "The following section provides a summary of the Fined Grained Password Policies on $($Domain.ToString().ToUpper())."
                    BlankLine
                    $OutObj = @()
                    if ($Domain) {
                        foreach ($Item in $Domain) {
                            Write-PscriboMessage "Collecting the Active Directory Fined Grained Password Policies of domain $Item."
                            $DC =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty PDCEmulator}
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            $PasswordPolicy =  Invoke-Command -Session $DCPssSession {Get-ADFineGrainedPasswordPolicy -Filter {Name -like "*"} -Properties * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName}
                            foreach ($FGPP in $PasswordPolicy) {
                                $Accounts = @()
                                foreach ($ADObject in $FGPP.AppliesTo) {
                                    $Accounts += Invoke-Command -Session $DCPssSession {Get-ADObject $using:ADObject -Properties * | Select-Object -ExpandProperty sAMAccountName }
                                }
                                $inObj = [ordered] @{
                                    'Password Setting Name' = $FGPP.Name
                                    'Domain Name' = $Item
                                    'Complexity Enabled' = ConvertTo-TextYN $FGPP.ComplexityEnabled
                                    'Path' = ConvertTo-ADCanonicalName -DN $FGPP.DistinguishedName -Credential $Cred -Domain $Domain
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
                                $OutObj += [pscustomobject]$inobj
                            }
                            Remove-PSSession -Session $DCPssSession
                        }

                        $TableParams = @{
                            Name = "Fined Grained Password Policies Information - $($Domain.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        if ($OutObj) {$OutObj | Table @TableParams}
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "WARNING: Could not retrieve fined grained password policies from domain $Item"
                Write-PscriboMessage -IsDebug $_.Exception.Message
            }
        }
        if ($InfoLevel.Domain -ge 2) {
            Section -Style Heading5 'Group Managed Service Accounts (GMSA) Summary' {
                Paragraph "The following section provides a summary of the Group Managed Service Accounts on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts for $Item."
                        try {
                            $DC = Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts from DC $DC."
                            $GMSA = Invoke-Command -Session $DCPssSession {Get-ADServiceAccount -Filter * -Properties *}
                            foreach ($Account in $GMSA) {
                                $inObj = [ordered] @{
                                    'Name' = $Account.Name
                                    'SamAccountName' = $Account.SamAccountName
                                    'Created' = $Account.Created
                                    'Enabled' = ConvertTo-TextYN $Account.Enabled
                                    'DNS Host Name' = $Account.DNSHostName
                                    'Host Computers' = (ConvertTo-ADObjectName -DN $Account.HostComputers -Session $DCPssSession) -join ", "
                                    'Retrieve Managed Password' = (ConvertTo-ADObjectName $Account.PrincipalsAllowedToRetrieveManagedPassword -Session $DCPssSession) -join ", "
                                    'Primary Group' = (ConvertTo-ADObjectName $Account.PrimaryGroup -Session $DCPssSession) -join ", "
                                    'Last Logon Date' = $Account.LastLogonDate
                                    'Locked Out' = ConvertTo-TextYN $Account.LockedOut
                                    'Logon Count' = $Account.logonCount
                                    'Password Expired' = ConvertTo-TextYN $Account.PasswordExpired
                                    'Password Last Set' =  $Account.PasswordLastSet
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            Remove-PSSession -Session $DCPssSession
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "WARNING: Could not retrieve Group Managed Service Accounts from domain $Item"
                            Write-PscriboMessage -IsDebug $_.Exception.Message
                        }
                    }

                    if ($HealthCheck.Domain.GMSA) {
                        $OutObj | Where-Object { $_.'Enabled' -notlike 'Yes'} | Set-Style -Style Warning -Property 'Enabled'
                    }

                    $TableParams = @{
                        Name = "Group Managed Service Accounts Information - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    if ($OutObj) {$OutObj | Table @TableParams}
                }
            }
        }
    }

    end {}

}