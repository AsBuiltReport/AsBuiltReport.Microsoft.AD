function Get-AbrADDomain {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
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
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering AD Domain information on forest $Forestinfo."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            foreach ($Item in $Domain) {
                try {
                    $DomainInfo =  Invoke-Command -Session $Session {Get-ADDomain $using:Item -ErrorAction Stop}
                    Write-PscriboMessage "Discovered Active Directory Domain information of domain $Domain."
                    if ($DomainInfo) {
                        Write-PscriboMessage "Collectin Domain information of '$($DomainInfo.Name)'."
                        $inObj = [ordered] @{
                            'Domain Name' = $DomainInfo.Name
                            'NetBIOS Name' = $DomainInfo.NetBIOSName
                            'Domain SID' = $DomainInfo.DomainSID
                            'Domain Functional Level' = $DomainInfo.DomainMode
                            'Domains' = $DomainInfo.Domains
                            'Forest' = $DomainInfo.Forest
                            'Parent Domain' = $DomainInfo.ParentDomain
                            'Replica Directory Servers' = $DomainInfo.ReplicaDirectoryServers
                            'Child Domains' = $DomainInfo.ChildDomains
                            'Computers Container' = $DomainInfo.ComputersContainer
                            'Distinguished Name' = $DomainInfo.DistinguishedName
                            'Domain Controllers Container' = $DomainInfo.DomainControllersContainer
                            'Systems Container' = $DomainInfo.SystemsContainer
                            'Users Container' = $DomainInfo.UsersContainer
                            'ReadOnly Replica Directory Servers' = $DomainInfo.ReadOnlyReplicaDirectoryServers
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "WARNING: Could not connect to domain $Item"
                    Write-PscriboMessage $_.Exception.Message
                }

                $TableParams = @{
                    Name = "AD Domain Summary Information - $($Domain.ToString().ToUpper())"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                if ($OutObj) {$OutObj | Table @TableParams}
            }
        }
        Section -Style Heading5 'Domain Object Count Summary' {
            Paragraph "The following section provides a summary of the Active Directory Object Count on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Object Count of domain $Item."
                    try {
                        $GlobalCatalog =  "$(Invoke-Command -Session $Session {Get-ADDomainController -Discover -Service GlobalCatalog | Select-Object -ExpandProperty HostName}):3268"
                        $Computers =  Invoke-Command -Session $Session {(Get-ADComputer -Filter * -Server $using:GlobalCatalog -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                        #$Servers = (Get-ADComputer -LDAPFilter "(&(objectClass=Computer)(operatingSystem=*Windows server*))" -Server "$($GlobalCatalog.name):3268" -Searchbase (Get-ADDomain -Identity $Item).distinguishedName) | Measure-Object
                        $Users =  Invoke-Command -Session $Session {(Get-ADUser -filter * -Server $using:GlobalCatalog -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                        $Group =  Invoke-Command -Session $Session {(Get-ADGroup -filter * -Server $using:GlobalCatalog -Searchbase (Get-ADDomain -Identity $using:Item).distinguishedName) | Measure-Object}
                        $inObj = [ordered] @{
                            'Domain Name' = $Item
                            'Computer Count' = $Computers.Count
                            #'Servers Count' = $Servers.Count
                            'Users Count' = $Users.Count
                            'Group Count' = $Group.Count
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "WARNING: Could not connect to domain $Item"
                        Write-PscriboMessage $_.Exception.Message
                    }
                }

                $TableParams = @{
                    Name = "Active Directory Object Count Information - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 40, 20, 20, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                if ($OutObj) {$OutObj | Table @TableParams}
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
                            'Distinguished Name' = $PasswordPolicy.DistinguishedName
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
                        Write-PscriboMessage -IsWarning "WARNING: Could not connect to domain $Item"
                        Write-PscriboMessage $_.Exception.Message
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
        Section -Style Heading5 'Group Managed Service Accounts (GMSA) Summary' {
            Paragraph "The following section provides a summary of the Group Managed Service Accounts on $($Domain.ToString().ToUpper())."
            BlankLine
            $Domain = "pharmax.local"
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts for $Item."
                    try {
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts from DC $DC."
                        $GMSA = Invoke-Command -Session $TempPssSession {Get-ADServiceAccount -Filter * -Server $using:DC -Properties *}
                        foreach ($Account in $GMSA) {
                            $inObj = [ordered] @{
                                'Name' = $Account.Name
                                'SamAccountName' = $Account.SamAccountName
                                'Created' = $Account.Created
                                'Enabled' = ConvertTo-TextYN $Account.Enabled
                                'DNS Host Name' = $Account.DNSHostName
                                'Host Computers' = $Account.HostComputers
                                'Retrieve Managed Password' = $Account.PrincipalsAllowedToRetrieveManagedPassword
                                'Primary Group' = $Account.PrimaryGroup
                                'Last Logon Date' = $Account.LastLogonDate
                                'Locked Out' = ConvertTo-TextYN $Account.LockedOut
                                'Logon Count' = $Account.logonCount
                                'Password Expired' = ConvertTo-TextYN $Account.PasswordExpired
                                'Password Last Set' =  $Account.PasswordLastSet
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "WARNING: Could not connect to domain $Item"
                        Write-PscriboMessage $_.Exception.Message
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

    end {}

}