function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.2
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
                Section -Style Heading4 'Domain Object Count' {
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
            Section -Style Heading4 'User Accounts in Active Directory' {
                Paragraph "The following table provide a summary of the User Accounts from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $Users = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter * -Properties *}
                if ($Users) {
                    $Categories = @('Enabled','Disabled')
                    Write-PscriboMessage "Collecting User Accounts in Active Directory."
                    foreach ($Category in $Categories) {
                        if ($Category -eq 'Enabled') {
                            $Values = $Users.Enabled -eq $True
                        }
                        else {$Values = $Users.Enabled -eq $False}
                        $inObj = [ordered] @{
                            'Status' = $Category
                            'Count' = $Values.Count
                            'Percentage' = "$([math]::Round((($Values).Count / $Users.Count * 100), 0))%"
                        }
                        $OutObj += [pscustomobject]$inobj
                    }

                    $TableParams = @{
                        Name = "User Accounts in Active Directory - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 50, 25, 25
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj |  Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Status of Users Accounts' {
                Paragraph "The following table provide a summary of the User Accounts from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $DaysInactive = 90
                $dormanttime = ((Get-Date).AddDays(-90)).Date
                $passwordtime = (Get-Date).Adddays(-42)
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $Users = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter * -Properties *}
                $CannotChangePassword = Invoke-Command -Session $TempPssSession {Get-ADUser -Filter * -Properties * | Where-Object {$_.CannotChangePassword}}
                $PasswordNextLogon = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -LDAPFilter "(pwdLastSet=0)"}
                $passwordNeverExpires = Invoke-Command -Session $TempPssSession {get-aduser -Server $using:DC -filter * -properties Name, PasswordNeverExpires | Where-Object {$_.passwordNeverExpires -eq "true" }}
                $SmartcardLogonRequired = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter * -Properties 'SmartcardLogonRequired' | Where-Object {$_.SmartcardLogonRequired -eq $True}}
                $SidHistory = $Users | Select-Object -ExpandProperty SIDHistory
                $PasswordLastSet = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter {PasswordNeverExpires -eq $false -and PasswordNotRequired -eq $false} -Properties PasswordLastSet,PasswordNeverExpires,PasswordNotRequired}
                $NeverloggedIn = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter {(lastlogontimestamp -notlike "*")}}
                $Dormant = $Users | Where-Object {($_.LastLogonDate) -lt $dormanttime}
                $PasswordNotRequired = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter {PasswordNotRequired -eq $true}}
                $AccountExpired = Invoke-Command -Session $TempPssSession {Search-ADAccount -Server $using:DC -AccountExpired}
                $AccountLockout = Invoke-Command -Session $TempPssSession {Search-ADAccount -Server $using:DC -LockedOut}
                $Categories = @('Cannot Change Password','Password Never Expires','Must Change Password at Logon','Password Age (> 42 days)','SmartcardLogonRequired','SidHistory', 'Never Logged in','Dormant (> 90 days)','Password Not Required','Account Expired','Account Lockout')
                if ($Categories) {
                    Write-PscriboMessage "Collecting User Accounts in Active Directory."
                    foreach ($Category in $Categories) {
                        try {
                            if ($Category -eq 'Cannot Change Password') {
                                $Values = $CannotChangePassword
                            }
                            elseif ($Category -eq 'Must Change Password at Logon') {
                                $Values = $PasswordNextLogon
                            }
                            elseif ($Category -eq 'Password Never Expires') {
                                $Values = $passwordNeverExpires
                            }
                            elseif ($Category -eq 'Password Age (> 42 days)') {
                                $Values = $PasswordLastSet | Where-Object {$_.PasswordLastSet -le $passwordtime}
                            }
                            elseif ($Category -eq 'SmartcardLogonRequired') {
                                $Values = $SmartcardLogonRequired
                            }
                            elseif ($Category -eq 'Never Logged in') {
                                $Values = $NeverloggedIn
                            }
                            elseif ($Category -eq 'Dormant (> 90 days)') {
                                $Values = $Dormant
                            }
                            elseif ($Category -eq 'Password Not Required') {
                                $Values = $PasswordNotRequired
                            }
                            elseif ($Category -eq 'Account Expired') {
                                $Values = $AccountExpired
                            }
                            elseif ($Category -eq 'Account Lockout') {
                                $Values = $AccountLockout
                            }
                            elseif ($Category -eq 'SidHistory') {
                                $Values = $SidHistory
                            }
                            $inObj = [ordered] @{
                                'Category' = $Category
                                'Enabled Count' = ($Values.Enabled -eq $True).Count
                                'Enabled %' = [math]::Round((($Values.Enabled -eq $True).Count / $Users.Count * 100), 0)
                                'Disabled Count' = ($Values.Enabled -eq $False).Count
                                'Disabled %' = [math]::Round((($Values.Enabled -eq $False).Count / $Users.Count * 100), 0)
                                'Total Count' = ($Values.Enabled).Count
                                'Total %' = [math]::Round((($Values.Enabled).Count / $Users.Count * 100), 0)

                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Status of User Accounts)"
                        }
                    }

                    $TableParams = @{
                        Name = "Status of User Accounts - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj |  Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Privileged Group Count' {
                Paragraph "The following table provide a summary of the Privileged Group count from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting Privileged Group in Active Directory."
                    try {
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        if ($Domain -eq (Get-ADForest).Name) {
                            $Groups = 'Domain Admins','Enterprise Admins','Administrators','Server Operators','DnsAdmins','Remote Desktop Users','Incoming Forest Trust Builders','Key Admins','Backup Operators','Cert Publishers','Print Operators','Account Operators','Schema Admins'
                        }
                        else {
                            $Groups = 'Domain Admins','Server Operators','DnsAdmins','Remote Desktop Users','Key Admins','Backup Operators','Cert Publishers','Print Operators','Account Operators'
                        }
                        if ($Groups) {
                            foreach ($Group in $Groups) {
                                $GroupObject = Invoke-Command -Session $TempPssSession {Get-ADGroupMember -Server $using:DC -Identity $using:Group -Recursive -ErrorAction SilentlyContinue}
                                $inObj = [ordered] @{
                                    'Group Name' = $Group
                                    'Count' = ($GroupObject | Measure-Object).Count
                                }
                                $OutObj += [pscustomobject]$inobj
                            }

                            $TableParams = @{
                                Name = "Privileged Group Count - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 60, 40
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Group Name' |  Table @TableParams
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Privileged Group in Active Directory)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Computer Accounts in Active Directory' {
                Paragraph "The following table provide a summary of the Computer Accounts from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $Computers = Invoke-Command -Session $TempPssSession {Get-ADComputer -Server $using:DC -Filter * -Properties *}
                if ($Computers) {
                    $Categories = @('Enabled','Disabled')
                    Write-PscriboMessage "Collecting Computer Accounts in Active Directory."
                    foreach ($Category in $Categories) {
                        if ($Category -eq 'Enabled') {
                            $Values = $Computers.Enabled -eq $True
                        }
                        else {$Values = $Computers.Enabled -eq $False}
                        $inObj = [ordered] @{
                            'Status' = $Category
                            'Count' = $Values.Count
                            'Percentage' = "$([math]::Round((($Values).Count / $Computers.Count * 100), 0))%"
                        }
                        $OutObj += [pscustomobject]$inobj
                    }

                    $TableParams = @{
                        Name = "Computer Accounts in Active Directory - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 50, 25, 25
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj |  Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Status of Computer Accounts' {
                Paragraph "The following table provide a summary of the Computer Accounts from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                $DaysInactive = 90
                $dormanttime = (Get-Date).Adddays(-90)
                $passwordtime = (Get-Date).Adddays(-30)
                $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                $Computers = Invoke-Command -Session $TempPssSession {Get-ADComputer -Server $using:DC -Filter * -Properties *}
                $Dormant = $Computers | Where-Object {[datetime]::FromFileTime($_.lastlogontimestamp) -lt $dormanttime}
                $PasswordAge = $Computers | Where-Object {$_.PasswordLastSet -le $passwordtime}
                $SidHistory = $Computers | Select-Object -ExpandProperty SIDHistory
                $Categories = @('Dormant (> 90 days)','Password Age (> 30 days)','SidHistory')
                if ($Categories) {
                    Write-PscriboMessage "Collecting Computer Accounts in Active Directory."
                    foreach ($Category in $Categories) {
                        try {
                            if ($Category -eq 'Dormant (> 90 days)') {
                                $Values = $Dormant
                            }
                            elseif ($Category -eq 'Password Age (> 30 days)') {
                                $Values = $PasswordAge
                            }
                            elseif ($Category -eq 'SidHistory') {
                                $Values = $SidHistory
                            }
                            $inObj = [ordered] @{
                                'Category' = $Category
                                'Enabled Count' = ($Values.Enabled -eq $True).Count
                                'Enabled %' = [math]::Round((($Values.Enabled -eq $True).Count / $Computers.Count * 100), 0)
                                'Disabled Count' = ($Values.Enabled -eq $False).Count
                                'Disabled %' = [math]::Round((($Values.Enabled -eq $False).Count / $Computers.Count * 100), 0)
                                'Total Count' = ($Values.Enabled).Count
                                'Total %' = [math]::Round((($Values.Enabled).Count / $Computers.Count * 100), 0)

                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Status of Computer Accounts)"
                        }
                    }

                    $TableParams = @{
                        Name = "Status of Computer Accounts - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj |  Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Operating Systems Count' {
                Paragraph "The following table provide a summary of the Operating System count from $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting Operating Systems in Active Directory."
                    try {
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        $OSObjects =  Invoke-Command -Session $TempPssSession {Get-ADComputer -Server $using:DC -Filter "name -like '*'" -Properties operatingSystem | Group-Object -Property operatingSystem | Select-Object Name,Count}
                        if ($OSObjects) {
                            foreach ($OSObject in $OSObjects) {
                                $inObj = [ordered] @{
                                    'Operating System' = Switch (($OSObject.Name).count) {
                                        0 {'Unknown'}
                                        default {$OSObject.Name}
                                    }
                                    'Count' = $OSObject.Count
                                }
                                $OutObj += [pscustomobject]$inobj
                            }

                            $TableParams = @{
                                Name = "Operating System Count - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 60, 40
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Operating System' |  Table @TableParams
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Operating Systems in Active Directory)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Default Domain Password Policy' {
                Paragraph "The following section provides a summary of the Default Domain Password Policy on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Default Domain Password Policy of domain $Item."
                    try {
                        $PasswordPolicy =  Invoke-Command -Session $TempPssSession {Get-ADDefaultDomainPasswordPolicy -Identity $using:Domain}
                        if ($PasswordPolicy) {
                            $inObj = [ordered] @{
                                'Password Must Meet Complexity Requirements' = ConvertTo-TextYN $PasswordPolicy.ComplexityEnabled
                                'Path' = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Domain $Domain
                                'Lockout Duration' = $PasswordPolicy.LockoutDuration.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Lockout Threshold' = $PasswordPolicy.LockoutThreshold
                                'Lockout Observation Window' = $PasswordPolicy.LockoutObservationWindow.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Max Password Age' = $PasswordPolicy.MaxPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Min Password Age' = $PasswordPolicy.MinPasswordAge.toString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
                                'Min Password Length' = $PasswordPolicy.MinPasswordLength
                                'Enforce Password History' = $PasswordPolicy.PasswordHistoryCount
                                'Store Password using Reversible Encryption' = ConvertTo-TextYN $PasswordPolicy.ReversibleEncryptionEnabled
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
                            Section -Style Heading4 'Fined Grained Password Policies' {
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
                            Section -Style Heading4 'Group Managed Service Accounts (GMSA)' {
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