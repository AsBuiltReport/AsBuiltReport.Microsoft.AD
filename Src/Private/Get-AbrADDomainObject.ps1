function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.5
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK
    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDcFromDomain
    )

    begin {
        Write-PScriboMessage -Message "Collecting AD Domain Objects information on forest $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Objects'
    }

    process {
        Section -Style Heading3 'Domain Objects' {
            Paragraph "The following section details information about computers, groups and users objects found in $($Domain.DNSRoot) "
            try {
                try {
                    $script:DomainSID = $Domain.domainsid

                    $ADUsersLimitedProperties = @('Name', 'Enabled', 'SAMAccountname', 'DisplayName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired', 'PasswordExpired', 'SmartcardLogonRequired', 'AccountExpirationDate', 'AdminCount', 'Created', 'Modified', 'LastBadPasswordAttempt', 'badpwdcount', 'mail', 'CanonicalName', 'DistinguishedName', 'ServicePrincipalName', 'SIDHistory', 'PrimaryGroupID', 'UserAccountControl', 'CannotChangePassword', 'PwdLastSet', 'LockedOut', 'TrustedForDelegation', 'TrustedtoAuthForDelegation', 'msds-keyversionnumber', 'SID', 'AccountNotDelegated', 'EmailAddress', 'ObjectClass')

                    $ADGroupsLimitedProperties = @('Sid', 'Members', 'GroupCategory', 'GroupScope', 'Name', 'SamAccountName', 'DistinguishedName', 'admincount', 'ObjectClass')

                    $ADComputerLimitedProperties = @('Enabled', 'OperatingSystem', 'lastlogontimestamp', 'PasswordLastSet', 'SIDHistory', 'PasswordNotRequired', 'Name', 'DistinguishedName')

                    $script:Computers = Invoke-Command -Session $TempPssSession { (Get-ADComputer -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Properties $using:ADComputerLimitedProperties -SearchBase ($using:Domain).distinguishedName) }

                    $Servers = $Computers | Where-Object { $_.OperatingSystem -like "*Serv*" } | Measure-Object

                    $script:Users = Invoke-Command -Session $TempPssSession { Get-ADUser -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Property $using:ADUsersLimitedProperties -SearchBase ($using:Domain).distinguishedName }

                    $script:FSP = Invoke-Command -Session $TempPssSession { Get-ADObject -Server $using:ValidDcFromDomain -Filter { ObjectClass -eq "foreignSecurityPrincipal" } -Properties msds-principalname, memberof }

                    $script:PrivilegedUsers = $Users | Where-Object { $_.AdminCount -eq 1 }

                    $script:GroupOBj = Invoke-Command -Session $TempPssSession { (Get-ADGroup -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Properties $using:ADGroupsLimitedProperties -SearchBase ($using:Domain).distinguishedName) }

                    $script:EmptyGroupOBj = $GroupOBj | Where-Object { (-Not $_.Members ) }

                    $excludedDomainGroupsBySID = @("$DomainSID-571", "$DomainSID-572", "$DomainSID-553", "$DomainSID-525", "$DomainSID-522", "$DomainSID-572", "$DomainSID-571", "$DomainSID-514", "$DomainSID-553", "$DomainSID-513", "$DomainSID-515", "$DomainSID-512", "$DomainSID-498", "$DomainSID-527", "$DomainSID-520", "$DomainSID-521", "$DomainSID-519", "$DomainSID-526", "$DomainSID-516", "$DomainSID-517", "$DomainSID-518")

                    $excludedDomainGroupsByName = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'Help Desk Operators', 'Domain Controllers', 'DNS Admins', 'Cert Publishers', 'Enterprise Read-Only Domain Controllers', 'Read-Only Domain Controllers', 'Group Policy Creator Owners', 'Key Admins', 'DHCP Administrators', 'DHCP Users', 'DnsAdmins', 'DnsUpdateProxy')

                    $excludedForestGroupsBySID = ($GroupOBj | Where-Object { $_.SID -like 'S-1-5-32-*' }).SID

                    $AdminGroupsBySID = "S-1-5-32-552", "$DomainSID-527", "$DomainSID-521", "$DomainSID-516", "$DomainSID-1107", "$DomainSID-512", "$DomainSID-519", 'S-1-5-32-544', 'S-1-5-32-549', "$DomainSID-1101", 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', "$DomainSID-518", 'S-1-5-32-578'

                    $script:DomainController = Invoke-Command -Session $TempPssSession { (Get-ADDomainController -Server $using:ValidDcFromDomain -Filter *) | Select-Object name, OperatingSystem }

                    $script:GC = Invoke-Command -Session $TempPssSession { (Get-ADDomainController -Server $using:ValidDcFromDomain -Filter { IsGlobalCatalog -eq "True" }) | Select-Object name }

                    $ADObjects = $Users + $GroupObj

                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Object Stats)"
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Object Stats)"
            }
            try {
                Section -Style Heading4 'User Objects' {
                    try {
                        $OutObj = @()
                        $inObj = [ordered] @{
                            'Users' = ($Users | Measure-Object).Count
                            'Privileged Users' = ($PrivilegedUsers | Measure-Object).Count
                            'Foreign Security Principals' = ($FSP | Measure-Object).Count
                        }
                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                        $TableParams = @{
                            Name = "User - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            # Chart Section
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Category'

                            $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'UsersObject' -XField 'Name' -YField 'Value' -ChartLegendName 'Category' -ChartTitleName 'UsersObject' -ChartTitleText 'User Objects' -ReversePalette $True

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (User Object Count Chart)"
                        }

                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Users' {
                                if ($chartFileItem) {
                                    Image -Text 'Users Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }

                    $OutObj = @()
                    $dormanttime = ((Get-Date).AddDays(-90)).Date
                    $passwordtime = (Get-Date).Adddays(-180)
                    $CannotChangePassword = $Users | Where-Object { $_.CannotChangePassword }
                    $PasswordNextLogon = $Users | Where-Object { $_.PasswordLastSet -eq 0 -or $_.PwdLastSet -eq 0 }
                    $passwordNeverExpires = $Users | Where-Object { $_.passwordNeverExpires -eq "true" }
                    $SmartcardLogonRequired = $Users | Where-Object { $_.SmartcardLogonRequired -eq $True }
                    $SidHistory = $Users  | Where-Object { $_.SIDHistory }
                    $PasswordLastSet = $Users | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.PasswordNotRequired -eq $false }
                    $NeverloggedIn = $Users | Where-Object { -not $_.LastLogonDate }
                    $Dormant = $Users | Where-Object { ($_.LastLogonDate) -lt $dormanttime }
                    $PasswordNotRequired = $Users | Where-Object { $_.PasswordNotRequired -eq $true }
                    $AccountExpired = Invoke-Command -Session $TempPssSession { Search-ADAccount -Server $using:ValidDcFromDomain -AccountExpired }
                    $AccountLockout = Invoke-Command -Session $TempPssSession { Search-ADAccount -Server $using:ValidDcFromDomain -LockedOut }
                    $Categories = @('Total Users', 'Cannot Change Password', 'Password Never Expires', 'Must Change Password at Logon', 'Password Age (> 180 days)', 'SmartcardLogonRequired', 'SidHistory', 'Never Logged in', 'Dormant (> 90 days)', 'Password Not Required', 'Account Expired', 'Account Lockout')
                    if ($Categories) {
                        foreach ($Category in $Categories) {
                            try {
                                if ($Category -eq 'Total Users') {
                                    $Values = $Users
                                } elseif ($Category -eq 'Cannot Change Password') {
                                    $Values = $CannotChangePassword
                                } elseif ($Category -eq 'Must Change Password at Logon') {
                                    $Values = $PasswordNextLogon
                                } elseif ($Category -eq 'Password Never Expires') {
                                    $Values = $passwordNeverExpires
                                } elseif ($Category -eq 'Password Age (> 42 days)') {
                                    $Values = $PasswordLastSet | Where-Object { $_.PasswordLastSet -le $passwordtime }
                                } elseif ($Category -eq 'SmartcardLogonRequired') {
                                    $Values = $SmartcardLogonRequired
                                } elseif ($Category -eq 'Never Logged in') {
                                    $Values = $NeverloggedIn
                                } elseif ($Category -eq 'Dormant (> 90 days)') {
                                    $Values = $Dormant
                                } elseif ($Category -eq 'Password Not Required') {
                                    $Values = $PasswordNotRequired
                                } elseif ($Category -eq 'Account Expired') {
                                    $Values = $AccountExpired
                                } elseif ($Category -eq 'Account Lockout') {
                                    $Values = $AccountLockout
                                } elseif ($Category -eq 'SidHistory') {
                                    $Values = $SidHistory
                                }
                                $inObj = [ordered] @{
                                    'Category' = $Category
                                    'Enabled' = ($Values.Enabled -eq $True | Measure-Object).Count
                                    'Enabled %' = Switch ($Users.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }
                                    'Disabled' = ($Values.Enabled -eq $False | Measure-Object).Count
                                    'Disabled %' = Switch ($Users.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }
                                    'Total' = ($Values | Measure-Object).Count
                                    'Total %' = Switch ($Users.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }

                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of User Accounts)"
                            }
                        }

                        $TableParams = @{
                            Name = "Status of User Accounts - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            # Chart Section
                            $sampleData = $OutObj

                            $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'StatusofUsersAccounts' -XField 'Category' -YField 'Total' -ChartLegendName 'Category' -ChartTitleName 'StatusofUsersAccounts' -ChartTitleText 'Status of Users Accounts' -ReversePalette $True

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Users Accounts Chart)"
                        }
                    }
                    if ($OutObj) {
                        Section -Style Heading5 'Status of Users Accounts' {
                            if ($chartFileItem) {
                                Image -Text 'Status of Users Accounts - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                            }
                            $OutObj | Table @TableParams
                        }
                    }

                    if ($InfoLevel.Domain -ge 4) {
                        try {
                            Section -Style Heading4 'Users Inventory' {
                                $OutObj = @()
                                foreach ($User in $Users) {
                                    try {
                                        $Groups = ($GroupOBj | Where-Object { $_.members -eq $User.DistinguishedName }).Name
                                        $inObj = [ordered] @{
                                            'Name' = $User.DisplayName
                                            'Logon Name' = $User.SamAccountName
                                            'Member Of Groups' = Switch ([string]::IsNullOrEmpty($Groups)) {
                                                $true { '--' }
                                                $false { $Groups }
                                                default { 'Unknown' }
                                            }
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Users Objects Table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Users - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 33, 33, 34
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Users Objects Section)"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            try {
                Section -Style Heading4 'Group Objects' {
                    try {
                        $OutObj = @()
                        $inObj = [ordered] @{
                            'Security Groups' = ($GroupOBj | Where-Object { $_.GroupCategory -eq "Security" } | Measure-Object).Count
                            'Distribution Groups' = ($GroupOBj | Where-Object { $_.GroupCategory -eq "Distribution" } | Measure-Object).Count
                        }
                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                        $TableParams = @{
                            Name = "Group Categories - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            # Chart Section
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Name'

                            $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'GroupCategoryObject' -XField 'Name' -YField 'Value' -ChartLegendName 'Category' -ChartTitleName 'GroupCategoryObject' -ChartTitleText 'Group Categories' -ReversePalette $True

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Category Object Chart)"
                        }
                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Groups Categories' {
                                if ($chartFileItem) {
                                    Image -Text 'Groups Categories Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }
                    try {
                        $OutObj = @()
                        $inObj = [ordered] @{
                            'Domain Locals' = ($GroupOBj | Where-Object { $_.GroupScope -eq "DomainLocal" } | Measure-Object).Count
                            'Globals' = ($GroupOBj | Where-Object { $_.GroupScope -eq "Global" } | Measure-Object).Count
                            'Universal' = ($GroupOBj | Where-Object { $_.GroupScope -eq "Universal" } | Measure-Object).Count
                        }
                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                        $TableParams = @{
                            Name = "Group Scopes - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            # Chart Section
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Name'

                            $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'GroupCategoryObject' -XField 'Name' -YField 'Value' -ChartLegendName 'Category' -ChartTitleName 'GroupScopesObject' -ChartTitleText 'Group Scopes' -ReversePalette $True

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Scopes Object Chart)"
                        }
                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Groups Scopes' {
                                if ($chartFileItem) {
                                    Image -Text 'Groups Scopes Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }
                    if ($InfoLevel.Domain -ge 4) {
                        try {
                            Section -Style Heading4 'Groups Inventory' {
                                $OutObj = @()
                                foreach ($Group in $GroupOBj) {
                                    try {
                                        $UserCount = ($Group.Members | Measure-Object).Count
                                        $inObj = [ordered] @{
                                            'Name' = $Group.Name
                                            'Category' = $Group.GroupCategory
                                            'Scope' = $Group.GroupScope
                                            'User Count' = $UserCount
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Groups Objects Table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Groups - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 25, 25, 15
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Groups Objects Section)"
                        }
                    }
                    Section -Style Heading5 'Privileged Groups (Built-in)' {
                        $OutObj = @()
                        try {
                            if ($Domain.DNSRoot -eq $ADSystem.Name) {
                                $GroupsSID = "$DomainSID-512", "$DomainSID-519", 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', "$DomainSID-518", 'S-1-5-32-578'
                            } else {
                                $GroupsSID = "$DomainSID-512", 'S-1-5-32-549', 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', 'S-1-5-32-578'
                            }
                            if ($GroupsSID) {
                                if ($InfoLevel.Domain -eq 1) {
                                    Paragraph "The following section summarizes the counts of users within the privileged groups."
                                    BlankLine
                                    foreach ($GroupSID in $GroupsSID) {
                                        try {
                                            if ($Group = $GroupOBj | Where-Object { $_.SID -like $GroupSID }) {
                                                $inObj = [ordered] @{
                                                    'Group Name' = $Group.Name
                                                    'Count' = ($Group.Members | Measure-Object).Count
                                                }
                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory item)"
                                        }
                                    }

                                    if ($HealthCheck.Domain.Security) {
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Group Name' -eq 'Schema Admins' -and $_.Count -gt 1 })) {
                                            $OBJ.'Group Name' = "*" + $OBJ.'Group Name'
                                        }
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Group Name' -eq 'Enterprise Admins' -and $_.Count -gt 1 })) {
                                            $OBJ.'Group Name' = "**" + $OBJ.'Group Name'
                                        }
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Group Name' -eq 'Domain Admins' -and $_.Count -gt 5 })) {
                                            $OBJ.'Group Name' = "***" + $OBJ.'Group Name'
                                        }
                                        $OutObj | Where-Object { $_.'Group Name' -eq '*Schema Admins' -and $_.Count -gt 1 } | Set-Style -Style Warning
                                        $OutObj | Where-Object { $_.'Group Name' -eq '**Enterprise Admins' -and $_.Count -gt 1 } | Set-Style -Style Warning
                                        $OutObj | Where-Object { $_.'Group Name' -eq '***Domain Admins' -and $_.Count -gt 5 } | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "Privileged Groups - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 60, 40
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Group Name' | Table @TableParams
                                    if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Group Name' -eq '*Schema Admins' -and $_.Count -gt 1 }) -or ($OutObj | Where-Object { $_.'Group Name' -eq '**Enterprise Admins' -and $_.Count -gt 1 }) -or ($OutObj | Where-Object { $_.'Group Name' -eq '***Domain Admins' -and $_.Count -gt 5 })) {
                                        Paragraph "Health Check:" -Bold -Underline
                                        BlankLine
                                        Paragraph "Security Best Practice:" -Bold
                                        if ($OutObj | Where-Object { $_.'Group Name' -eq '*Schema Admins' -and $_.Count -gt 1 }) {
                                            BlankLine
                                            Paragraph {
                                                Text "*The Schema Admins group is a privileged group in a forest root domain. Members of the Schema Admins group can make changes to the schema, which is the framework for the Active Directory forest. Changes to the schema are not frequently required. This group only contains the Built-in Administrator account by default. Additional accounts must only be added when changes to the schema are necessary and then must be removed."
                                            }
                                        }
                                        if ($OutObj | Where-Object { $_.'Group Name' -eq '**Enterprise Admins' -and $_.Count -gt 1 }) {
                                            BlankLine
                                            Paragraph {
                                                Text "**Unless an account is doing specific tasks needing those highly elevated permissions, every account should be removed from Enterprise Admins (EA) group. A side benefit of having an empty Enterprise Admins group is that it adds just enough friction to ensure that enterprise-wide changes requiring Enterprise Admin rights are done purposefully and methodically."
                                            }
                                        }
                                        if ($OutObj | Where-Object { $_.'Group Name' -eq '***Domain Admins' -and $_.Count -gt 5 }) {
                                            BlankLine
                                            Paragraph {
                                                Text "***Microsoft recommends that Domain Admins contain no more than five members to minimize the risk of privilege escalation and to ensure better control over administrative access."
                                            }
                                        }
                                    }
                                } else {
                                    Paragraph "The following section details the members users within the privilege groups. (Empty group are excluded)"
                                    BlankLine
                                    foreach ($GroupSID in $GroupsSID) {
                                        try {
                                            if ($Group = ($GroupOBj | Where-Object { $_.SID -like $GroupSID })) {
                                                $GroupObjects = $Group.Members
                                                if ($GroupObjFilter = $ADObjects | Where-Object { $_.distinguishedName -in $GroupObjects }) {
                                                    Section -ExcludeFromTOC -Style NOTOCHeading4 "$($Group.Name) ($(($GroupObjects | Measure-Object).count) Members)" {
                                                        $OutObj = @()
                                                        foreach ($GroupObject in $GroupObjFilter) {
                                                            try {
                                                                $inObj = [ordered] @{
                                                                    'Name' = "$($GroupObject.SamAccountName) ($($GroupObject.ObjectClass.toUpper()))"
                                                                    'Last Logon Date' = Switch ([string]::IsNullOrEmpty($GroupObject.LastLogonDate)) {
                                                                        $true { "--" }
                                                                        $false { $GroupObject.LastLogonDate.ToShortDateString() }
                                                                        default { "Unknown" }
                                                                    }
                                                                    'Password Never Expires' = $GroupObject.passwordNeverExpires
                                                                    'Account Enabled' = $GroupObject.Enabled
                                                                }
                                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                                            } catch {
                                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory item)"

                                                            }
                                                        }

                                                        if ($HealthCheck.Domain.Security) {
                                                            $OutObj | Where-Object { $_.'Password Never Expires' -eq 'Yes' } | Set-Style -Style Warning -Property 'Password Never Expires'
                                                            foreach ( $OBJ in ($OutObj | Where-Object { $_.'Password Never Expires' -eq 'Yes' })) {
                                                                $OBJ.'Password Never Expires' = "**Yes"
                                                            }
                                                            $OutObj | Where-Object { $_.'Account Enabled' -eq 'No' } | Set-Style -Style Warning -Property 'Account Enabled'
                                                            $OutObj | Where-Object { $_.'Last Logon Date' -ne "--" -and [DateTime]$_.'Last Logon Date' -le (Get-Date).AddDays(-90) } | Set-Style -Style Warning -Property 'Last Logon Date'
                                                            foreach ( $OBJ in ($OutObj | Where-Object { $_.'Last Logon Date' -ne "--" -and [DateTime]$_.'Last Logon Date' -le (Get-Date).AddDays(-90) })) {
                                                                $OBJ.'Last Logon Date' = "*" + $OBJ.'Last Logon Date'
                                                            }
                                                        }

                                                        $TableParams = @{
                                                            Name = "$($Group.Name) - $($Domain.DNSRoot.ToString().ToUpper())"
                                                            List = $false
                                                            ColumnWidths = 50, 20, 15, 15
                                                        }
                                                        if ($Report.ShowTableCaptions) {
                                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                                        }
                                                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                                        if ($HealthCheck.Domain.Security -and ((($Group.Name -eq 'Schema Admins') -and ($GroupObjects | Measure-Object).count -gt 0) -or ($Group.Name -eq 'Enterprise Admins') -and ($GroupObjects | Measure-Object).count -gt 0) -or (($Group.Name -eq 'Domain Admins') -and ($GroupObjects | Measure-Object).count -gt 5) -or ($OutObj | Where-Object { $_.'Password Never Expires' -eq '**Yes' }) -or ($OutObj | Where-Object { $_.'Last Logon Date' -ne "--" -and $_.'Last Logon Date' -match "\*" })) {
                                                            Paragraph "Health Check:" -Bold -Underline
                                                            BlankLine
                                                            Paragraph "Security Best Practice:" -Bold

                                                            if (($Group.Name -eq 'Schema Admins') -and ($GroupObjects | Measure-Object).count -gt 0) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text "The Schema Admins group is a privileged group in a forest root domain. Members of the Schema Admins group can make changes to the schema, which is the framework for the Active Directory forest. Changes to the schema are not frequently required. This group only contains the Built-in Administrator account by default. Additional accounts must only be added when changes to the schema are necessary and then must be removed."
                                                                }
                                                            }
                                                            if (($Group.Name -eq 'Enterprise Admins') -and ($GroupObjects | Measure-Object).count -gt 0) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text "Unless an account is doing specific tasks needing those highly elevated permissions, every account should be removed from Enterprise Admins (EA) group. A side benefit of having an empty Enterprise Admins group is that it adds just enough friction to ensure that enterprise-wide changes requiring Enterprise Admin rights are done purposefully and methodically."
                                                                }
                                                            }
                                                            if (($Group.Name -eq 'Domain Admins') -and ($GroupObjects | Measure-Object).count -gt 5) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text "Microsoft recommends that Domain Admins contain no more than five members to minimize the risk of privilege escalation and to ensure better control over administrative access."
                                                                }
                                                            }
                                                            if ($OutObj | Where-Object { $_.'Password Never Expires' -eq '**Yes' }) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text "**Accounts with passwords set to never expire were found in the environment. Ensure there are no accounts with weak security postures. Accounts with passwords that never expire can pose a significant security risk as they may not be updated regularly. It is recommended to enforce password expiration policies to enhance security."
                                                                }
                                                            }
                                                            if ($OutObj | Where-Object { $_.'Last Logon Date' -match "\*" }) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text "*Regularly check for and remove inactive privileged user accounts in Active Directory. Inactive accounts can pose a security risk as they may be exploited by malicious actors. Ensuring that only active and necessary accounts have privileged access helps maintain a secure environment."
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory item)"
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory)"
                        }
                    }
                    if ($HealthCheck.Domain.BestPractice) {
                        try {
                            if ($AdminGroupOBj = $GroupOBj | Where-Object { $_.admincount -eq 1 }) {
                                $OutObj = @()
                                foreach ($Group in $AdminGroupOBj) {
                                    if ($Group.SID -notin $AdminGroupsBySID) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Group Name' = $Group.Name
                                                'Group SID' = $Group.SID
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group (Non-Default) Table)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "Privileged Group (Non-Default) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 50, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                if ($OutObj) {
                                    Section -Style Heading5 'Privileged Group (Non-Default)' {
                                        Paragraph "The following section summarizes the privileged groups with AdminCount set to 1 (non-defaults)."
                                        BlankLine
                                        $OutObj | Sort-Object -Property 'Group Name' | Table @TableParams
                                        Paragraph "Health Check:" -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text "Best Practice:" -Bold
                                            Text "Regularly validate and remove unneeded privileged group members in Active Directory. Ensuring that only necessary accounts have privileged access helps maintain a secure environment and reduces the risk of unauthorized access or privilege escalation. Regular audits and reviews of group memberships can help identify and mitigate potential security risks."
                                        }
                                    }
                                }
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group (Non-Default) Section)"
                        }
                    }
                    if ($HealthCheck.Domain.BestPractice -and ($EmptyGroupOBj)) {
                        try {
                            if ($EmptyGroupArray = $EmptyGroupOBj | Where-Object { $_.SID -notin $excludedForestGroupsBySID -and $_.SID -notin $excludedDomainGroupsBySID -and $_.Name -notin $excludedDomainGroupsByName }) {
                                Section -Style Heading5 'Empty Groups (Non-Default)' {
                                    $OutObj = @()
                                    foreach ($Group in $EmptyGroupArray) {
                                        if ($Group.SID -notin $excludedForestGroupsBySID -and $Group.SID -notin $excludedDomainGroupsBySID -and $Group.Name -notin $excludedDomainGroupsByName) {
                                            try {
                                                $inObj = [ordered] @{
                                                    'Group Name' = $Group.Name
                                                    'Group SID' = $Group.SID
                                                }
                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Empty Groups Objects Table)"
                                            }
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "Empty Groups - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 50, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Group Name' | Table @TableParams
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Best Practice:" -Bold
                                        Text "Remove empty or unused Active Directory Groups. An empty Active Directory security group causes two major problems. First, they add unnecessary clutter and make active directory administration difficult, even when paired with user friendly Active Directory tools. The second and most important point to note is that empty groups are a security risk to your network."
                                    }
                                }
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Empty Groups Objects Section)"
                        }
                    }
                    if ($HealthCheck.Domain.BestPractice -and $InfoLevel.Domain -ge 2) {
                        try {
                            $OutObj = @()
                            $NonEmptyGroups = ($GroupOBj | Where-Object { ( $_.Members ) })
                            # Loop through each parent group
                            ForEach ($Parent in $NonEmptyGroups) {
                                # Create an array of the group members, limited to sub-groups (not users)
                                $Children = @(
                                    $NonEmptyGroups | Where-Object { $_.distinguishedName -in $Parent.Members -and $_.objectClass -eq "group" }
                                )

                                if ($Children) {
                                    ForEach ($Child in $Children) {
                                        $nestedGroup = @(
                                            $NonEmptyGroups | Where-Object { $Parent.distinguishedName -in $_.Members -and $_.SID -eq $Child.SID }
                                        )
                                        if ($nestedGroup) {
                                            try {
                                                $inObj = [ordered] @{
                                                    'Parent Group Name' = $Parent.Name
                                                    'Child Group Name' = $nestedGroup.Name
                                                }
                                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Circular Group Membership Table)"
                                            }
                                        }
                                    }
                                }
                            }

                            if ($OutObj) {
                                Section -Style Heading5 'Circular Group Membership' {
                                    Paragraph "If an Active Directory (AD) group has another AD group as both its parent and as a child member you have a circular nested reference."
                                    BlankLine
                                    Paragraph "Why would that matter?"
                                    BlankLine
                                    Paragraph "There is no technical reason preventing the use of circular references between AD groups, Active Directory can still calculate and grant access. The main reason that circular references are considered harmful is that they tend to make management more difficult."
                                    BlankLine

                                    $OutObj | Set-Style -Style Warning

                                    $TableParams = @{
                                        Name = "Circular Group Membership - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 50, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Parent Group Name' | Table @TableParams
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Best Practice:" -Bold
                                        Text "In a well structured Active Directory every group will have a single purpose, ideally with people and resources in separate groups and following a clear hierarchy. If the personnel group is a member of the color_printing group and the color_printing group is also a member of the personnel group, then neither group has a single clear purpose, both groups are now granting two permissions. Circular references are often the cause of unintended privilege escalation."
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Circular Group Membership Section)"
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            Section -Style Heading4 'Computer Objects' {
                try {
                    $OutObj = @()
                    $inObj = [ordered] @{
                        'Computers' = ($Computers | Measure-Object).Count
                        'Servers' = ($Servers).Count
                    }
                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                    $TableParams = @{
                        Name = "Computers - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    try {
                        # Chart Section
                        $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Category'

                        $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'ComputersObject' -XField 'Name' -YField 'Value' -ChartLegendName 'Category' -ChartTitleName 'ComputersObject' -ChartTitleText 'Computers Count' -ReversePalette $True

                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Object Count Chart)"
                    }
                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 'Computers' {
                            if ($chartFileItem) {
                                Image -Text 'Computers Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    $OutObj = @()
                    $dormanttime = (Get-Date).Adddays(-90)
                    $passwordtime = (Get-Date).Adddays(-30)
                    $Dormant = $Computers | Where-Object { [datetime]::FromFileTime($_.lastlogontimestamp) -lt $dormanttime }
                    $PasswordAge = $Computers | Where-Object { $_.PasswordLastSet -le $passwordtime }
                    $SidHistory = $Computers.SIDHistory
                    $Categories = @('Total Computers', 'Dormant (> 90 days)', 'Password Age (> 30 days)', 'SidHistory')
                    if ($Categories) {
                        foreach ($Category in $Categories) {
                            try {
                                if ($Category -eq 'Total Computers') {
                                    $Values = $Computers
                                } elseif ($Category -eq 'Dormant (> 90 days)') {
                                    $Values = $Dormant
                                } elseif ($Category -eq 'Password Age (> 30 days)') {
                                    $Values = $PasswordAge
                                } elseif ($Category -eq 'SidHistory') {
                                    $Values = $SidHistory
                                }
                                $inObj = [ordered] @{
                                    'Category' = $Category
                                    'Enabled' = ($Values.Enabled -eq $True | Measure-Object).Count
                                    'Enabled %' = Switch ($Computers.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }
                                    'Disabled' = ($Values.Enabled -eq $False | Measure-Object).Count
                                    'Disabled %' = Switch ($Computers.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }
                                    'Total' = ($Values | Measure-Object).Count
                                    'Total %' = Switch ($Computers.Count) {
                                        0 { '0' }
                                        $Null { '0' }
                                        default { [math]::Round((($Values | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }

                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Computer Accounts)"
                            }
                        }

                        $TableParams = @{
                            Name = "Status of Computer Accounts - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }

                        try {
                            # Chart Section
                            $sampleData = $OutObj

                            $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'StatusofComputerAccounts' -XField 'Category' -YField 'Total' -ChartLegendName 'Category' -ChartTitleName 'StatusofComputerAccounts' -ChartTitleText 'Status of Computers Accounts' -ReversePalette $True

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Computers Accounts Chart)"
                        }

                        if ($OutObj) {
                            Section -Style Heading5 'Status of Computer Accounts' {
                                if ($chartFileItem -and ($OutObj.'Total' | Measure-Object -Sum).Sum -ne 0) {
                                    Image -Text 'Status of Computer Accounts - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    Section -Style Heading5 'Operating Systems Count' {
                        $OutObj = @()
                        try {
                            $OSObjects = $Computers | Where-Object { $_.name -like '*' } | Group-Object -Property operatingSystem | Select-Object Name, Count
                            if ($OSObjects) {
                                foreach ($OSObject in $OSObjects) {
                                    $inObj = [ordered] @{
                                        'Operating System' = Switch ([string]::IsNullOrEmpty($OSObject.Name)) {
                                            $True { 'No OS Specified' }
                                            default { $OSObject.Name }
                                        }
                                        'Count' = $OSObject.Count
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                }
                                if ($HealthCheck.Domain.Security) {
                                    $OutObj | Where-Object { $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '*2003*' -or $_.'Operating System' -like '*2008*' -or $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '* 95*' -or $_.'Operating System' -like '* 7*' -or $_.'Operating System' -like '* 8 *' -or $_.'Operating System' -like '* 98*' -or $_.'Operating System' -like '*XP*' -or $_.'Operating System' -like '* Vista*' } | Set-Style -Style Critical -Property 'Operating System'
                                }

                                $TableParams = @{
                                    Name = "Operating System Count - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 60, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Operating System' |  Table @TableParams
                                if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '*2003*' -or $_.'Operating System' -like '*2008*' -or $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '* 95*' -or $_.'Operating System' -like '* 7*' -or $_.'Operating System' -like '* 8 *' -or $_.'Operating System' -like '* 98*' -or $_.'Operating System' -like '*XP*' -or $_.'Operating System' -like '* Vista*' })) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Security Best Practice:" -Bold
                                        Text "Operating systems that are no longer supported for security updates are not maintained or updated for vulnerabilities leaving them open to potential attack. Organizations must transition to a supported operating system to ensure continued support and to increase the organization security posture."
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Operating Systems in Active Directory)"
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    if ($HealthCheck.Domain.Security) {
                        if ($ComputerObjects = $Computers | Where-Object { $_.PasswordNeverExpires }) {
                            Section -ExcludeFromTOC -Style NOTOCHeading5 'Computers with Password-Not-Required Attribute Set' {
                                $OutObj = @()
                                try {
                                    foreach ($ComputerObject in $ComputerObjects) {
                                        $inObj = [ordered] @{
                                            'Computer Name' = $ComputerObject.Name
                                            'Distinguished Name' = $ComputerObject.DistinguishedName
                                            'Enabled' = $ComputerObject.Enabled
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    }

                                    $OutObj | Set-Style -Style Warning

                                    $TableParams = @{
                                        Name = "Computers with Password-Not-Required - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 30, 58, 12
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Computer Name' |  Table @TableParams
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Security Best Practice:" -Bold
                                        Text "Computers with Password-Not-Required attribute set can pose a significant security risk. This setting allows computer accounts to have no password, which can be exploited by malicious actors to gain unauthorized access to the network. It is recommended to review and update these accounts to ensure they comply with security policies and have strong, complex passwords set."
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers with Password-Not-Required table)"
                                }
                            }
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers with Password-Not-Required section)"
                }
                if ($InfoLevel.Domain -ge 4) {
                    try {
                        Section -Style Heading4 'Computers Inventory' {
                            $OutObj = @()
                            foreach ($Computer in $Computers) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Computer.Name
                                        'DNS HostName' = $Computer.DNSHostName
                                        'Operating System' = $Computer.operatingSystem
                                        'Status' = Switch ($Computer.Enabled) {
                                            'True' { 'Enabled' }
                                            'False' { 'Disabled' }
                                            default { 'Unknown' }
                                        }
                                    }
                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Objects Table)"
                                }
                            }

                            $TableParams = @{
                                Name = "Computers - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 30, 30, 25, 15
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                        }

                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Objects Section)"
                    }
                }
            }
            try {
                Section -Style Heading3 'Default Domain Password Policy' {
                    $OutObj = @()
                    try {
                        $PasswordPolicy = Invoke-Command -Session $TempPssSession { Get-ADDefaultDomainPasswordPolicy -Identity ($using:Domain).DNSRoot }
                        if ($PasswordPolicy) {
                            $inObj = [ordered] @{
                                'Password Must Meet Complexity Requirements' = $PasswordPolicy.ComplexityEnabled
                                'Path' = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Domain $Domain.Name
                                'Lockout Duration' = $PasswordPolicy.LockoutDuration.toString("mm' minutes'")
                                'Lockout Threshold' = $PasswordPolicy.LockoutThreshold
                                'Lockout Observation Window' = $PasswordPolicy.LockoutObservationWindow.toString("mm' minutes'")
                                'Maximum Password Age' = $PasswordPolicy.MaxPasswordAge.toString("dd' days'")
                                'Minimum Password Age' = $PasswordPolicy.MinPasswordAge.toString("dd' days'")
                                'Minimum Password Length' = $PasswordPolicy.MinPasswordLength
                                'Enforce Password History' = $PasswordPolicy.PasswordHistoryCount
                                'Store Password using Reversible Encryption' = $PasswordPolicy.ReversibleEncryptionEnabled
                            }
                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                            if ($HealthCheck.Domain.Security -and ($PasswordPolicy.MaxPasswordAge.Days -gt 90)) {
                                $OutObj | Set-Style -Style Warning -Property 'Maximun Password Age'
                            }

                            $TableParams = @{
                                Name = "Default Domain Password Policy - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams

                            if ($HealthCheck.Domain.Security -and ($PasswordPolicy.MaxPasswordAge.Days -gt 90)) {
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Security Best Practice:" -Bold
                                    Text "The MS-ISAC recommends organizations establish a standard for the creation, maintenance, and storage of strong passwords. A Password policies should enforce a maximum password age of between 30 and 90 days."
                                }
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Default Domain Password Policy)"
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            try {
                foreach ($Item in $Domain) {
                    if ($PasswordPolicy = Invoke-Command -Session $TempPssSession { Get-ADFineGrainedPasswordPolicy -Server ($using:Domain).PDCEmulator -Filter { Name -like "*" } -Properties * -SearchBase ($using:Domain).distinguishedName } | Sort-Object -Property Name) {
                        Section -Style Heading3 'Fined Grained Password Policies' {
                            $FGPPInfo = @()
                            foreach ($FGPP in $PasswordPolicy) {
                                try {
                                    $Accounts = @()
                                    foreach ($ADObject in $FGPP.AppliesTo) {
                                        $Accounts += ($Users | Where-Object { $_.distinguishedName -eq $ADObject }).sAMAccountName
                                    }
                                    $inObj = [ordered] @{
                                        'Name' = $FGPP.Name
                                        'Domain Name' = $Item
                                        'Complexity Enabled' = $FGPP.ComplexityEnabled
                                        'Path' = ConvertTo-ADCanonicalName -DN $FGPP.DistinguishedName -Domain $Domain.DNSRoot
                                        'Lockout Duration' = $FGPP.LockoutDuration.toString("mm' minutes'")
                                        'Lockout Threshold' = $FGPP.LockoutThreshold
                                        'Lockout Observation Window' = $FGPP.LockoutObservationWindow.toString("mm' minutes'")
                                        'Max Password Age' = $FGPP.MaxPasswordAge.toString("dd' days'")
                                        'Min Password Age' = $FGPP.MinPasswordAge.toString("dd' days'")
                                        'Min Password Length' = $FGPP.MinPasswordLength
                                        'Password History Count' = $FGPP.PasswordHistoryCount
                                        'Reversible Encryption Enabled' = $FGPP.ReversibleEncryptionEnabled
                                        'Precedence' = $FGPP.Precedence
                                        'Applies To' = $Accounts -join ", "
                                    }
                                    $FGPPInfo += [pscustomobject](ConvertTo-HashToYN $inObj)
                                } catch {
                                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($FGPP in $FGPPInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($FGPP.Name)" {
                                        $TableParams = @{
                                            Name = "Fined Grained Password Policies - $($FGPP.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $FGPP | Table @TableParams
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "Fined Grained Password Policies -  $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'Lockout Duration', 'Max Password Age', 'Min Password Age', 'Min Password Length', 'Password History Count'
                                    ColumnWidths = 20, 20, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $FGPPInfo | Table @TableParams
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Fined Grained Password Policies)"
            }

            try {
                if ($Domain.DNSRoot -eq $ADSystem.RootDomain) {
                    foreach ($Item in $Domain) {
                        $LAPS = try { Invoke-Command -Session $TempPssSession -ErrorAction Stop { Get-ADObject -Server ($using:Domain).PDCEmulator "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$(($using:Domain).distinguishedName)" -ErrorAction SilentlyContinue } | Sort-Object -Property Name } catch { Out-Null }
                        Section -Style Heading3 'Microsoft LAPS' {
                            $LAPSInfo = @()
                            try {
                                $inObj = [ordered] @{
                                    'Name' = 'Local Administrator Password Solution'
                                    'Domain Name' = $Item
                                    'Enabled' = Switch ($LAPS.Count) {
                                        0 { 'No' }
                                        default { 'Yes' }
                                    }
                                    'Distinguished Name' = $LAPS.DistinguishedName

                                }
                                $LAPSInfo += [pscustomobject](ConvertTo-HashToYN $inObj)

                                if ($HealthCheck.Domain.Security) {
                                    $LAPSInfo | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning -Property 'Enabled'
                                }

                            } catch {
                                Write-PScriboMessage -IsWarning $($_.Exception.Message)
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($LAP in $LAPSInfo) {
                                    $TableParams = @{
                                        Name = "Microsoft LAPS - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $LAP | Table @TableParams
                                }
                            } else {
                                $TableParams = @{
                                    Name = "Microsoft LAPS -  $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'Domain Name', 'Enabled'
                                    ColumnWidths = 34, 33, 33
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $LAPSInfo | Table @TableParams
                            }

                            if ($HealthCheck.Domain.Security -and ($LAPSInfo | Where-Object { $_.'Enabled' -eq 'No' })) {
                                Paragraph "Health Check:" -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text "Security Best Practice:" -Bold
                                    Text "LAPS simplifies password management while helping customers implement additional recommended defenses against cyberattacks. In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. Download, install, and configure Microsoft LAPS or a third-party solution."
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Windows LAPS)"
            }

            try {
                try {
                    if ($GMSA = Invoke-Command -Session $TempPssSession { Get-ADServiceAccount -Server $using:ValidDcFromDomain -Filter * -Properties * }) {
                        Section -Style Heading3 'gMSA Identities' {
                            $GMSAInfo = @()
                            foreach ($Account in $GMSA) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Account.Name
                                        'SamAccountName' = $Account.SamAccountName
                                        'Created' = Switch ($Account.Created) {
                                            $null { '--' }
                                            default { $Account.Created.ToShortDateString() }
                                        }
                                        'Enabled' = $Account.Enabled
                                        'DNS Host Name' = $Account.DNSHostName
                                        'Host Computers' = ((ConvertTo-ADObjectName -DN $Account.HostComputers -Session $TempPssSession -DC $ValidDcFromDomain) -join ", ")
                                        'Retrieve Managed Password' = ((ConvertTo-ADObjectName $Account.PrincipalsAllowedToRetrieveManagedPassword -Session $TempPssSession -DC $ValidDcFromDomain) -join ", ")
                                        'Primary Group' = (ConvertTo-ADObjectName $Account.PrimaryGroup -Session $TempPssSession -DC $ValidDcFromDomain) -join ", "
                                        'Last Logon Date' = Switch ($Account.LastLogonDate) {
                                            $null { '--' }
                                            default { $Account.LastLogonDate.ToShortDateString() }
                                        }
                                        'Locked Out' = $Account.LockedOut
                                        'Logon Count' = $Account.logonCount
                                        'Password Expired' = $Account.PasswordExpired
                                        'Password Last Set' = Switch ([string]::IsNullOrEmpty($Account.PasswordLastSet)) {
                                            $true { '--' }
                                            $false { $Account.PasswordLastSet.ToShortDateString() }
                                            default { "Unknown" }
                                        }
                                    }
                                    $GMSAInfo += [pscustomobject](ConvertTo-HashToYN $inObj)

                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Managed Service Accounts Item)"
                                }
                            }

                            if ($HealthCheck.Domain.GMSA) {
                                $GMSAInfo | Where-Object { $_.'Enabled' -ne 'Yes' } | Set-Style -Style Warning -Property 'Enabled'
                                $GMSAInfo | Where-Object { $_.'Password Last Set' -ne '--' -and [datetime]$_.'Password Last Set' -lt (Get-Date).adddays(-60) } | Set-Style -Style Warning -Property 'Password Last Set'
                                $GMSAInfo | Where-Object { $_.'Password Last Set' -eq '--' } | Set-Style -Style Warning -Property 'Password Last Set'
                                $GMSAInfo | Where-Object { $_.'Last Logon Date' -ne '--' -and [datetime]$_.'Last Logon Date' -lt (Get-Date).adddays(-60) } | Set-Style -Style Warning -Property 'Last Logon Date'
                                $GMSAInfo | Where-Object { $_.'Last Logon Date' -eq '--' } | Set-Style -Style Warning -Property 'Last Logon Date'
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.'Last Logon Date' -eq '--' })) {
                                    $OBJ.'Last Logon Date' = "*" + $OBJ.'Last Logon Date'
                                }
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.'Last Logon Date' -ne '*--' -and [datetime]$_.'Last Logon Date' -lt (Get-Date).adddays(-60) })) {
                                    $OBJ.'Last Logon Date' = "*" + $OBJ.'Last Logon Date'
                                }
                                $GMSAInfo | Where-Object { $_.'Locked Out' -eq 'Yes' } | Set-Style -Style Warning -Property 'Locked Out'
                                $GMSAInfo | Where-Object { $_.'Logon Count' -eq 0 } | Set-Style -Style Warning -Property 'Logon Count'
                                $GMSAInfo | Where-Object { $_.'Password Expired' -eq 'Yes' } | Set-Style -Style Warning -Property 'Password Expired'
                                $GMSAInfo | Where-Object { $_.'Host Computers' -eq '--' } | Set-Style -Style Warning -Property 'Host Computers'
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.'Host Computers' -eq '--' })) {
                                    $OBJ.'Host Computers' = "**" + $OBJ.'Host Computers'
                                }
                                $GMSAInfo | Where-Object { $_.'Retrieve Managed Password' -eq '--' } | Set-Style -Style Warning -Property 'Retrieve Managed Password'
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.'Retrieve Managed Password' -eq '--' })) {
                                    $OBJ.'Retrieve Managed Password' = "***" + $OBJ.'Retrieve Managed Password'
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($Account in $GMSAInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($Account.Name)" {
                                        $TableParams = @{
                                            Name = "gMSA - $($Account.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $Account | Table @TableParams
                                        if (($Account | Where-Object { $_.'Last Logon Date' -ne '*--' -or $_.'Enabled' -ne 'Yes' -or ($_.'Last Logon Date' -eq '--') }) -or ($Account | Where-Object { $_.'Host Computers' -eq '**--' }) -or ($Account | Where-Object { $_.'Retrieve Managed Password' -eq '**--' })) {
                                            Paragraph "Health Check:" -Bold -Underline
                                            BlankLine
                                            Paragraph "Security Best Practice:" -Bold
                                            if ($Account | Where-Object { $_.'Last Logon Date' -ne '*--' -or $_.'Enabled' -ne 'Yes' -or ($_.'Last Logon Date' -eq '*--') }) {
                                                BlankLine
                                                Paragraph {
                                                    Text "*Regularly check for and remove inactive group managed service accounts from Active Directory. Inactive accounts can pose a security risk as they may be exploited by malicious actors. Ensuring that only active and necessary accounts exist helps maintain a secure environment and reduces the risk of unauthorized access or privilege escalation."
                                                }
                                            }
                                            if ($Account | Where-Object { $_.'Host Computers' -eq '**--' }) {
                                                BlankLine
                                                Paragraph {
                                                    Text "**No 'Host Computers' has been defined, please validate that the gMSA is currently in use. If not, it is recommended to remove these unused resources from Active Directory."
                                                }
                                            }
                                            if ($Account | Where-Object { $_.'Retrieve Managed Password' -eq '***--' }) {
                                                BlankLine
                                                Paragraph {
                                                    Text "***No 'Retrieve Managed Password' has been defined, please validate that the gMSA is currently in use. If not, it is recommended to remove these unused resources from Active Directory."
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "gMSA - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'Logon Count', 'Locked Out', 'Last Logon Date', 'Password Last Set', 'Enabled'
                                    ColumnWidths = 25, 15, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $GMSAInfo | Table @TableParams
                                if (($GMSAInfo | Where-Object { $_.'Last Logon Date' -eq '*--' -or $_.'Enabled' -ne 'Yes' -or ($_.'Last Logon Date' -eq '--') })) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    if ($GMSAInfo | Where-Object { $_.'Last Logon Date' -eq "*--" }) {
                                        Paragraph {
                                            Text "Security Best Practice:" -Bold
                                            Text "*Regularly check for and remove inactive group managed service accounts from Active Directory. Inactive accounts can pose a security risk as they may be exploited by malicious actors. Ensuring that only active and necessary accounts exist helps maintain a secure environment and reduces the risk of unauthorized access or privilege escalation."
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Managed Service Accounts Section)"
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            try {
                try {
                    if ($FSP) {
                        Section -Style Heading3 'Foreign Security Principals' {
                            $FSPInfo = @()
                            foreach ($Account in $FSP) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $Account.'msds-principalname'
                                        'Principal Name' = $Account.memberof | ForEach-Object {
                                            if ($Null -ne $_) {
                                                ConvertTo-ADObjectName -DN $_ -Session $TempPssSession -DC $ValidDcFromDomain
                                            } else {
                                                return "--"
                                            }
                                        }
                                    }
                                    $FSPInfo += [pscustomobject](ConvertTo-HashToYN $inObj)

                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Foreign Security Principals Item)"
                                }
                            }

                            $TableParams = @{
                                Name = "Foreign Security Principals - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 50, 50
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $FSPInfo | Table @TableParams
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Foreign Security Principals Section)"
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "AD Domain Objects"
    }

}