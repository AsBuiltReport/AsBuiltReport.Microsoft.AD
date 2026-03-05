function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.11
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
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADDomainObject.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Domain Objects'
    }

    process {
        Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.DomainObjectsSection {
            Paragraph ($reportTranslate.GetAbrADDomainObject.DomainObjectsParagraph -f $Domain.DNSRoot)
            try {
                try {
                    $script:DomainSID = $Domain.domainsid

                    $ADUsersLimitedProperties = @('Name', 'Enabled', 'SAMAccountname', 'DisplayName', 'Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired', 'PasswordExpired', 'SmartcardLogonRequired', 'AccountExpirationDate', 'AdminCount', 'Created', 'Modified', 'LastBadPasswordAttempt', 'badpwdcount', 'mail', 'CanonicalName', 'DistinguishedName', 'ServicePrincipalName', 'SIDHistory', 'PrimaryGroupID', 'UserAccountControl', 'CannotChangePassword', 'PwdLastSet', 'LockedOut', 'TrustedForDelegation', 'TrustedtoAuthForDelegation', 'msds-keyversionnumber', 'SID', 'AccountNotDelegated', 'EmailAddress', 'ObjectClass')

                    $ADGroupsLimitedProperties = @('Sid', 'Members', 'GroupCategory', 'GroupScope', 'Name', 'SamAccountName', 'DistinguishedName', 'admincount', 'ObjectClass')

                    $ADComputerLimitedProperties = @('Enabled', 'OperatingSystem', 'lastlogontimestamp', 'PasswordLastSet', 'SIDHistory', 'PasswordNotRequired', 'Name', 'DistinguishedName')

                    $script:Computers = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADComputer -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Properties $using:ADComputerLimitedProperties -SearchBase ($using:Domain).distinguishedName) }

                    $Servers = $Computers | Where-Object { $_.OperatingSystem -like '*Serv*' } | Measure-Object

                    $script:Users = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADUser -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Property $using:ADUsersLimitedProperties -SearchBase ($using:Domain).distinguishedName }
                    $script:FSP = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADObject -Server $using:ValidDcFromDomain -Filter { ObjectClass -eq 'foreignSecurityPrincipal' } -Properties msds-principalname, memberof }

                    $script:PrivilegedUsers = $Users | Where-Object { $_.AdminCount -eq 1 }

                    $script:GroupOBj = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADGroup -ResultPageSize 1000 -Server $using:ValidDcFromDomain -Filter * -Properties $using:ADGroupsLimitedProperties -SearchBase ($using:Domain).distinguishedName) }
                    $script:EmptyGroupOBj = $GroupOBj | Where-Object { (-not $_.Members ) }

                    $excludedDomainGroupsBySID = @("$DomainSID-571", "$DomainSID-572", "$DomainSID-553", "$DomainSID-525", "$DomainSID-522", "$DomainSID-572", "$DomainSID-571", "$DomainSID-514", "$DomainSID-553", "$DomainSID-513", "$DomainSID-515", "$DomainSID-512", "$DomainSID-498", "$DomainSID-527", "$DomainSID-520", "$DomainSID-521", "$DomainSID-519", "$DomainSID-526", "$DomainSID-516", "$DomainSID-517", "$DomainSID-518")

                    $excludedDomainGroupsByName = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'Help Desk Operators', 'Domain Controllers', 'DNS Admins', 'Cert Publishers', 'Enterprise Read-Only Domain Controllers', 'Read-Only Domain Controllers', 'Group Policy Creator Owners', 'Key Admins', 'DHCP Administrators', 'DHCP Users', 'DnsAdmins', 'DnsUpdateProxy')

                    $excludedForestGroupsBySID = ($GroupOBj | Where-Object { $_.SID -like 'S-1-5-32-*' }).SID

                    $AdminGroupsBySID = 'S-1-5-32-552', "$DomainSID-527", "$DomainSID-521", "$DomainSID-516", "$DomainSID-1107", "$DomainSID-512", "$DomainSID-519", 'S-1-5-32-544', 'S-1-5-32-549', "$DomainSID-1101", 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', "$DomainSID-518", 'S-1-5-32-578'

                    $script:DomainController = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomainController -Server $using:ValidDcFromDomain -Filter *) | Select-Object name, OperatingSystem }

                    $script:GC = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomainController -Server $using:ValidDcFromDomain -Filter { IsGlobalCatalog -eq 'True' }) | Select-Object name }

                    $ADObjects = $Users + $GroupObj

                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Object Stats)"
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Object Stats)"
            }
            try {
                Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.UserObjectsSection {
                    Show-AbrDebugExecutionTime -Start -TitleMessage 'User Objects'
                    try {
                        $OutObj = [System.Collections.ArrayList]::new()
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADDomainObject.Users = ($Users | Measure-Object).Count
                            $reportTranslate.GetAbrADDomainObject.PrivilegedUsers = ($PrivilegedUsers | Measure-Object).Count
                            $reportTranslate.GetAbrADDomainObject.ForeignSecurityPrincipals = ($FSP | Measure-Object).Count
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainObject.User) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Category'
                            $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Name -Title "$($reportTranslate.GetAbrADDomainObject.UserObjectsSection)" -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (User Object Count Chart)"
                        }

                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading5 $reportTranslate.GetAbrADDomainObject.UsersSubSection {
                                if ($Chart) {
                                    Image -Text "$($reportTranslate.GetAbrADDomainObject.UserObjectsSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }

                    $OutObj = [System.Collections.ArrayList]::new()
                    $dormanttime = ((Get-Date).AddDays(-90)).Date
                    $passwordtime = (Get-Date).Adddays(-180)
                    $CannotChangePassword = $Users | Where-Object { $_.CannotChangePassword }
                    $PasswordNextLogon = $Users | Where-Object { $_.PasswordLastSet -eq 0 -or $_.PwdLastSet -eq 0 }
                    $passwordNeverExpires = $Users | Where-Object { $_.passwordNeverExpires -eq 'true' }
                    $SmartcardLogonRequired = $Users | Where-Object { $_.SmartcardLogonRequired -eq $True }
                    $SidHistory = $Users | Where-Object { $_.SIDHistory }
                    $PasswordLastSet = $Users | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.PasswordNotRequired -eq $false }
                    $NeverloggedIn = $Users | Where-Object { -not $_.LastLogonDate }
                    $Dormant = $Users | Where-Object { ($_.LastLogonDate) -lt $dormanttime }
                    $PasswordNotRequired = $Users | Where-Object { $_.PasswordNotRequired -eq $true }
                    $AccountExpired = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Search-ADAccount -Server $using:ValidDcFromDomain -AccountExpired }
                    $AccountLockout = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Search-ADAccount -Server $using:ValidDcFromDomain -LockedOut }
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
                                    $reportTranslate.GetAbrADDomainObject.Category = $Category
                                    $reportTranslate.GetAbrADDomainObject.Enabled = switch ([string]::IsNullOrEmpty($Values.Enabled)) {
                                        $true { '0' }
                                        default { ($Values.Enabled -eq $True | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.EnabledPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.Disabled = switch ([string]::IsNullOrEmpty($Values.Enabled)) {
                                        $true { '0' }
                                        default { ($Values.Enabled -eq $False | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.DisabledPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.Total = switch ([string]::IsNullOrEmpty($Values)) {
                                        $true { '0' }
                                        default { ($Values | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.TotalPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values | Measure-Object).Count / $Users.Count * 100), 2) }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of User Accounts)"
                            }
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainObject.StatusOfUsersSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            $sampleData = $OutObj
                            $Chart = New-PieChart -Values $sampleData.$($reportTranslate.GetAbrADDomainObject.Total) -Labels $sampleData.$($reportTranslate.GetAbrADDomainObject.Category) -Title "$($reportTranslate.GetAbrADDomainObject.StatusOfUsersSection)" -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 800 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Users Accounts Chart)"
                        }
                    }
                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading5 $reportTranslate.GetAbrADDomainObject.StatusOfUsersSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Status of Users Accounts'
                            if ($Chart) {
                                Image -Text "$($reportTranslate.GetAbrADDomainObject.StatusOfUsersSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                            }
                            $OutObj | Table @TableParams
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Status of Users Accounts'
                        }
                    }

                    if ($InfoLevel.Domain -ge 4) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.UsersInventorySection {
                                Show-AbrDebugExecutionTime -Start -TitleMessage 'Users Inventory'
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($User in $Users) {
                                    try {
                                        $Groups = ($GroupOBj | Where-Object { $_.members -eq $User.DistinguishedName }).Name
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDomainObject.Name = switch ([string]::IsNullOrEmpty($User.DisplayName)) {
                                                $true { $User.Name }
                                                $false { $User.DisplayName }
                                                default { 'Unknown' }
                                            }
                                            $reportTranslate.GetAbrADDomainObject.LogonName = $User.SamAccountName
                                            $reportTranslate.GetAbrADDomainObject.MemberOfGroups = switch ([string]::IsNullOrEmpty($Groups)) {
                                                $true { '--' }
                                                $false { $Groups }
                                                default { 'Unknown' }
                                            }
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Users Objects Table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDomainObject.UsersSubSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 33, 33, 34
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.Name | Table @TableParams
                                Show-AbrDebugExecutionTime -End -TitleMessage 'Users Inventory'
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Users Objects Section)"
                        }
                    }
                    Show-AbrDebugExecutionTime -End -TitleMessage 'User Objects'
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            try {
                Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.GroupObjectsSection {
                    Show-AbrDebugExecutionTime -Start -TitleMessage 'Group Objects'
                    try {
                        $OutObj = [System.Collections.ArrayList]::new()
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADDomainObject.SecurityGroups = ($GroupOBj | Where-Object { $_.GroupCategory -eq 'Security' } | Measure-Object).Count
                            $reportTranslate.GetAbrADDomainObject.DistributionGroups = ($GroupOBj | Where-Object { $_.GroupCategory -eq 'Distribution' } | Measure-Object).Count
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainObject.GroupCategoriesSubSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Name'
                            $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Name -Title $reportTranslate.GetAbrADDomainObject.GroupCategoriesSubSection -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Category Object Chart)"
                        }
                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDomainObject.GroupCategoriesSubSection {
                                if ($Chart) {
                                    Image -Text "$($reportTranslate.GetAbrADDomainObject.GroupCategoriesSubSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }
                    try {
                        $OutObj = [System.Collections.ArrayList]::new()
                        $inObj = [ordered] @{
                            $reportTranslate.GetAbrADDomainObject.DomainLocals = ($GroupOBj | Where-Object { $_.GroupScope -eq 'DomainLocal' } | Measure-Object).Count
                            $reportTranslate.GetAbrADDomainObject.Globals = ($GroupOBj | Where-Object { $_.GroupScope -eq 'Global' } | Measure-Object).Count
                            $reportTranslate.GetAbrADDomainObject.Universal = ($GroupOBj | Where-Object { $_.GroupScope -eq 'Universal' } | Measure-Object).Count
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainObject.GroupScopesSubSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $true
                            ColumnWidths = 40, 60
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Name'
                            $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Name -Title $reportTranslate.GetAbrADDomainObject.GroupScopesSubSection -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Scopes Object Chart)"
                        }
                        if ($OutObj) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDomainObject.GroupScopesSubSection {
                                if ($Chart) {
                                    Image -Text "$($reportTranslate.GetAbrADDomainObject.GroupScopesSubSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning $($_.Exception.Message)
                    }
                    if ($InfoLevel.Domain -ge 4) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.GroupsInventorySection {
                                Show-AbrDebugExecutionTime -Start -TitleMessage 'Groups Inventory'
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Group in $GroupOBj) {
                                    try {
                                        $UserCount = ($Group.Members | Measure-Object).Count
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDomainObject.Name = $Group.Name
                                            $reportTranslate.GetAbrADDomainObject.GroupCategory = $Group.GroupCategory
                                            $reportTranslate.GetAbrADDomainObject.GroupScope = $Group.GroupScope
                                            $reportTranslate.GetAbrADDomainObject.UserCount = $UserCount
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Groups Objects Table)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDomainObject.Group) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 25, 25, 15
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.Name | Table @TableParams
                                Show-AbrDebugExecutionTime -End -TitleMessage 'Groups Inventory'
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Groups Objects Section)"
                        }
                    }
                    if ($GroupOBj) {
                        Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.PrivilegedGroupsSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Privileged Groups (Built-in)'
                            $OutObj = [System.Collections.ArrayList]::new()
                            try {
                                if ($Domain.DNSRoot -eq $ADSystem.Name) {
                                    $GroupsSID = "$DomainSID-512", "$DomainSID-519", 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', "$DomainSID-518", 'S-1-5-32-578'
                                } else {
                                    $GroupsSID = "$DomainSID-512", 'S-1-5-32-549', 'S-1-5-32-555', 'S-1-5-32-557', "$DomainSID-526", 'S-1-5-32-551', "$DomainSID-517", 'S-1-5-32-550', 'S-1-5-32-548', 'S-1-5-32-578'
                                }
                                if ($InfoLevel.Domain -eq 1) {
                                    Paragraph $reportTranslate.GetAbrADDomainObject.PrivilegedGroupsSummaryParagraph
                                    BlankLine
                                    foreach ($GroupSID in $GroupsSID) {
                                        try {
                                            if ($Group = $GroupOBj | Where-Object { $_.SID -like $GroupSID }) {
                                                $inObj = [ordered] @{
                                                    $reportTranslate.GetAbrADDomainObject.GroupName = $Group.Name
                                                    $reportTranslate.GetAbrADDomainObject.Count = ($Group.Members | Measure-Object).Count
                                                }
                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory item)"
                                        }
                                    }

                                    if ($HealthCheck.Domain.Security) {
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq 'Schema Admins' -and $_.Count -gt 1 })) {
                                            $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName) = '*' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName)
                                        }
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq 'Enterprise Admins' -and $_.Count -gt 1 })) {
                                            $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName) = '**' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName)
                                        }
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq 'Domain Admins' -and $_.Count -gt 5 })) {
                                            $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName) = '***' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GroupName)
                                        }
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '*Schema Admins' -and $_.Count -gt 1 } | Set-Style -Style Warning
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '**Enterprise Admins' -and $_.Count -gt 1 } | Set-Style -Style Warning
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '***Domain Admins' -and $_.Count -gt 5 } | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainObject.PrivilegedGroups) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 60, 40
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.GroupName | Table @TableParams
                                    if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '*Schema Admins' -and $_.Count -gt 1 }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '**Enterprise Admins' -and $_.Count -gt 1 }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '***Domain Admins' -and $_.Count -gt 5 })) {
                                        Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '*Schema Admins' -and $_.Count -gt 1 }) {
                                            BlankLine
                                            Paragraph {
                                                Text $reportTranslate.GetAbrADDomainObject.SchemaAdminsSummaryBP
                                            }
                                        }
                                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '**Enterprise Admins' -and $_.Count -gt 1 }) {
                                            BlankLine
                                            Paragraph {
                                                Text $reportTranslate.GetAbrADDomainObject.EnterpriseAdminsSummaryBP
                                            }
                                        }
                                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GroupName) -eq '***Domain Admins' -and $_.Count -gt 5 }) {
                                            BlankLine
                                            Paragraph {
                                                Text $reportTranslate.GetAbrADDomainObject.DomainAdminsSummaryBP
                                            }
                                        }
                                    }
                                } else {
                                    Paragraph $reportTranslate.GetAbrADDomainObject.PrivilegedGroupsDetailParagraph
                                    BlankLine
                                    foreach ($GroupSID in $GroupsSID) {
                                        try {
                                            if ($Group = ($GroupOBj | Where-Object { $_.SID -like $GroupSID })) {
                                                $GroupObjects = $Group.Members
                                                if ($GroupObjFilter = $ADObjects | Where-Object { $_.distinguishedName -in $GroupObjects }) {
                                                    Section -ExcludeFromTOC -Style NOTOCHeading4 "$($Group.Name) ($(($GroupObjects | Measure-Object).count) Members)" {
                                                        $OutObj = [System.Collections.ArrayList]::new()
                                                        foreach ($GroupObject in $GroupObjFilter) {
                                                            try {
                                                                $inObj = [ordered] @{
                                                                    $reportTranslate.GetAbrADDomainObject.Name = "$($GroupObject.SamAccountName) ($($GroupObject.ObjectClass.toUpper()))"
                                                                    $reportTranslate.GetAbrADDomainObject.LastLogonDate = switch ([string]::IsNullOrEmpty($GroupObject.LastLogonDate)) {
                                                                        $true { '--' }
                                                                        $false { $GroupObject.LastLogonDate.ToShortDateString() }
                                                                        default { 'Unknown' }
                                                                    }
                                                                    $reportTranslate.GetAbrADDomainObject.PasswordNeverExpires = $GroupObject.passwordNeverExpires
                                                                    $reportTranslate.GetAbrADDomainObject.AccountEnabled = $GroupObject.Enabled
                                                                }
                                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                            } catch {
                                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory item)"

                                                            }
                                                        }

                                                        if ($HealthCheck.Domain.Security) {
                                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.PasswordNeverExpires) -eq 'Yes' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.PasswordNeverExpires
                                                            foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.PasswordNeverExpires) -eq 'Yes' })) {
                                                                $OBJ.$($reportTranslate.GetAbrADDomainObject.PasswordNeverExpires) = '**Yes'
                                                            }
                                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.AccountEnabled) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.AccountEnabled
                                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -ne '--' -and [DateTime]$_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -le (Get-Date).AddDays(-90) } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.LastLogonDate
                                                            foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -ne '--' -and [DateTime]$_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -le (Get-Date).AddDays(-90) })) {
                                                                $OBJ.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) = '*' + $OBJ.$($reportTranslate.GetAbrADDomainObject.LastLogonDate)
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
                                                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.Name | Table @TableParams
                                                        if ($HealthCheck.Domain.Security -and ((($Group.Name -eq 'Schema Admins') -and ($GroupObjects | Measure-Object).count -gt 0) -or ($Group.Name -eq 'Enterprise Admins') -and ($GroupObjects | Measure-Object).count -gt 0) -or (($Group.Name -eq 'Domain Admins') -and ($GroupObjects | Measure-Object).count -gt 5) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.PasswordNeverExpires) -eq '**Yes' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -ne '--' -and $_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -match '\*' })) {
                                                            Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                                            BlankLine
                                                            Paragraph $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold

                                                            if (($Group.Name -eq 'Schema Admins') -and ($GroupObjects | Measure-Object).count -gt 0) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text $reportTranslate.GetAbrADDomainObject.SchemaAdminsBP
                                                                }
                                                            }
                                                            if (($Group.Name -eq 'Enterprise Admins') -and ($GroupObjects | Measure-Object).count -gt 0) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text $reportTranslate.GetAbrADDomainObject.EnterpriseAdminsBP
                                                                }
                                                            }
                                                            if (($Group.Name -eq 'Domain Admins') -and ($GroupObjects | Measure-Object).count -gt 5) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text $reportTranslate.GetAbrADDomainObject.DomainAdminsBP
                                                                }
                                                            }
                                                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.PasswordNeverExpires) -eq '**Yes' }) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text $reportTranslate.GetAbrADDomainObject.PasswordNeverExpiresBP
                                                                }
                                                            }
                                                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LastLogonDate) -match '\*' }) {
                                                                BlankLine
                                                                Paragraph {
                                                                    Text $reportTranslate.GetAbrADDomainObject.InactivePrivilegedUserBP
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

                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group in Active Directory)"
                            }
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Privileged Groups (Built-in)'
                        }
                    }
                    if ($HealthCheck.Domain.BestPractice) {
                        Show-AbrDebugExecutionTime -Start -TitleMessage 'Privileged Group (Non-Default)'
                        try {
                            if ($AdminGroupOBj = $GroupOBj | Where-Object { $_.admincount -eq 1 }) {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Group in $AdminGroupOBj) {
                                    if ($Group.SID -notin $AdminGroupsBySID) {
                                        try {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDomainObject.GroupName = $Group.Name
                                                $reportTranslate.GetAbrADDomainObject.GroupSID = $Group.SID
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Privileged Group (Non-Default) Table)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDomainObject.PrivilegedGroupsNonDefault) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 50, 50
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                if ($OutObj) {
                                    Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.PrivilegedGroupsNonDefaultSection {
                                        Paragraph $reportTranslate.GetAbrADDomainObject.PrivilegedGroupsNonDefaultParagraph
                                        BlankLine
                                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.GroupName | Table @TableParams
                                        Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDomainObject.BestPractice -Bold
                                            Text $reportTranslate.GetAbrADDomainObject.NonDefaultPrivilegedGroupBP
                                        }
                                        Show-AbrDebugExecutionTime -End -TitleMessage 'Privileged Group (Non-Default)'
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
                                Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.EmptyGroupsSection {
                                    Show-AbrDebugExecutionTime -Start -TitleMessage 'Empty Groups (Non-Default)'
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Group in $EmptyGroupArray) {
                                        if ($Group.SID -notin $excludedForestGroupsBySID -and $Group.SID -notin $excludedDomainGroupsBySID -and $Group.Name -notin $excludedDomainGroupsByName) {
                                            try {
                                                $inObj = [ordered] @{
                                                    $reportTranslate.GetAbrADDomainObject.GroupName = $Group.Name
                                                    $reportTranslate.GetAbrADDomainObject.GroupSID = $Group.SID
                                                }
                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Empty Groups Objects Table)"
                                            }
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainObject.EmptyGroupsTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 50, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.GroupName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDomainObject.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADDomainObject.EmptyGroupBP
                                    }
                                    Show-AbrDebugExecutionTime -End -TitleMessage 'Empty Groups (Non-Default)'
                                }
                            }

                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Empty Groups Objects Section)"
                        }
                    }
                    if ($HealthCheck.Domain.BestPractice -and $InfoLevel.Domain -ge 2) {
                        Show-AbrDebugExecutionTime -Start -TitleMessage 'Circular Group Membership'
                        try {
                            $OutObj = [System.Collections.ArrayList]::new()
                            $NonEmptyGroups = ($GroupOBj | Where-Object { ( $_.Members ) })
                            # Loop through each parent group
                            foreach ($Parent in $NonEmptyGroups) {
                                # Create an array of the group members, limited to sub-groups (not users)
                                $Children = @(
                                    $NonEmptyGroups | Where-Object { $_.distinguishedName -in $Parent.Members -and $_.objectClass -eq 'group' }
                                )

                                if ($Children) {
                                    foreach ($Child in $Children) {
                                        $nestedGroup = @(
                                            $NonEmptyGroups | Where-Object { $Parent.distinguishedName -in $_.Members -and $_.SID -eq $Child.SID }
                                        )
                                        if ($nestedGroup) {
                                            try {
                                                $inObj = [ordered] @{
                                                    $reportTranslate.GetAbrADDomainObject.ParentGroupName = $Parent.Name
                                                    $reportTranslate.GetAbrADDomainObject.ChildGroupName = $nestedGroup.Name
                                                }
                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Circular Group Membership Table)"
                                            }
                                        }
                                    }
                                }
                            }

                            if ($OutObj) {
                                Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.CircularGroupMembershipSection {
                                    Paragraph $reportTranslate.GetAbrADDomainObject.CircularGroupMembershipParagraph1
                                    BlankLine
                                    Paragraph $reportTranslate.GetAbrADDomainObject.CircularGroupMembershipParagraph2
                                    BlankLine
                                    Paragraph $reportTranslate.GetAbrADDomainObject.CircularGroupMembershipParagraph3
                                    BlankLine

                                    $OutObj | Set-Style -Style Warning

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainObject.CircularGroupMembershipSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 50, 50
                                    }

                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.ParentGroupName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDomainObject.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADDomainObject.CircularGroupBP
                                    }
                                    Show-AbrDebugExecutionTime -End -TitleMessage 'Circular Group Membership'
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Circular Group Membership Section)"
                        }
                    }
                    if ($HealthCheck.Domain.Security) {
                        Show-AbrDebugExecutionTime -Start -TitleMessage 'Pre-Windows 2000 Compatible Access Group'
                        try {
                            if ($PreWin2000Group = $GroupOBj | Where-Object { $_.SID -eq 'S-1-5-32-554' }) {
                                $GroupMembers = $PreWin2000Group.Members
                                if ($GroupMembers) {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($MemberDN in $GroupMembers) {
                                        try {
                                            if ($MemberUser = $Users | Where-Object { $_.DistinguishedName -eq $MemberDN }) {
                                                $MemberName = "$($MemberUser.SamAccountName) (USER)"
                                            } elseif ($MemberComputer = $Computers | Where-Object { $_.DistinguishedName -eq $MemberDN }) {
                                                $MemberName = "$($MemberComputer.Name) (COMPUTER)"
                                            } elseif ($MemberGroup = $GroupOBj | Where-Object { $_.DistinguishedName -eq $MemberDN }) {
                                                $MemberName = "$($MemberGroup.Name) (GROUP)"
                                            } elseif ($MemberFSP = $FSP | Where-Object { $_.DistinguishedName -eq $MemberDN }) {
                                                $MemberName = "$($MemberFSP.'msds-principalname') (FOREIGN SECURITY PRINCIPAL)"
                                            } elseif ($MemberDN -match 'ForeignSecurityPrincipals') {
                                                $MemberName = "$(($MemberDN -split ',')[0] -replace '^CN=') (FOREIGN SECURITY PRINCIPAL)"
                                            } else {
                                                $MemberName = ($MemberDN -split ',')[0] -replace '^CN='
                                            }
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDomainObject.Name = $MemberName
                                                $reportTranslate.GetAbrADDomainObject.DistinguishedName = $MemberDN
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Pre-Windows 2000 Compatible Access Group Member)"
                                        }
                                    }
                                    if ($OutObj) {
                                        Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.PreWin2000Section {
                                            Paragraph $reportTranslate.GetAbrADDomainObject.PreWin2000Paragraph
                                            BlankLine
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.Name) -match 'Authenticated Users|ANONYMOUS LOGON' } | Set-Style -Style Critical
                                            $TableParams = @{
                                                Name = "$($reportTranslate.GetAbrADDomainObject.PreWin2000Table) - $($Domain.DNSRoot.ToString().ToUpper())"
                                                List = $false
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.Name | Table @TableParams
                                            Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                            BlankLine
                                            Paragraph {
                                                Text $reportTranslate.GetAbrADDomainObject.SecurityRisk -Bold
                                                Text $reportTranslate.GetAbrADDomainObject.PreWin2000BP
                                            }
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Pre-Windows 2000 Compatible Access Group Section)"
                        }
                        Show-AbrDebugExecutionTime -End -TitleMessage 'Pre-Windows 2000 Compatible Access Group'
                    }
                    Show-AbrDebugExecutionTime -End -TitleMessage 'Group Objects'
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.ComputerObjectsSection {
                Show-AbrDebugExecutionTime -Start -TitleMessage 'Computer Objects'
                try {
                    $OutObj = [System.Collections.ArrayList]::new()
                    $inObj = [ordered] @{
                        $reportTranslate.GetAbrADDomainObject.Computers = ($Computers | Measure-Object).Count
                        $reportTranslate.GetAbrADDomainObject.Servers = ($Servers).Count
                    }
                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDomainObject.ComputersSubSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    try {
                        $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Name'
                        $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Name -Title "$($reportTranslate.GetAbrADDomainObject.ComputersCount)" -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Object Count Chart)"
                    }
                    if ($OutObj) {
                        Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADDomainObject.ComputersSubSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Computers Object - Diagram'
                            if ($Chart) {
                                Image -Text "$($reportTranslate.GetAbrADDomainObject.ComputerObjectsSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                            }
                            $OutObj | Table @TableParams
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Computers Object - Diagram'
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    Show-AbrDebugExecutionTime -Start -TitleMessage 'Status of Computer Accounts'
                    $OutObj = [System.Collections.ArrayList]::new()
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
                                    $reportTranslate.GetAbrADDomainObject.Category = $Category
                                    $reportTranslate.GetAbrADDomainObject.Enabled = switch ([string]::IsNullOrEmpty($Values.Enabled)) {
                                        $true { '0' }
                                        default { ($Values.Enabled -eq $True | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.EnabledPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.Disabled = switch ([string]::IsNullOrEmpty($Values.Enabled)) {
                                        $true { '0' }
                                        default { ($Values.Enabled -eq $False | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.DisabledPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.Total = switch ([string]::IsNullOrEmpty($Values)) {
                                        $true { '0' }
                                        default { ($Values | Measure-Object).Count }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.TotalPct = switch ($Values.Count) {
                                        0 { '0' }
                                        default { [math]::Round((($Values | Measure-Object).Count / $Computers.Count * 100), 2) }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Computer Accounts)"
                            }
                        }

                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainObject.StatusOfComputerAccountsSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 28, 12, 12, 12, 12, 12, 12
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        try {
                            $sampleData = $OutObj
                            $Chart = New-PieChart -Values $sampleData.$($reportTranslate.GetAbrADDomainObject.Total) -Labels $sampleData.$($reportTranslate.GetAbrADDomainObject.Category) -Title "$($reportTranslate.GetAbrADDomainObject.StatusOfComputerAccountsSection)" -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Status of Computers Accounts Chart)"
                        }

                        if ($OutObj) {
                            Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.StatusOfComputerAccountsSection {
                                if ($Chart -and ($OutObj.'Total' | Measure-Object -Sum).Sum -ne 0) {
                                    Image -Text "$($reportTranslate.GetAbrADDomainObject.StatusOfComputerAccountsSection) - Diagram" -Align 'Center' -Percent 100 -Base64 $Chart
                                }
                                $OutObj | Table @TableParams
                                Show-AbrDebugExecutionTime -End -TitleMessage 'Status of Computer Accounts'
                            }
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    Section -Style Heading5 $reportTranslate.GetAbrADDomainObject.OperatingSystemsCountSection {
                        Show-AbrDebugExecutionTime -Start -TitleMessage 'Operating Systems Count'
                        $OutObj = [System.Collections.ArrayList]::new()
                        try {
                            $OSObjects = $Computers | Where-Object { $_.name -like '*' } | Group-Object -Property operatingSystem | Select-Object Name, Count
                            if ($OSObjects) {
                                foreach ($OSObject in $OSObjects) {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADDomainObject.OperatingSystem = switch ([string]::IsNullOrEmpty($OSObject.Name)) {
                                            $True { 'No OS Specified' }
                                            default { $OSObject.Name }
                                        }
                                        $reportTranslate.GetAbrADDomainObject.Count = $OSObject.Count
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                }
                                if ($HealthCheck.Domain.Security) {
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* NT*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2000*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2003*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2008*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* NT*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2000*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 95*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 7*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 8 *' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 98*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*XP*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* Vista*' } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainObject.OperatingSystem
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDomainObject.OperatingSystemCountSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 60, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.OperatingSystem | Table @TableParams
                                if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* NT*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2000*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2003*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2008*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* NT*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*2000*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 95*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 7*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 8 *' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* 98*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '*XP*' -or $_.$($reportTranslate.GetAbrADDomainObject.OperatingSystem) -like '* Vista*' })) {
                                    Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                        Text $reportTranslate.GetAbrADDomainObject.UnsupportedOSBP
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Operating Systems in Active Directory)"
                        }
                        Show-AbrDebugExecutionTime -End -TitleMessage 'Operating Systems Count'
                    }
                } catch {
                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                }
                try {
                    if ($HealthCheck.Domain.Security) {
                        if ($ComputerObjects = $Computers | Where-Object { $_.PasswordNeverExpires }) {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Computers with Password-Not-Required Attribute Set'
                            Section -ExcludeFromTOC -Style NOTOCHeading5 $reportTranslate.GetAbrADDomainObject.PasswordNotRequiredSection {
                                $OutObj = [System.Collections.ArrayList]::new()
                                try {
                                    foreach ($ComputerObject in $ComputerObjects) {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDomainObject.ComputerName = $ComputerObject.Name
                                            $reportTranslate.GetAbrADDomainObject.DistinguishedName = $ComputerObject.DistinguishedName
                                            $reportTranslate.GetAbrADDomainObject.Enabled = $ComputerObject.Enabled
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    }

                                    $OutObj | Set-Style -Style Warning

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainObject.PasswordNotRequiredSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 30, 58, 12
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.ComputerName | Table @TableParams
                                    Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                        Text $reportTranslate.GetAbrADDomainObject.PasswordNotRequiredBP
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers with Password-Not-Required table)"
                                }
                            }
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Computers with Password-Not-Required Attribute Set'
                        }
                    }
                } catch {
                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers with Password-Not-Required section)"
                }
                if ($InfoLevel.Domain -ge 4) {
                    try {
                        Section -Style Heading4 $reportTranslate.GetAbrADDomainObject.ComputersInventorySection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Computers Inventory'
                            $OutObj = [System.Collections.ArrayList]::new()
                            foreach ($Computer in $Computers) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADDomainObject.Name = $Computer.Name
                                        $reportTranslate.GetAbrADDomainObject.DNSHostName = $Computer.DNSHostName
                                        $reportTranslate.GetAbrADDomainObject.OperatingSystem = $Computer.operatingSystem
                                        $reportTranslate.GetAbrADDomainObject.Status = switch ($Computer.Enabled) {
                                            'True' { $reportTranslate.GetAbrADDomainObject.StatusEnabled }
                                            'False' { $reportTranslate.GetAbrADDomainObject.StatusDisabled }
                                            default { $reportTranslate.GetAbrADDomainObject.StatusUnknown }
                                        }
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Objects Table)"
                                }
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADDomainObject.ComputersInventorySection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 30, 30, 25, 15
                            }

                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainObject.Name | Table @TableParams
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Computers Inventory'
                        }

                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Computers Objects Section)"
                    }
                }
                Show-AbrDebugExecutionTime -End -TitleMessage 'Computer Objects'
            }
            try {
                Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.DefaultPasswordPolicySection {
                    Show-AbrDebugExecutionTime -Start -TitleMessage 'Default Domain Password Policy'
                    $OutObj = [System.Collections.ArrayList]::new()
                    try {
                        $PasswordPolicy = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDefaultDomainPasswordPolicy -Identity ($using:Domain).DNSRoot }
                        if ($PasswordPolicy) {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADDomainObject.PasswordComplexity = $PasswordPolicy.ComplexityEnabled
                                $reportTranslate.GetAbrADDomainObject.Path = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Domain $Domain.Name
                                $reportTranslate.GetAbrADDomainObject.LockoutDuration = $PasswordPolicy.LockoutDuration.toString("mm' minutes'")
                                $reportTranslate.GetAbrADDomainObject.LockoutThreshold = $PasswordPolicy.LockoutThreshold
                                $reportTranslate.GetAbrADDomainObject.LockoutObservationWindow = $PasswordPolicy.LockoutObservationWindow.toString("mm' minutes'")
                                $reportTranslate.GetAbrADDomainObject.MaxPasswordAge = $PasswordPolicy.MaxPasswordAge.toString("dd' days'")
                                $reportTranslate.GetAbrADDomainObject.MinPasswordAge = $PasswordPolicy.MinPasswordAge.toString("dd' days'")
                                $reportTranslate.GetAbrADDomainObject.MinPasswordLength = $PasswordPolicy.MinPasswordLength
                                $reportTranslate.GetAbrADDomainObject.EnforcePasswordHistory = $PasswordPolicy.PasswordHistoryCount
                                $reportTranslate.GetAbrADDomainObject.StorePasswordReversible = $PasswordPolicy.ReversibleEncryptionEnabled
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                            if ($HealthCheck.Domain.Security -and ($PasswordPolicy.MaxPasswordAge.Days -gt 90)) {
                                $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.MaxPasswordAge
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADDomainObject.DefaultPasswordPolicySection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams

                            if ($HealthCheck.Domain.Security -and ($PasswordPolicy.MaxPasswordAge.Days -gt 90)) {
                                Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                    Text $reportTranslate.GetAbrADDomainObject.MaxPasswordAgeBP
                                }
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Default Domain Password Policy)"
                    }
                    Show-AbrDebugExecutionTime -End -TitleMessage 'Default Domain Password Policy'
                }
            } catch {
                Write-PScriboMessage -IsWarning $($_.Exception.Message)
            }
            try {
                foreach ($Item in $Domain) {
                    if ($PasswordPolicy = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADFineGrainedPasswordPolicy -Server ($using:Domain).PDCEmulator -Filter { Name -like '*' } -Properties * -SearchBase ($using:Domain).distinguishedName } | Sort-Object -Property Name) {
                        Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.FineGrainedPasswordPoliciesSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Fined Grained Password Policies'
                            $FGPPInfo = [System.Collections.ArrayList]::new()
                            foreach ($FGPP in $PasswordPolicy) {
                                try {
                                    $Accounts = [System.Collections.ArrayList]::new()
                                    foreach ($ADObject in $FGPP.AppliesTo) {
                                        $Accounts.Add(($Users | Where-Object { $_.distinguishedName -eq $ADObject }).sAMAccountName) | Out-Null
                                    }
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADDomainObject.FGPPName = $FGPP.Name
                                        $reportTranslate.GetAbrADDomainObject.FGPPDomainName = $Item
                                        $reportTranslate.GetAbrADDomainObject.FGPPComplexityEnabled = $FGPP.ComplexityEnabled
                                        $reportTranslate.GetAbrADDomainObject.FGPPPath = ConvertTo-ADCanonicalName -DN $FGPP.DistinguishedName -Domain $Domain.DNSRoot
                                        $reportTranslate.GetAbrADDomainObject.FGPPLockoutDuration = $FGPP.LockoutDuration.toString("mm' minutes'")
                                        $reportTranslate.GetAbrADDomainObject.FGPPLockoutThreshold = $FGPP.LockoutThreshold
                                        $reportTranslate.GetAbrADDomainObject.FGPPLockoutObservationWindow = $FGPP.LockoutObservationWindow.toString("mm' minutes'")
                                        $reportTranslate.GetAbrADDomainObject.FGPPMaxPasswordAge = $FGPP.MaxPasswordAge.toString("dd' days'")
                                        $reportTranslate.GetAbrADDomainObject.FGPPMinPasswordAge = $FGPP.MinPasswordAge.toString("dd' days'")
                                        $reportTranslate.GetAbrADDomainObject.FGPPMinPasswordLength = $FGPP.MinPasswordLength
                                        $reportTranslate.GetAbrADDomainObject.FGPPPasswordHistoryCount = $FGPP.PasswordHistoryCount
                                        $reportTranslate.GetAbrADDomainObject.FGPPReversibleEncryptionEnabled = $FGPP.ReversibleEncryptionEnabled
                                        $reportTranslate.GetAbrADDomainObject.FGPPPrecedence = $FGPP.Precedence
                                        $reportTranslate.GetAbrADDomainObject.FGPPAppliesTo = $Accounts -join ', '
                                    }
                                    $FGPPInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($FGPP in $FGPPInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($FGPP.$($reportTranslate.GetAbrADDomainObject.FGPPName))" {
                                        $TableParams = @{
                                            Name = "$($reportTranslate.GetAbrADDomainObject.FGPPName) - $($FGPP.Name)"
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
                                    Name = "$($reportTranslate.GetAbrADDomainObject.FineGrainedPasswordPoliciesSection) -  $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = $reportTranslate.GetAbrADDomainObject.FGPPName, $reportTranslate.GetAbrADDomainObject.FGPPLockoutDuration, $reportTranslate.GetAbrADDomainObject.FGPPMaxPasswordAge, $reportTranslate.GetAbrADDomainObject.FGPPMinPasswordAge, $reportTranslate.GetAbrADDomainObject.FGPPMinPasswordLength, $reportTranslate.GetAbrADDomainObject.FGPPPasswordHistoryCount
                                    ColumnWidths = 20, 20, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $FGPPInfo | Table @TableParams
                            }
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Fined Grained Password Policies'
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Fined Grained Password Policies)"
            }

            try {
                if ($Domain.DNSRoot -eq $ADSystem.RootDomain) {
                    foreach ($Item in $Domain) {
                        $LAPS = try { Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-ADObject -Server ($using:Domain).PDCEmulator "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$(($using:Domain).distinguishedName)" -ErrorAction SilentlyContinue } | Sort-Object -Property Name } catch { Out-Null }
                        Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.MicrosoftLAPSSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Microsoft LAPS'
                            $LAPSInfo = [System.Collections.ArrayList]::new()
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDomainObject.LAPSName = $reportTranslate.GetAbrADDomainObject.LAPSName_Value
                                    $reportTranslate.GetAbrADDomainObject.LAPSDomainName = $Item
                                    $reportTranslate.GetAbrADDomainObject.LAPSEnabled = switch ($LAPS.Count) {
                                        0 { 'No' }
                                        default { 'Yes' }
                                    }
                                    $reportTranslate.GetAbrADDomainObject.LAPSDistinguishedName = $LAPS.DistinguishedName

                                }
                                $LAPSInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                if ($HealthCheck.Domain.Security) {
                                    $LAPSInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LAPSEnabled) -eq 'No' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.LAPSEnabled
                                }

                            } catch {
                                Write-PScriboMessage -IsWarning $($_.Exception.Message)
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($LAP in $LAPSInfo) {
                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainObject.MicrosoftLAPSSection) - $($Domain.DNSRoot.ToString().ToUpper())"
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
                                    Name = "$($reportTranslate.GetAbrADDomainObject.MicrosoftLAPSSection) -  $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = $reportTranslate.GetAbrADDomainObject.LAPSName, $reportTranslate.GetAbrADDomainObject.LAPSDomainName, $reportTranslate.GetAbrADDomainObject.LAPSEnabled
                                    ColumnWidths = 34, 33, 33
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $LAPSInfo | Table @TableParams
                            }

                            if ($HealthCheck.Domain.Security -and ($LAPSInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.LAPSEnabled) -eq 'No' })) {
                                Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                    Text $reportTranslate.GetAbrADDomainObject.LAPSInstalledBP
                                }
                            }
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Microsoft LAPS'
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Windows LAPS)"
            }

            try {
                try {
                    if ($GMSA = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADServiceAccount -Server $using:ValidDcFromDomain -Filter * -Properties * }) {
                        Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.GMSASection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'gMSA Identities'
                            $GMSAInfo = [System.Collections.ArrayList]::new()
                            foreach ($Account in $GMSA) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADDomainObject.GMSAName = $Account.Name
                                        $reportTranslate.GetAbrADDomainObject.GMSASamAccountName = $Account.SamAccountName
                                        $reportTranslate.GetAbrADDomainObject.GMSACreated = switch ($Account.Created) {
                                            $null { '--' }
                                            default { $Account.Created.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADDomainObject.GMSAEnabled = $Account.Enabled
                                        $reportTranslate.GetAbrADDomainObject.GMSADNSHostName = $Account.DNSHostName
                                        $reportTranslate.GetAbrADDomainObject.GMSAHostComputers = ((ConvertTo-ADObjectName -DN $Account.HostComputers -Session $TempPssSession -DC $ValidDcFromDomain) -join ', ')
                                        $reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword = ((ConvertTo-ADObjectName $Account.PrincipalsAllowedToRetrieveManagedPassword -Session $TempPssSession -DC $ValidDcFromDomain) -join ', ')
                                        $reportTranslate.GetAbrADDomainObject.GMSAPrimaryGroup = (ConvertTo-ADObjectName $Account.PrimaryGroup -Session $TempPssSession -DC $ValidDcFromDomain) -join ', '
                                        $reportTranslate.GetAbrADDomainObject.GMSALastLogonDate = switch ($Account.LastLogonDate) {
                                            $null { '--' }
                                            default { $Account.LastLogonDate.ToShortDateString() }
                                        }
                                        $reportTranslate.GetAbrADDomainObject.GMSALockedOut = $Account.LockedOut
                                        $reportTranslate.GetAbrADDomainObject.GMSALogonCount = $Account.logonCount
                                        $reportTranslate.GetAbrADDomainObject.GMSAPasswordExpired = $Account.PasswordExpired
                                        $reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet = switch ([string]::IsNullOrEmpty($Account.PasswordLastSet)) {
                                            $true { '--' }
                                            $false { $Account.PasswordLastSet.ToShortDateString() }
                                            default { 'Unknown' }
                                        }
                                    }
                                    $GMSAInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Group Managed Service Accounts Item)"
                                }
                            }

                            if ($HealthCheck.Domain.GMSA) {
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAEnabled) -ne 'Yes' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSAEnabled
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet) -ne '--' -and [datetime]$_.$($reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet) -lt (Get-Date).adddays(-60) } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -ne '--' -and [datetime]$_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -lt (Get-Date).adddays(-60) } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSALastLogonDate
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSALastLogonDate
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '--' })) {
                                    $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) = '*' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate)
                                }
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -ne '*--' -and [datetime]$_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -lt (Get-Date).adddays(-60) })) {
                                    $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) = '*' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate)
                                }
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALockedOut) -eq 'Yes' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSALockedOut
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALogonCount) -eq 0 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSALogonCount
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAPasswordExpired) -eq 'Yes' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSAPasswordExpired
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSAHostComputers
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers) -eq '--' })) {
                                    $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers) = '**' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers)
                                }
                                $GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword
                                foreach ( $OBJ in ($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword) -eq '--' })) {
                                    $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword) = '***' + $OBJ.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword)
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($Account in $GMSAInfo) {
                                    Section -Style NOTOCHeading4 -ExcludeFromTOC "$($Account.$($reportTranslate.GetAbrADDomainObject.GMSAName))" {
                                        $TableParams = @{
                                            Name = "gMSA - $($Account.$($reportTranslate.GetAbrADDomainObject.GMSAName))"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $Account | Table @TableParams
                                        if (($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -ne '*--' -or $_.$($reportTranslate.GetAbrADDomainObject.GMSAEnabled) -ne 'Yes' -or ($_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '--') }) -or ($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers) -eq '**--' }) -or ($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword) -eq '**--' })) {
                                            Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                            BlankLine
                                            Paragraph $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                            if ($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -ne '*--' -or $_.$($reportTranslate.GetAbrADDomainObject.GMSAEnabled) -ne 'Yes' -or ($_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '*--') -and ($_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -match '\*') }) {
                                                BlankLine
                                                Paragraph {
                                                    Text $reportTranslate.GetAbrADDomainObject.GMSAInactiveBP
                                                }
                                            }
                                            if ($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSAHostComputers) -eq '**--' }) {
                                                BlankLine
                                                Paragraph {
                                                    Text $reportTranslate.GetAbrADDomainObject.GMSANoHostComputersBP
                                                }
                                            }
                                            if ($Account | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSARetrieveManagedPassword) -eq '***--' }) {
                                                BlankLine
                                                Paragraph {
                                                    Text $reportTranslate.GetAbrADDomainObject.GMSANoRetrieveManagedPasswordBP
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "gMSA - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    Columns = $reportTranslate.GetAbrADDomainObject.GMSAName, $reportTranslate.GetAbrADDomainObject.GMSALogonCount, $reportTranslate.GetAbrADDomainObject.GMSALockedOut, $reportTranslate.GetAbrADDomainObject.GMSALastLogonDate, $reportTranslate.GetAbrADDomainObject.GMSAPasswordLastSet, $reportTranslate.GetAbrADDomainObject.GMSAEnabled
                                    ColumnWidths = 25, 15, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $GMSAInfo | Table @TableParams
                                if (($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '*--' -or $_.$($reportTranslate.GetAbrADDomainObject.GMSAEnabled) -ne 'Yes' -or ($_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '--') })) {
                                    Paragraph $reportTranslate.GetAbrADDomainObject.HealthCheck -Bold -Underline
                                    BlankLine
                                    if ($GMSAInfo | Where-Object { $_.$($reportTranslate.GetAbrADDomainObject.GMSALastLogonDate) -eq '*--' }) {
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDomainObject.SecurityBestPractice -Bold
                                            Text $reportTranslate.GetAbrADDomainObject.GMSAInactiveBP
                                        }
                                    }
                                }
                            }
                            Show-AbrDebugExecutionTime -End -TitleMessage 'gMSA Identities'
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
                        Section -Style Heading3 $reportTranslate.GetAbrADDomainObject.FSPSection {
                            Show-AbrDebugExecutionTime -Start -TitleMessage 'Foreign Security Principals'
                            $FSPInfo = [System.Collections.ArrayList]::new()
                            foreach ($Account in $FSP) {
                                try {
                                    $inObj = [ordered] @{
                                        $reportTranslate.GetAbrADDomainObject.FSPName = $Account.'msds-principalname'
                                        $reportTranslate.GetAbrADDomainObject.FSPPrincipalName = $Account.memberof | ForEach-Object {
                                            if ($Null -ne $_) {
                                                ConvertTo-ADObjectName -DN $_ -Session $TempPssSession -DC $ValidDcFromDomain
                                            } else {
                                                '--'
                                            }
                                        }
                                    }
                                    $FSPInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Foreign Security Principals Item)"
                                }
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADDomainObject.FSPSection) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 50, 50
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $FSPInfo | Table @TableParams
                            Show-AbrDebugExecutionTime -End -TitleMessage 'Foreign Security Principals'
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
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Domain Objects'
    }

}