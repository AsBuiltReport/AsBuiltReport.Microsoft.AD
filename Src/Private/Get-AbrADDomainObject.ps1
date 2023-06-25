function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.13
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
        try {
            Section -Style Heading4 'Domain Object Stats' {
                if ($Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Object Count of domain $Domain."
                    try {
                        $ADLimitedProperties = @("Name","Enabled","SAMAccountname","DisplayName","Enabled","LastLogonDate","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired","PasswordExpired","SmartcardLogonRequired","AccountExpirationDate","AdminCount","Created","Modified","LastBadPasswordAttempt","badpwdcount","mail","CanonicalName","DistinguishedName","ServicePrincipalName","SIDHistory","PrimaryGroupID","UserAccountControl","CannotChangePassword","PwdLastSet","LockedOut","TrustedForDelegation","TrustedtoAuthForDelegation","msds-keyversionnumber","SID")
                        $script:DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        $script:Computers =  Invoke-Command -Session $TempPssSession {(Get-ADComputer -ResultPageSize 1000 -Server $using:DC -Filter * -Properties Enabled,OperatingSystem,lastlogontimestamp,PasswordLastSet,SIDHistory -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName)}
                        $Servers = $Computers | Where-Object { $_.OperatingSystem -like "Windows Ser*" } | Measure-Object
                        $script:Users = Invoke-Command -Session $TempPssSession {Get-ADUser -ResultPageSize 1000 -Server $using:DC -Filter * -Property $using:ADLimitedProperties -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName }
                        $script:PrivilegedUsers =  $Users | Where-Object {$_.AdminCount -eq 1}
                        $Group =  Invoke-Command -Session $TempPssSession {(Get-ADGroup -Server $using:DC -filter * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName) | Measure-Object}
                        $DomainController = Invoke-Command -Session $TempPssSession {(Get-ADDomainController -Server $using:DC -filter *) | Select-Object name | Measure-Object}
                        $GC = Invoke-Command -Session $TempPssSession {(Get-ADDomainController -Server $using:DC -filter {IsGlobalCatalog -eq "True"}) | Select-Object name | Measure-Object}

                        try {
                            $OutObj = @()
                            $inObj = [ordered] @{
                                'Computers' = $Computers.Count
                                'Servers' = $Servers.Count
                            }
                            $OutObj += [pscustomobject]$inobj

                            $TableParams = @{
                                Name = "Computers - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            if ($Options.EnableCharts) {
                                try {
                                    $sampleData = $inObj.GetEnumerator()

                                    $exampleChart = New-Chart -Name UserAccountsinAD -Width 600 -Height 400

                                    $addChartAreaParams = @{
                                        Chart = $exampleChart
                                        Name  = 'exampleChartArea'
                                    }
                                    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                                    $addChartSeriesParams = @{
                                        Chart             = $exampleChart
                                        ChartArea         = $exampleChartArea
                                        Name              = 'exampleChartSeries'
                                        XField            = 'name'
                                        YField            = 'value'
                                        Palette           = 'Blue'
                                        ColorPerDataPoint = $true
                                    }
                                    $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                                    $addChartLegendParams = @{
                                        Chart             = $exampleChart
                                        Name              = 'Category'
                                        TitleAlignment    = 'Center'
                                    }
                                    Add-ChartLegend @addChartLegendParams

                                    $addChartTitleParams = @{
                                        Chart     = $exampleChart
                                        ChartArea = $exampleChartArea
                                        Name      = 'ComputersObject'
                                        Text      = 'Computers Count'
                                        Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                                    }
                                    Add-ChartTitle @addChartTitleParams

                                    $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 'Computers' {
                                    if ($chartFileItem) {
                                        Image -Text 'Computers Object - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $($_.Exception.Message)
                        }
                        try {
                            $OutObj = @()
                            $inObj = [ordered] @{
                                'Domain Controller' = $DomainController.Count
                                'Global Catalog' = $GC.Count
                            }
                            $OutObj += [pscustomobject]$inobj

                            $TableParams = @{
                                Name = "Domain Controller - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            if ($Options.EnableCharts) {
                                try {
                                    $sampleData = $inObj.GetEnumerator()

                                    $exampleChart = New-Chart -Name UserAccountsinAD -Width 600 -Height 400

                                    $addChartAreaParams = @{
                                        Chart = $exampleChart
                                        Name  = 'exampleChartArea'
                                    }
                                    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                                    $addChartSeriesParams = @{
                                        Chart             = $exampleChart
                                        ChartArea         = $exampleChartArea
                                        Name              = 'exampleChartSeries'
                                        XField            = 'name'
                                        YField            = 'value'
                                        Palette           = 'Blue'
                                        ColorPerDataPoint = $true
                                    }
                                    $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                                    $addChartLegendParams = @{
                                        Chart             = $exampleChart
                                        Name              = 'Category'
                                        TitleAlignment    = 'Center'
                                    }
                                    Add-ChartLegend @addChartLegendParams

                                    $addChartTitleParams = @{
                                        Chart     = $exampleChart
                                        ChartArea = $exampleChartArea
                                        Name      = 'DomainControllerObject'
                                        Text      = 'Domain Controller Count'
                                        Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                                    }
                                    Add-ChartTitle @addChartTitleParams

                                    $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 'Domain Controller' {
                                    if ($chartFileItem) {
                                        Image -Text 'Domain Controller Object - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $($_.Exception.Message)
                        }
                        try {
                            $OutObj = @()
                            $inObj = [ordered] @{
                                'Users' = ($Users | Measure-Object).Count
                                'Privileged Users' = ($PrivilegedUsers | Measure-Object).Count
                                'Groups' = $Group.Count
                            }
                            $OutObj += [pscustomobject]$inobj

                            $TableParams = @{
                                Name = "User - $($Domain.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            if ($Options.EnableCharts) {
                                try {
                                    $sampleData = $inObj.GetEnumerator()

                                    $exampleChart = New-Chart -Name UserAccountsinAD -Width 600 -Height 400

                                    $addChartAreaParams = @{
                                        Chart = $exampleChart
                                        Name  = 'exampleChartArea'
                                    }
                                    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                                    $addChartSeriesParams = @{
                                        Chart             = $exampleChart
                                        ChartArea         = $exampleChartArea
                                        Name              = 'exampleChartSeries'
                                        XField            = 'name'
                                        YField            = 'value'
                                        Palette           = 'Blue'
                                        ColorPerDataPoint = $true
                                    }
                                    $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                                    $addChartLegendParams = @{
                                        Chart             = $exampleChart
                                        Name              = 'Category'
                                        TitleAlignment    = 'Center'
                                    }
                                    Add-ChartLegend @addChartLegendParams

                                    $addChartTitleParams = @{
                                        Chart     = $exampleChart
                                        ChartArea = $exampleChartArea
                                        Name      = 'UsersObject'
                                        Text      = 'Users Count'
                                        Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                                    }
                                    Add-ChartTitle @addChartTitleParams

                                    $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }
                            if ($OutObj) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 'Users' {
                                    if ($chartFileItem) {
                                        Image -Text 'Users Object  - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $($_.Exception.Message)
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Object Stats)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Object Stats)"
        }
        try {
            $OutObj = @()
            $DaysInactive = 90
            $dormanttime = ((Get-Date).AddDays(-90)).Date
            $passwordtime = (Get-Date).Adddays(-42)
            $CannotChangePassword = $Users | Where-Object {$_.CannotChangePassword}
            $PasswordNextLogon = $Users | Where-Object {$_.PasswordLastSet -eq 0 -or $_.PwdLastSet -eq 0}
            $passwordNeverExpires = $Users | Where-Object { $_.passwordNeverExpires -eq "true" }
            $SmartcardLogonRequired = $Users | Where-Object {$_.SmartcardLogonRequired -eq $True}
            $SidHistory = $Users | Select-Object -ExpandProperty SIDHistory
            $PasswordLastSet = $Users | Where-Object { $_.PasswordNeverExpires -eq $false -and $_.PasswordNotRequired -eq $false}
            $NeverloggedIn = $Users | Where-Object {-not $_.LastLogonDate}
            $Dormant = $Users | Where-Object {($_.LastLogonDate) -lt $dormanttime}
            $PasswordNotRequired = $Users | Where-Object {$_.PasswordNotRequired -eq $true}
            $AccountExpired = Invoke-Command -Session $TempPssSession {Search-ADAccount -Server $using:DC -AccountExpired}
            $AccountLockout = Invoke-Command -Session $TempPssSession {Search-ADAccount -Server $using:DC -LockedOut}
            $Categories = @('Total Users','Cannot Change Password','Password Never Expires','Must Change Password at Logon','Password Age (> 42 days)','SmartcardLogonRequired','SidHistory', 'Never Logged in','Dormant (> 90 days)','Password Not Required','Account Expired','Account Lockout')
            if ($Categories) {
                Write-PscriboMessage "Collecting User Accounts in Domain."
                foreach ($Category in $Categories) {
                    try {
                        if ($Category -eq 'Total Users') {
                            $Values = $Users
                        }
                        elseif ($Category -eq 'Cannot Change Password') {
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
                            'Enabled' = ($Values.Enabled -eq $True | Measure-Object).Count
                            'Enabled %' = Switch ($Users.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Users.Count * 100), 2)}
                            }
                            'Disabled' = ($Values.Enabled -eq $False | Measure-Object).Count
                            'Disabled %' = Switch ($Users.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Users.Count * 100), 2)}
                            }
                            'Total' = ($Values | Measure-Object).Count
                            'Total %' = Switch ($Users.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values | Measure-Object).Count / $Users.Count * 100), 2)}
                            }

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
                if ($Options.EnableCharts) {
                    try {
                        $sampleData = $OutObj

                        $exampleChart = New-Chart -Name UserAccountsinAD -Width 600 -Height 400

                        $addChartAreaParams = @{
                            Chart = $exampleChart
                            Name  = 'exampleChartArea'
                        }
                        $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                        $addChartSeriesParams = @{
                            Chart             = $exampleChart
                            ChartArea         = $exampleChartArea
                            Name              = 'exampleChartSeries'
                            XField            = 'Category'
                            YField            = 'Total'
                            Palette           = 'Blue'
                            ColorPerDataPoint = $true
                        }
                        $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                        $addChartLegendParams = @{
                            Chart             = $exampleChart
                            Name              = 'Category'
                            TitleAlignment    = 'Center'
                        }
                        Add-ChartLegend @addChartLegendParams

                        $addChartTitleParams = @{
                            Chart     = $exampleChart
                            ChartArea = $exampleChartArea
                            Name      = 'StatusofUsersAccounts'
                            Text      = 'Status of Users Accounts'
                            Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                        }
                        Add-ChartTitle @addChartTitleParams

                        $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $($_.Exception.Message)
                    }
                }
            }
            if ($OutObj) {
                Section -Style Heading4 'Status of Users Accounts' {
                    if ($chartFileItem) {
                        Image -Text 'Status of Users Accounts - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Privileged Group Stats' {
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting Privileged Group in Active Directory."
                    try {
                        $DomainSID = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity $using:Domain).domainsid.Value}
                        if ($Domain -eq $ADSystem.Name) {
                            $GroupsSID = "$DomainSID-512","$DomainSID-519",'S-1-5-32-544','S-1-5-32-549',"$DomainSID-1101",'S-1-5-32-555','S-1-5-32-557',"$DomainSID-526",'S-1-5-32-551',"$DomainSID-517",'S-1-5-32-550','S-1-5-32-548',"$DomainSID-518"
                        }
                        else {
                            $GroupsSID = "$DomainSID-512",'S-1-5-32-549',"$DomainSID-1101",'S-1-5-32-555','S-1-5-32-557',"$DomainSID-526",'S-1-5-32-551',"$DomainSID-517",'S-1-5-32-550','S-1-5-32-548'
                        }
                        if ($GroupsSID) {
                            foreach ($GroupSID in $GroupsSID) {
                                try {
                                    $Group = Invoke-Command -Session $TempPssSession {Get-ADGroup -Server $using:DC -Filter * | Where-Object {$_.SID -like $using:GroupSID}}
                                    if ($Group) {
                                        Write-PscriboMessage "Collecting Privileged Group $($Group.Name) with SID $($Group.SID)"
                                        $GroupObject = Invoke-Command -Session $TempPssSession {Get-ADGroupMember -Server $using:DC -Identity ($using:Group).Name -Recursive -ErrorAction SilentlyContinue}
                                        $inObj = [ordered] @{
                                            'Group Name' = $Group.Name
                                            'Count' = ($GroupObject | Measure-Object).Count
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Privileged Group in Active Directory item)"
                                }
                            }

                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Where-Object { $_.'Group Name' -eq 'Schema Admins' -and $_.Count -gt 1 } | Set-Style -Style Warning
                            }

                            $TableParams = @{
                                Name = "Privileged Group Stats - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 60, 40
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Group Name' | Table @TableParams
                            if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Group Name' -eq 'Schema Admins' -and $_.Count -gt 1 })) {
                                Paragraph "Health Check:" -Italic -Bold -Underline
                                BlankLine
                                Paragraph "Security Best Practice: The Schema Admins group is a privileged group in a forest root domain. Members of the Schema Admins group can make changes to the schema, which is the framework for the Active Directory forest. Changes to the schema are not frequently required. This group only contains the Built-in Administrator account by default. Additional accounts must only be added when changes to the schema are necessary and then must be removed." -Italic -Bold
                            }
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
            $OutObj = @()
            $DaysInactive = 90
            $dormanttime = (Get-Date).Adddays(-90)
            $passwordtime = (Get-Date).Adddays(-30)
            $Dormant = $Computers | Where-Object {[datetime]::FromFileTime($_.lastlogontimestamp) -lt $dormanttime}
            $PasswordAge = $Computers | Where-Object {$_.PasswordLastSet -le $passwordtime}
            $SidHistory = $Computers.SIDHistory
            $Categories = @('Total Computers', 'Dormant (> 90 days)','Password Age (> 30 days)','SidHistory')
            if ($Categories) {
                Write-PscriboMessage "Collecting Status of Computer Accounts."
                foreach ($Category in $Categories) {
                    try {
                        if ($Category -eq 'Total Computers') {
                            $Values = $Computers
                        }
                        elseif ($Category -eq 'Dormant (> 90 days)') {
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
                            'Enabled' = ($Values.Enabled -eq $True | Measure-Object).Count
                            'Enabled %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled -eq $True | Measure-Object).Count / $Computers.Count * 100), 2)}
                            }
                            'Disabled' = ($Values.Enabled -eq $False | Measure-Object).Count
                            'Disabled %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled -eq $False | Measure-Object).Count / $Computers.Count * 100), 2)}
                            }
                            'Total' = ($Values | Measure-Object).Count
                            'Total %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values | Measure-Object).Count / $Computers.Count * 100), 2)}
                            }

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
                if ($Options.EnableCharts) {
                    try {
                        $sampleData = $OutObj

                        $exampleChart = New-Chart -Name StatusofComputerAccounts -Width 600 -Height 400

                        $addChartAreaParams = @{
                            Chart = $exampleChart
                            Name  = 'exampleChartArea'
                        }
                        $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                        $addChartSeriesParams = @{
                            Chart             = $exampleChart
                            ChartArea         = $exampleChartArea
                            Name              = 'exampleChartSeries'
                            XField            = 'Category'
                            YField            = 'Total'
                            Palette           = 'Blue'
                            ColorPerDataPoint = $true
                        }
                        $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                        $addChartLegendParams = @{
                            Chart             = $exampleChart
                            Name              = 'Category'
                            TitleAlignment    = 'Center'
                        }
                        Add-ChartLegend @addChartLegendParams

                        $addChartTitleParams = @{
                            Chart     = $exampleChart
                            ChartArea = $exampleChartArea
                            Name      = 'StatusofComputerAccounts'
                            Text      = 'Computer Accounts'
                            Font      = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Arial', '12', [System.Drawing.FontStyle]::Bold)
                        }
                        Add-ChartTitle @addChartTitleParams

                        $chartFileItem = Export-Chart -Chart $exampleChart -Path (Get-Location).Path -Format "PNG" -PassThru
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $($_.Exception.Message)
                    }
                }
                if ($OutObj) {
                    Section -Style Heading4 'Status of Computer Accounts' {
                        if ($chartFileItem -and ($OutObj.'Total' | Measure-Object -Sum).Sum -ne 0) {
                            Image -Text 'Status of Computer Accounts - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
                        }
                        $OutObj | Table @TableParams
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $($_.Exception.Message)
        }
        try {
            Section -Style Heading4 'Operating Systems Count' {
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting Operating Systems in Active Directory."
                    try {
                        $OSObjects =  $Computers | Where-Object {$_.name -like '*' } | Group-Object -Property operatingSystem | Select-Object Name,Count
                        if ($OSObjects) {
                            foreach ($OSObject in $OSObjects) {
                                $inObj = [ordered] @{
                                    'Operating System' = Switch ([string]::IsNullOrEmpty($OSObject.Name)) {
                                        $True {'No OS Specified'}
                                        default {$OSObject.Name}
                                    }
                                    'Count' = $OSObject.Count
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            if ($HealthCheck.Domain.Security) {
                                $OutObj | Where-Object {$_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '*2003*' -or $_.'Operating System' -like '*2008*' -or $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '* 95*' -or $_.'Operating System' -like '* 7*' -or $_.'Operating System' -like '* 8 *'  -or $_.'Operating System' -like '* 98*' -or $_.'Operating System' -like '*XP*' -or $_.'Operating System' -like '* Vista*'} | Set-Style -Style Critical -Property 'Operating System'
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
                            if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object {$_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '*2003*' -or $_.'Operating System' -like '*2008*' -or $_.'Operating System' -like '* NT*' -or $_.'Operating System' -like '*2000*' -or $_.'Operating System' -like '* 95*' -or $_.'Operating System' -like '* 7*' -or $_.'Operating System' -like '* 8 *'  -or $_.'Operating System' -like '* 98*' -or $_.'Operating System' -like '*XP*' -or $_.'Operating System' -like '* Vista*'})) {
                                Paragraph "Health Check:" -Italic -Bold -Underline
                                BlankLine
                                Paragraph "Security Best Practice: Operating systems that are no longer supported for security updates are not maintained or updated for vulnerabilities leaving them open to potential attack. Organizations must transition to a supported operating system to ensure continued support and to increase the organization security posture" -Italic -Bold
                            }
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
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Default Domain Password Policy of domain $Item."
                    try {
                        $PasswordPolicy =  Invoke-Command -Session $TempPssSession {Get-ADDefaultDomainPasswordPolicy -Identity $using:Domain}
                        if ($PasswordPolicy) {
                            $inObj = [ordered] @{
                                'Password Must Meet Complexity Requirements' = ConvertTo-TextYN $PasswordPolicy.ComplexityEnabled
                                'Path' = ConvertTo-ADCanonicalName -DN $PasswordPolicy.DistinguishedName -Domain $Domain
                                'Lockout Duration' = $PasswordPolicy.LockoutDuration.toString("mm' minutes'")
                                'Lockout Threshold' = $PasswordPolicy.LockoutThreshold
                                'Lockout Observation Window' = $PasswordPolicy.LockoutObservationWindow.toString("mm' minutes'")
                                'Max Password Age' = $PasswordPolicy.MaxPasswordAge.toString("dd' days'")
                                'Min Password Age' = $PasswordPolicy.MinPasswordAge.toString("dd' days'")
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
        try {
            if ($Domain) {
                foreach ($Item in $Domain) {
                    Write-PscriboMessage "Collecting the Active Directory Fined Grained Password Policies of domain $Item."
                    $DCPDC =  Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty PDCEmulator}
                    $PasswordPolicy = Invoke-Command -Session $TempPssSession {Get-ADFineGrainedPasswordPolicy -Server $using:DCPDC -Filter {Name -like "*"} -Properties * -Searchbase (Get-ADDomain -Identity $using:Domain).distinguishedName} | Sort-Object -Property Name
                    if ($PasswordPolicy) {
                        Section -Style Heading4 'Fined Grained Password Policies' {
                            $FGPPInfo = @()
                            foreach ($FGPP in $PasswordPolicy) {
                                try {
                                    $Accounts = @()
                                    foreach ($ADObject in $FGPP.AppliesTo) {
                                        $Accounts += Invoke-Command -Session $TempPssSession {Get-ADObject $using:ADObject -Server $using:DC -Properties sAMAccountName | Select-Object -ExpandProperty sAMAccountName }
                                    }
                                    $inObj = [ordered] @{
                                        'Name' = $FGPP.Name
                                        'Domain Name' = $Item
                                        'Complexity Enabled' = ConvertTo-TextYN $FGPP.ComplexityEnabled
                                        'Path' = ConvertTo-ADCanonicalName -DN $FGPP.DistinguishedName -Domain $Domain
                                        'Lockout Duration' = $FGPP.LockoutDuration.toString("mm' minutes'")
                                        'Lockout Threshold' = $FGPP.LockoutThreshold
                                        'Lockout Observation Window' = $FGPP.LockoutObservationWindow.toString("mm' minutes'")
                                        'Max Password Age' = $FGPP.MaxPasswordAge.toString("dd' days'")
                                        'Min Password Age' = $FGPP.MinPasswordAge.toString("dd' days'")
                                        'Min Password Length' = $FGPP.MinPasswordLength
                                        'Password History Count' = $FGPP.PasswordHistoryCount
                                        'Reversible Encryption Enabled' = ConvertTo-TextYN $FGPP.ReversibleEncryptionEnabled
                                        'Precedence' = $FGPP.Precedence
                                        'Applies To' = $Accounts -join ", "
                                    }
                                    $FGPPInfo += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($FGPP in $FGPPInfo) {
                                    Section -Style NOTOCHeading5 -ExcludeFromTOC "$($FGPP.Name)" {
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
                                    Name = "Fined Grained Password Policies -  $($Domain.ToString().ToUpper())"
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
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Fined Grained Password Policies)"
        }

        try {
            if ($Domain -eq $ADSystem.RootDomain) {
                foreach ($Item in $Domain) {
                    Write-PscriboMessage "Collecting the Active Directory LAPS Policies from domain $Item."
                    $DomainInfo =  Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop}
                    $DCPDC =  Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty PDCEmulator}
                    $LAPS =  Invoke-Command -Session $TempPssSession {Get-ADObject -Server $using:DCPDC "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,$(($using:DomainInfo).DistinguishedName)"} | Sort-Object -Property Name
                    Section -Style Heading4 'Local Administrator Password Solution' {
                        $LAPSInfo = @()
                        try {
                            $inObj = [ordered] @{
                                'Name' = $LAPS.Name
                                'Domain Name' = $Item
                                'Enabled' = Switch ($LAPS.Count) {
                                    0 {'No'}
                                    default {'Yes'}
                                }
                                'Distinguished Name' = $LAPS.DistinguishedName

                            }
                            $LAPSInfo += [pscustomobject]$inobj

                            if ($HealthCheck.Domain.Security) {
                                $LAPSInfo | Where-Object { $_.'Enabled' -eq 'No' } | Set-Style -Style Warning
                            }

                        }
                        catch {
                            Write-PscriboMessage -IsWarning $($_.Exception.Message)
                        }

                        if ($InfoLevel.Domain -ge 2) {
                            foreach ($LAP in $LAPSInfo) {
                                $TableParams = @{
                                    Name = "Local Administrator Password Solution - $($Domain.ToString().ToUpper())"
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
                                Name = "Local Administrator Password Solution -  $($Domain.ToString().ToUpper())"
                                List = $false
                                Columns = 'Name', 'Domain Name', 'Enabled'
                                ColumnWidths = 34, 33, 33
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $LAPSInfo | Table @TableParams
                        }

                        if ($HealthCheck.Domain.Security -and ($LAPSInfo | Where-Object { $_.'Enabled' -eq 'No'  })) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Security Best Practice: LAPS simplifies password management while helping customers implement additional recommended defenses against cyberattacks. In particular, the solution mitigates the risk of lateral escalation that results when customers use the same administrative local account and password combination on their computers. Download, install, and configure Microsoft LAPS or a third-party solution." -Italic -Bold
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Local Administrator Password Solution)"
        }

        try {
            if ($Domain) {
                Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts for $Item."
                try {
                    Write-PScriboMessage "Collecting the Active Directory Group Managed Service Accounts from DC $DC."
                    $GMSA = Invoke-Command -Session $TempPssSession {Get-ADServiceAccount -Server $using:DC -Filter * -Properties *}
                    if ($GMSA) {
                        Section -Style Heading4 'gMSA identities' {
                            $GMSAInfo = @()
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
                                    $GMSAInfo += [pscustomobject]$inobj

                                    if ($HealthCheck.Domain.GMSA) {
                                        $GMSAInfo | Where-Object { $_.'Enabled' -notlike 'Yes'} | Set-Style -Style Warning -Property 'Enabled'
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Group Managed Service Accounts)"
                                }
                            }

                            if ($InfoLevel.Domain -ge 2) {
                                foreach ($Account in $GMSAInfo) {
                                    Section -Style NOTOCHeading5 -ExcludeFromTOC "$($Account.Name)" {
                                        $TableParams = @{
                                            Name = "gMSA - $($Account.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $Account | Table @TableParams
                                    }
                                }
                            } else {
                                $TableParams = @{
                                    Name = "gMSA - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    Columns = 'Name', 'SamAccountName', 'DNS Host Name', 'Host Computers', 'Retrieve Managed Password', 'Primary Group', 'Enabled'
                                    ColumnWidths = 16, 14, 16, 14, 14, 14, 12
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $GMSAInfo | Table @TableParams
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
    }

    end {}

}