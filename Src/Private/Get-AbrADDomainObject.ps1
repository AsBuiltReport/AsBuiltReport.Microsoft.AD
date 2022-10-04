function Get-AbrADDomainObject {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Object information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.8
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
                        XField            = 'Status'
                        YField            = 'Count'
                        Palette           = 'Blue'
                        ColorPerDataPoint = $true
                    }
                    $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                    $addChartLegendParams = @{
                        Chart             = $exampleChart
                        Name              = 'Status'
                        TitleAlignment    = 'Center'
                    }
                    Add-ChartLegend @addChartLegendParams

                    $addChartTitleParams = @{
                        Chart     = $exampleChart
                        ChartArea = $exampleChartArea
                        Name      = 'UserAccountsinAD'
                        Text      = 'User Accounts'
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
                Section -Style Heading4 'User Accounts in Active Directory' {
                    if ($chartFileItem) {
                        Image -Text 'User Accounts in Active Directory - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
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
            $DaysInactive = 90
            $dormanttime = ((Get-Date).AddDays(-90)).Date
            $passwordtime = (Get-Date).Adddays(-42)
            $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
            $Users = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter * -Properties *}
            $CannotChangePassword = Invoke-Command -Session $TempPssSession {Get-ADUser -Server $using:DC -Filter * -Properties * | Where-Object {$_.CannotChangePassword}}
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
                            'Enabled Count' = ($Values.Enabled).Count
                            'Enabled %' = [math]::Round((($Values.Enabled).Count / $Users.Count * 100), 0)
                            'Disabled Count' = ($Null -eq $Values.Enabled).Count
                            'Disabled %' = [math]::Round((($Null -eq $Values.Enabled).Count / $Users.Count * 100), 0)
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
                        YField            = 'Total Count'
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
            Section -Style Heading4 'Privileged Group Count' {
                $OutObj = @()
                if ($Domain) {
                    Write-PscriboMessage "Collecting Privileged Group in Active Directory."
                    try {
                        $DomainSID = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity $using:Domain).domainsid.Value}
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        if ($Domain -eq $ADSystem.Name) {
                            #$Groups = 'Domain Admins','Enterprise Admins','Administrators','Server Operators','DnsAdmins','Remote Desktop Users','Incoming Forest Trust Builders','Key Admins','Backup Operators','Cert Publishers','Print Operators','Account Operators','Schema Admins'
                            $GroupsSID = "$DomainSID-512","$DomainSID-519",'S-1-5-32-544','S-1-5-32-549',"$DomainSID-1101",'S-1-5-32-555','S-1-5-32-557',"$DomainSID-526",'S-1-5-32-551',"$DomainSID-517",'S-1-5-32-550','S-1-5-32-548',"$DomainSID-518"
                        }
                        else {
                            #$Groups = 'Domain Admins','Server Operators','DnsAdmins','Remote Desktop Users','Key Admins','Backup Operators','Cert Publishers','Print Operators','Account Operators'
                            $GroupsSID = "$DomainSID-512",'S-1-5-32-544','S-1-5-32-549',"$DomainSID-1101",'S-1-5-32-555','S-1-5-32-557',"$DomainSID-526",'S-1-5-32-551',"$DomainSID-517",'S-1-5-32-550','S-1-5-32-548'
                        }
                        if ($GroupsSID) {
                            foreach ($GroupSID in $GroupsSID) {
                                try {
                                    $Group = Invoke-Command -Session $TempPssSession {Get-ADGroup -Server $using:DC -Filter * | Select-Object -Property SID,Name | Where-Object {$_.SID -like $using:GroupSID}}
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
                                Name = "Privileged Group Count - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 60, 40
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Group Name' | Table @TableParams
                            if ($HealthCheck.Domain.Security -and ($OutObj | Where-Object { $_.'Group Name' -eq 'Schema Admins' -and $_.Count -gt 1 })) {
                                Paragraph "Health Check:" -Italic -Bold -Underline
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
            $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
            $Computers = Invoke-Command -Session $TempPssSession {Get-ADComputer -Server $using:DC -Filter * -Properties *}
            if ($Computers) {
                $Categories = @('Enabled','Disabled')
                Write-PscriboMessage "Collecting Computer Accounts in Active Directory."
                foreach ($Category in $Categories) {
                        try {
                        if ($Category -eq 'Enabled') {
                            $Values = $Computers.Enabled -eq $True
                        }
                        else {$Values = $Computers.Enabled -eq $False}
                        $inObj = [ordered] @{
                            'Status' = $Category
                            'Count' = $Values.Count
                            'Percentage' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {"$([math]::Round((($Values).Count / $Computers.Count * 100), 0))%"}
                            }
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Computer Accounts in Active Directory)"
                    }
                }

                $TableParams = @{
                    Name = "Computer Accounts in Active Directory - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 50, 25, 25
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                try {
                    $sampleData = $OutObj

                    $exampleChart = New-Chart -Name ComputerAccountsinAD -Width 600 -Height 400

                    $addChartAreaParams = @{
                        Chart = $exampleChart
                        Name  = 'exampleChartArea'
                    }
                    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

                    $addChartSeriesParams = @{
                        Chart             = $exampleChart
                        ChartArea         = $exampleChartArea
                        Name              = 'exampleChartSeries'
                        XField            = 'Status'
                        YField            = 'Count'
                        Palette           = 'Blue'
                        ColorPerDataPoint = $true
                    }
                    $exampleChartSeries = $sampleData | Add-PieChartSeries @addChartSeriesParams -PassThru

                    $addChartLegendParams = @{
                        Chart             = $exampleChart
                        Name              = 'Status'
                        TitleAlignment    = 'Center'
                    }
                    Add-ChartLegend @addChartLegendParams

                    $addChartTitleParams = @{
                        Chart     = $exampleChart
                        ChartArea = $exampleChartArea
                        Name      = 'ComputerAccountsinAD'
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
                Section -Style Heading4 'Computer Accounts in Active Directory' {
                    if ($chartFileItem) {
                        Image -Text 'Computer Accounts in Active Directory - Diagram' -Align 'Center' -Percent 100 -Path $chartFileItem
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
                Write-PscriboMessage "Collecting Status of Computer Accounts."
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
                            'Enabled Count' = ($Values.Enabled).Count
                            'Enabled %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled).Count / $Computers.Count * 100), 0)}
                            }
                            'Disabled Count' = ($Null -eq $Values.Enabled).Count
                            'Disabled %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Null -eq $Values.Enabled).Count / $Computers.Count * 100), 0)}
                            }
                            'Total Count' = ($Values.Enabled).Count
                            'Total %' = Switch ($Computers.Count) {
                                0 {'0'}
                                $Null {'0'}
                                default {[math]::Round((($Values.Enabled).Count / $Computers.Count * 100), 0)}
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
                        YField            = 'Total Count'
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
                if ($OutObj) {
                    Section -Style Heading4 'Status of Computer Accounts' {
                        if ($chartFileItem -and ($OutObj.'Total Count' | Measure-Object -Sum).Sum -ne 0) {
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
                        $DC = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Select-Object -First 1}
                        $OSObjects =  Invoke-Command -Session $TempPssSession {Get-ADComputer -Server $using:DC -Filter "name -like '*'" -Properties operatingSystem | Group-Object -Property operatingSystem | Select-Object Name,Count}
                        if ($OSObjects) {
                            foreach ($OSObject in $OSObjects) {
                                $inObj = [ordered] @{
                                    'Operating System' = Switch ([string]::IsNullOrEmpty($OSObject.Name)) {
                                        $True {'Unknown'}
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