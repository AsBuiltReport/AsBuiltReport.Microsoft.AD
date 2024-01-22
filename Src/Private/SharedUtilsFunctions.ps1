function ConvertTo-TextYN {
    <#
    .SYNOPSIS
    Used by As Built Report to convert true or false automatically to Yes or No.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         LEE DAILEY

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [AllowEmptyString()]
            [string]
            $TEXT
        )

    switch ($TEXT) {
            "" {"--"; break}
            $Null {"--"; break}
            "True" {"Yes"; break}
            "False" {"No"; break}
            default {$TEXT}
        }
    } # end

function ConvertTo-FileSizeString {
    <#
    .SYNOPSIS
    Used by As Built Report to convert bytes automatically to GB or TB based on size.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         LEE DAILEY

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [int64]
            $Size
        )

    switch ($Size) {
        {$_ -gt 1TB}
            {[string]::Format("{0:0.00} TB", $Size / 1TB); break}
        {$_ -gt 1GB}
            {[string]::Format("{0:0.00} GB", $Size / 1GB); break}
        {$_ -gt 1MB}
            {[string]::Format("{0:0.00} MB", $Size / 1MB); break}
        {$_ -gt 1KB}
            {[string]::Format("{0:0.00} KB", $Size / 1KB); break}
        {$_ -gt 0}
            {[string]::Format("{0} B", $Size); break}
        {$_ -eq 0}
            {"0 KB"; break}
        default
            {"0 KB"}
        }
    } # end >> function Format-FileSize

function Invoke-DcDiag {
    <#
    .SYNOPSIS
    Used by As Built Report to get the dcdiag tests for a Domain Controller.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Adam Bertram

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )
    $result = Invoke-Command -Session $TempPssSession {dcdiag /c /s:$using:DomainController}
    $result | select-string -pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
        $obj = @{
            TestName = $_.Matches.Groups[3].Value
            TestResult = $_.Matches.Groups[2].Value
            Entity = $_.Matches.Groups[1].Value
        }
        [pscustomobject]$obj
    }
}# end

function ConvertTo-EmptyToFiller {
        <#
        .SYNOPSIS
        Used by As Built Report to convert empty culumns to "--".
        .DESCRIPTION

        .NOTES
            Version:        0.4.0
            Author:         Jonathan Colon

        .EXAMPLE

        .LINK

        #>
        [CmdletBinding()]
        [OutputType([String])]
        Param
            (
            [Parameter (
                Position = 0,
                Mandatory)]
                [AllowEmptyString()]
                [string]
                $TEXT
            )

        switch ($TEXT) {
                "" {"--"; break}
                $Null {"--"; break}
                "True" {"Yes"; break}
                "False" {"No"; break}
                default {$TEXT}
            }
        } # end

function Convert-IpAddressToMaskLength {
    <#
    .SYNOPSIS
    Used by As Built Report to convert subnet mask to dotted notation.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Ronald Rink

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([String])]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $SubnetMask
        )

    [IPAddress] $MASK = $SubnetMask
    $octets = $MASK.IPAddressToString.Split('.')
    $result = $Null
    foreach ($octet in $octets) {
        while (0 -ne $octet) {
            $octet = ($octet -shl 1) -band [byte]::MaxValue
            $result++;
        }
    }
    return $result;
}

function ConvertTo-ADObjectName {
    <#
    .SYNOPSIS
    Used by As Built Report to translate Active Directory DN to Name.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Session,
        $DC
    )
    $ADObject = @()
    foreach ($Object in $DN) {
        $ADObject += Invoke-Command -Session $Session {Get-ADObject $using:Object -Server $using:DC | Select-Object -ExpandProperty Name}
    }
    return $ADObject;
}# end

function Get-ADObjectSearch {
    <#
    .SYNOPSIS
    Used by As Built Report to lookup Object subtree in Active Directory.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Session,
        $Filter,
        $Properties="*",
        $SelectPrty

    )
    $ADObject = @()
    foreach ($Object in $DN) {
        $ADObject += Invoke-Command -Session $Session {Get-ADObject -SearchBase $using:DN -SearchScope OneLevel -Filter $using:Filter -Properties $using:Properties -EA 0 | Select-Object $using:SelectPrty }
    }
    return $ADObject;
}# end

function ConvertTo-ADCanonicalName {
    <#
    .SYNOPSIS
    Used by As Built Report to translate Active Directory DN to CanonicalName.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        $DN,
        $Domain,
        $DC
    )
    $ADObject = @()
    $DC = Invoke-Command -Session $TempPssSession -ScriptBlock {Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName}
    foreach ($Object in $DN) {
        $ADObject += Invoke-Command -Session $TempPssSession {Get-ADObject $using:Object -Properties * -Server $using:DC| Select-Object -ExpandProperty CanonicalName}
    }
    return $ADObject;
}# end

function Copy-DictionaryManual {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [System.Collections.IDictionary] $Dictionary
    )

    $clone = @{}
    foreach ($Key in $Dictionary.Keys) {
        $value = $Dictionary.$Key

        $clonedValue = switch ($Dictionary.$Key) {
            { $null -eq $_ } {
                $null
                continue
            }
            { $_ -is [System.Collections.IDictionary] } {
                Copy-DictionaryManual -Dictionary $_
                continue
            }
            {
                $type = $_.GetType()
                $type.IsPrimitive -or $type.IsValueType -or $_ -is [string]
            } {
                $_
                continue
            }
            default {
                $_ | Select-Object -Property *
            }

        }

        if ($value -is [System.Collections.IList]) {
            $clone[$Key] = @($clonedValue)
        } else {
            $clone[$Key] = $clonedValue
        }
    }

    $clone
}
function Convert-TimeToDay {
    [CmdletBinding()]
    param (
        $StartTime,
        $EndTime,
        #[nullable[DateTime]] $StartTime, # can't use this just yet, some old code uses strings in StartTime/EndTime.
        #[nullable[DateTime]] $EndTime, # After that's fixed will change this.
        [string] $Ignore = '*1601*'
    )
    if ($null -ne $StartTime -and $null -ne $EndTime) {
        try {
            if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
                $Days = (NEW-TIMESPAN -Start $StartTime -End $EndTime).Days
            }
        } catch {}
    } elseif ($null -ne $EndTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (NEW-TIMESPAN -Start (Get-Date) -End ($EndTime)).Days
        }
    } elseif ($null -ne $StartTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (NEW-TIMESPAN -Start $StartTime -End (Get-Date)).Days
        }
    }
    return $Days
}
function Get-WinADLastBackup {
    <#
    .SYNOPSIS
    Gets Active directory forest or domain last backup time
    .DESCRIPTION
    Gets Active directory forest or domain last backup time
    .PARAMETER Domain
    Optionally you can pass Domains by hand
    .EXAMPLE
    $LastBackup = Get-WinADLastBackup
    $LastBackup | Format-Table -AutoSize
    .EXAMPLE
    $LastBackup = Get-WinADLastBackup -Domain 'ad.evotec.pl'
    $LastBackup | Format-Table -AutoSize
    .NOTES
    General notes
    #>
    [cmdletBinding()]
    param(
        [string[]] $Domains,
        [pscredential] $Credential
    )
    $NameUsed = [System.Collections.Generic.List[string]]::new()
    [DateTime] $CurrentDate = Get-Date
    if (-not $Domains) {
        try {
            $Forest = $ADSystem
            $Domains = $Forest.Domains
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
            break
        }
    }
    foreach ($Domain in $Domains) {
        try {
            [string[]]$Partitions = (Get-ADRootDSE -Credential $Credential -Server $Domain -ErrorAction Stop).namingContexts
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain, $Credential.UserName,$Credential.GetNetworkCredential().Password)
            [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error: $($_.Exception.Message)"
            break
        }
        $Output = ForEach ($Name in $Partitions) {
            if ($NameUsed -contains $Name) {
                continue
            } else {
                $NameUsed.Add($Name)
            }
            $domainControllerMetadata = $domainController.GetReplicationMetadata($Name)
            $dsaSignature = $domainControllerMetadata.Item("dsaSignature")
            $LastBackup = [DateTime] $($dsaSignature.LastOriginatingChangeTime)
            [PSCustomObject] @{
                Domain            = $Domain
                NamingContext     = $Name
                LastBackup        = $LastBackup
                LastBackupDaysAgo = - (Convert-TimeToDay -StartTime ($CurrentDate) -EndTime ($LastBackup))
            }
        }
        $Output
    }
}
function Get-WinADDFSHealth {
    <#
    .SYNOPSIS
    Used by As Built Report to get DFS health AD forest info.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>
    [cmdletBinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [string[]] $ExcludeDomainControllers,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [alias('DomainControllers')][string[]] $IncludeDomainControllers,
        [switch] $SkipRODC,
        [int] $EventDays = 1,
        [switch] $SkipGPO,
        [switch] $SkipAutodetection,
        [System.Collections.IDictionary] $ExtendedForestInformation,
        [pscredential] $Credential
    )
    $Today = (Get-Date)
    $Yesterday = (Get-Date -Hour 0 -Second 0 -Minute 0 -Millisecond 0).AddDays(-$EventDays)

    if (-not $SkipAutodetection) {
        $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExcludeDomainControllers $ExcludeDomainControllers -IncludeDomainControllers $IncludeDomainControllers -SkipRODC:$SkipRODC -ExtendedForestInformation $ExtendedForestInformation -Extended -Credential $Credential
    } else {
        if (-not $IncludeDomains) {
            Write-Warning "Get-WinADDFSHealth - You need to specify domain when using SkipAutodetection."
            return
        }
        # This is for case when Get-ADDomainController -Filter * is broken
        $ForestInformation = @{
            Domains                 = $IncludeDomains
            DomainDomainControllers = @{}
        }
        foreach ($Domain in $IncludeDomains) {
            $ForestInformation['DomainDomainControllers'][$Domain] = [System.Collections.Generic.List[Object]]::new()
            foreach ($DC in $IncludeDomainControllers) {
                try {
                    $DCInformation = Get-ADDomainController -Identity $DC -Server $Domain -ErrorAction Stop -Credential $Credential
                    Add-Member -InputObject $DCInformation -MemberType NoteProperty -Value $DCInformation.ComputerObjectDN -Name 'DistinguishedName' -Force
                    $ForestInformation['DomainDomainControllers'][$Domain].Add($DCInformation)
                } catch {
                    Write-Warning "Get-WinADDFSHealth - Can't get DC details. Skipping with error: $($_.Exception.Message)"
                    continue
                }
            }
        }
    }
    [Array] $Table = foreach ($Domain in $ForestInformation.Domains) {
        Write-Verbose "Get-WinADDFSHealth - Processing $Domain"
        [Array] $DomainControllersFull = $ForestInformation['DomainDomainControllers']["$Domain"]
        if ($DomainControllersFull.Count -eq 0) {
            continue
        }
        if (-not $SkipAutodetection) {
            $QueryServer = $ForestInformation['QueryServers']["$Domain"].HostName[0]
        } else {
            $QueryServer = $DomainControllersFull[0].HostName
        }
        if (-not $SkipGPO) {
            try {
                #[Array]$GPOs = @(Get-GPO -All -Domain $Domain -Server $QueryServer)
                $SystemsContainer = $ForestInformation['DomainsExtended'][$Domain].SystemsContainer
                if ($SystemsContainer) {
                    $PoliciesSearchBase = -join ("CN=Policies,", $SystemsContainer)
                }
                [Array]$GPOs = Get-ADObject -ErrorAction Stop -SearchBase $PoliciesSearchBase -SearchScope OneLevel -Filter * -Server $QueryServer -Properties Name, gPCFileSysPath, DisplayName, DistinguishedName, Description, Created, Modified, ObjectClass, ObjectGUID -Credential $Credential
            } catch {
                $GPOs = $null
            }
        }
        try {
            $CentralRepository = Get-ChildItem -Path "\\$Domain\SYSVOL\$Domain\policies\PolicyDefinitions" -ErrorAction Stop
            $CentralRepositoryDomain = if ($CentralRepository) { $true } else { $false }
        } catch {
            $CentralRepositoryDomain = $false
        }

        foreach ($DC in $DomainControllersFull) {
            Write-Verbose "Get-WinADDFSHealth - Processing $($DC.Name) $($DC.HostName) for $Domain"
            $DCName = $DC.Name
            $Hostname = $DC.Hostname
            $DN = $DC.DistinguishedName

            $LocalSettings = "CN=DFSR-LocalSettings,$DN"
            $Subscriber = "CN=Domain System Volume,$LocalSettings"
            $Subscription = "CN=SYSVOL Subscription,$Subscriber"

            $ReplicationStatus = @{
                '0' = 'Uninitialized'
                '1' = 'Initialized'
                '2' = 'Initial synchronization'
                '3' = 'Auto recovery'
                '4' = 'Normal'
                '5' = 'In error state'
                '6' = 'Disabled'
                '7' = 'Unknown'
            }

            $DomainSummary = [ordered] @{
                "DomainController"              = $DCName
                "Domain"                        = $Domain
                "Status"                        = $false
                "ReplicationState"              = 'Unknown'
                "IsPDC"                         = $DC.OperationMasterRoles -contains 'PDCEmulator'
                'GroupPolicyOutput'             = $null -ne $GPOs # This shows whether output was on Get-GPO
                "GroupPolicyCount"              = if ($GPOs) { $GPOs.Count } else { 0 };
                "SYSVOLCount"                   = 0
                'CentralRepository'             = $CentralRepositoryDomain
                'CentralRepositoryDC'           = $false
                'IdenticalCount'                = $false
                "Availability"                  = $false
                "MemberReference"               = $false
                "DFSErrors"                     = 0
                "DFSEvents"                     = $null
                "DFSLocalSetting"               = $false
                "DomainSystemVolume"            = $false
                "SYSVOLSubscription"            = $false
                "StopReplicationOnAutoRecovery" = $false
                "DFSReplicatedFolderInfo"       = $null
            }
            if ($SkipGPO) {
                $DomainSummary.Remove('GroupPolicyOutput')
                $DomainSummary.Remove('GroupPolicyCount')
                $DomainSummary.Remove('SYSVOLCount')
            }

            $WarningVar = $null
            $DFSReplicatedFolderInfoAll = Get-CimData -NameSpace "root\microsoftdfs" -Class 'dfsrreplicatedfolderinfo' -ComputerName $Hostname -WarningAction SilentlyContinue -WarningVariable WarningVar -Verbose:$false
            $DFSReplicatedFolderInfo = $DFSReplicatedFolderInfoAll | Where-Object { $_.ReplicationGroupName -eq 'Domain System Volume' }
            if ($WarningVar) {
                $DomainSummary['ReplicationState'] = 'Unknown'
                #$DomainSummary['ReplicationState'] = $WarningVar -join ', '
            } else {
                $DomainSummary['ReplicationState'] = $ReplicationStatus["$($DFSReplicatedFolderInfo.State)"]
            }
            try {
                $CentralRepositoryDC = Get-ChildItem -Path "\\$Hostname\SYSVOL\$Domain\policies\PolicyDefinitions" -ErrorAction Stop
                $DomainSummary['CentralRepositoryDC'] = if ($CentralRepositoryDC) { $true } else { $false }
            } catch {
                $DomainSummary['CentralRepositoryDC'] = $false
            }
            try {
                $MemberReference = (Get-ADObject -Credential $Credential -Identity $Subscriber -Properties msDFSR-MemberReference -Server $QueryServer -ErrorAction Stop).'msDFSR-MemberReference' -like "CN=$DCName,*"
                $DomainSummary['MemberReference'] = if ($MemberReference) { $true } else { $false }
            } catch {
                $DomainSummary['MemberReference'] = $false
            }
            try {
                $DFSLocalSetting = Get-ADObject -Credential $Credential -Identity $LocalSettings -Server $QueryServer -ErrorAction Stop
                $DomainSummary['DFSLocalSetting'] = if ($DFSLocalSetting) { $true } else { $false }
            } catch {
                $DomainSummary['DFSLocalSetting'] = $false
            }

            try {
                $DomainSystemVolume = Get-ADObject -Credential $Credential -Identity $Subscriber -Server $QueryServer -ErrorAction Stop
                $DomainSummary['DomainSystemVolume'] = if ($DomainSystemVolume) { $true } else { $false }
            } catch {
                $DomainSummary['DomainSystemVolume'] = $false
            }
            try {
                $SysVolSubscription = Get-ADObject -Credential $Credential -Identity $Subscription -Server $QueryServer -ErrorAction Stop
                $DomainSummary['SYSVOLSubscription'] = if ($SysVolSubscription) { $true } else { $false }
            } catch {
                $DomainSummary['SYSVOLSubscription'] = $false
            }
            if (-not $SkipGPO) {
                try {
                    [Array] $SYSVOL = Get-ChildItem -Path "\\$Hostname\SYSVOL\$Domain\Policies" -Exclude "PolicyDefinitions*" -ErrorAction Stop
                    $DomainSummary['SysvolCount'] = $SYSVOL.Count
                } catch {
                    $DomainSummary['SysvolCount'] = 0
                }
            }
            if (Test-Connection $Hostname -ErrorAction SilentlyContinue) {
                $DomainSummary['Availability'] = $true
            } else {
                $DomainSummary['Availability'] = $false
            }
            try {
                [Array] $Events = Get-Events -LogName "DFS Replication" -Level Error -ComputerName $Hostname -DateFrom $Yesterday -DateTo $Today
                $DomainSummary['DFSErrors'] = $Events.Count
                $DomainSummary['DFSEvents'] = $Events
            } catch {
                $DomainSummary['DFSErrors'] = $null
            }
            $DomainSummary['IdenticalCount'] = $DomainSummary['GroupPolicyCount'] -eq $DomainSummary['SYSVOLCount']

            try {
                $Registry = Get-PSRegistry -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Services\DFSR\Parameters" -ComputerName $Hostname -ErrorAction Stop
            } catch {
                #$ErrorMessage = $_.Exception.Message
                $Registry = $null
            }
            if ($null -ne $Registry.StopReplicationOnAutoRecovery) {
                $DomainSummary['StopReplicationOnAutoRecovery'] = [bool] $Registry.StopReplicationOnAutoRecovery
            } else {
                $DomainSummary['StopReplicationOnAutoRecovery'] = $null
                # $DomainSummary['StopReplicationOnAutoRecovery'] = $ErrorMessage
            }
            $DomainSummary['DFSReplicatedFolderInfo'] = $DFSReplicatedFolderInfoAll

            $All = @(
                if (-not $SkipGPO) {
                    $DomainSummary['GroupPolicyOutput']
                }
                $DomainSummary['SYSVOLSubscription']
                $DomainSummary['ReplicationState'] -eq 'Normal'
                $DomainSummary['DomainSystemVolume']
                $DomainSummary['DFSLocalSetting']
                $DomainSummary['MemberReference']
                $DomainSummary['Availability']
                $DomainSummary['IdenticalCount']
                $DomainSummary['DFSErrors'] -eq 0
            )
            $DomainSummary['Status'] = $All -notcontains $false
            [PSCustomObject] $DomainSummary
        }
    }
    $Table
}

function ConvertTo-OperatingSystem {
    <#
    .SYNOPSIS
    Allows easy conversion of OperatingSystem, Operating System Version to proper Windows 10 naming based on WMI or AD

    .DESCRIPTION
    Allows easy conversion of OperatingSystem, Operating System Version to proper Windows 10 naming based on WMI or AD

    .PARAMETER OperatingSystem
    Operating System as returned by Active Directory

    .PARAMETER OperatingSystemVersion
    Operating System Version as returned by Active Directory

    .EXAMPLE
    $Computers = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion | ForEach-Object {
        $OPS = ConvertTo-OperatingSystem -OperatingSystem $_.OperatingSystem -OperatingSystemVersion $_.OperatingSystemVersion
        Add-Member -MemberType NoteProperty -Name 'OperatingSystemTranslated' -Value $OPS -InputObject $_ -Force
        $_
    }
    $Computers | Select-Object DNS*, Name, SamAccountName, Enabled, OperatingSystem*, DistinguishedName | Format-Table

    .EXAMPLE
    $Registry = Get-PSRegistry -ComputerName 'AD1' -RegistryPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    ConvertTo-OperatingSystem -OperatingSystem $Registry.ProductName -OperatingSystemVersion $Registry.CurrentBuildNumber

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [string] $OperatingSystem,
        [string] $OperatingSystemVersion
    )

    if ($OperatingSystem -like 'Windows 10*' -or $OperatingSystem -like 'Windows 11*') {
        $Systems = @{
            # This is how it's written in AD
            '10.0 (22000)' = 'Windows 11 21H2'
            '10.0 (19043)' = 'Windows 10 21H1'
            '10.0 (19042)' = 'Windows 10 20H2'
            '10.0 (19041)' = 'Windows 10 2004'
            '10.0 (18898)' = 'Windows 10 Insider Preview'
            '10.0 (18363)' = "Windows 10 1909"
            '10.0 (18362)' = "Windows 10 1903"
            '10.0 (17763)' = "Windows 10 1809"
            '10.0 (17134)' = "Windows 10 1803"
            '10.0 (16299)' = "Windows 10 1709"
            '10.0 (15063)' = "Windows 10 1703"
            '10.0 (14393)' = "Windows 10 1607"
            '10.0 (10586)' = "Windows 10 1511"
            '10.0 (10240)' = "Windows 10 1507"

            # This is how WMI/CIM stores it
            '10.0.22000'   = 'Windows 11 21H2'
            '10.0.19043'   = 'Windows 10 21H1'
            '10.0.19042'   = 'Windows 10 20H2'
            '10.0.19041'   = 'Windows 10 2004'
            '10.0.18898'   = 'Windows 10 Insider Preview'
            '10.0.18363'   = "Windows 10 1909"
            '10.0.18362'   = "Windows 10 1903"
            '10.0.17763'   = "Windows 10 1809"
            '10.0.17134'   = "Windows 10 1803"
            '10.0.16299'   = "Windows 10 1709"
            '10.0.15063'   = "Windows 10 1703"
            '10.0.14393'   = "Windows 10 1607"
            '10.0.10586'   = "Windows 10 1511"
            '10.0.10240'   = "Windows 10 1507"

            # This is how it's written in registry
            '22000'        = 'Windows 11 21H2'
            '19043'        = 'Windows 10 21H1'
            '19042'        = 'Windows 10 20H2'
            '19041'        = 'Windows 10 2004'
            '18898'        = 'Windows 10 Insider Preview'
            '18363'        = "Windows 10 1909"
            '18362'        = "Windows 10 1903"
            '17763'        = "Windows 10 1809"
            '17134'        = "Windows 10 1803"
            '16299'        = "Windows 10 1709"
            '15063'        = "Windows 10 1703"
            '14393'        = "Windows 10 1607"
            '10586'        = "Windows 10 1511"
            '10240'        = "Windows 10 1507"
        }
        $System = $Systems[$OperatingSystemVersion]
        if (-not $System) {
            $System = $OperatingSystem
        }
    } elseif ($OperatingSystem -like 'Windows Server*') {
        # May need updates https://docs.microsoft.com/en-us/windows-server/get-started/windows-server-release-info
        # to detect Core

        $Systems = @{
            # This is how it's written in AD
            '10.0 (20348)' = 'Windows Server 2022'
            '10.0 (19042)' = 'Windows Server 2019 20H2'
            '10.0 (19041)' = 'Windows Server 2019 2004'
            '10.0 (18363)' = 'Windows Server 2019 1909'
            '10.0 (18362)' = "Windows Server 2019 1903" # (Datacenter Core, Standard Core)
            '10.0 (17763)' = "Windows Server 2019 1809" # (Datacenter, Essentials, Standard)
            '10.0 (17134)' = "Windows Server 2016 1803" # (Datacenter, Standard)
            '10.0 (14393)' = "Windows Server 2016 1607"
            '6.3 (9600)'   = 'Windows Server 2012 R2'
            '6.1 (7601)'   = 'Windows Server 2008 R2'
            '5.2 (3790)'   = 'Windows Server 2003'

            # This is how WMI/CIM stores it
            '10.0.20348'   = 'Windows Server 2022'
            '10.0.19042'   = 'Windows Server 2019 20H2'
            '10.0.19041'   = 'Windows Server 2019 2004'
            '10.0.18363'   = 'Windows Server 2019 1909'
            '10.0.18362'   = "Windows Server 2019 1903" #  (Datacenter Core, Standard Core)
            '10.0.17763'   = "Windows Server 2019 1809"  # (Datacenter, Essentials, Standard)
            '10.0.17134'   = "Windows Server 2016 1803" ## (Datacenter, Standard)
            '10.0.14393'   = "Windows Server 2016 1607"
            '6.3.9600'     = 'Windows Server 2012 R2'
            '6.1.7601'     = 'Windows Server 2008 R2' # i think
            '5.2.3790'     = 'Windows Server 2003' # i think

            # This is how it's written in registry
            '20348'        = 'Windows Server 2022'
            '19042'        = 'Windows Server 2019 20H2'
            '19041'        = 'Windows Server 2019 2004'
            '18363'        = 'Windows Server 2019 1909'
            '18362'        = "Windows Server 2019 1903" # (Datacenter Core, Standard Core)
            '17763'        = "Windows Server 2019 1809" # (Datacenter, Essentials, Standard)
            '17134'        = "Windows Server 2016 1803" # (Datacenter, Standard)
            '14393'        = "Windows Server 2016 1607"
            '9600'         = 'Windows Server 2012 R2'
            '7601'         = 'Windows Server 2008 R2'
            '3790'         = 'Windows Server 2003'
        }
        $System = $Systems[$OperatingSystemVersion]
        if (-not $System) {
            $System = $OperatingSystem
        }
    } else {
        $System = $OperatingSystem
    }
    if ($System) {
        $System
    } else {
        'Unknown'
    }
}

function Get-WinADDuplicateSPN {
    <#
    .SYNOPSIS
    Detects and lists duplicate Service Principal Names (SPNs) in the Active Directory Domain.
    .DESCRIPTION
    Detects and lists duplicate Service Principal Names (SPNs) in the Active Directory Domain.
    .PARAMETER All
    Returns all duplicate and non-duplicate SPNs. Default is to only return duplicate SPNs.
    .PARAMETER Exclude
    Provides ability to exclude specific SPNs from the duplicate detection. By default it excludes kadmin/changepw as with multiple forests it will happen for sure.
    .PARAMETER Forest
    Target different Forest, by default current forest is used
    .PARAMETER ExcludeDomains
    Exclude domain from search, by default whole forest is scanned
    .PARAMETER IncludeDomains
    Include only specific domains, by default whole forest is scanned
    .PARAMETER ExtendedForestInformation
    Ability to provide Forest Information from another command to speed up processing
    .EXAMPLE
    Get-WinADDuplicateSPN | Format-Table
    .EXAMPLE
    Get-WinADDuplicateSPN -All | Format-Table
    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys
    #>
    [CmdletBinding()]
    param(
        [switch] $All,
        [string[]] $Exclude,
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [Parameter(ParameterSetName = 'Forest')][System.Collections.IDictionary] $ExtendedForestInformation,
        [pscredential] $Credential
    )
    $Excluded = @(
        'kadmin/changepw'
        foreach ($Item in $Exclude) {
            $iTEM
        }
    )

    $SPNCache = [ordered] @{}
    $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation -Credential $Credential
    foreach ($Domain in $ForestInformation.Domains) {
        Write-Verbose -Message "Get-WinADDuplicateSPN - Processing $Domain"
        $Objects = (Get-ADObject -Credential $Credential -LDAPFilter "ServicePrincipalName=*" -Properties ServicePrincipalName -Server $ForestInformation['QueryServers'][$domain]['HostName'][0])
        Write-Verbose -Message "Get-WinADDuplicateSPN - Found $($Objects.Count) objects. Processing..."
        foreach ($Object in $Objects) {
            foreach ($SPN in $Object.ServicePrincipalName) {
                if (-not $SPNCache[$SPN]) {
                    $SPNCache[$SPN] = [PSCustomObject] @{
                        Name      = $SPN
                        Duplicate = $false
                        Count     = 0
                        Excluded  = $false
                        List      = [System.Collections.Generic.List[Object]]::new()
                    }
                }
                if ($SPN -in $Excluded) {
                    $SPNCache[$SPN].Excluded = $true
                }
                $SPNCache[$SPN].List.Add($Object)
                $SPNCache[$SPN].Count++
            }
        }
    }
    Write-Verbose -Message "Get-WinADDuplicateSPN - Finalizing output. Processing..."
    foreach ($SPN in $SPNCache.Values) {
        if ($SPN.Count -gt 1 -and $SPN.Excluded -ne $true) {
            $SPN.Duplicate = $true
        }
        if ($All) {
            $SPN
        } else {
            if ($SPN.Duplicate) {
                $SPN
            }
        }
    }
}

Function Get-WinADDuplicateObject {
    <#
    .SYNOPSIS
    Used by As Built Report to get AD duplicate object info.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>

    [alias('Get-WinADForestObjectsConflict')]
    [CmdletBinding()]
    Param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [System.Collections.IDictionary] $ExtendedForestInformation,
        [string] $PartialMatchDistinguishedName,
        [string[]] $IncludeObjectClass,
        [string[]] $ExcludeObjectClass,
        [switch] $Extended,
        [switch] $NoPostProcessing,
        [pscredential] $Credential

    )
    # Based on https://gallery.technet.microsoft.com/scriptcenter/Get-ADForestConflictObjects-4667fa37
    $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation -Credential $Credential
    foreach ($Domain in $ForestInformation.Domains) {
        $DC = $ForestInformation['QueryServers']["$Domain"].HostName[0]
        #Get conflict objects
        $getADObjectSplat = @{
            LDAPFilter  = "(|(cn=*\0ACNF:*)(ou=*CNF:*))"
            Properties  = 'DistinguishedName', 'ObjectClass', 'DisplayName', 'SamAccountName', 'Name', 'ObjectCategory', 'WhenCreated', 'WhenChanged', 'ProtectedFromAccidentalDeletion', 'ObjectGUID'
            Server      = $DC
            SearchScope = 'Subtree'
            Credential = $Credential
        }
        $Objects = Get-ADObject @getADObjectSplat
        foreach ($_ in $Objects) {
            # Lets allow users to filter on it
            if ($ExcludeObjectClass) {
                if ($ExcludeObjectClass -contains $_.ObjectClass) {
                    continue
                }
            }
            if ($IncludeObjectClass) {
                if ($IncludeObjectClass -notcontains $_.ObjectClass) {
                    continue
                }
            }
            if ($PartialMatchDistinguishedName) {
                if ($_.DistinguishedName -notlike $PartialMatchDistinguishedName) {
                    continue
                }
            }
            if ($NoPostProcessing) {
                $_
                continue
            }
            $DomainName = ConvertFrom-DistinguishedName -DistinguishedName $_.DistinguishedName -ToDomainCN
            # Lets create separate objects for different purpoeses
            $ConflictObject = [ordered] @{
                ConflictDN          = $_.DistinguishedName
                ConflictWhenChanged = $_.WhenChanged
                DomainName          = $DomainName
                ObjectClass         = $_.ObjectClass
            }
            $LiveObjectData = [ordered] @{
                LiveDn          = "N/A"
                LiveWhenChanged = "N/A"
            }
            $RestData = [ordered] @{
                DisplayName                     = $_.DisplayName
                Name                            = $_.Name.Replace("`n", ' ')
                SamAccountName                  = $_.SamAccountName
                ObjectCategory                  = $_.ObjectCategory
                WhenCreated                     = $_.WhenCreated
                WhenChanged                     = $_.WhenChanged
                ProtectedFromAccidentalDeletion = $_.ProtectedFromAccidentalDeletion
                ObjectGUID                      = $_.ObjectGUID.Guid
            }
            if ($Extended) {
                $LiveObject = $null
                $ConflictObject = $ConflictObject + $LiveObjectData + $RestData
                #See if we are dealing with a 'cn' conflict object
                if (Select-String -SimpleMatch "\0ACNF:" -InputObject $ConflictObject.ConflictDn) {
                    #Split the conflict object DN so we can remove the conflict notation
                    $SplitConfDN = $ConflictObject.ConflictDn -split "0ACNF:"
                    #Remove the conflict notation from the DN and try to get the live AD object
                    try {
                        $LiveObject = Get-ADObject -Credential $Credential -Identity "$($SplitConfDN[0].TrimEnd("\"))$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
                    } catch {}
                    if ($LiveObject) {
                        $ConflictObject.LiveDN = $LiveObject.DistinguishedName
                        $ConflictObject.LiveWhenChanged = $LiveObject.WhenChanged
                    }
                } else {
                    #Split the conflict object DN so we can remove the conflict notation for OUs
                    $SplitConfDN = $ConflictObject.ConflictDn -split "CNF:"
                    #Remove the conflict notation from the DN and try to get the live AD object
                    try {
                        $LiveObject = Get-ADObject -Credential $Credential -Identity "$($SplitConfDN[0])$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
                    } catch {}
                    if ($LiveObject) {
                        $ConflictObject.LiveDN = $LiveObject.DistinguishedName
                        $ConflictObject.LiveWhenChanged = $LiveObject.WhenChanged
                    }
                }
            } else {
                $ConflictObject = $ConflictObject + $RestData
            }
            [PSCustomObject] $ConflictObject
        }
    }
}

function Get-ComputerSplit {
    <#
    .SYNOPSIS

    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([Array])]
    param(
        [string[]] $ComputerName
    )
    if ($null -eq $ComputerName) {
        $ComputerName = $Env:COMPUTERNAME
    }
    try {
        $LocalComputerDNSName = [System.Net.Dns]::GetHostByName($Env:COMPUTERNAME).HostName
    } catch {
        $LocalComputerDNSName = $Env:COMPUTERNAME
    }
    $ComputersLocal = $null
    [Array] $Computers = foreach ($Computer in $ComputerName) {
        if ($Computer -eq '' -or $null -eq $Computer) {
            $Computer = $Env:COMPUTERNAME
        }
        if ($Computer -ne $Env:COMPUTERNAME -and $Computer -ne $LocalComputerDNSName) {
            $Computer
        } else {
            $ComputersLocal = $Computer
        }
    }
    , @($ComputersLocal, $Computers)
}

function Get-WinADForestDetail {

    <#
    .SYNOPSIS
    Used by As Built Report to get AD duplicate object info.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param(
        [alias('ForestName')][string] $Forest,
        [string[]] $ExcludeDomains,
        [string[]] $ExcludeDomainControllers,
        [alias('Domain', 'Domains')][string[]] $IncludeDomains,
        [alias('DomainControllers', 'ComputerName')][string[]] $IncludeDomainControllers,
        [switch] $SkipRODC,
        [string] $Filter = '*',
        [switch] $TestAvailability,
        [ValidateSet('All', 'Ping', 'WinRM', 'PortOpen', 'Ping+WinRM', 'Ping+PortOpen', 'WinRM+PortOpen')] $Test = 'All',
        [int[]] $Ports = 135,
        [int] $PortsTimeout = 100,
        [int] $PingCount = 1,
        [switch] $Extended,
        [System.Collections.IDictionary] $ExtendedForestInformation,
        [pscredential] $Credential
    )
    if ($Global:ProgressPreference -ne 'SilentlyContinue') {
        $TemporaryProgress = $Global:ProgressPreference
        $Global:ProgressPreference = 'SilentlyContinue'
    }

    if (-not $ExtendedForestInformation) {
        # standard situation, building data from AD
        $Findings = [ordered] @{ }
        try {
            if ($Forest) {
                $ForestInformation = Get-ADForest -ErrorAction Stop -Server $System -Credential $Credential
            } else {
                $ForestInformation = Get-ADForest -ErrorAction Stop -Server $System -Credential $Credential
            }

        } catch {
            Write-Warning "Get-WinADForestDetail - Error discovering DC for Forest - $($_.Exception.Message)"
            return
        }
        if (-not $ForestInformation) {
            return
        }
        $Findings['Forest'] = $ForestInformation
        $Findings['ForestDomainControllers'] = @()
        $Findings['QueryServers'] = @{ }
        $Findings['DomainDomainControllers'] = @{ }
        [Array] $Findings['Domains'] = foreach ($Domain in $ForestInformation.Domains) {
            if ($IncludeDomains) {
                if ($Domain -in $IncludeDomains) {
                    $Domain.ToLower()
                }
                # We skip checking for exclusions
                continue
            }
            if ($Domain -notin $ExcludeDomains) {
                $Domain.ToLower()
            }
        }
        # We want to have QueryServers always available for all domains
        [Array] $DomainsActive = foreach ($Domain in $Findings['Forest'].Domains) {
            try {
                $DC = Get-ADDomainController -DomainName $Domain -Discover -ErrorAction Stop

                $OrderedDC = [ordered] @{
                    Domain      = $DC.Domain
                    Forest      = $DC.Forest
                    HostName    = [Array] $DC.HostName
                    IPv4Address = $DC.IPv4Address
                    IPv6Address = $DC.IPv6Address
                    Name        = $DC.Name
                    Site        = $DC.Site
                }

            } catch {
                Write-Warning "Get-WinADForestDetail - Error discovering DC for domain $Domain - $($_.Exception.Message)"
                continue
            }
            if ($Domain -eq $Findings['Forest']['Name']) {
                $Findings['QueryServers']['Forest'] = $OrderedDC
            }
            $Findings['QueryServers']["$Domain"] = $OrderedDC
            # lets return domain as something that wroks
            $Domain
        }

        # we need to make sure to remove domains that don't have DCs for some reason
        [Array] $Findings['Domains'] = foreach ($Domain in $Findings['Domains']) {
            if ($Domain -notin $DomainsActive) {
                Write-Warning "Get-WinADForestDetail - Domain $Domain doesn't seem to be active (no DCs). Skipping."
                continue
            }
            $Domain
        }

        [Array] $Findings['ForestDomainControllers'] = foreach ($Domain in $Findings.Domains) {
            $QueryServer = $Findings['QueryServers'][$Domain]['HostName'][0]

            [Array] $AllDC = try {
                try {
                    $DomainControllers = Get-ADDomainController -Filter $Filter -Server $QueryServer -ErrorAction Stop -Credential $Credential
                } catch {
                    Write-Warning "Get-WinADForestDetail - Error listing DCs for domain $Domain - $($_.Exception.Message)"
                    continue
                }
                foreach ($S in $DomainControllers) {
                    if ($IncludeDomainControllers.Count -gt 0) {
                        If (-not $IncludeDomainControllers[0].Contains('.')) {
                            if ($S.Name -notin $IncludeDomainControllers) {
                                continue
                            }
                        } else {
                            if ($S.HostName -notin $IncludeDomainControllers) {
                                continue
                            }
                        }
                    }
                    if ($ExcludeDomainControllers.Count -gt 0) {
                        If (-not $ExcludeDomainControllers[0].Contains('.')) {
                            if ($S.Name -in $ExcludeDomainControllers) {
                                continue
                            }
                        } else {
                            if ($S.HostName -in $ExcludeDomainControllers) {
                                continue
                            }
                        }
                    }
                    $Server = [ordered] @{
                        Domain                 = $Domain
                        HostName               = $S.HostName
                        Name                   = $S.Name
                        Forest                 = $ForestInformation.RootDomain
                        Site                   = $S.Site
                        IPV4Address            = $S.IPV4Address
                        IPV6Address            = $S.IPV6Address
                        IsGlobalCatalog        = $S.IsGlobalCatalog
                        IsReadOnly             = $S.IsReadOnly
                        IsSchemaMaster         = ($S.OperationMasterRoles -contains 'SchemaMaster')
                        IsDomainNamingMaster   = ($S.OperationMasterRoles -contains 'DomainNamingMaster')
                        IsPDC                  = ($S.OperationMasterRoles -contains 'PDCEmulator')
                        IsRIDMaster            = ($S.OperationMasterRoles -contains 'RIDMaster')
                        IsInfrastructureMaster = ($S.OperationMasterRoles -contains 'InfrastructureMaster')
                        OperatingSystem        = $S.OperatingSystem
                        OperatingSystemVersion = $S.OperatingSystemVersion
                        OperatingSystemLong    = ConvertTo-OperatingSystem -OperatingSystem $S.OperatingSystem -OperatingSystemVersion $S.OperatingSystemVersion
                        LdapPort               = $S.LdapPort
                        SslPort                = $S.SslPort
                        DistinguishedName      = $S.ComputerObjectDN
                        Pingable               = $null
                        WinRM                  = $null
                        PortOpen               = $null
                        Comment                = ''
                    }
                    if ($TestAvailability) {
                        if ($Test -eq 'All' -or $Test -like 'Ping*') {
                            $Server.Pingable = Test-Connection -ComputerName $Server.IPV4Address -Quiet -Count $PingCount
                        }
                        if ($Test -eq 'All' -or $Test -like '*WinRM*') {
                            $Server.WinRM = (Test-WinRM -ComputerName $Server.HostName).Status
                        }
                        if ($Test -eq 'All' -or '*PortOpen*') {
                            $Server.PortOpen = (Test-ComputerPort -Server $Server.HostName -PortTCP $Ports -Timeout $PortsTimeout).Status
                        }
                    }
                    [PSCustomObject] $Server
                }
            } catch {
                [PSCustomObject]@{
                    Domain                   = $Domain
                    HostName                 = ''
                    Name                     = ''
                    Forest                   = $ForestInformation.RootDomain
                    IPV4Address              = ''
                    IPV6Address              = ''
                    IsGlobalCatalog          = ''
                    IsReadOnly               = ''
                    Site                     = ''
                    SchemaMaster             = $false
                    DomainNamingMasterMaster = $false
                    PDCEmulator              = $false
                    RIDMaster                = $false
                    InfrastructureMaster     = $false
                    LdapPort                 = ''
                    SslPort                  = ''
                    DistinguishedName        = ''
                    Pingable                 = $null
                    WinRM                    = $null
                    PortOpen                 = $null
                    Comment                  = $_.Exception.Message -replace "`n", " " -replace "`r", " "
                }
            }
            if ($SkipRODC) {
                [Array] $Findings['DomainDomainControllers'][$Domain] = $AllDC | Where-Object { $_.IsReadOnly -eq $false }
                #$Findings[$Domain] = $AllDC | Where-Object { $_.IsReadOnly -eq $false }
            } else {
                [Array] $Findings['DomainDomainControllers'][$Domain] = $AllDC
                #$Findings[$Domain] = $AllDC
            }
            # Building all DCs for whole Forest
            [Array] $Findings['DomainDomainControllers'][$Domain]
        }
        if ($Extended) {
            $Findings['DomainsExtended'] = @{ }
            $Findings['DomainsExtendedNetBIOS'] = @{ }
            foreach ($DomainEx in $Findings['Domains']) {
                try {
                    #$Findings['DomainsExtended'][$DomainEx] = Get-ADDomain -Server $Findings['QueryServers'][$DomainEx].HostName[0]

                    $Findings['DomainsExtended'][$DomainEx] = Get-ADDomain -Credential $Credential -Server $Findings['QueryServers'][$DomainEx].HostName[0] | ForEach-Object {
                        # We need to use ForEach-Object to convert ADPropertyValueCollection to normal strings. Otherwise Copy-Dictionary fails
                        #True     False    ADPropertyValueCollection                System.Collections.CollectionBase

                        [ordered] @{
                            AllowedDNSSuffixes                 = $_.AllowedDNSSuffixes | ForEach-Object -Process { $_ }                #: { }
                            ChildDomains                       = $_.ChildDomains | ForEach-Object -Process { $_ }                      #: { }
                            ComputersContainer                 = $_.ComputersContainer                 #: CN = Computers, DC = ad, DC = evotec, DC = xyz
                            DeletedObjectsContainer            = $_.DeletedObjectsContainer            #: CN = Deleted Objects, DC = ad, DC = evotec, DC = xyz
                            DistinguishedName                  = $_.DistinguishedName                  #: DC = ad, DC = evotec, DC = xyz
                            DNSRoot                            = $_.DNSRoot                            #: ad.evotec.xyz
                            DomainControllersContainer         = $_.DomainControllersContainer         #: OU = Domain Controllers, DC = ad, DC = evotec, DC = xyz
                            DomainMode                         = $_.DomainMode                         #: Windows2012R2Domain
                            DomainSID                          = $_.DomainSID.Value                        #: S - 1 - 5 - 21 - 853615985 - 2870445339 - 3163598659
                            ForeignSecurityPrincipalsContainer = $_.ForeignSecurityPrincipalsContainer #: CN = ForeignSecurityPrincipals, DC = ad, DC = evotec, DC = xyz
                            Forest                             = $_.Forest                             #: ad.evotec.xyz
                            InfrastructureMaster               = $_.InfrastructureMaster               #: AD1.ad.evotec.xyz
                            LastLogonReplicationInterval       = $_.LastLogonReplicationInterval       #:
                            LinkedGroupPolicyObjects           = $_.LinkedGroupPolicyObjects | ForEach-Object -Process { $_ }           #:
                            LostAndFoundContainer              = $_.LostAndFoundContainer              #: CN = LostAndFound, DC = ad, DC = evotec, DC = xyz
                            ManagedBy                          = $_.ManagedBy                          #:
                            Name                               = $_.Name                               #: ad
                            NetBIOSName                        = $_.NetBIOSName                        #: EVOTEC
                            ObjectClass                        = $_.ObjectClass                        #: domainDNS
                            ObjectGUID                         = $_.ObjectGUID                         #: bc875580 - 4c70-41ad-a487-c57337e26024
                            ParentDomain                       = $_.ParentDomain                       #:
                            PDCEmulator                        = $_.PDCEmulator                        #: AD1.ad.evotec.xyz
                            PublicKeyRequiredPasswordRolling   = $_.PublicKeyRequiredPasswordRolling | ForEach-Object -Process { $_ }   #:
                            QuotasContainer                    = $_.QuotasContainer                    #: CN = NTDS Quotas, DC = ad, DC = evotec, DC = xyz
                            ReadOnlyReplicaDirectoryServers    = $_.ReadOnlyReplicaDirectoryServers | ForEach-Object -Process { $_ }    #: { }
                            ReplicaDirectoryServers            = $_.ReplicaDirectoryServers | ForEach-Object -Process { $_ }           #: { AD1.ad.evotec.xyz, AD2.ad.evotec.xyz, AD3.ad.evotec.xyz }
                            RIDMaster                          = $_.RIDMaster                          #: AD1.ad.evotec.xyz
                            SubordinateReferences              = $_.SubordinateReferences | ForEach-Object -Process { $_ }            #: { DC = ForestDnsZones, DC = ad, DC = evotec, DC = xyz, DC = DomainDnsZones, DC = ad, DC = evotec, DC = xyz, CN = Configuration, DC = ad, DC = evotec, DC = xyz }
                            SystemsContainer                   = $_.SystemsContainer                   #: CN = System, DC = ad, DC = evotec, DC = xyz
                            UsersContainer                     = $_.UsersContainer                     #: CN = Users, DC = ad, DC = evotec, DC = xyz
                        }
                    }

                    $NetBios = $Findings['DomainsExtended'][$DomainEx]['NetBIOSName']
                    $Findings['DomainsExtendedNetBIOS'][$NetBios] = $Findings['DomainsExtended'][$DomainEx]
                } catch {
                    Write-Warning "Get-WinADForestDetail - Error gathering Domain Information for domain $DomainEx - $($_.Exception.Message)"
                    continue
                }
            }
        }
        # Bring back setting as per default
        if ($TemporaryProgress) {
            $Global:ProgressPreference = $TemporaryProgress
        }

        $Findings
    } else {
        # this takes care of limiting output to only what we requested, but based on prior input
        # this makes sure we ask once for all AD stuff and then subsequent calls just filter out things
        # this should be much faster then asking again and again for stuff from AD
        $Findings = Copy-DictionaryManual -Dictionary $ExtendedForestInformation
        [Array] $Findings['Domains'] = foreach ($_ in $Findings.Domains) {
            if ($IncludeDomains) {
                if ($_ -in $IncludeDomains) {
                    $_.ToLower()
                }
                # We skip checking for exclusions
                continue
            }
            if ($_ -notin $ExcludeDomains) {
                $_.ToLower()
            }
        }
        # Now that we have Domains we need to remove all DCs that are not from domains we excluded or included
        foreach ($_ in [string[]] $Findings.DomainDomainControllers.Keys) {
            if ($_ -notin $Findings.Domains) {
                $Findings.DomainDomainControllers.Remove($_)
            }
        }
        # Same as above but for query servers - we don't remove queried servers
        #foreach ($_ in [string[]] $Findings.QueryServers.Keys) {
        #    if ($_ -notin $Findings.Domains -and $_ -ne 'Forest') {
        #        $Findings.QueryServers.Remove($_)
        #    }
        #}
        # Now that we have Domains we need to remove all Domains that are excluded or included
        foreach ($_ in [string[]] $Findings.DomainsExtended.Keys) {
            if ($_ -notin $Findings.Domains) {
                $Findings.DomainsExtended.Remove($_)
                $NetBiosName = $Findings.DomainsExtended.$_.'NetBIOSName'
                if ($NetBiosName) {
                    $Findings.DomainsExtendedNetBIOS.Remove($NetBiosName)
                }
            }
        }
        [Array] $Findings['ForestDomainControllers'] = foreach ($Domain in $Findings.Domains) {
            [Array] $AllDC = foreach ($S in $Findings.DomainDomainControllers["$Domain"]) {
                if ($IncludeDomainControllers.Count -gt 0) {
                    If (-not $IncludeDomainControllers[0].Contains('.')) {
                        if ($S.Name -notin $IncludeDomainControllers) {
                            continue
                        }
                    } else {
                        if ($S.HostName -notin $IncludeDomainControllers) {
                            continue
                        }
                    }
                }
                if ($ExcludeDomainControllers.Count -gt 0) {
                    If (-not $ExcludeDomainControllers[0].Contains('.')) {
                        if ($S.Name -in $ExcludeDomainControllers) {
                            continue
                        }
                    } else {
                        if ($S.HostName -in $ExcludeDomainControllers) {
                            continue
                        }
                    }
                }
                $S
            }
            if ($SkipRODC) {
                [Array] $Findings['DomainDomainControllers'][$Domain] = $AllDC | Where-Object { $_.IsReadOnly -eq $false }
            } else {
                [Array] $Findings['DomainDomainControllers'][$Domain] = $AllDC
            }
            # Building all DCs for whole Forest
            [Array] $Findings['DomainDomainControllers'][$Domain]
        }
        $Findings
    }
}

function Get-CimData {
    <#
    .SYNOPSIS
    Helper function for retreiving CIM data from local and remote computers

    .DESCRIPTION
    Helper function for retreiving CIM data from local and remote computers

    .PARAMETER ComputerName
    Specifies computer on which you want to run the CIM operation. You can specify a fully qualified domain name (FQDN), a NetBIOS name, or an IP address. If you do not specify this parameter, the cmdlet performs the operation on the local computer using Component Object Model (COM).

    .PARAMETER Protocol
    Specifies the protocol to use. The acceptable values for this parameter are: DCOM, Default, or Wsman.

    .PARAMETER Class
    Specifies the name of the CIM class for which to retrieve the CIM instances. You can use tab completion to browse the list of classes, because PowerShell gets a list of classes from the local WMI server to provide a list of class names.

    .PARAMETER Properties
    Specifies a set of instance properties to retrieve. Use this parameter when you need to reduce the size of the object returned, either in memory or over the network. The object returned also contains the key properties even if you have not listed them using the Property parameter. Other properties of the class are present but they are not populated.

    .EXAMPLE
    Get-CimData -Class 'win32_bios' -ComputerName AD1,EVOWIN

    Get-CimData -Class 'win32_bios'

    # Get-CimClass to get all classes

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    #>

    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [parameter(Mandatory)][string] $Class,
        [string] $NameSpace = 'root\cimv2',
        [string[]] $ComputerName = $Env:COMPUTERNAME,
        [ValidateSet('Default', 'Dcom', 'Wsman')][string] $Protocol = 'Default',
        [string[]] $Properties = '*'
    )
    $ExcludeProperties = 'CimClass', 'CimInstanceProperties', 'CimSystemProperties', 'SystemCreationClassName', 'CreationClassName'

    # Querying CIM locally usually doesn't work. This means if you're querying same computer you neeed to skip CimSession/ComputerName if it's local query
    [Array] $ComputersSplit = Get-ComputerSplit -ComputerName $ComputerName

    $CimObject = @(
        # requires removal of this property for query
        [string[]] $PropertiesOnly = $Properties | Where-Object { $_ -ne 'PSComputerName' }
        # Process all remote computers
        $Computers = $ComputersSplit[1]
        if ($Computers.Count -gt 0) {
            if ($Protocol -eq 'Default') {
                Get-CimInstance -ClassName $Class -ComputerName $Computers -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsToProcess | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
            } else {
                $Option = New-CimSessionOption -Protocol $Protocol
                $Session = New-CimSession -ComputerName $Computers -SessionOption $Option -ErrorAction SilentlyContinue
                $Info = Get-CimInstance -ClassName $Class -CimSession $Session -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsToProcess | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
                $null = Remove-CimSession -CimSession $Session -ErrorAction SilentlyContinue
                $Info
            }
        }
        foreach ($E in $ErrorsToProcess) {
            Write-Warning -Message "Get-CimData - No data for computer $($E.OriginInfo.PSComputerName). Failed with errror: $($E.Exception.Message)"
        }
        # Process local computer
        $Computers = $ComputersSplit[0]
        if ($Computers.Count -gt 0) {
            $Info = Get-CimInstance -ClassName $Class -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsLocal | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
            $Info | Add-Member -Name 'PSComputerName' -Value $Computers -MemberType NoteProperty -Force
            $Info
        }
        foreach ($E in $ErrorsLocal) {
            Write-Warning -Message "Get-CimData - No data for computer $($Env:COMPUTERNAME). Failed with errror: $($E.Exception.Message)"
        }
    )
    $CimObject
}

function ConvertFrom-DistinguishedName {
    <#
    .SYNOPSIS
    Converts a Distinguished Name to CN, OU, Multiple OUs or DC

    .DESCRIPTION
    Converts a Distinguished Name to CN, OU, Multiple OUs or DC

    .PARAMETER DistinguishedName
    Distinguished Name to convert

    .PARAMETER ToOrganizationalUnit
    Converts DistinguishedName to Organizational Unit

    .PARAMETER ToDC
    Converts DistinguishedName to DC

    .PARAMETER ToDomainCN
    Converts DistinguishedName to Domain CN

    .EXAMPLE
    $DistinguishedName = 'CN=Przemyslaw Klys,OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz'
    ConvertFrom-DistinguishedName -DistinguishedName $DistinguishedName -ToOrganizationalUnit

    Output:
    OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    $DistinguishedName = 'CN=Przemyslaw Klys,OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz'
    ConvertFrom-DistinguishedName -DistinguishedName $DistinguishedName

    Output:
    Przemyslaw Klys

    .EXAMPLE
    ConvertFrom-DistinguishedName -DistinguishedName 'OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz' -ToMultipleOrganizationalUnit -IncludeParent

    Output:
    OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz
    OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    ConvertFrom-DistinguishedName -DistinguishedName 'OU=Users,OU=Production,DC=ad,DC=evotec,DC=xyz' -ToMultipleOrganizationalUnit

    Output:
    OU=Production,DC=ad,DC=evotec,DC=xyz

    .EXAMPLE
    $Con = @(
        'CN=Windows Authorization Access Group,CN=Builtin,DC=ad,DC=evotec,DC=xyz'
        'CN=Mmm,DC=elo,CN=nee,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=ad,DC=evotec,DC=xyz'
        'CN=e6d5fd00-385d-4e65-b02d-9da3493ed850,CN=Operations,CN=DomainUpdates,CN=System,DC=ad,DC=evotec,DC=xyz'
        'OU=Domain Controllers,DC=ad,DC=evotec,DC=pl'
        'OU=Microsoft Exchange Security Groups,DC=ad,DC=evotec,DC=xyz'
    )

    ConvertFrom-DistinguishedName -DistinguishedName $Con -ToLastName

    Output:
    Windows Authorization Access Group
    Mmm
    e6d5fd00-385d-4e65-b02d-9da3493ed850
    Domain Controllers
    Microsoft Exchange Security Groups

    .NOTES
        Version:        0.1.0
        Author:         Przemysław Kłys

    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(ParameterSetName = 'ToOrganizationalUnit')]
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')]
        [Parameter(ParameterSetName = 'ToDC')]
        [Parameter(ParameterSetName = 'ToDomainCN')]
        [Parameter(ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'ToLastName')]
        [alias('Identity', 'DN')][Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)][string[]] $DistinguishedName,
        [Parameter(ParameterSetName = 'ToOrganizationalUnit')][switch] $ToOrganizationalUnit,
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')][alias('ToMultipleOU')][switch] $ToMultipleOrganizationalUnit,
        [Parameter(ParameterSetName = 'ToMultipleOrganizationalUnit')][switch] $IncludeParent,
        [Parameter(ParameterSetName = 'ToDC')][switch] $ToDC,
        [Parameter(ParameterSetName = 'ToDomainCN')][switch] $ToDomainCN,
        [Parameter(ParameterSetName = 'ToLastName')][switch] $ToLastName
    )
    Process {
        foreach ($Distinguished in $DistinguishedName) {
            if ($ToDomainCN) {
                $DN = $Distinguished -replace '.*?((DC=[^=]+,)+DC=[^=]+)$', '$1'
                $CN = $DN -replace ',DC=', '.' -replace "DC="
                if ($CN) {
                    $CN
                }
            } elseif ($ToOrganizationalUnit) {
                $Value = [Regex]::Match($Distinguished, '(?=OU=)(.*\n?)(?<=.)').Value
                if ($Value) {
                    $Value
                }
            } elseif ($ToMultipleOrganizationalUnit) {
                if ($IncludeParent) {
                    $Distinguished
                }
                while ($true) {
                    #$dn = $dn -replace '^.+?,(?=CN|OU|DC)'
                    $Distinguished = $Distinguished -replace '^.+?,(?=..=)'
                    if ($Distinguished -match '^DC=') {
                        break
                    }
                    $Distinguished
                }
            } elseif ($ToDC) {
                #return [Regex]::Match($DistinguishedName, '(?=DC=)(.*\n?)(?<=.)').Value
                # return [Regex]::Match($DistinguishedName, '.*?(DC=.*)').Value
                $Value = $Distinguished -replace '.*?((DC=[^=]+,)+DC=[^=]+)$', '$1'
                if ($Value) {
                    $Value
                }
                #return [Regex]::Match($DistinguishedName, 'CN=.*?(DC=.*)').Groups[1].Value
            } elseif ($ToLastName) {
                # Would be best if it worked, but there is too many edge cases so hand splits seems to be the best solution
                # Feel free to change it back to regex if you know how ;)
                <# https://stackoverflow.com/questions/51761894/regex-extract-ou-from-distinguished-name
                $Regex = "^(?:(?<cn>CN=(?<name>.*?)),)?(?<parent>(?:(?<path>(?:CN|OU).*?),)?(?<domain>(?:DC=.*)+))$"
                $Found = $Distinguished -match $Regex
                if ($Found) {
                    $Matches.name
                }
                #>
                $NewDN = $Distinguished -split ",DC="
                if ($NewDN[0].Contains(",OU=")) {
                    [Array] $ChangedDN = $NewDN[0] -split ",OU="
                } elseif ($NewDN[0].Contains(",CN=")) {
                    [Array] $ChangedDN = $NewDN[0] -split ",CN="
                } else {
                    [Array] $ChangedDN = $NewDN[0]
                }
                if ($ChangedDN[0].StartsWith('CN=')) {
                    $ChangedDN[0] -replace 'CN=', ''
                } else {
                    $ChangedDN[0] -replace 'OU=', ''
                }
            } else {
                $Regex = '^CN=(?<cn>.+?)(?<!\\),(?<ou>(?:(?:OU|CN).+?(?<!\\),)+(?<dc>DC.+?))$'
                #$Output = foreach ($_ in $Distinguished) {
                $Found = $Distinguished -match $Regex
                if ($Found) {
                    $Matches.cn
                }
                #}
                #$Output.cn
            }
        }
    }
}
function Test-WinRM {
    [CmdletBinding()]
    param (
        [alias('Server')][string[]] $ComputerName
    )
    $Output = foreach ($Computer in $ComputerName) {
        $Test = [PSCustomObject] @{
            Output       = $null
            Status       = $null
            ComputerName = $Computer
        }
        try {
            $Test.Output = Test-WSMan -ComputerName $Computer -ErrorAction Stop
            $Test.Status = $true
        } catch {
            $Test.Status = $false
        }
        $Test
    }
    $Output
}

function Test-ComputerPort {
    [CmdletBinding()]
    param (
        [alias('Server')][string[]] $ComputerName,
        [int[]] $PortTCP,
        [int[]] $PortUDP,
        [int]$Timeout = 5000
    )
    begin {
        if ($Global:ProgressPreference -ne 'SilentlyContinue') {
            $TemporaryProgress = $Global:ProgressPreference
            $Global:ProgressPreference = 'SilentlyContinue'
        }
    }
    process {
        foreach ($Computer in $ComputerName) {
            foreach ($P in $PortTCP) {
                $Output = [ordered] @{
                    'ComputerName' = $Computer
                    'Port'         = $P
                    'Protocol'     = 'TCP'
                    'Status'       = $null
                    'Summary'      = $null
                    'Response'     = $null
                }

                $TcpClient = Test-NetConnection -ComputerName $Computer -Port $P -InformationLevel Detailed -WarningAction SilentlyContinue
                if ($TcpClient.TcpTestSucceeded) {
                    $Output['Status'] = $TcpClient.TcpTestSucceeded
                    $Output['Summary'] = "TCP $P Successful"
                } else {
                    $Output['Status'] = $false
                    $Output['Summary'] = "TCP $P Failed"
                    $Output['Response'] = $Warnings
                }
                [PSCustomObject]$Output
            }
            foreach ($P in $PortUDP) {
                $Output = [ordered] @{
                    'ComputerName' = $Computer
                    'Port'         = $P
                    'Protocol'     = 'UDP'
                    'Status'       = $null
                    'Summary'      = $null
                }
                $UdpClient = [System.Net.Sockets.UdpClient]::new($Computer, $P)
                $UdpClient.Client.ReceiveTimeout = $Timeout
                # $UdpClient.Connect($Computer, $P)
                $Encoding = [System.Text.ASCIIEncoding]::new()
                $byte = $Encoding.GetBytes("Evotec")
                [void]$UdpClient.Send($byte, $byte.length)
                $RemoteEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
                try {
                    $Bytes = $UdpClient.Receive([ref]$RemoteEndpoint)
                    [string]$Data = $Encoding.GetString($Bytes)
                    If ($Data) {
                        $Output['Status'] = $true
                        $Output['Summary'] = "UDP $P Successful"
                        $Output['Response'] = $Data
                    }
                } catch {
                    $Output['Status'] = $false
                    $Output['Summary'] = "UDP $P Failed"
                    $Output['Response'] = $_.Exception.Message
                }
                $UdpClient.Close()
                $UdpClient.Dispose()
                [PSCustomObject]$Output
            }

        }
    }
    end {
        # Bring back setting as per default
        if ($TemporaryProgress) {
            $Global:ProgressPreference = $TemporaryProgress
        }
    }
}

function Get-ComputerADDomain
{
    <#
            .Synopsis
            Return the current domain
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-ComputerADDomain
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    Param
    ()
    Write-Verbose -Message 'Calling GetCurrentDomain()'
    ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
}

function Find-AuditingIssue {
    <#
    .SYNOPSIS
    Used by As Built Report to find PKI Server auditing not enabled.
    .DESCRIPTION

    .NOTES
        Version:        2023.08
        Author:         Jake Hildreth

    .EXAMPLE

    .LINK
        https://github.com/TrimarcJake/Locksmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ADCSObjects
    )
    $ADCSObjects | Where-Object {
        ($_.objectClass -eq 'pKIEnrollmentService') -and
        ($_.AuditFilter -ne '127')
    } | ForEach-Object {
        $Issue = New-Object -TypeName pscustomobject
        $Issue | Add-Member -MemberType NoteProperty -Name Forest -Value $_.CanonicalName.split('/')[0] -Force
        $Issue | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name -Force
        $Issue | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName -Force
        if ($_.AuditFilter -match 'CA Unavailable') {
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value $_.AuditFilter -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert -Value 'N/A' -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        }
        else {
            $AuditValue = Switch ($_.AuditFilter) {
                $Null {'Never Configured'}
                default {$_.AuditFilter}
            }
            $Issue | Add-Member -MemberType NoteProperty -Name Issue -Value "Auditing is not fully enabled. Current value is $($AuditValue)" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Fix `
                -Value "certutil -config `'$($_.CAFullname)`' -setreg `'CA\AuditFilter`' 127; Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Revert `
                -Value "certutil -config $($_.CAFullname) -setreg CA\AuditFilter  $($_.AuditFilter); Invoke-Command -ComputerName `'$($_.dNSHostName)`' -ScriptBlock { Get-Service -Name `'certsvc`' | Restart-Service -Force }" -Force
            $Issue | Add-Member -MemberType NoteProperty -Name Technique -Value 'DETECT' -Force
        }
        $Severity = Get-Severity -Issue $Issue
        $Issue | Add-Member -MemberType NoteProperty -Name Severity -Value $Severity
        $Issue
    }
}

function Get-ADCSObject {
    <#
    .SYNOPSIS
    Used by As Built Report to find PKI Server auditing not enabled.
    .DESCRIPTION

    .NOTES
        Version:        2023.08
        Author:         Jake Hildreth

    .EXAMPLE

    .LINK
        https://github.com/TrimarcJake/Locksmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Target
        )
    try {
        $ADRoot = Invoke-Command -Session $TempPssSession {(Get-ADRootDSE -Server $Using:Target).defaultNamingContext}
        Invoke-Command -Session $TempPssSession {Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$Using:ADRoot" -SearchScope 2 -Properties *}
    } catch {
        Write-PScriboMessage -IsWarning "Unable to find CA auditing information"
    }
}

function get-Severity {
    <#
    .SYNOPSIS
    Used by As Built Report to find PKI Server auditing not enabled.
    .DESCRIPTION

    .NOTES
        Version:        2023.08
        Author:         Spencer Alessi


    .EXAMPLE

    .LINK
        https://github.com/TrimarcJake/Locksmith
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Issue
    )
    foreach ($Finding in $Issue) {
        try {
            # Auditing
            if ($Finding.Technique -eq 'DETECT') {
                return 'Medium'
            }
            # ESC6
            if ($Finding.Technique -eq 'ESC6') {
                return 'High'
            }
            # ESC8
            if ($Finding.Technique -eq 'ESC8') {
                return 'High'
            }
            # ESC1, ESC2, ESC4, ESC5
            $SID = ConvertFrom-IdentityReference -Object $Finding.IdentityReference
            if ($SID -match $SafeUsers -or $SID -match $SafeOwners) {
                return 'Medium'
            }
            if (($SID -notmatch $SafeUsers -and $SID -notmatch $SafeOwners) -and ($Finding.ActiveDirectoryRights -match $DangerousRights)) {
                return 'Critical'
            }
        } catch {
            Write-Error 'Could not determine issue severity'
        }
    }
}

function Get-ImagePercent {
    <#
    .SYNOPSIS
    Used by As Built Report to get base64 image percentage calculated from image width.
    This low the diagram image to fit the report page margins
    .DESCRIPTION
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
    .EXAMPLE
    .LINK
    #>
    [CmdletBinding()]
    [OutputType([System.Int32])]
    Param
        (
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Graph
        )
    $Image_FromStream = [System.Drawing.Image]::FromStream((new-object System.IO.MemoryStream(,[convert]::FromBase64String($Graph))))
    If ($Image_FromStream.Width -gt 1500) {
        return 20
    } else {
        return 50
    }
} # end