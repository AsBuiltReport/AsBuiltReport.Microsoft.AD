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
            "" {"-"; break}
            $Null {"-"; break}
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
    $result = Invoke-Command -Session $TempPssSession {dcdiag /s:$using:DomainController}
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
        Used by As Built Report to convert empty culumns to "-".
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
                "" {"-"; break}
                $Null {"-"; break}
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
        Version:        0.1.0
        Author:         Przemysław Kłys
    #>
    [cmdletBinding()]
    param(
        [string[]] $Domains
    )
    $NameUsed = [System.Collections.Generic.List[string]]::new()
    [DateTime] $CurrentDate = Get-Date
    if (-not $Domains) {
        try {
            $Forest = Get-ADForest -ErrorAction Stop
            $Domains = $Forest.Domains
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
        }
    }
    foreach ($Domain in $Domains) {
        try {
            [string[]]$Partitions = (Get-ADRootDSE -Server $Domain -ErrorAction Stop).namingContexts
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain)
            [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        } catch {
            Write-Warning "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error $($_.Exception.Message)"
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
        [System.Collections.IDictionary] $ExtendedForestInformation
    )
    $Today = (Get-Date)
    $Yesterday = (Get-Date -Hour 0 -Second 0 -Minute 0 -Millisecond 0).AddDays(-$EventDays)

    if (-not $SkipAutodetection) {
        $ForestInformation = Get-WinADForestDetails -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExcludeDomainControllers $ExcludeDomainControllers -IncludeDomainControllers $IncludeDomainControllers -SkipRODC:$SkipRODC -ExtendedForestInformation $ExtendedForestInformation -Extended
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
                    $DCInformation = Get-ADDomainController -Identity $DC -Server $Domain -ErrorAction Stop
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
                [Array]$GPOs = Get-ADObject -ErrorAction Stop -SearchBase $PoliciesSearchBase -SearchScope OneLevel -Filter * -Server $QueryServer -Properties Name, gPCFileSysPath, DisplayName, DistinguishedName, Description, Created, Modified, ObjectClass, ObjectGUID
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
            Write-Verbose "Get-WinADDFSHealth - Processing $($DC.HostName) for $Domain"
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
                $MemberReference = (Get-ADObject -Identity $Subscriber -Properties msDFSR-MemberReference -Server $QueryServer -ErrorAction Stop).'msDFSR-MemberReference' -like "CN=$DCName,*"
                $DomainSummary['MemberReference'] = if ($MemberReference) { $true } else { $false }
            } catch {
                $DomainSummary['MemberReference'] = $false
            }
            try {
                $DFSLocalSetting = Get-ADObject -Identity $LocalSettings -Server $QueryServer -ErrorAction Stop
                $DomainSummary['DFSLocalSetting'] = if ($DFSLocalSetting) { $true } else { $false }
            } catch {
                $DomainSummary['DFSLocalSetting'] = $false
            }

            try {
                $DomainSystemVolume = Get-ADObject -Identity $Subscriber -Server $QueryServer -ErrorAction Stop
                $DomainSummary['DomainSystemVolume'] = if ($DomainSystemVolume) { $true } else { $false }
            } catch {
                $DomainSummary['DomainSystemVolume'] = $false
            }
            try {
                $SysVolSubscription = Get-ADObject -Identity $Subscription -Server $QueryServer -ErrorAction Stop
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
        [Parameter(ParameterSetName = 'Forest')][System.Collections.IDictionary] $ExtendedForestInformation
    )
    $Excluded = @(
        'kadmin/changepw'
        foreach ($Item in $Exclude) {
            $iTEM
        }
    )

    $SPNCache = [ordered] @{}
    $ForestInformation = Get-WinADForestDetails -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation
    foreach ($Domain in $ForestInformation.Domains) {
        Write-Verbose -Message "Get-WinADDuplicateSPN - Processing $Domain"
        $Objects = (Get-ADObject -LDAPFilter "ServicePrincipalName=*" -Properties ServicePrincipalName -Server $ForestInformation['QueryServers'][$domain]['HostName'][0])
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
        [switch] $NoPostProcessing
    )
    # Based on https://gallery.technet.microsoft.com/scriptcenter/Get-ADForestConflictObjects-4667fa37
    $ForestInformation = Get-WinADForestDetails -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation
    foreach ($Domain in $ForestInformation.Domains) {
        $DC = $ForestInformation['QueryServers']["$Domain"].HostName[0]
        #Get conflict objects
        $getADObjectSplat = @{
            LDAPFilter  = "(|(cn=*\0ACNF:*)(ou=*CNF:*))"
            Properties  = 'DistinguishedName', 'ObjectClass', 'DisplayName', 'SamAccountName', 'Name', 'ObjectCategory', 'WhenCreated', 'WhenChanged', 'ProtectedFromAccidentalDeletion', 'ObjectGUID'
            Server      = $DC
            SearchScope = 'Subtree'
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
                        $LiveObject = Get-ADObject -Identity "$($SplitConfDN[0].TrimEnd("\"))$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
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
                        $LiveObject = Get-ADObject -Identity "$($SplitConfDN[0])$($SplitConfDN[1].Substring(36))" -Properties WhenChanged -Server $DC -ErrorAction Stop
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