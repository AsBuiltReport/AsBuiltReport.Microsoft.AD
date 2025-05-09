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
    Param (
        [Parameter (
            Position = 0,
            Mandatory)]
        [AllowEmptyString()]
        [string] $TEXT
    )

    switch ($TEXT) {
        "" { "--"; break }
        " " { "--"; break }
        $Null { "--"; break }
        "True" { "Yes"; break }
        "False" { "No"; break }
        default { $TEXT }
    }
} # end

function ConvertTo-FileSizeString {
    <#
    .SYNOPSIS
    Used by As Built Report to convert bytes automatically to GB or TB based on size.
    .DESCRIPTION
    .NOTES
        Version:        0.1.0
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
        [int64]
        $Size
    )

    $Unit = Switch ($Size) {
        { $Size -gt 1PB } { 'PB' ; Break }
        { $Size -gt 1TB } { 'TB' ; Break }
        { $Size -gt 1GB } { 'GB' ; Break }
        { $Size -gt 1Mb } { 'MB' ; Break }
        Default { 'KB' }
    }
    return "$([math]::Round(($Size / $("1" + $Unit)), 0)) $Unit"
} # end

# Disabled function Invoke-DcDiag for now, as it is not working properly.
# function Invoke-DcDiag {
#     <#
#     .SYNOPSIS
#     Used by As Built Report to get the dcdiag tests for a Domain Controller.
#     .DESCRIPTION

#     .NOTES
#         Version:        0.4.0
#         Author:         Adam Bertram

#     .EXAMPLE

#     .LINK

#     #>
#     param(
#         [Parameter(Mandatory)]
#         [ValidateNotNullOrEmpty()]
#         [string]$DomainController
#     )
#     $DCPssSessionDCDiag = Get-ValidPSSession -ComputerName $DomainController -SessionName 'DCDiag'
#     try {
#         $result = Invoke-Command -Session $DCPssSessionDCDiag { dcdiag /c /s:$using:DomainController }
#     } catch {
#         if ($DCPssSessionDCDiag) {
#             Remove-PSSession -Session $DCPssSessionDCDiag -ErrorAction SilentlyContinue
#         }
#         Write-PScriboMessage -Message "Invoke-DcDiag - Failed to get DCDiag for $DomainController with error: $($_.Exception.Message)"
#         return
#     }
#     $result | Select-String -Pattern '\. (.*) \b(passed|failed)\b test (.*)' | ForEach-Object {
#         $obj = @{
#             TestName = $_.Matches.Groups[3].Value
#             TestResult = $_.Matches.Groups[2].Value
#             Entity = $_.Matches.Groups[1].Value
#         }
#         [pscustomobject]$obj
#     }
# }# end

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
        "" { "--"; break }
        $Null { "--"; break }
        "True" { "Yes"; break }
        "False" { "No"; break }
        default { $TEXT }
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
        $ADObject += Invoke-Command -Session $Session { Get-ADObject $using:Object -Server $using:DC | Select-Object -ExpandProperty Name }
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
        $Properties = "*",
        $SelectPrty

    )
    $ADObject = @()
    foreach ($Object in $DN) {
        $ADObject += Invoke-Command -Session $Session { Get-ADObject -SearchBase $using:DN -SearchScope OneLevel -Filter $using:Filter -Properties $using:Properties -EA 0 | Select-Object $using:SelectPrty }
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
    $DC = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADDomainController -Discover -Domain $using:Domain | Select-Object -ExpandProperty HostName }
    foreach ($Object in $DN) {
        $ADObject += Invoke-Command -Session $TempPssSession { Get-ADObject $using:Object -Properties * -Server $using:DC | Select-Object -ExpandProperty CanonicalName }
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
                $Days = (New-TimeSpan -Start $StartTime -End $EndTime).Days
            }
        } catch { Out-Null }
    } elseif ($null -ne $EndTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (New-TimeSpan -Start (Get-Date) -End ($EndTime)).Days
        }
    } elseif ($null -ne $StartTime) {
        if ($StartTime -notlike $Ignore -and $EndTime -notlike $Ignore) {
            $Days = (New-TimeSpan -Start $StartTime -End (Get-Date)).Days
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
        [pscredential] $Credential,
        [ref]$DCStatus
    )
    $NameUsed = [System.Collections.Generic.List[string]]::new()
    [DateTime] $CurrentDate = Get-Date
    if (-not $Domains) {
        try {
            $Forest = $ADSystem
            $Domains = $Forest.Domains
        } catch {
            Write-PScriboMessage -Message "Get-WinADLastBackup - Failed to gather Forest Domains $($_.Exception.Message)"
            break
        }
    }
    foreach ($Domain in $Domains) {
        try {
            $DCServer = Get-ValidDCfromDomain -Domain $Domain -DCStatus $DCStatus
            [string[]]$Partitions = (Get-ADRootDSE -Credential $Credential -Server $DCServer -ErrorAction Stop).namingContexts
            [System.DirectoryServices.ActiveDirectory.DirectoryContextType] $contextType = [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain
            [System.DirectoryServices.ActiveDirectory.DirectoryContext] $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($contextType, $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            [System.DirectoryServices.ActiveDirectory.DomainController] $domainController = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context)
        } catch {
            Write-PScriboMessage -Message "Get-WinADLastBackup - Failed to gather partitions information for $Domain with error: $($_.Exception.Message)"
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
                Domain = $Domain
                NamingContext = $Name
                LastBackup = $LastBackup
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
            Write-PScriboMessage -Message "Get-WinADDFSHealth - You need to specify domain when using SkipAutodetection."
            return
        }
        # This is for case when Get-ADDomainController -Filter * is broken
        $ForestInformation = @{
            Domains = $IncludeDomains
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
                    Write-PScriboMessage -Message "Get-WinADDFSHealth - Can't get DC details. Skipping with error: $($_.Exception.Message)"
                    continue
                }
            }
        }
    }
    [Array] $Table = foreach ($Domain in $ForestInformation.Domains) {
        Write-PScriboMessage -Message "Get-WinADDFSHealth - Processing $Domain"
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
            try {
                Write-PScriboMessage -Message "Get-WinADDFSHealth - Processing $($DC.Name) $($DC.HostName) for $Domain"
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
                    "DomainController" = $DCName
                    "Domain" = $Domain
                    "Status" = $false
                    "ReplicationState" = 'Unknown'
                    "IsPDC" = $DC.OperationMasterRoles -contains 'PDCEmulator'
                    'GroupPolicyOutput' = $null -ne $GPOs # This shows whether output was on Get-GPO
                    "GroupPolicyCount" = if ($GPOs) { $GPOs.Count } else { 0 };
                    "SYSVOLCount" = 0
                    'CentralRepository' = $CentralRepositoryDomain
                    'CentralRepositoryDC' = $false
                    'IdenticalCount' = $false
                    "Availability" = $false
                    "MemberReference" = $false
                    "DFSErrors" = 0
                    "DFSEvents" = $null
                    "DFSLocalSetting" = $false
                    "DomainSystemVolume" = $false
                    "SYSVOLSubscription" = $false
                    "StopReplicationOnAutoRecovery" = $false
                    "DFSReplicatedFolderInfo" = $null
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
                    [Array] $Events = 0
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
            } catch {
                Write-PScriboMessage -Message "Get-WinADDFSHealth - Failed to gather DFS Health for $Domain $($DC.Name) with error: $($_.Exception.Message)"
                continue
            }
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
            '10.0.22000' = 'Windows 11 21H2'
            '10.0.19043' = 'Windows 10 21H1'
            '10.0.19042' = 'Windows 10 20H2'
            '10.0.19041' = 'Windows 10 2004'
            '10.0.18898' = 'Windows 10 Insider Preview'
            '10.0.18363' = "Windows 10 1909"
            '10.0.18362' = "Windows 10 1903"
            '10.0.17763' = "Windows 10 1809"
            '10.0.17134' = "Windows 10 1803"
            '10.0.16299' = "Windows 10 1709"
            '10.0.15063' = "Windows 10 1703"
            '10.0.14393' = "Windows 10 1607"
            '10.0.10586' = "Windows 10 1511"
            '10.0.10240' = "Windows 10 1507"

            # This is how it's written in registry
            '22000' = 'Windows 11 21H2'
            '19043' = 'Windows 10 21H1'
            '19042' = 'Windows 10 20H2'
            '19041' = 'Windows 10 2004'
            '18898' = 'Windows 10 Insider Preview'
            '18363' = "Windows 10 1909"
            '18362' = "Windows 10 1903"
            '17763' = "Windows 10 1809"
            '17134' = "Windows 10 1803"
            '16299' = "Windows 10 1709"
            '15063' = "Windows 10 1703"
            '14393' = "Windows 10 1607"
            '10586' = "Windows 10 1511"
            '10240' = "Windows 10 1507"
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
            '6.3 (9600)' = 'Windows Server 2012 R2'
            '6.1 (7601)' = 'Windows Server 2008 R2'
            '5.2 (3790)' = 'Windows Server 2003'

            # This is how WMI/CIM stores it
            '10.0.20348' = 'Windows Server 2022'
            '10.0.19042' = 'Windows Server 2019 20H2'
            '10.0.19041' = 'Windows Server 2019 2004'
            '10.0.18363' = 'Windows Server 2019 1909'
            '10.0.18362' = "Windows Server 2019 1903" #  (Datacenter Core, Standard Core)
            '10.0.17763' = "Windows Server 2019 1809"  # (Datacenter, Essentials, Standard)
            '10.0.17134' = "Windows Server 2016 1803" ## (Datacenter, Standard)
            '10.0.14393' = "Windows Server 2016 1607"
            '6.3.9600' = 'Windows Server 2012 R2'
            '6.1.7601' = 'Windows Server 2008 R2' # i think
            '5.2.3790' = 'Windows Server 2003' # i think

            # This is how it's written in registry
            '20348' = 'Windows Server 2022'
            '19042' = 'Windows Server 2019 20H2'
            '19041' = 'Windows Server 2019 2004'
            '18363' = 'Windows Server 2019 1909'
            '18362' = "Windows Server 2019 1903" # (Datacenter Core, Standard Core)
            '17763' = "Windows Server 2019 1809" # (Datacenter, Essentials, Standard)
            '17134' = "Windows Server 2016 1803" # (Datacenter, Standard)
            '14393' = "Windows Server 2016 1607"
            '9600' = 'Windows Server 2012 R2'
            '7601' = 'Windows Server 2008 R2'
            '3790' = 'Windows Server 2003'
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
        # 'kadmin/changepw'
        foreach ($Item in $Exclude) {
            $iTEM
        }
    )

    $SPNCache = [ordered] @{}
    $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExtendedForestInformation $ExtendedForestInformation -Credential $Credential
    foreach ($Domain in $ForestInformation.Domains) {
        Write-PScriboMessage -Message "Get-WinADDuplicateSPN - Processing $Domain"
        Write-PScriboMessage -Message "Get-WinADDuplicateSPN - Found $($Users.Count) objects. Processing..."
        foreach ($Object in $Users) {
            foreach ($SPN in $Object.ServicePrincipalName) {
                if (-not $SPNCache[$SPN]) {
                    $SPNCache[$SPN] = [PSCustomObject] @{
                        Name = $SPN
                        Duplicate = $false
                        Count = 0
                        Excluded = $false
                        List = [System.Collections.Generic.List[Object]]::new()
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
    Write-PScriboMessage -Message "Get-WinADDuplicateSPN - Finalizing output. Processing..."
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
            LDAPFilter = "(|(cn=*\0ACNF:*)(ou=*CNF:*))"
            Properties = 'DistinguishedName', 'ObjectClass', 'DisplayName', 'SamAccountName', 'Name', 'ObjectCategory', 'WhenCreated', 'WhenChanged', 'ProtectedFromAccidentalDeletion', 'ObjectGUID'
            Server = $DC
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
                ConflictDN = $_.DistinguishedName
                ConflictWhenChanged = $_.WhenChanged
                DomainName = $DomainName
                ObjectClass = $_.ObjectClass
            }
            $LiveObjectData = [ordered] @{
                LiveDn = "N/A"
                LiveWhenChanged = "N/A"
            }
            $RestData = [ordered] @{
                DisplayName = $_.DisplayName
                Name = $_.Name.Replace("`n", ' ')
                SamAccountName = $_.SamAccountName
                ObjectCategory = $_.ObjectCategory
                WhenCreated = $_.WhenCreated
                WhenChanged = $_.WhenChanged
                ProtectedFromAccidentalDeletion = $_.ProtectedFromAccidentalDeletion
                ObjectGUID = $_.ObjectGUID.Guid
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
                    } catch { Out-Null }
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
                    } catch { Out-Null }
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
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
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
            Write-PScriboMessage -Message "Get-WinADForestDetail - Error discovering DC for Forest - $($_.Exception.Message)"
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
                    Domain = $DC.Domain
                    Forest = $DC.Forest
                    HostName = [Array] $DC.HostName
                    IPv4Address = $DC.IPv4Address
                    IPv6Address = $DC.IPv6Address
                    Name = $DC.Name
                    Site = $DC.Site
                }

            } catch {
                Write-PScriboMessage -Message "Get-WinADForestDetail - Error discovering DC for domain $Domain - $($_.Exception.Message)"
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
                Write-PScriboMessage -Message "Get-WinADForestDetail - Domain $Domain doesn't seem to be active (no DCs). Skipping."
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
                    Write-PScriboMessage -Message "Get-WinADForestDetail - Error listing DCs for domain $Domain - $($_.Exception.Message)"
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
                        Domain = $Domain
                        HostName = $S.HostName
                        Name = $S.Name
                        Forest = $ForestInformation.RootDomain
                        Site = $S.Site
                        IPV4Address = $S.IPV4Address
                        IPV6Address = $S.IPV6Address
                        IsGlobalCatalog = $S.IsGlobalCatalog
                        IsReadOnly = $S.IsReadOnly
                        IsSchemaMaster = ($S.OperationMasterRoles -contains 'SchemaMaster')
                        IsDomainNamingMaster = ($S.OperationMasterRoles -contains 'DomainNamingMaster')
                        IsPDC = ($S.OperationMasterRoles -contains 'PDCEmulator')
                        IsRIDMaster = ($S.OperationMasterRoles -contains 'RIDMaster')
                        IsInfrastructureMaster = ($S.OperationMasterRoles -contains 'InfrastructureMaster')
                        OperatingSystem = $S.OperatingSystem
                        OperatingSystemVersion = $S.OperatingSystemVersion
                        OperatingSystemLong = ConvertTo-OperatingSystem -OperatingSystem $S.OperatingSystem -OperatingSystemVersion $S.OperatingSystemVersion
                        LdapPort = $S.LdapPort
                        SslPort = $S.SslPort
                        DistinguishedName = $S.ComputerObjectDN
                        Pingable = $null
                        WinRM = $null
                        PortOpen = $null
                        Comment = ''
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
                    Domain = $Domain
                    HostName = ''
                    Name = ''
                    Forest = $ForestInformation.RootDomain
                    IPV4Address = ''
                    IPV6Address = ''
                    IsGlobalCatalog = ''
                    IsReadOnly = ''
                    Site = ''
                    SchemaMaster = $false
                    DomainNamingMasterMaster = $false
                    PDCEmulator = $false
                    RIDMaster = $false
                    InfrastructureMaster = $false
                    LdapPort = ''
                    SslPort = ''
                    DistinguishedName = ''
                    Pingable = $null
                    WinRM = $null
                    PortOpen = $null
                    Comment = $_.Exception.Message -replace "`n", " " -replace "`r", " "
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
                            AllowedDNSSuffixes = $_.AllowedDNSSuffixes | ForEach-Object -Process { $_ }                #: { }
                            ChildDomains = $_.ChildDomains | ForEach-Object -Process { $_ }                      #: { }
                            ComputersContainer = $_.ComputersContainer                 #: CN = Computers, DC = ad, DC = evotec, DC = xyz
                            DeletedObjectsContainer = $_.DeletedObjectsContainer            #: CN = Deleted Objects, DC = ad, DC = evotec, DC = xyz
                            DistinguishedName = $_.DistinguishedName                  #: DC = ad, DC = evotec, DC = xyz
                            DNSRoot = $_.DNSRoot                            #: ad.evotec.xyz
                            DomainControllersContainer = $_.DomainControllersContainer         #: OU = Domain Controllers, DC = ad, DC = evotec, DC = xyz
                            DomainMode = $_.DomainMode                         #: Windows2012R2Domain
                            DomainSID = $_.DomainSID.Value                        #: S - 1 - 5 - 21 - 853615985 - 2870445339 - 3163598659
                            ForeignSecurityPrincipalsContainer = $_.ForeignSecurityPrincipalsContainer #: CN = ForeignSecurityPrincipals, DC = ad, DC = evotec, DC = xyz
                            Forest = $_.Forest                             #: ad.evotec.xyz
                            InfrastructureMaster = $_.InfrastructureMaster               #: AD1.ad.evotec.xyz
                            LastLogonReplicationInterval = $_.LastLogonReplicationInterval       #:
                            LinkedGroupPolicyObjects = $_.LinkedGroupPolicyObjects | ForEach-Object -Process { $_ }           #:
                            LostAndFoundContainer = $_.LostAndFoundContainer              #: CN = LostAndFound, DC = ad, DC = evotec, DC = xyz
                            ManagedBy = $_.ManagedBy                          #:
                            Name = $_.Name                               #: ad
                            NetBIOSName = $_.NetBIOSName                        #: EVOTEC
                            ObjectClass = $_.ObjectClass                        #: domainDNS
                            ObjectGUID = $_.ObjectGUID                         #: bc875580 - 4c70-41ad-a487-c57337e26024
                            ParentDomain = $_.ParentDomain                       #:
                            PDCEmulator = $_.PDCEmulator                        #: AD1.ad.evotec.xyz
                            PublicKeyRequiredPasswordRolling = $_.PublicKeyRequiredPasswordRolling | ForEach-Object -Process { $_ }   #:
                            QuotasContainer = $_.QuotasContainer                    #: CN = NTDS Quotas, DC = ad, DC = evotec, DC = xyz
                            ReadOnlyReplicaDirectoryServers = $_.ReadOnlyReplicaDirectoryServers | ForEach-Object -Process { $_ }    #: { }
                            ReplicaDirectoryServers = $_.ReplicaDirectoryServers | ForEach-Object -Process { $_ }           #: { AD1.ad.evotec.xyz, AD2.ad.evotec.xyz, AD3.ad.evotec.xyz }
                            RIDMaster = $_.RIDMaster                          #: AD1.ad.evotec.xyz
                            SubordinateReferences = $_.SubordinateReferences | ForEach-Object -Process { $_ }            #: { DC = ForestDnsZones, DC = ad, DC = evotec, DC = xyz, DC = DomainDnsZones, DC = ad, DC = evotec, DC = xyz, CN = Configuration, DC = ad, DC = evotec, DC = xyz }
                            SystemsContainer = $_.SystemsContainer                   #: CN = System, DC = ad, DC = evotec, DC = xyz
                            UsersContainer = $_.UsersContainer                     #: CN = Users, DC = ad, DC = evotec, DC = xyz
                        }
                    }

                    $NetBios = $Findings['DomainsExtended'][$DomainEx]['NetBIOSName']
                    $Findings['DomainsExtendedNetBIOS'][$NetBios] = $Findings['DomainsExtended'][$DomainEx]
                } catch {
                    Write-PScriboMessage -Message "Get-WinADForestDetail - Error gathering Domain Information for domain $DomainEx - $($_.Exception.Message)"
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
                $CimSession = Get-ValidCIMSession -ComputerName $Computers[0] -SessionName $Computers[0] -CIMTable ([ref]$CIMTable)
                Get-CimInstance -CimSession $CimSession -ClassName $Class -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsToProcess | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
            } else {
                $Option = New-CimSessionOption -Protocol $Protocol
                $Session = New-CimSession -ComputerName $Computers -SessionOption $Option -ErrorAction SilentlyContinue -Credential $Credential
                $Info = Get-CimInstance -ClassName $Class -CimSession $Session -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsToProcess | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
                $null = Remove-CimSession -CimSession $Session -ErrorAction SilentlyContinue
                $Info
            }
        }
        foreach ($E in $ErrorsToProcess) {
            Write-PScriboMessage -Message "Get-CimData - No data for computer $($E.OriginInfo.PSComputerName). Failed with errror: $($E.Exception.Message)"
        }
        # Process local computer
        $Computers = $ComputersSplit[0]
        if ($Computers.Count -gt 0) {
            $Info = Get-CimInstance  -CimSession $CimSession  -ClassName $Class -ErrorAction SilentlyContinue -Property $PropertiesOnly -Namespace $NameSpace -Verbose:$false -ErrorVariable ErrorsLocal | Select-Object -Property $Properties -ExcludeProperty $ExcludeProperties
            $Info | Add-Member -Name 'PSComputerName' -Value $Computers -MemberType NoteProperty -Force
            $Info
        }
        foreach ($E in $ErrorsLocal) {
            Write-PScriboMessage -Message "Get-CimData - No data for computer $($Env:COMPUTERNAME). Failed with errror: $($E.Exception.Message)"
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
                    $Distinguished = $Distinguished -replace '^.+?,(?=..=)'
                    if ($Distinguished -match '^DC=') {
                        break
                    }
                    $Distinguished
                }
            } elseif ($ToDC) {
                $Value = $Distinguished -replace '.*?((DC=[^=]+,)+DC=[^=]+)$', '$1'
                if ($Value) {
                    $Value
                }
            } elseif ($ToLastName) {
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
                $Found = $Distinguished -match $Regex
                if ($Found) {
                    $Matches.cn
                }
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
            Output = $null
            Status = $null
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
                    'Port' = $P
                    'Protocol' = 'TCP'
                    'Status' = $null
                    'Summary' = $null
                    'Response' = $null
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
                    'Port' = $P
                    'Protocol' = 'UDP'
                    'Status' = $null
                    'Summary' = $null
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

function Get-ComputerADDomain {
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
    Write-PScriboMessage -Message 'Calling GetCurrentDomain()'
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
        } else {
            $AuditValue = Switch ($_.AuditFilter) {
                $Null { 'Never Configured' }
                default { $_.AuditFilter }
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
        $ADRoot = Invoke-Command -Session $TempPssSession { (Get-ADRootDSE -Server $Using:Target).defaultNamingContext }
        Invoke-Command -Session $TempPssSession { Get-ADObject -Filter * -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$Using:ADRoot" -SearchScope 2 -Properties * }
    } catch {
        Write-PScriboMessage -IsWarning -Message "Unable to find CA auditing information"
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
    [OutputType([String])]
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
            Write-PScriboMessage -IsWarning -Message 'Could not determine issue severity'
        }
    }
}
Function Get-ADExchangeServer {
    <#
    .SYNOPSIS
    Used by As Built Report to get Exchange information from AD forest.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
        Author:         Brian Farnsworth

    .EXAMPLE
    Get-ADExchangeServer

    .LINK
    https://codeandkeep.com/PowerShell-ActiveDirectory-Exchange-Part1/
    #>
    Function ConvertToExchangeRole {
        Param(
            [Parameter(Position = 0)]
            [int]$roles
        )

        $roleNumber = @{
            2 = 'MBX';
            4 = 'CAS';
            16 = 'UM';
            32 = 'HUB';
            64 = 'EDGE';
        }

        $roleList = New-Object -TypeName Collections.ArrayList

        foreach ($key in ($roleNumber).Keys) {
            if ($key -band $roles) {
                [void]$roleList.Add($roleNumber.$key)
            }
        }

        Write-Output $roleList
    }

    # Get the Configuration Context
    $rootDse = Invoke-Command -Session $TempPssSession { Get-ADRootDSE }
    $cfgCtx = $rootDse.ConfigurationNamingContext

    # Query AD for Exchange Servers
    $exchServers = Invoke-Command -ErrorAction SilentlyContinue -Session $TempPssSession { Get-ADObject -Filter "ObjectCategory -eq 'msExchExchangeServer'" -SearchBase $using:cfgCtx -Properties msExchCurrentServerRoles, networkAddress, serialNumber }
    foreach ($server in $exchServers) {
        Try {
            $roles = ConvertToExchangeRole -roles $server.msExchCurrentServerRoles

            $fqdn = ($server.networkAddress | Where-Object { $_ -like 'ncacn_ip_tcp:*' }).Split(':')[1]

            New-Object -TypeName PSObject -Property @{
                Name = $server.Name;
                DnsHostName = $fqdn;
                Version = $server.serialNumber[0];
                ServerRoles = $roles;
            }
        } Catch {
            Write-PScriboMessage -IsWarning -Message "ExchangeServer: [$($server.Name)]. $($_.Exception.Message)"
        }
    }
}

function Get-PieChart {
    <#
    .SYNOPSIS
    Used by As Built Report to generate PScriboChart pie charts.

    .DESCRIPTION
    The Get-PieChart function generates a pie chart using the PScriboChart module. It accepts various parameters to customize the chart, such as sample data, chart name, fields for the X and Y axes, legend name and alignment, chart title, dimensions, and palette options. The function returns the pie chart as a Base64-encoded string.

    .PARAMETER SampleData
    An array of data to be used for generating the pie chart.

    .PARAMETER ChartName
    The name of the chart.

    .PARAMETER XField
    The field to be used for the X-axis.

    .PARAMETER YField
    The field to be used for the Y-axis.

    .PARAMETER ChartLegendName
    The name of the chart legend.

    .PARAMETER ChartLegendAlignment
    The alignment of the chart legend. Default is 'Center'.

    .PARAMETER ChartTitleName
    The name of the chart title. Default is a space character.

    .PARAMETER ChartTitleText
    The text of the chart title. Default is a space character.

    .PARAMETER Width
    The width of the chart in pixels. Default is 600.

    .PARAMETER Height
    The height of the chart in pixels. Default is 400.

    .PARAMETER ReversePalette
    A boolean indicating whether to reverse the color palette. Default is $false.

    .EXAMPLE
    $sampleData = @(
        @{ Category = 'A'; Value = 10 },
        @{ Category = 'B'; Value = 20 },
        @{ Category = 'C'; Value = 30 }
    )
    Get-PieChart -SampleData $sampleData -ChartName 'ExampleChart' -XField 'Category' -YField 'Value' -ChartLegendName 'Legend'

    .LINK
    https://github.com/iainbrighton/PScriboCharts
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    Param
    (
        [Parameter (
            Position = 0,
            Mandatory,
            HelpMessage = 'An array of data to be used for generating the pie chart.')]
        [System.Array]
        $SampleData,
        [Parameter (
            HelpMessage = 'The name of the chart.')]
        [String]
        $ChartName,
        [Parameter (
            HelpMessage = 'The field to be used for the X-axis.')]
        [String]
        $XField,
        [Parameter (
            HelpMessage = 'The field to be used for the Y-axis.')]
        [String]
        $YField,
        [Parameter (
            HelpMessage = 'The name of the chart legend.')]
        [String]
        $ChartLegendName,
        [Parameter (
            HelpMessage = 'The alignment of the chart legend. Default is Center.')]
        [String]
        $ChartLegendAlignment = 'Center',
        [Parameter (
            HelpMessage = 'The name of the chart title. Default is a space character.')]
        [String]
        $ChartTitleName = ' ',
        [Parameter (
            HelpMessage = 'The text of the chart title. Default is a space character.')]
        [String]
        $ChartTitleText = ' ',
        [Parameter (
            HelpMessage = 'The width of the chart in pixels. Default is 600.')]
        [int]
        $Width = 600,
        [Parameter (
            HelpMessage = 'The height of the chart in pixels. Default is 400.')]
        [int]
        $Height = 400,
        [Parameter (
            HelpMessage = 'A boolean indicating whether to reverse the color palette. Default is $false.')]
        [bool]
        $ReversePalette = $false
    )

    $AbrCustomPalette = @(
        [System.Drawing.ColorTranslator]::FromHtml('#355780')
        [System.Drawing.ColorTranslator]::FromHtml('#48678f')
        [System.Drawing.ColorTranslator]::FromHtml('#5b789e')
        [System.Drawing.ColorTranslator]::FromHtml('#6e89ae')
        [System.Drawing.ColorTranslator]::FromHtml('#809bbe')
        [System.Drawing.ColorTranslator]::FromHtml('#94acce')
        [System.Drawing.ColorTranslator]::FromHtml('#a7bfde')
        [System.Drawing.ColorTranslator]::FromHtml('#bbd1ee')
        [System.Drawing.ColorTranslator]::FromHtml('#cfe4ff')
    )

    $exampleChart = New-Chart -Name $ChartName -Width $Width -Height $Height -BorderColor 'DarkBlue' -BorderStyle Dash -BorderWidth 1

    $addChartAreaParams = @{
        Chart = $exampleChart
        Name = 'exampleChartArea'
        AxisXInterval = 1
    }
    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

    $addChartSeriesParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = 'exampleChartSeries'
        XField = $XField
        YField = $YField
        CustomPalette = $AbrCustomPalette
        ColorPerDataPoint = $true
        ReversePalette = $ReversePalette
    }
    $sampleData | Add-PieChartSeries @addChartSeriesParams

    $addChartLegendParams = @{
        Chart = $exampleChart
        Name = $ChartLegendName
        TitleAlignment = $ChartLegendAlignment
    }
    Add-ChartLegend @addChartLegendParams

    $addChartTitleParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = $ChartTitleName
        Text = $ChartTitleText
        Font = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Segoe Ui', '12', [System.Drawing.FontStyle]::Bold)
    }
    Add-ChartTitle @addChartTitleParams

    $TempPath = Resolve-Path ([System.IO.Path]::GetTempPath())

    $ChartImage = Export-Chart -Chart $exampleChart -Path $TempPath.Path -Format "PNG" -PassThru

    $Base64Image = [convert]::ToBase64String((Get-Content $ChartImage -Encoding byte))

    Remove-Item -Path $ChartImage.FullName

    return $Base64Image

} # end


function Get-ColumnChart {
    <#
    .SYNOPSIS
        Generates a column chart based on the provided sample data.

    .DESCRIPTION
        The Get-ColumnChart function creates a column chart using the provided sample data array.
        You can specify the chart name, X-axis title, and Y-axis title.

    .PARAMETER SampleData
        An array of sample data to be used for generating the column chart. This parameter is mandatory.

    .PARAMETER ChartName
        The name of the chart. This parameter is optional.

    .PARAMETER AxisXTitle
        The title for the X-axis of the chart. This parameter is optional.

    .PARAMETER AxisYTitle
        The title for the Y-axis of the chart. This parameter is optional.

    .OUTPUTS
        System.String
        Returns a string representation of the generated column chart.

    .EXAMPLE
        $data = @(1, 2, 3, 4, 5)
        Get-ColumnChart -SampleData $data -ChartName "Sample Chart" -AxisXTitle "X Axis" -AxisYTitle "Y Axis"

    .NOTES
        Author: Your Name
        Date: Today's Date
    #>

    [CmdletBinding()]
    [OutputType([System.String])]
    Param
    (
        [Parameter (
            Position = 0,
            Mandatory,
            HelpMessage = "Provide the sample data as an array."
        )]
        [System.Array]
        $SampleData,

        [Parameter (
            HelpMessage = "Specify the name of the chart."
        )]
        [String]
        $ChartName,

        [Parameter (
            HelpMessage = "Specify the title for the X axis."
        )]
        [String]
        $AxisXTitle,

        [Parameter (
            HelpMessage = "Specify the title for the Y axis."
        )]
        [String]
        $AxisYTitle,

        [Parameter (
            HelpMessage = "Specify the field for the X axis."
        )]
        [String]
        $XField,

        [Parameter (
            HelpMessage = "Specify the field for the Y axis."
        )]
        [String]
        $YField,

        [Parameter (
            HelpMessage = "Specify the name of the chart area."
        )]
        [String]
        $ChartAreaName,

        [Parameter (
            HelpMessage = "Specify the name of the chart title."
        )]
        [String]
        $ChartTitleName = '',

        [Parameter (
            HelpMessage = "Specify the text for the chart title."
        )]
        [String]
        $ChartTitleText = ' ',

        [Parameter (
            HelpMessage = "Specify the width of the chart."
        )]
        [int]
        $Width = 600,

        [Parameter (
            HelpMessage = "Specify the height of the chart."
        )]
        [int]
        $Height = 400,

        [Parameter (
            HelpMessage = "Specify whether to reverse the color palette."
        )]
        [bool]
        $ReversePalette = $false
    )

    $AbrCustomPalette = @(
        [System.Drawing.ColorTranslator]::FromHtml('#355780')
        [System.Drawing.ColorTranslator]::FromHtml('#48678f')
        [System.Drawing.ColorTranslator]::FromHtml('#5b789e')
        [System.Drawing.ColorTranslator]::FromHtml('#6e89ae')
        [System.Drawing.ColorTranslator]::FromHtml('#809bbe')
        [System.Drawing.ColorTranslator]::FromHtml('#94acce')
        [System.Drawing.ColorTranslator]::FromHtml('#a7bfde')
        [System.Drawing.ColorTranslator]::FromHtml('#bbd1ee')
        [System.Drawing.ColorTranslator]::FromHtml('#cfe4ff')
    )

    $exampleChart = New-Chart -Name $ChartName -Width $Width -Height $Height -BorderColor 'DarkBlue' -BorderStyle Dash -BorderWidth 1

    $addChartAreaParams = @{
        Chart = $exampleChart
        Name = $ChartAreaName
        AxisXTitle = $AxisXTitle
        AxisYTitle = $AxisYTitle
        NoAxisXMajorGridLines = $true
        NoAxisYMajorGridLines = $true
        AxisXInterval = 1
    }
    $exampleChartArea = Add-ChartArea @addChartAreaParams -PassThru

    $addChartSeriesParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = 'exampleChartSeries'
        XField = $XField
        YField = $YField
        CustomPalette = $AbrCustomPalette
        ColorPerDataPoint = $true
        ReversePalette = $ReversePalette
    }
    $sampleData | Add-ColumnChartSeries @addChartSeriesParams

    $addChartTitleParams = @{
        Chart = $exampleChart
        ChartArea = $exampleChartArea
        Name = $ChartTitleName
        Text = $ChartTitleText
        Font = New-Object -TypeName 'System.Drawing.Font' -ArgumentList @('Segoe Ui', '12', [System.Drawing.FontStyle]::Bold)
    }
    Add-ChartTitle @addChartTitleParams

    $TempPath = Resolve-Path ([System.IO.Path]::GetTempPath())

    $ChartImage = Export-Chart -Chart $exampleChart -Path $TempPath.Path -Format "PNG" -PassThru

    if ($PassThru) {
        Write-Output -InputObject $chartFileItem
    }

    $Base64Image = [convert]::ToBase64String((Get-Content $ChartImage -Encoding byte))

    Remove-Item -Path $ChartImage.FullName

    return $Base64Image

} # end

function Get-ADObjectList {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Users", "Computers", "Groups", "DomainControllers", "GPOs", "OUs")]
        [string[]]$Object
    )

    [System.Collections.Generic.List[PSObject]]$adObjects = New-Object System.Collections.Generic.List[PSObject]
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $ConstructedDomainName = "DC=" + $Domain.Split(".")
    $ConstructedDomainName = $ConstructedDomainName -replace " ", ",DC="

    if ($Server) {
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$ConstructedDomainName", $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        $searcher.SearchRoot = "LDAP://$ConstructedDomainName"
    }

    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.Add("*") | Out-Null
    $searcher.SearchScope = "Subtree"

    # Construct the LDAP filter based on the -Collect parameter
    $filters = @()
    foreach ($item in $Object) {
        switch ($item) {
            "Users" { $filters += "(objectCategory=person)" }
            "Computers" { $filters += "(objectCategory=computer)" }
            "Groups" { $filters += "(objectCategory=group)" }
            "DomainControllers" { $filters += "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" }
            "OUs" { $filters += "(objectCategory=organizationalUnit)" }
            "GPOs" { $filters += "(objectClass=groupPolicyContainer)" }
        }
    }
    # Combine the filters with an OR if multiple categories are specified
    $searcher.Filter = if ($filters.Count -gt 1) { "(|" + ($filters -join "") + ")" } else { $filters[0] }

    $results = $searcher.FindAll()
    foreach ($result in $results) {
        $properties = $result.Properties
        $obj = New-Object PSObject
        foreach ($propertyName in $properties.PropertyNames) {
            $value = if ($properties[$propertyName].Count -eq 1) { $properties[$propertyName][0] } else { $properties[$propertyName] }
            $obj | Add-Member -NotePropertyName $propertyName -NotePropertyValue $value
        }
        $obj | Add-Member -NotePropertyName "domain" -NotePropertyValue $Domain
        $adObjects.Add($obj)
    }
    $searcher.Dispose()
    return $adObjects
}

function ConvertTo-HashToYN {
    <#
    .SYNOPSIS
        Used by As Built Report to convert array content true or false automatically to Yes or No.
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
        Author:         Jonathan Colon

    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    Param (
        [Parameter (Position = 0, Mandatory)]
        [AllowEmptyString()]
        [System.Collections.Specialized.OrderedDictionary] $TEXT
    )

    $result = [ordered] @{}
    foreach ($i in $TEXT.GetEnumerator()) {
        try {
            $result.add($i.Key, (ConvertTo-TextYN $i.Value))
        } catch {
            $result.add($i.Key, ($i.Value))
        }
    }
    if ($result) {
        return $result
    } else { return $TEXT }
} # end

function Get-ValidDCfromDomain {
    <#
    .SYNOPSIS
        Used by As Built Report to get a valid Domain Controller from Domain.
    .DESCRIPTION
        Function to get a valid DC from a Active Directory Domain string.
        It use Test-WsMan to test WinRM status of the machine.
    .NOTES
        Version:        0.1.0
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidDCfromDomain -Domain 'pharmax.local'
            Server-DC-01V.pharmax.local
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,
        [ref]$DCStatus
    )

    $DCList = Invoke-Command -Session $TempPssSession { (Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers }

    if ($DCList) {
        foreach ($TestedDC in $DCList) {
            if (Get-DCWinRMState -ComputerName $TestedDC -DCStatus $DCStatus) {
                Write-PScriboMessage -Message "Using $TestedDC to retreive $Domain information."
                $TestedDC
                break
            } else {
                Write-PScriboMessage -Message "Unable to connect to $TestedDC to retreive $Domain information."
            }
        }
    } else {
        Write-PScriboMessage -Message "Unable to connect to $Domain to get a valid Domain Controller list."
    }
}# end

function Get-DCWinRMState {
    <#
    .SYNOPSIS
        Checks the WinRM status of a specified domain controller.

    .DESCRIPTION
        The Get-DCWinRMState function checks if the Windows Remote Management (WinRM) service is available and accessible on a specified domain controller.

    .PARAMETER ComputerName
        The name of the computer (domain controller) to check the WinRM status for.

    .OUTPUTS
        [Bool]
        Returns $true if WinRM is accessible on the specified computer, otherwise returns $false.

    .EXAMPLE
        PS C:\> Get-DCWinRMState -ComputerName "DC01"
        Checks the WinRM status on the domain controller named "DC01".

    .NOTES
        This function requires the PScribo module for logging messages.
        Ensure that the $Credential and $Options variables are properly set in the calling scope.
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [ref]$DCStatus
    )
    $PingStatus = switch (Test-Connection -ComputerName $ComputerName -Count 2 -Quiet) {
        'True' { "Online" }
        'False' { "Offline" }
    }

    Write-PScriboMessage -Message "Validating WinRM status of $ComputerName in Cache"
    if ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'WinRMSSL' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: Offline"
        return $false
    } elseif ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'WinRM' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: Offline"
        return $false
    }


    if ($DCStatus.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' }) {
        Write-PScriboMessage -Message "Valid WinRM status of $ComputerName found in Cache: return True"
        return $true
    } else {
        Write-PScriboMessage -Message "No valid WinRM status of $ComputerName found in Cache: Building new connection."
        # build the connection to the DC
        $ConnectionParams = @{
            ComputerName = $ComputerName
            Credential = $Credential
            Authentication = $Options.PSDefaultAuthentication
            ErrorAction = 'SilentlyContinue'
        }

        if ($Options.WinRMSSL) {
            $ConnectionParams.Add('UseSSL', $true)
            $ConnectionParams.Add('Port', $Options.WinRMSSLPort)
            $WinRMType = "WinRMSSL"
        } else {
            $ConnectionParams.Add('Port', $Options.WinRMPort)
            $WinRMType = "WinRM"
        }

        if (Test-WSMan @ConnectionParams) {
            $DCStatus.Value += @{
                DCName = $ComputerName
                Status = 'Online'
                Protocol = $WinRMType
                PingStatus = $PingStatus
            }
            Write-PScriboMessage -Message "WinRM status in $ComputerName is Online ($WinRMType)."
            return $true
        }

        if ($Options.WinRMFallbackToNoSSL) {
            $ConnectionParams['UseSSL'] = $false
            $ConnectionParams['Port'] = $Options.WinRMPort
            $WinRMType = "WinRM"
            if (Test-WSMan @ConnectionParams) {
                Write-PScriboMessage -Message "WinRM status in $ComputerName is Online ($WinRMType)."
                $DCStatus.Value += @{
                    DCName = $ComputerName
                    Status = 'Online'
                    Protocol = $WinRMType
                    PingStatus = $PingStatus
                }
                return $true
            } else {
                Write-PScriboMessage -Message "Unable to connect to $ComputerName through $WinRMType."
                $DCStatus.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = $WinRMType
                    PingStatus = $PingStatus
                }
                return $false
            }

        } else {
            $DCStatus.Value += @{
                DCName = $ComputerName
                Status = 'Offline'
                Protocol = $WinRMType
                PingStatus = $PingStatus
            }
            Write-PScriboMessage -Message "Unable to connect to $ComputerName through $WinRMType."
            return $false
        }
    }
}# end

function Get-ValidPSSession {
    <#
    .SYNOPSIS
        Used by As Built Report to get generate a valid WinRM session.
    .DESCRIPTION
        Function to generate a valid WinRM session from a computer string.
    .NOTES
        Version:        0.9.5
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidPSSession -ComputerName 'server-dc-01v.pharmax.local'
            Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
            -- ----            ------------    ------------    -----         -----------------     ------------
            9 Global:TempP... server-dc-01... RemoteMachine   Opened        Microsoft.PowerShell     Available

    .Todo
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionName,
        [ref]$PSSTable

    )

    if ((-Not $Options.WinRMFallbackToNoSSL) -and ($PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'PSSessionSSL' })) {
        throw "Unable to connect to $ComputerName through PSSession (WinRM with SSL)."
    } elseif (($Options.WinRMFallbackToNoSSL) -and ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSession' })) {
        # Write-PScriboMessage -Message "Unable to connect to $ComputerName through PSSession (WinRM with SSL)."
        Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM)."
        return Get-PSSession $PSessionObj.Id
    }

    if ($Options.WinRMSSL) {
        if ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSessionSSL' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM with SSL)."
            return Get-PSSession $PSessionObj.Id
        } else {
            try {
                Write-PScriboMessage -Message "Connecting to '$ComputerName' through PSSession with SSL."
                if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -UseSSL -Port $Options.WinRMSSLPort) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' through PSSession (WinRM with SSL)."
                    $PSSTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'PSSessionSSL'
                        Id = $SessionObject.Id
                    }
                    return $SessionObject
                }
            } catch {
                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession with SSL."
                $PSSTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'PSSessionSSL'
                    Id = 'None'
                }
                if ($Options.WinRMFallbackToNoSSL) {
                    if ($PSessionObj = Get-PSSession | Where-Object { $_.ComputerName -eq $ComputerName -and $_.Availability -eq 'Available' -and $_.State -eq 'Opened' -and $_.Runspace.ConnectionInfo.Scheme -eq 'http' -and $_.Runspace.ConnectionInfo.Credential.Username -eq $Credential.UserName }) {
                        Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id) (WinRM without SSL)."
                        $PSSTable.Value += @{
                            DCName = $ComputerName
                            Status = 'Online'
                            Protocol = 'PSSession'
                            Id = $PSessionObj.Id
                        }
                        return $PSessionObj
                    } else {
                        Write-PScriboMessage -Message "Generating a PSSession to '$ComputerName' (WinRM without SSL)."
                        try {
                            if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                                Write-PScriboMessage -Message "Connected to '$ComputerName' through PSSession (WinRM without SSL)."
                                $PSSTable.Value += @{
                                    DCName = $ComputerName
                                    Status = 'Online'
                                    Protocol = 'PSSession'
                                    Id = $SessionObject.Id
                                }
                                return $SessionObject
                            }
                        } catch {
                            Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession."
                            $PSSTable.Value += @{
                                DCName = $ComputerName
                                Status = 'Offline'
                                Protocol = 'PSSession'
                                Id = 'None'
                            }
                        }
                    }
                } else {
                    throw
                }
            }
        }
    } else {
        if ($PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'PSSession' }) {
            throw "Unable to connect to $ComputerName through PSSession (WinRM)."
        } elseif ($PSessionObj = $PSSTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'PSSession' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' PSSession id: $($PSessionObj.Id)"
            return Get-PSSession $PSessionObj.Id
        } else {
            Write-PScriboMessage -Message "Generating a PSSession to '$ComputerName'."
            try {
                if ($SessionObject = New-PSSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                    $PSSTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'PSSession'
                        Id = $SessionObject.Id
                    }
                    return $SessionObject
                }
            } catch {
                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through PSSession."
                $PSSTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'PSSession'
                    Id = 'None'
                }
            }
        }
    }
}# end

function Get-ValidCIMSession {
    <#
    .SYNOPSIS
        Used by As Built Report to get generate a valid CIM session.
    .DESCRIPTION
        Function to generate a valid CIM session from a computer string.
    .NOTES
        Version:        0.9.5
        Author:         Jonathan Colon
    .EXAMPLE
        PS C:\Users\JohnDoe> Get-ValidCIMSession -ComputerName 'server-dc-01v.pharmax.local'
            Server-DC-01V.pharmax.local
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionName,
        [ref]$CIMTable
    )

    if ((-Not $Options.WinRMFallbackToNoSSL) -and ($CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'CimSessionSSL' })) {
        throw "Unable to connect to $ComputerName through CimSession (CIM with SSL)."
    } elseif (($Options.WinRMFallbackToNoSSL) -and ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSession' })) {
        Write-PScriboMessage -Message "Unable to connect to $ComputerName through CimSession (CIM with SSL)."
        Write-PScriboMessage -Message "WinRMFallbackToNoSSL option set using available '$ComputerName' CimSession id: $($CIMSessionObj.Id) (WinRM)."
        return Get-CimSession $CIMSessionObj.Id
    }

    if ($Options.WinRMSSL) {
        if ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSessionSSL' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' CIMSession id: $($CIMSessionObj.Id) (CimSession)."
            return Get-CimSession $CIMSessionObj.Id
        } else {
            try {
                Write-PScriboMessage -Message "No available CimSession with SSL found for '$ComputerName': Generating a new one."
                $CimSessionOptions = New-CimSessionOption -ProxyAuthentication $Options.PSDefaultAuthentication -ProxyCredential $Credential -UseSsl
                Write-PScriboMessage -Message "Connecting to '$ComputerName' through CimSession with SSL."
                if ($CIMSessionObj = New-CimSession $ComputerName -SessionOption $CimSessionOptions -Port $Options.WinRMSSLPort -Name $SessionName -ErrorAction Stop) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' through CimSession with SSL."
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'CimSessionSSL'
                        Id = $CIMSessionObj.Id
                        InstanceId = $CIMSessionObj.InstanceId
                    }
                    $CIMSessionObj
                }
            } catch {
                if ($Options.WinRMFallbackToNoSSL) {
                    Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession with SSL. Reverting to Cim without SSL!"
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Offline'
                        Protocol = 'CimSessionSSL'
                        Id = 'None'
                        InstanceId = 'None'
                    }
                    try {
                        if ($CIMSessionObj = New-CimSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name $SessionName -Port $Options.WinRMPort) {
                            Write-PScriboMessage -Message "Connected to '$ComputerName' through CimSession without SSL."
                            $CIMTable.Value += @{
                                DCName = $ComputerName
                                Status = 'Online'
                                Protocol = 'CimSession'
                                Id = $CIMSessionObj.Id
                                InstanceId = $CIMSessionObj.InstanceId
                            }
                            $CIMSessionObj
                        }
                    } catch {
                        Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession without SSL."
                        $CIMTable.Value += @{
                            DCName = $ComputerName
                            Status = 'Offline'
                            Protocol = 'CimSession'
                            Id = 'None'
                            InstanceId = 'None'
                        }
                    }
                }
            }
        }
    } else {
        if ($CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Offline' -and $_.Protocol -eq 'CimSession' }) {
            throw "Unable to connect to $ComputerName through CimSession (CimSession)."
        } elseif ($CIMSessionObj = $CIMTable.Value | Where-Object { $_.DCName -eq $ComputerName -and $_.Status -eq 'Online' -and $_.Protocol -eq 'CimSession' }) {
            Write-PScriboMessage -Message "Using available '$ComputerName' CIMSession id: $($CIMSessionObj.Id) (CimSession without SSL)."
            return Get-CimSession $CIMSessionObj.Id
        } else {
            Write-PScriboMessage -Message "Connecting to '$ComputerName' through CimSession without SSL."
            try {
                if ($CIMSessionObj = New-CimSession $ComputerName -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name $SessionName -Port $Options.WinRMPort) {
                    Write-PScriboMessage -Message "Connected to '$ComputerName' CimSession without SSL."
                    $CIMTable.Value += @{
                        DCName = $ComputerName
                        Status = 'Online'
                        Protocol = 'CimSession'
                        Id = $CIMSessionObj.Id
                        InstanceId = $CIMSessionObj.InstanceId
                    }
                    $CIMSessionObj
                }
            } catch {
                Write-PScriboMessage -Message "Unable to Connect to '$ComputerName' through CimSession without SSL."
                $CIMTable.Value += @{
                    DCName = $ComputerName
                    Status = 'Offline'
                    Protocol = 'CimSession'
                    Id = 'None'
                    InstanceId = 'None'
                }
            }
        }
    }
}# end