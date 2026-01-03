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
        [switch] $SkipGPO,
        [switch] $SkipAutodetection,
        [System.Collections.IDictionary] $ExtendedForestInformation,
        [pscredential] $Credential
    )

    if (-not $SkipAutodetection) {
        $ForestInformation = Get-WinADForestDetail -Forest $Forest -IncludeDomains $IncludeDomains -ExcludeDomains $ExcludeDomains -ExcludeDomainControllers $ExcludeDomainControllers -IncludeDomainControllers $IncludeDomainControllers -SkipRODC:$SkipRODC -ExtendedForestInformation $ExtendedForestInformation -Extended -Credential $Credential
    } else {
        if (-not $IncludeDomains) {
            Write-PScriboMessage -Message 'Get-WinADDFSHealth - You need to specify domain when using SkipAutodetection.'
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
                    $PoliciesSearchBase = -join ('CN=Policies,', $SystemsContainer)
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
                    'DomainController' = $DCName
                    'Domain' = $Domain
                    'Status' = $false
                    'ReplicationState' = 'Unknown'
                    'IsPDC' = $DC.OperationMasterRoles -contains 'PDCEmulator'
                    'GroupPolicyOutput' = $null -ne $GPOs # This shows whether output was on Get-GPO
                    'GroupPolicyCount' = if ($GPOs) { $GPOs.Count } else { 0 };
                    'SYSVOLCount' = 0
                    'CentralRepository' = $CentralRepositoryDomain
                    'CentralRepositoryDC' = $false
                    'IdenticalCount' = $false
                    'Availability' = $false
                    'MemberReference' = $false
                    'DFSErrors' = 0
                    'DFSEvents' = $null
                    'DFSLocalSetting' = $false
                    'DomainSystemVolume' = $false
                    'SYSVOLSubscription' = $false
                    'StopReplicationOnAutoRecovery' = $false
                    'DFSReplicatedFolderInfo' = $null
                }
                if ($SkipGPO) {
                    $DomainSummary.Remove('GroupPolicyOutput')
                    $DomainSummary.Remove('GroupPolicyCount')
                    $DomainSummary.Remove('SYSVOLCount')
                }

                $WarningVar = $null
                $DFSReplicatedFolderInfoAll = Get-CimData -NameSpace 'root\microsoftdfs' -Class 'dfsrreplicatedfolderinfo' -ComputerName $Hostname -WarningAction SilentlyContinue -WarningVariable WarningVar -Verbose:$false
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
                        [Array] $SYSVOL = Get-ChildItem -Path "\\$Hostname\SYSVOL\$Domain\Policies" -Exclude 'PolicyDefinitions*' -ErrorAction Stop
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
                    # $Registry = Get-PSRegistry -RegistryPath "HKLM\SYSTEM\CurrentControlSet\Services\DFSR\Parameters" -ComputerName $Hostname -ErrorAction Stop
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