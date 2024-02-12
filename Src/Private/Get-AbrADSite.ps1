function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.1
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PScriboMessage "Discovering Active Directory Sites information of forest $ForestInfo"
    }

    process {
        try {
            $Site = Invoke-Command -Session $TempPssSession { Get-ADReplicationSite -Filter * -Properties * }
            if ($Site) {
                Section -Style Heading3 'Sites' {
                    $OutObj = @()
                    foreach ($Item in $Site) {
                        try {
                            Write-PScriboMessage "Collecting '$($Item.Name)' Site"
                            $SubnetArray = @()
                            $Subnets = $Item.Subnets
                            foreach ($Object in $Subnets) {
                                $SubnetName = Invoke-Command -Session $TempPssSession { Get-ADReplicationSubnet $using:Object }
                                $SubnetArray += $SubnetName.Name
                            }
                            $inObj = [ordered] @{
                                'Site Name' = $Item.Name
                                'Description' = ConvertTo-EmptyToFiller $Item.Description
                                'Subnets' = Switch (($SubnetArray).count) {
                                    0 { "No subnet assigned" }
                                    default { $SubnetArray }
                                }
                                'Domain Controllers' = & {
                                    $ServerArray = @()
                                    $Servers = try { Get-ADObjectSearch -DN "CN=Servers,$($Item.DistinguishedName)" -Filter { objectClass -eq "Server" } -Properties "DNSHostName" -SelectPrty 'DNSHostName', 'Name' -Session $TempPssSession } catch { 'Unknown' }
                                    foreach ($Object in $Servers) {
                                        $ServerArray += $Object.Name
                                    }

                                    if ($ServerArray) {
                                        return $ServerArray
                                    } else { 'No DC assigned' }
                                }
                            }
                            $OutObj += [pscustomobject]$inobj

                            if ($HealthCheck.Site.BestPractice) {
                                $OutObj | Where-Object { $_.'Subnets' -eq 'No subnet assigned' } | Set-Style -Style Warning -Property 'Subnets'
                                $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                $OutObj | Where-Object { $_.'Domain Controllers' -eq 'No DC assigned' } | Set-Style -Style Warning -Property 'Domain Controllers'
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Site)"
                        }
                    }

                    $TableParams = @{
                        Name = "Sites - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 25, 30, 20, 25
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Site Name' | Table @TableParams
                    if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Subnets' -eq '--' }) -or ($OutObj | Where-Object { $_.'Description' -eq '--' }))) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        if ($OutObj | Where-Object { $_.'Subnets' -eq 'No subnet assigned' }) {
                            Paragraph {
                                Write-PScriboMessage "Discovered Active Directory Sites information of forest $ForestInfo"
                                Text -Bold "Corrective Actions:"
                                Text "Ensure Sites have an associated subnet. If subnets are not associated with AD Sites users in the AD Sites might choose a remote domain controller for authentication which in turn might result in excessive use of a remote domain controller." }
                        }
                        if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                            BlankLine
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment."
                            }
                        }
                    }
                    try {
                        $Replications = Invoke-Command -Session $TempPssSession -ScriptBlock { Get-ADReplicationConnection -Properties * -Filter * }
                        if ($Replications) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Connection Objects' {
                                $OutObj = @()
                                Write-PScriboMessage "Discovered Connection Objects information of forest $ForestInfo"
                                foreach ($Repl in $Replications) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = & {
                                                if ($Repl.AutoGenerated) {
                                                    "<automatically generated>"
                                                } else {
                                                    $Repl.Name
                                                }
                                            }
                                            'From Server' = $Repl.ReplicateFromDirectoryServer.Split(",")[1].SubString($Repl.ReplicateFromDirectoryServer.Split(",")[1].IndexOf("=") + 1)
                                            'To Server' = $Repl.ReplicateToDirectoryServer.Split(",")[0].SubString($Repl.ReplicateToDirectoryServer.Split(",")[0].IndexOf("=") + 1)
                                            'From Site' = $Repl.fromserver.Split(",")[3].SubString($Repl.fromserver.Split(",")[3].IndexOf("=") + 1)
                                        }
                                        $OutObj += [pscustomobject]$inobj

                                        if ($HealthCheck.Site.Replication) {
                                            $OutObj | Where-Object { $_.'Name' -ne '<automatically generated>' } | Set-Style -Style Warning -Property 'Name'
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Site Replication Connection Item)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Connection Objects - $($ForestInfo)"
                                    List = $false
                                    ColumnWidths = 25, 25, 25, 25
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'From Site' | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and ($OutObj | Where-Object { $_.'Name' -ne '<automatically generated>' })) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    if ($OutObj | Where-Object { $_.'Name' -ne '<automatically generated>' }) {
                                        Paragraph {
                                            Text "Best Practice:" -Bold
                                            Text "By default, the replication topology is managed automatically and optimizes existing connections. However, manual connections created by an administrator are not modified or optimized. Verify that all topology information is entered for Site Links and delete all manual connection objects."
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Connection Objects information found in $ForestInfo, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Connection Objects)"
                    }
                    try {
                        $Subnet = Invoke-Command -Session $TempPssSession { Get-ADReplicationSubnet -Filter * -Properties * }
                        if ($Subnet) {
                            Section -Style Heading4 'Site Subnets' {
                                $OutObj = @()
                                Write-PScriboMessage "Discovered Active Directory Sites Subnets information of forest $ForestInfo"
                                foreach ($Item in $Subnet) {
                                    try {
                                        Write-PScriboMessage "Collecting $($Item.Name) Site Subnet."
                                        $inObj = [ordered] @{
                                            'Subnet' = $Item.Name
                                            'Description' = ConvertTo-EmptyToFiller $Item.Description
                                            'Sites' = & {
                                                try {
                                                    $Item.Site.Split(",")[0].SubString($Item.Site.Split(",")[0].IndexOf("=") + 1)
                                                } catch { "No site assigned" }
                                            }
                                        }
                                        $OutObj += [pscustomobject]$inObj

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                            $OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' } | Set-Style -Style Warning -Property 'Sites'
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Site Subnets - $($ForestInfo)"
                                    List = $false
                                    ColumnWidths = 20, 40, 40
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Subnet' | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Description' -eq '--' }) -or ($OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' }))) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                        Paragraph {
                                            Text "Best Practice:" -Bold
                                            Text "It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment."
                                        }
                                        BlankLine
                                    }
                                    if ($OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' }) {
                                        Paragraph {
                                            Text "Corrective Actions:" -Bold
                                            Text "Ensure Subnet have an associated site. If subnets are not associated with AD Sites users in the AD Sites might choose a remote domain controller for authentication which in turn might result in excessive use of a remote domain controller."
                                        }
                                    }
                                }
                                if ($HealthCheck.Site.BestPractice) {
                                    try {
                                        $OutObj = @()
                                        foreach ($Domain in $ADSystem.Domains | Where-Object { $_ -notin $Options.Exclude.Domains }) {
                                            Write-PScriboMessage "Discovered Missing Subnet in AD information from $Domain."
                                            $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }
                                            foreach ($DC in ($DomainInfo.ReplicaDirectoryServers | Where-Object { $_ -notin $Options.Exclude.DCs })) {
                                                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                                                    try {
                                                        $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'MissingSubnetinAD'
                                                        $Path = "\\$DC\admin`$\debug\netlogon.log"
                                                        if ((Invoke-Command -Session $DCPssSession { Test-Path -Path $using:path }) -and (Invoke-Command -Session $DCPssSession { (Get-Content -Path $using:path | Measure-Object -Line).lines -gt 0 })) {
                                                            Write-PScriboMessage "Collecting Missing Subnet in AD information from $($Domain)."
                                                            $NetLogonContents = Invoke-Command -Session $DCPssSession { (Get-Content -Path $using:Path)[-200..-1] }
                                                            foreach ($Line in $NetLogonContents) {
                                                                if ($Line -match "NO_CLIENT_SITE") {
                                                                    $inObj = [ordered] @{
                                                                        'DC' = $DC
                                                                        'IP' = $Line.Split(":")[4].trim(" ").Split(" ")[1]
                                                                    }

                                                                    $OutObj += [pscustomobject]$inobj
                                                                }

                                                                if ($HealthCheck.Site.BestPractice) {
                                                                    $OutObj | Set-Style -Style Warning -Property 'IP'
                                                                }
                                                            }
                                                        } else {
                                                            Write-PScriboMessage "Unable to read $Path on $DC"
                                                        }
                                                        if ($DCPssSession) {
                                                            Remove-PSSession -Session $DCPssSession
                                                        }
                                                    } catch {
                                                        Write-PScriboMessage -IsWarning "Missing Subnet in AD Item Section: $($_.Exception.Message)"
                                                    }
                                                }
                                            }
                                        }
                                        if ($OutObj) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Missing Subnets in AD' {
                                                Paragraph "The following table list the NO_CLIENT_SITE entries found in the netlogon.log file at each DC in the forest."
                                                BlankLine
                                                $TableParams = @{
                                                    Name = "Missing Subnets - $($ForestInfo)"
                                                    List = $false
                                                    ColumnWidths = 40, 60
                                                }

                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }

                                                $OutObj | Sort-Object -Property 'DC', 'IP' | Get-Unique -AsString | Table @TableParams
                                                if ($HealthCheck.Site.BestPractice) {
                                                    Paragraph "Health Check:" -Bold -Underline
                                                    BlankLine
                                                    Paragraph {
                                                        Text "Corrective Actions:" -Bold
                                                        Text "Make sure that all the subnets at each Site are properly defined. Missing subnets can cause clients to not use the site's local DCs."
                                                    }
                                                    BlankLine
                                                }
                                            }
                                        } else {
                                            Write-PScriboMessage -IsWarning "No Missing Subnets in AD information found in $ForestInfo, disabling the section."
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "Sysvol Replication Table Section: $($_.Exception.Message)"
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Site Subnets information found in $ForestInfo, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                    }
                    if ($Options.EnableDiagrams) {
                        try {
                            try {
                                $Graph = New-ADDiagram -Target $System -Credential $Credential -Format base64 -Direction top-to-bottom -DiagramType Sites
                            } catch {
                                Write-PScriboMessage -IsWarning "Site Inventory Diagram Graph: $($_.Exception.Message)"
                            }

                            if ($Graph) {
                                Section -Style Heading3 "Site Inventory Diagram." {
                                    Image -Base64 $Graph -Text "Site Inventory Diagram" -Percent (Get-ImagePercent -Graph $Graph) -Align Center
                                    Paragraph "Image preview: Opens the image in a new tab to view it at full resolution." -Tabs 2
                                }
                                BlankLine -Count 2
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "Site Inventory Diagram Section: $($_.Exception.Message)"
                        }
                    }
                    try {
                        $Link = Invoke-Command -Session $TempPssSession { Get-ADReplicationSiteLink -Filter * -Properties * }
                        if ($Link) {
                            Section -Style Heading4 'Site Links' {
                                $OutObj = @()
                                Write-PScriboMessage "Discovered Active Directory Sites Link information of forest $ForestInfo"
                                foreach ($Item in $Link) {
                                    try {
                                        Write-PScriboMessage "Collecting '$($Item.Name)' Site Link"
                                        $SiteArray = @()
                                        $Sites = $Item.siteList
                                        foreach ($Object in $Sites) {
                                            $SiteName = Invoke-Command -Session $TempPssSession { Get-ADReplicationSite -Identity $using:Object }
                                            $SiteArray += $SiteName.Name
                                        }
                                        $inObj = [ordered] @{
                                            'Site Link Name' = $Item.Name
                                            'Cost' = $Item.Cost
                                            'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                                            'Transport Protocol' = $Item.InterSiteTransportProtocol
                                            'Options' = Switch ($Item.Options) {
                                                $null { 'Change Notification is Disabled' }
                                                '0' { '(0)Change Notification is Disabled' }
                                                '1' { '(1)Change Notification is Enabled with Compression' }
                                                '2' { '(2)Force sync in opposite direction at end of sync' }
                                                '3' { '(3)Change Notification is Enabled with Compression and Force sync in opposite direction at end of sync' }
                                                '4' { '(4)Disable compression of Change Notification messages' }
                                                '5' { '(5)Change Notification is Enabled without Compression' }
                                                '6' { '(6)Force sync in opposite direction at end of sync and Disable compression of Change Notification messages' }
                                                '7' { '(7)Change Notification is Enabled without Compression and Force sync in opposite direction at end of sync' }
                                                Default { "Unknown siteLink option: $($Item.Options)" }
                                            }
                                            'Sites' = $SiteArray -join "; "
                                            'Protected From Accidental Deletion' = ConvertTo-TextYN $Item.ProtectedFromAccidentalDeletion
                                            'Description' = ConvertTo-EmptyToFiller $Item.Description
                                        }
                                        $OutObj = [pscustomobject]$inobj

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                            $OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' } | Set-Style -Style Warning -Property 'Options'
                                            $OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' } | Set-Style -Style Warning -Property 'Protected From Accidental Deletion'
                                        }

                                        $TableParams = @{
                                            Name = "Site Links - $($Item.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Sort-Object -Property 'Site Link Name' | Table @TableParams
                                        if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) -or (($OutObj | Where-Object { $_.'Description' -eq '--' }) -or ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' })))) {
                                            Paragraph "Health Check:" -Bold -Underline
                                            BlankLine
                                            if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                                Paragraph {
                                                    Text "Best Practice:" -Bold
                                                    Text "It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment."
                                                }
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' }) {
                                                Paragraph {
                                                    Text "Best Practice:" -Bold
                                                    Text "Enabling change notification treats an INTER-site replication connection like an INTRA-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an Option number value of 5 (Change Notification is Enabled without Compression)."
                                                }
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) {
                                                Paragraph {
                                                    Text "Best Practice:" -Bold
                                                    Text "If the Site Links in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects."
                                                }
                                                BlankLine
                                            }
                                        }

                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Site Links)"
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Site Links information found in $ForestInfo, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                    }
                    try {
                        $OutObj = @()
                        foreach ($Domain in $ADSystem.Domains | Where-Object { $_ -notin $Options.Exclude.Domains }) {
                            Write-PScriboMessage "Discovered AD Domain Sysvol Replication information from $Domain."
                            $DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }
                            foreach ($DC in ($DomainInfo.ReplicaDirectoryServers | Where-Object { $_ -notin $Options.Exclude.DCs })) {
                                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                                    $DCCIMSession = New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name "SysvolReplication"
                                    $Replication = Get-CimInstance -CimSession $DCCIMSession -Namespace "root/microsoftdfs" -Class "dfsrreplicatedfolderinfo" -Filter "ReplicatedFolderName = 'SYSVOL Share'" -EA 0 -Verbose:$False | Select-Object State
                                    if ($DCCIMSession) {
                                        Remove-CimSession -CimSession $DCCIMSession
                                    }

                                    try {
                                        Write-PScriboMessage "Collecting Sysvol Replication information from $($Domain)."
                                        $inObj = [ordered] @{
                                            'DC Name' = $DC.split(".", 2)[0]
                                            'Replication Status' = Switch ($Replication.State) {
                                                0 { 'Uninitialized' }
                                                1 { 'Initialized' }
                                                2 { 'Initial synchronization' }
                                                3 { 'Auto recovery' }
                                                4 { 'Normal' }
                                                5 { 'In error state' }
                                                6 { 'Disabled' }
                                                7 { 'Unknown' }
                                            }
                                            'Domain' = $Domain
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    } catch {
                                        Write-PScriboMessage -IsWarning "Sysvol Replication Item Section: $($_.Exception.Message)"
                                    }

                                    if ($HealthCheck.Site.BestPractice) {
                                        $ReplicationStatusError = @(
                                            'Uninitialized',
                                            'Auto recovery',
                                            'In error state',
                                            'Disabled',
                                            'Unknown'
                                        )
                                        $ReplicationStatusWarn = @(
                                            'Initialized',
                                            'Initial synchronization'
                                        )
                                        $OutObj | Where-Object { $_.'Replication Status' -eq 'Normal' } | Set-Style -Style OK -Property 'Replication Status'
                                        $OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusError } | Set-Style -Style Critical -Property 'Replication Status'
                                        $OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusWarn } | Set-Style -Style Warning -Property 'Replication Status'
                                    }
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading4 'Sysvol Replication' {
                                $TableParams = @{
                                    Name = "Sysvol Replication - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 33, 33, 34
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }

                                $OutObj | Sort-Object -Property 'Domain' | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Identical Count' -like 'No' }) -or ($OutObj | Where-Object { $_.'Replication Status' -in $ReplicationStatusError }))) {
                                    Paragraph "Health Check:" -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text "Corrective Actions:" -Bold
                                        Text "SYSVOL is a special directory that resides on each domain controller (DC) within a domain. The directory comprises folders that store Group Policy objects (GPOs) and logon scripts that clients need to access and synchronize between DCs. For these logon scripts and GPOs to function properly, SYSVOL should be replicated accurately and rapidly throughout the domain. Ensure that proper SYSVOL replication is in place to ensure identical GPO/SYSVOL content for the domain controller across all Active Directory domains."
                                    }
                                    BlankLine
                                }
                            }
                        } else {
                            Write-PScriboMessage -IsWarning "No Sysvol Replication information found in $ForestInfo, disabling the section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "Sysvol Replication Table Section: $($_.Exception.Message)"
                    }
                }
            } else {
                Write-PScriboMessage -IsWarning "No Sites information found in $ForestInfo, disabling the section."
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Site Global)"
        }
    }

    end {}

}