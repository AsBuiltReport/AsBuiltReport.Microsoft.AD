function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
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
        Write-PScriboMessage -Message "Collecting Active Directory Sites information of forest $ForestInfo"
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Site'
    }

    process {
        try {
            $Site = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSite -Filter * -Properties * }
            if ($Site) {
                Section -Style Heading3 'Replication' {
                    Paragraph 'Replication is the process by which Active Directory objects are transferred and synchronized between domain controllers within the domain and forest, ensuring consistency across the infrastructure.'
                    BlankLine
                    Paragraph 'The following section provides detailed information about Active Directory replication and its associated relationships.'
                    if ($Options.EnableDiagrams) {
                        try {
                            try {
                                $Graph = Get-AbrDiagrammer -DiagramType 'SitesInventory' -DiagramOutput base64 -PSSessionObject $TempPssSession
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Site Inventory Diagram Graph: $($_.Exception.Message)"
                            }

                            if ($Graph) {
                                $BestAspectRatio = Get-DiaBestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                                Section -Style Heading4 'Site Inventory Diagram' {
                                    Image -Base64 $Graph -Text 'Site Inventory Diagram' -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
                                }
                                BlankLine -Count 2
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Site Inventory Diagram Section: $($_.Exception.Message)"
                        }
                    }
                    Section -Style Heading4 'Sites' {
                        $OutObj = [System.Collections.ArrayList]::new()
                        foreach ($Item in $Site) {
                            try {
                                $SubnetArray = [System.Collections.ArrayList]::new()
                                $Subnets = $Item.Subnets
                                foreach ($Object in $Subnets) {
                                    $SubnetName = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSubnet $using:Object }
                                    $SubnetArray.Add($SubnetName.Name) | Out-Null
                                }
                                $inObj = [ordered] @{
                                    'Site Name' = $Item.Name
                                    'Description' = $Item.Description
                                    'Subnets' = switch (($SubnetArray).count) {
                                        0 { 'No subnet assigned' }
                                        default { $SubnetArray }
                                    }
                                    'Domain Controllers' = & {
                                        $ServerArray = [System.Collections.ArrayList]::new()
                                        $Servers = try { Get-ADObjectSearch -DN "CN=Servers,$($Item.DistinguishedName)" -Filter { objectClass -eq 'Server' } -Properties 'DNSHostName' -SelectPrty 'DNSHostName', 'Name' -Session $TempPssSession } catch { 'Unknown' }
                                        foreach ($Object in $Servers) {
                                            $ServerArray.Add($Object.Name) | Out-Null
                                        }

                                        if ($ServerArray) {
                                            return $ServerArray
                                        } else { 'No DC assigned' }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Site)"
                            }
                        }

                        if ($HealthCheck.Site.BestPractice) {
                            $List = @()
                            $Num = 0
                            if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Description' -eq '--' }) ) {
                                    $OBJ.'Description' = $OBJ.'Description' + " ($Num)"
                                }
                                $List += 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                            }
                            if ($OutObj | Where-Object { $_.'Subnets' -eq 'No subnet assigned' }) {
                                $OutObj | Where-Object { $_.'Subnets' -eq 'No subnet assigned' } | Set-Style -Style Warning -Property 'Subnets'
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Subnets' -eq 'No subnet assigned' }) ) {
                                    $OBJ.'Subnets' = $OBJ.'Subnets' + " ($Num)"
                                }
                                $List += 'Ensure Sites have an associated subnet. If subnets are not associated with AD Sites users in the AD Sites might choose a remote domain controller for authentication which in turn might result in excessive use of a remote domain controller.'
                            }
                            if ($OutObj | Where-Object { $_.'Domain Controllers' -eq 'No DC assigned' }) {
                                $OutObj | Where-Object { $_.'Domain Controllers' -eq 'No DC assigned' } | Set-Style -Style Warning -Property 'Domain Controllers'
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.'Domain Controllers' -eq 'No DC assigned' } ) ) {
                                    $OBJ.'Domain Controllers' = $OBJ.'Domain Controllers' + " ($Num)"
                                }
                                $List += 'It is important to ensure that each site has at least one assigned domain controller. Missing domain controllers can lead to authentication delays and potential service disruptions for users in the site.'
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
                        if ($List) {
                            Paragraph 'Health Check:' -Bold -Underline
                            List -Item $List -Numbered
                        }
                    }
                    try {
                        $Replications = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationConnection -Properties * -Filter * }
                        if ($Replications) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Connection Objects' {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Repl in $Replications) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = & {
                                                if ($Repl.AutoGenerated) {
                                                    '<automatically generated>'
                                                } else {
                                                    $Repl.Name
                                                }
                                            }
                                            'From Server' = $Repl.ReplicateFromDirectoryServer.Split(',')[1].SubString($Repl.ReplicateFromDirectoryServer.Split(',')[1].IndexOf('=') + 1)
                                            'To Server' = $Repl.ReplicateToDirectoryServer.Split(',')[0].SubString($Repl.ReplicateToDirectoryServer.Split(',')[0].IndexOf('=') + 1)
                                            'From Site' = $Repl.fromserver.Split(',')[3].SubString($Repl.fromserver.Split(',')[3].IndexOf('=') + 1)
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.Site.Replication) {
                                            $OutObj | Where-Object { $_.'Name' -ne '<automatically generated>' } | Set-Style -Style Warning -Property 'Name'
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Site Replication Connection Item)"
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
                                    Paragraph 'Health Check:' -Bold -Underline
                                    BlankLine
                                    if ($OutObj | Where-Object { $_.'Name' -ne '<automatically generated>' }) {
                                        Paragraph {
                                            Text 'Best Practice:' -Bold
                                            Text 'By default, the replication topology is managed automatically and optimizes existing connections. However, manual connections created by an administrator are not modified or optimized. Verify that all topology information is entered for Site Links and delete all manual connection objects.'
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -Message "No Connection Objects information found in $ForestInfo, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Connection Objects)"
                    }
                    try {
                        $Subnet = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSubnet -Filter * -Properties * }
                        if ($Subnet) {
                            Section -Style Heading4 'Site Subnets' {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Item in $Subnet) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Subnet' = $Item.Name
                                            'Description' = $Item.Description
                                            'Sites' = switch ([string]::IsNullOrEmpty($Item.Site)) {
                                                $true { 'No site assigned' }
                                                $false { $Item.Site.Split(',')[0].SubString($Item.Site.Split(',')[0].IndexOf('=') + 1) }
                                                default { 'Unknown' }
                                            }
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                            $OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' } | Set-Style -Style Warning -Property 'Sites'
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Site Subnets)"
                                    }
                                }

                                if ($HealthCheck.Site.BestPractice) {
                                    $List = @()
                                    $Num = 0
                                    if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                        $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                        $Num++
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Description' -eq '--' }) ) {
                                            $OBJ.'Description' = $OBJ.'Description' + " ($Num)"
                                        }
                                        $List += 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                                    }
                                    if ($OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' }) {
                                        $OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' } | Set-Style -Style Warning -Property 'Sites'
                                        $Num++
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.'Sites' -eq 'No site assigned' }) ) {
                                            $OBJ.'Sites' = $OBJ.'Sites' + " ($Num)"
                                        }
                                        $List += 'Ensure Subnet have an associated site. If subnets are not associated with AD Sites, users in the AD Sites might choose a remote domain controller for authentication. This can lead to increased latency and potential performance issues for users authenticating against a domain controller that is not local to their site.'
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
                                if ($List) {
                                    Paragraph 'Health Check:' -Bold -Underline
                                    List -Item $List -Numbered
                                }
                                if ($HealthCheck.Site.BestPractice) {
                                    try {
                                        $OutObj = [System.Collections.ArrayList]::new()
                                        foreach ($Domain in $ADSystem.Domains | Where-Object { $_ -notin $Options.Exclude.Domains }) {
                                            $DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain $using:Domain -ErrorAction Stop }
                                            foreach ($DC in ($DomainInfo.ReplicaDirectoryServers | Where-Object { $_ -notin $Options.Exclude.DCs })) {
                                                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                                    try {
                                                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                                                        if ($DCPssSession) {
                                                            $Path = "\\$DC\admin`$\debug\netlogon.log"
                                                            if ((Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Test-Path -Path $using:path }) -and (Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { (Get-Content -Path $using:path | Measure-Object -Line).lines -gt 0 })) {
                                                                $NetLogonContents = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { (Get-Content -Path $using:Path)[-200..-1] }
                                                                foreach ($Line in $NetLogonContents) {
                                                                    if ($Line -match 'NO_CLIENT_SITE') {
                                                                        $inObj = [ordered] @{
                                                                            'DC' = $DC
                                                                            'IP' = $Line.Split(':')[4].trim(' ').Split(' ')[1]
                                                                        }

                                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                                    }

                                                                    if ($HealthCheck.Site.BestPractice) {
                                                                        $OutObj | Set-Style -Style Warning -Property 'IP'
                                                                    }
                                                                }
                                                            } else {
                                                                Write-PScriboMessage -Message "Unable to read $Path on $DC"
                                                            }
                                                        } else {
                                                            if (-not $_.Exception.MessageId) {
                                                                $ErrorMessage = $_.FullyQualifiedErrorId
                                                            } else { $ErrorMessage = $_.Exception.MessageId }
                                                            Write-PScriboMessage -IsWarning -Message "Missing Subnet in AD Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                                                        }
                                                    } catch {
                                                        Write-PScriboMessage -IsWarning -Message "Missing Subnet in AD Item table: $($_.Exception.Message)"
                                                    }
                                                }
                                            }
                                        }
                                        if ($OutObj) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading4 'Missing Subnets in AD' {
                                                Paragraph 'The following table lists the NO_CLIENT_SITE entries found in the netlogon.log file on each Domain Controller in the forest. These entries indicate client IP addresses that could not be mapped to an Active Directory site.'
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
                                                    Paragraph 'Health Check:' -Bold -Underline
                                                    BlankLine
                                                    Paragraph {
                                                        Text 'Best Practice:' -Bold
                                                        Text "Ensure that all subnets at each site are properly defined. Missing subnets can cause clients to not use the site's local Domain Controllers."
                                                    }
                                                    BlankLine
                                                }
                                            }
                                        } else {
                                            Write-PScriboMessage -Message "No Missing Subnets in AD information found in $ForestInfo, Disabling this section."
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "Missing Subnet in AD Item Section: $($_.Exception.Message)"
                                    }
                                }
                            }
                        } else {
                            Write-PScriboMessage -Message "No Site Subnets information found in $ForestInfo, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Site Subnets)"
                    }
                    if ($Options.EnableDiagrams) {
                        try {
                            try {
                                $Graph = Get-AbrDiagrammer -DiagramType 'Sites' -DiagramOutput base64 -PSSessionObject $TempPssSession
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Site Topology Diagram Graph: $($_.Exception.Message)"
                            }

                            if ($Graph) {
                                $BestAspectRatio = Get-DiaBestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                                Section -Style Heading4 'Site Topology Diagram' {
                                    Image -Base64 $Graph -Text 'Site Topology Diagram' -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
                                }
                                BlankLine -Count 2
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Site Topology Diagram Section: $($_.Exception.Message)"
                        }
                    }
                    try {
                        $DomainDN = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { (Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName }
                        $InterSiteTransports = try { Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-ADObject -Filter { (objectClass -eq 'interSiteTransport') } -SearchBase "CN=Inter-Site Transports,CN=Sites,CN=Configuration,$using:DomainDN" -Properties * } } catch { Out-Null }
                        if ($InterSiteTransports) {
                            Section -Style Heading4 'Inter-Site Transports' {
                                Paragraph 'Site links in Active Directory represent the inter-site connectivity and method used to transfer replication traffic. There are two transport protocols that can be used for replication via site links. The default protocol used in site link is IP, and it performs synchronous replication between available domain controllers. The SMTP method can be used when the link between sites is not reliable.'
                                BlankLine
                                try {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Item in $InterSiteTransports) {
                                        $SiteArray = [System.Collections.ArrayList]::new()
                                        switch ($Item.options) {
                                            $null {
                                                $BridgeAlSiteLinks = 'Yes'
                                                $IgnoreSchedules = 'No'
                                            }
                                            0 {
                                                $BridgeAlSiteLinks = 'Yes'
                                                $IgnoreSchedules = 'No'
                                            }
                                            1 {
                                                $BridgeAlSiteLinks = 'Yes'
                                                $IgnoreSchedules = 'Yes'
                                            }
                                            2 {
                                                $BridgeAlSiteLinks = 'No'
                                                $IgnoreSchedules = 'No'
                                            }
                                            3 {
                                                $BridgeAlSiteLinks = 'No'
                                                $IgnoreSchedules = 'Yes'
                                            }
                                            default {
                                                $BridgeAlSiteLinks = 'Unknown'
                                                $IgnoreSchedules = 'Unknown'
                                            }
                                        }

                                        $inObj = [ordered] @{
                                            'Name' = $Item.Name
                                            'Bridge All Site Links' = $BridgeAlSiteLinks
                                            'Ignore Schedules' = $IgnoreSchedules
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    }

                                    $TableParams = @{
                                        Name = "Inter-Site Transports - $($ForestInfo)"
                                        List = $false
                                        ColumnWidths = 34, 33, 33
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Inter-Site Transports section)"
                                }
                                try {
                                    Section -Style Heading4 'IP' {
                                        try {
                                            $IPLink = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Filter * -Properties * | Where-Object { $_.InterSiteTransportProtocol -eq 'IP' } }
                                            if ($IPLink) {
                                                Section -Style Heading5 'Site Links' {
                                                    foreach ($Item in $IPLink) {
                                                        $OutObj = [System.Collections.ArrayList]::new()
                                                        try {
                                                            $SiteArray = [System.Collections.ArrayList]::new()
                                                            $Sites = $Item.siteList
                                                            foreach ($Object in $Sites) {
                                                                $SiteName = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSite -Identity $using:Object }
                                                                $SiteArray.Add($SiteName.Name) | Out-Null
                                                            }
                                                            $inObj = [ordered] @{
                                                                'Site Link Name' = $Item.Name
                                                                'Cost' = $Item.Cost
                                                                'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                                                                'Transport Protocol' = $Item.InterSiteTransportProtocol
                                                                'Options' = switch ($Item.Options) {
                                                                    $null { 'Change Notification is Disabled' }
                                                                    '0' { '(0) Change Notification is Disabled' }
                                                                    '1' { '(1) Change Notification is Enabled with Compression' }
                                                                    '2' { '(2) Force sync in opposite direction at end of sync' }
                                                                    '3' { '(3) Change Notification is Enabled with Compression and Force sync in opposite direction at end of sync' }
                                                                    '4' { '(4) Disable compression of Change Notification messages' }
                                                                    '5' { '(5) Change Notification is Enabled without Compression' }
                                                                    '6' { '(6) Force sync in opposite direction at end of sync and Disable compression of Change Notification messages' }
                                                                    '7' { '(7) Change Notification is Enabled without Compression and Force sync in opposite direction at end of sync' }
                                                                    default { "Unknown siteLink option: $($Item.Options)" }
                                                                }
                                                                'Sites' = $SiteArray -join '; '
                                                                'Protected From Accidental Deletion' = $Item.ProtectedFromAccidentalDeletion
                                                                'Description' = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

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
                                                                Paragraph 'Health Check:' -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'Enabling change notification treats an inter-site replication connection like an intra-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an option number value of 5 (Change Notification is Enabled without Compression).'
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'If the Site Links in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                            }

                                                        } catch {
                                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (IP Site Links table)"
                                                        }
                                                    }
                                                }
                                            } else {
                                                Write-PScriboMessage -Message "No IP Site Links information found in $ForestInfo, Disabling this section."
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (IP Site Links Section)"
                                        }
                                        try {
                                            $IPLinkBridges = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLinkBridge -Filter * -Properties * | Where-Object { $_.InterSiteTransportProtocol -eq 'IP' } }
                                            if ($IPLinkBridges) {
                                                Section -Style Heading5 'Site Link Bridges' {
                                                    foreach ($Item in $IPLinkBridges) {
                                                        $OutObj = [System.Collections.ArrayList]::new()
                                                        try {
                                                            $SiteArray = [System.Collections.ArrayList]::new()
                                                            $Sites = $Item.siteLinkList
                                                            foreach ($Object in $Sites) {
                                                                $SiteName = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Identity $using:Object }
                                                                $SiteArray.Add($SiteName.Name) | Out-Null
                                                            }
                                                            $inObj = [ordered] @{
                                                                'Site Link Bridges Name' = $Item.Name
                                                                'Transport Protocol' = $Item.InterSiteTransportProtocol
                                                                'Site Links' = $SiteArray -join '; '
                                                                'Protected From Accidental Deletion' = $Item.ProtectedFromAccidentalDeletion
                                                                'Description' = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                            if ($HealthCheck.Site.BestPractice) {
                                                                $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                                                $OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' } | Set-Style -Style Warning -Property 'Protected From Accidental Deletion'
                                                            }

                                                            $TableParams = @{
                                                                Name = "Site Links Bridges - $($Item.Name)"
                                                                List = $true
                                                                ColumnWidths = 40, 60
                                                            }
                                                            if ($Report.ShowTableCaptions) {
                                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                                            }
                                                            $OutObj | Table @TableParams
                                                            if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) -or (($OutObj | Where-Object { $_.'Description' -eq '--' })))) {
                                                                Paragraph 'Health Check:' -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'If the Site Links Bridges in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                            }

                                                        } catch {
                                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (IP Site Links Bridges table)"
                                                        }
                                                    }
                                                }
                                            } else {
                                                Write-PScriboMessage -Message "No IP Site Links Bridges information found in $ForestInfo, Disabling this section."
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (IP Site Links Section)"
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (IP)"
                                }
                                try {
                                    $IPLink = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Filter * -Properties * | Where-Object { $_.InterSiteTransportProtocol -eq 'SMTP' } }
                                    if ($IPLink) {
                                        Section -Style Heading4 'SMTP' {
                                            Paragraph 'SMTP replication is used for sites that cannot use the others, but as a general rule, it should never be used. It is reserved when network connections are not always available, therefore, you can schedule replication.'
                                            try {
                                                Section -Style Heading5 'Site Links' {
                                                    foreach ($Item in $IPLink) {
                                                        $OutObj = [System.Collections.ArrayList]::new()
                                                        try {
                                                            $SiteArray = [System.Collections.ArrayList]::new()
                                                            $Sites = $Item.siteList
                                                            foreach ($Object in $Sites) {
                                                                $SiteName = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSite -Identity $using:Object }
                                                                $SiteArray.Add($SiteName.Name) | Out-Null
                                                            }
                                                            $inObj = [ordered] @{
                                                                'Site Link Name' = $Item.Name
                                                                'Cost' = $Item.Cost
                                                                'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                                                                'Transport Protocol' = $Item.InterSiteTransportProtocol
                                                                'Options' = switch ($Item.Options) {
                                                                    $null { 'Change Notification is Disabled' }
                                                                    '0' { '(0)Change Notification is Disabled' }
                                                                    '1' { '(1)Change Notification is Enabled with Compression' }
                                                                    '2' { '(2)Force sync in opposite direction at end of sync' }
                                                                    '3' { '(3)Change Notification is Enabled with Compression and Force sync in opposite direction at end of sync' }
                                                                    '4' { '(4)Disable compression of Change Notification messages' }
                                                                    '5' { '(5)Change Notification is Enabled without Compression' }
                                                                    '6' { '(6)Force sync in opposite direction at end of sync and Disable compression of Change Notification messages' }
                                                                    '7' { '(7)Change Notification is Enabled without Compression and Force sync in opposite direction at end of sync' }
                                                                    default { "Unknown siteLink option: $($Item.Options)" }
                                                                }
                                                                'Sites' = $SiteArray -join '; '
                                                                'Protected From Accidental Deletion' = $Item.ProtectedFromAccidentalDeletion
                                                                'Description' = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

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
                                                                Paragraph 'Health Check:' -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'Enabling change notification treats an INTER-site replication connection like an INTRA-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an Option number value of 5 (Change Notification is Enabled without Compression).'
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) {
                                                                    Paragraph {
                                                                        Text 'Best Practice:' -Bold
                                                                        Text 'If the Site Links in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.'
                                                                    }
                                                                    BlankLine
                                                                }
                                                            }

                                                        } catch {
                                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SMTP Site Links table)"
                                                        }
                                                    }
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SMTP Site Links Section)"
                                            }
                                            try {
                                                $IPLinkBridges = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLinkBridge -Filter * -Properties * | Where-Object { $_.InterSiteTransportProtocol -eq 'SMTP' } }
                                                if ($IPLinkBridges) {
                                                    Section -Style Heading5 'Site Link Bridges' {
                                                        foreach ($Item in $IPLinkBridges) {
                                                            $OutObj = [System.Collections.ArrayList]::new()
                                                            try {
                                                                $SiteArray = [System.Collections.ArrayList]::new()
                                                                $Sites = $Item.siteLinkList
                                                                foreach ($Object in $Sites) {
                                                                    $SiteName = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Identity $using:Object }
                                                                    $SiteArray.Add($SiteName.Name) | Out-Null
                                                                }
                                                                $inObj = [ordered] @{
                                                                    'Site Link Bridges Name' = $Item.Name
                                                                    'Transport Protocol' = $Item.InterSiteTransportProtocol
                                                                    'Site Links' = $SiteArray -join '; '
                                                                    'Protected From Accidental Deletion' = $Item.ProtectedFromAccidentalDeletion
                                                                    'Description' = $Item.Description
                                                                }
                                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                                if ($HealthCheck.Site.BestPractice) {
                                                                    $OutObj | Where-Object { $_.'Description' -eq '--' } | Set-Style -Style Warning -Property 'Description'
                                                                    $OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' } | Set-Style -Style Warning -Property 'Protected From Accidental Deletion'
                                                                }

                                                                $TableParams = @{
                                                                    Name = "Site Links Bridges - $($Item.Name)"
                                                                    List = $true
                                                                    ColumnWidths = 40, 60
                                                                }
                                                                if ($Report.ShowTableCaptions) {
                                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                                }
                                                                $OutObj | Table @TableParams
                                                                if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) -or (($OutObj | Where-Object { $_.'Description' -eq '--' })))) {
                                                                    Paragraph 'Health Check:' -Bold -Underline
                                                                    BlankLine
                                                                    if ($OutObj | Where-Object { $_.'Description' -eq '--' }) {
                                                                        Paragraph {
                                                                            Text 'Best Practice:' -Bold
                                                                            Text 'It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.'
                                                                        }
                                                                        BlankLine
                                                                    }
                                                                    if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No' }) {
                                                                        Paragraph {
                                                                            Text 'Best Practice:' -Bold
                                                                            Text 'If the Site Links Bridges in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.'
                                                                        }
                                                                        BlankLine
                                                                    }
                                                                }
                                                            } catch {
                                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SMTP Site Links Bridges table)"
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    Write-PScriboMessage -Message "No SMTP Site Links Bridges information found in $ForestInfo, Disabling this section."
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SMTP Site Links Section)"
                                            }
                                        }
                                    } else {
                                        Write-PScriboMessage -Message "No SMTP Site Links information found in $ForestInfo, Disabling this section."
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SMTP)"
                                }
                            }
                        } else {
                            Write-PScriboMessage -Message "No SMTP Site Links information found in $ForestInfo, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Site Subnets)"
                    }
                    try {
                        $OutObj = [System.Collections.ArrayList]::new()
                        foreach ($Domain in $ADSystem.Domains | Where-Object { $_ -notin $Options.Exclude.Domains }) {
                            $DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain $using:Domain -ErrorAction Stop }
                            foreach ($DC in ($DomainInfo.ReplicaDirectoryServers | Where-Object { $_ -notin $Options.Exclude.DCs })) {
                                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                    $DCCIMSession = Get-ValidCIMSession -ComputerName $DC -SessionName $DC -CIMTable ([ref]$CIMTable)

                                    if ($DCCIMSession) {
                                        $Replication = Get-CimInstance -CimSession $DCCIMSession -Namespace 'root/microsoftdfs' -Class 'dfsrreplicatedfolderinfo' -Filter "ReplicatedFolderName = 'SYSVOL Share'" -EA 0 -Verbose:$False | Select-Object State

                                        try {
                                            $inObj = [ordered] @{
                                                'DC Name' = $DC.split('.', 2)[0]
                                                'Replication Status' = switch ($Replication.State) {
                                                    0 { 'Uninitialized' }
                                                    1 { 'Initialized' }
                                                    2 { 'Initial synchronization' }
                                                    3 { 'Auto recovery' }
                                                    4 { 'Normal' }
                                                    5 { 'In error state' }
                                                    6 { 'Disabled' }
                                                    7 { 'Unknown' }
                                                    default { 'Offline' }
                                                }
                                                'Domain' = $Domain
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "Sysvol Replication Item Section: $($_.Exception.Message)"
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
                                } else {
                                    try {
                                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                                        $inObj = [ordered] @{
                                            'DC Name' = $DC.split('.', 2)[0]
                                            'Replication Status' = switch ($Replication.State) {
                                                0 { 'Uninitialized' }
                                                1 { 'Initialized' }
                                                2 { 'Initial synchronization' }
                                                3 { 'Auto recovery' }
                                                4 { 'Normal' }
                                                5 { 'In error state' }
                                                6 { 'Disabled' }
                                                7 { 'Unknown' }
                                                default { 'Offline' }
                                            }
                                            'Domain' = $Domain
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DNS IP Configuration Item)"
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
                                    Paragraph 'Health Check:' -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text 'Best Practice:' -Bold
                                        Text 'SYSVOL is a special directory that resides on each domain controller (DC) within a domain. The directory comprises folders that store Group Policy objects (GPOs) and logon scripts that clients need to access and synchronize between DCs. For these logon scripts and GPOs to function properly, SYSVOL should be replicated accurately and rapidly throughout the domain. Ensure that proper SYSVOL replication is in place to ensure identical GPO/SYSVOL content for the domain controller across all Active Directory domains.'
                                    }
                                    BlankLine
                                }
                            }
                        } else {
                            Write-PScriboMessage -Message "No Sysvol Replication information found in $ForestInfo, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Sysvol Replication Table Section: $($_.Exception.Message)"
                    }
                }
            } else {
                Write-PScriboMessage -Message "No Sites information found in $ForestInfo, Disabling this section."
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Site Global)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD Site'
    }

}