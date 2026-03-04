function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
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
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADSite.Collecting -f $ForestInfo)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD Site'
    }

    process {
        try {
            $Site = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSite -Filter * -Properties * }
            if ($Site) {
                Section -Style Heading3 $reportTranslate.GetAbrADSite.Replication {
                    Paragraph $reportTranslate.GetAbrADSite.ReplicationParagraph1
                    BlankLine
                    Paragraph $reportTranslate.GetAbrADSite.ReplicationParagraph2
                    if ($Options.EnableDiagrams) {
                        try {
                            try {
                                $Graph = Get-AbrDiagrammer -DiagramType 'SitesInventory' -DiagramOutput base64 -PSSessionObject $TempPssSession
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "Site Inventory Diagram Graph: $($_.Exception.Message)"
                            }

                            if ($Graph) {
                                $BestAspectRatio = Get-DiaBestImageAspectRatio -GraphObj $Graph -MaxWidth 600
                                Section -Style Heading4 $reportTranslate.GetAbrADSite.SiteInventoryDiagram {
                                    Image -Base64 $Graph -Text $reportTranslate.GetAbrADSite.SiteInventoryDiagram -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
                                }
                                BlankLine -Count 2
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "Site Inventory Diagram Section: $($_.Exception.Message)"
                        }
                    }
                    Section -Style Heading4 $reportTranslate.GetAbrADSite.Sites {
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
                                    $reportTranslate.GetAbrADSite.SiteName = $Item.Name
                                    $reportTranslate.GetAbrADSite.Description = $Item.Description
                                    $reportTranslate.GetAbrADSite.SubnetsCol = switch (($SubnetArray).count) {
                                        0 { $reportTranslate.GetAbrADSite.NoSubnetAssigned }
                                        default { $SubnetArray }
                                    }
                                    $reportTranslate.GetAbrADSite.DomainControllers = & {
                                        $ServerArray = [System.Collections.ArrayList]::new()
                                        $Servers = try { Get-ADObjectSearch -DN "CN=Servers,$($Item.DistinguishedName)" -Filter { objectClass -eq 'Server' } -Properties 'DNSHostName' -SelectPrty 'DNSHostName', 'Name' -Session $TempPssSession } catch { 'Unknown' }
                                        foreach ($Object in $Servers) {
                                            $ServerArray.Add($Object.Name) | Out-Null
                                        }

                                        if ($ServerArray) {
                                            $ServerArray
                                        } else { $reportTranslate.GetAbrADSite.NoDCAssigned }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Site)"
                            }
                        }

                        if ($HealthCheck.Site.BestPractice) {
                            $List = [System.Collections.ArrayList]::new()
                            $Num = 0
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) ) {
                                    $OBJ.$($reportTranslate.GetAbrADSite.Description) = $OBJ.$($reportTranslate.GetAbrADSite.Description) + " ($Num)"
                                }
                                $List.Add($reportTranslate.GetAbrADSite.DescBP) | Out-Null
                            }
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.SubnetsCol) -eq $reportTranslate.GetAbrADSite.NoSubnetAssigned }) {
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.SubnetsCol) -eq $reportTranslate.GetAbrADSite.NoSubnetAssigned } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.SubnetsCol
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.SubnetsCol) -eq $reportTranslate.GetAbrADSite.NoSubnetAssigned }) ) {
                                    $OBJ.$($reportTranslate.GetAbrADSite.SubnetsCol) = $OBJ.$($reportTranslate.GetAbrADSite.SubnetsCol) + " ($Num)"
                                }
                                $List.Add($reportTranslate.GetAbrADSite.SiteSubnetBP) | Out-Null
                            }
                            if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.DomainControllers) -eq $reportTranslate.GetAbrADSite.NoDCAssigned }) {
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.DomainControllers) -eq $reportTranslate.GetAbrADSite.NoDCAssigned } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.DomainControllers
                                $Num++
                                foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.DomainControllers) -eq $reportTranslate.GetAbrADSite.NoDCAssigned } ) ) {
                                    $OBJ.$($reportTranslate.GetAbrADSite.DomainControllers) = $OBJ.$($reportTranslate.GetAbrADSite.DomainControllers) + " ($Num)"
                                }
                                $List.Add($reportTranslate.GetAbrADSite.SiteDCBP) | Out-Null
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
                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.SiteName | Table @TableParams
                        if ($List) {
                            Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                            List -Item $List -Numbered
                        }
                    }
                    try {
                        $Replications = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationConnection -Properties * -Filter * }
                        if ($Replications) {
                            Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSite.ConnectionObjects {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Repl in $Replications) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADSite.Name = & {
                                                if ($Repl.AutoGenerated) {
                                                    $reportTranslate.GetAbrADSite.AutoGenerated
                                                } else {
                                                    $Repl.Name
                                                }
                                            }
                                            $reportTranslate.GetAbrADSite.FromServer = $Repl.ReplicateFromDirectoryServer.Split(',')[1].SubString($Repl.ReplicateFromDirectoryServer.Split(',')[1].IndexOf('=') + 1)
                                            $reportTranslate.GetAbrADSite.ToServer = $Repl.ReplicateToDirectoryServer.Split(',')[0].SubString($Repl.ReplicateToDirectoryServer.Split(',')[0].IndexOf('=') + 1)
                                            $reportTranslate.GetAbrADSite.FromSite = $Repl.fromserver.Split(',')[3].SubString($Repl.fromserver.Split(',')[3].IndexOf('=') + 1)
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.Site.Replication) {
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Name) -ne $reportTranslate.GetAbrADSite.AutoGenerated } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Name
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
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.FromSite | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Name) -ne $reportTranslate.GetAbrADSite.AutoGenerated })) {
                                    Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                    BlankLine
                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Name) -ne $reportTranslate.GetAbrADSite.AutoGenerated }) {
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                            Text $reportTranslate.GetAbrADSite.ConnectionObjectsBP
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
                            Section -Style Heading4 $reportTranslate.GetAbrADSite.SiteSubnets {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Item in $Subnet) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADSite.Subnet = $Item.Name
                                            $reportTranslate.GetAbrADSite.Description = $Item.Description
                                            $reportTranslate.GetAbrADSite.Sites = switch ([string]::IsNullOrEmpty($Item.Site)) {
                                                $true { $reportTranslate.GetAbrADSite.NoSiteAssigned }
                                                $false { $Item.Site.Split(',')[0].SubString($Item.Site.Split(',')[0].IndexOf('=') + 1) }
                                                default { $reportTranslate.GetAbrADSite.Unknown }
                                            }
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Sites) -eq $reportTranslate.GetAbrADSite.NoSiteAssigned } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Sites
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Site Subnets)"
                                    }
                                }

                                if ($HealthCheck.Site.BestPractice) {
                                    $List = [System.Collections.ArrayList]::new()
                                    $Num = 0
                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                        $Num++
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) ) {
                                            $OBJ.$($reportTranslate.GetAbrADSite.Description) = $OBJ.$($reportTranslate.GetAbrADSite.Description) + " ($Num)"
                                        }
                                        $List.Add($reportTranslate.GetAbrADSite.DescBP) | Out-Null
                                    }
                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Sites) -eq $reportTranslate.GetAbrADSite.NoSiteAssigned }) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Sites) -eq $reportTranslate.GetAbrADSite.NoSiteAssigned } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Sites
                                        $Num++
                                        foreach ( $OBJ in ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Sites) -eq $reportTranslate.GetAbrADSite.NoSiteAssigned }) ) {
                                            $OBJ.$($reportTranslate.GetAbrADSite.Sites) = $OBJ.$($reportTranslate.GetAbrADSite.Sites) + " ($Num)"
                                        }
                                        $List.Add($reportTranslate.GetAbrADSite.SubnetSiteBP) | Out-Null
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
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.Subnet | Table @TableParams
                                if ($List) {
                                    Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
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
                                                                            $reportTranslate.GetAbrADSite.DC = $DC
                                                                            $reportTranslate.GetAbrADSite.IP = $Line.Split(':')[4].trim(' ').Split(' ')[1]
                                                                        }

                                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                                    }

                                                                    if ($HealthCheck.Site.BestPractice) {
                                                                        $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.IP
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
                                            Section -ExcludeFromTOC -Style NOTOCHeading4 $reportTranslate.GetAbrADSite.MissingSubnets {
                                                Paragraph $reportTranslate.GetAbrADSite.MissingSubnetsParagraph
                                                BlankLine
                                                $TableParams = @{
                                                    Name = "Missing Subnets - $($ForestInfo)"
                                                    List = $false
                                                    ColumnWidths = 40, 60
                                                }

                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }

                                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.DC, $reportTranslate.GetAbrADSite.IP | Get-Unique -AsString | Table @TableParams
                                                if ($HealthCheck.Site.BestPractice) {
                                                    Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                                    BlankLine
                                                    Paragraph {
                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                        Text $reportTranslate.GetAbrADSite.MissingSubnetsBP
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
                                Section -Style Heading4 $reportTranslate.GetAbrADSite.SiteTopologyDiagram {
                                    Image -Base64 $Graph -Text $reportTranslate.GetAbrADSite.SiteTopologyDiagram -Width $BestAspectRatio.Width -Height $BestAspectRatio.Height -Align Center
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
                            Section -Style Heading4 $reportTranslate.GetAbrADSite.InterSiteTransports {
                                Paragraph $reportTranslate.GetAbrADSite.InterSiteTransportsParagraph
                                BlankLine
                                try {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Item in $InterSiteTransports) {
                                        $SiteArray = [System.Collections.ArrayList]::new()
                                        switch ($Item.options) {
                                            $null {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.Yes
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.No
                                            }
                                            0 {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.Yes
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.No
                                            }
                                            1 {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.Yes
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.Yes
                                            }
                                            2 {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.No
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.No
                                            }
                                            3 {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.No
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.Yes
                                            }
                                            default {
                                                $BridgeAlSiteLinks = $reportTranslate.GetAbrADSite.Unknown
                                                $IgnoreSchedules = $reportTranslate.GetAbrADSite.Unknown
                                            }
                                        }

                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADSite.Name = $Item.Name
                                            $reportTranslate.GetAbrADSite.BridgeAllSiteLinks = $BridgeAlSiteLinks
                                            $reportTranslate.GetAbrADSite.IgnoreSchedules = $IgnoreSchedules
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
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.Name | Table @TableParams
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Inter-Site Transports section)"
                                }
                                try {
                                    Section -Style Heading4 $reportTranslate.GetAbrADSite.IPSection {
                                        try {
                                            $IPLink = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADReplicationSiteLink -Filter * -Properties * | Where-Object { $_.InterSiteTransportProtocol -eq 'IP' } }
                                            if ($IPLink) {
                                                Section -Style Heading5 $reportTranslate.GetAbrADSite.SiteLinks {
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
                                                                $reportTranslate.GetAbrADSite.SiteLinkName = $Item.Name
                                                                $reportTranslate.GetAbrADSite.Cost = $Item.Cost
                                                                $reportTranslate.GetAbrADSite.ReplicationFrequency = "$($Item.ReplicationFrequencyInMinutes) min"
                                                                $reportTranslate.GetAbrADSite.TransportProtocol = $Item.InterSiteTransportProtocol
                                                                $reportTranslate.GetAbrADSite.Options = switch ($Item.Options) {
                                                                    $null { $reportTranslate.GetAbrADSite.ChangeNotificationDisabled }
                                                                    '0' { $reportTranslate.GetAbrADSite.Option0 }
                                                                    '1' { $reportTranslate.GetAbrADSite.Option1 }
                                                                    '2' { $reportTranslate.GetAbrADSite.Option2 }
                                                                    '3' { $reportTranslate.GetAbrADSite.Option3 }
                                                                    '4' { $reportTranslate.GetAbrADSite.Option4 }
                                                                    '5' { $reportTranslate.GetAbrADSite.Option5 }
                                                                    '6' { $reportTranslate.GetAbrADSite.Option6 }
                                                                    '7' { $reportTranslate.GetAbrADSite.Option7 }
                                                                    default { "Unknown siteLink option: $($Item.Options)" }
                                                                }
                                                                $reportTranslate.GetAbrADSite.Sites = $SiteArray -join '; '
                                                                $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion = $Item.ProtectedFromAccidentalDeletion
                                                                $reportTranslate.GetAbrADSite.Description = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                            if ($HealthCheck.Site.BestPractice) {
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Options
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion
                                                            }

                                                            $TableParams = @{
                                                                Name = "Site Links - $($Item.Name)"
                                                                List = $true
                                                                ColumnWidths = 40, 60
                                                            }
                                                            if ($Report.ShowTableCaptions) {
                                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                                            }
                                                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.SiteLinkName | Table @TableParams
                                                            if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) -or (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options })))) {
                                                                Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.DescBP
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.SiteLinkChangeNotifBP
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.SiteLinkProtectedBP
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
                                                Section -Style Heading5 $reportTranslate.GetAbrADSite.SiteLinkBridges {
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
                                                                $reportTranslate.GetAbrADSite.SiteLinkBridgesName = $Item.Name
                                                                $reportTranslate.GetAbrADSite.TransportProtocol = $Item.InterSiteTransportProtocol
                                                                $reportTranslate.GetAbrADSite.SiteLinksCol = $SiteArray -join '; '
                                                                $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion = $Item.ProtectedFromAccidentalDeletion
                                                                $reportTranslate.GetAbrADSite.Description = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                            if ($HealthCheck.Site.BestPractice) {
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion
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
                                                            if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) -or (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' })))) {
                                                                Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.DescBP
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.SiteLinkBridgesProtectedBP
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
                                        Section -Style Heading4 $reportTranslate.GetAbrADSite.SMTPSection {
                                            Paragraph $reportTranslate.GetAbrADSite.SMTPParagraph
                                            try {
                                                Section -Style Heading5 $reportTranslate.GetAbrADSite.SiteLinks {
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
                                                                $reportTranslate.GetAbrADSite.SiteLinkName = $Item.Name
                                                                $reportTranslate.GetAbrADSite.Cost = $Item.Cost
                                                                $reportTranslate.GetAbrADSite.ReplicationFrequency = "$($Item.ReplicationFrequencyInMinutes) min"
                                                                $reportTranslate.GetAbrADSite.TransportProtocol = $Item.InterSiteTransportProtocol
                                                                $reportTranslate.GetAbrADSite.Options = switch ($Item.Options) {
                                                                    $null { $reportTranslate.GetAbrADSite.ChangeNotificationDisabled }
                                                                    '0' { $reportTranslate.GetAbrADSite.Option0 }
                                                                    '1' { $reportTranslate.GetAbrADSite.Option1 }
                                                                    '2' { $reportTranslate.GetAbrADSite.Option2 }
                                                                    '3' { $reportTranslate.GetAbrADSite.Option3 }
                                                                    '4' { $reportTranslate.GetAbrADSite.Option4 }
                                                                    '5' { $reportTranslate.GetAbrADSite.Option5 }
                                                                    '6' { $reportTranslate.GetAbrADSite.Option6 }
                                                                    '7' { $reportTranslate.GetAbrADSite.Option7 }
                                                                    default { "Unknown siteLink option: $($Item.Options)" }
                                                                }
                                                                $reportTranslate.GetAbrADSite.Sites = $SiteArray -join '; '
                                                                $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion = $Item.ProtectedFromAccidentalDeletion
                                                                $reportTranslate.GetAbrADSite.Description = $Item.Description
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                            if ($HealthCheck.Site.BestPractice) {
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Options
                                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion
                                                            }

                                                            $TableParams = @{
                                                                Name = "Site Links - $($Item.Name)"
                                                                List = $true
                                                                ColumnWidths = 40, 60
                                                            }
                                                            if ($Report.ShowTableCaptions) {
                                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                                            }
                                                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.SiteLinkName | Table @TableParams
                                                            if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) -or (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options })))) {
                                                                Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                                                BlankLine
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.DescBP
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Options) -eq $reportTranslate.GetAbrADSite.ChangeNotificationDisabled -or $Null -eq $reportTranslate.GetAbrADSite.Options }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.SMTPChangeNotifBP
                                                                    }
                                                                    BlankLine
                                                                }
                                                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) {
                                                                    Paragraph {
                                                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                        Text $reportTranslate.GetAbrADSite.SiteLinkProtectedBP
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
                                                    Section -Style Heading5 $reportTranslate.GetAbrADSite.SiteLinkBridges {
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
                                                                    $reportTranslate.GetAbrADSite.SiteLinkBridgesName = $Item.Name
                                                                    $reportTranslate.GetAbrADSite.TransportProtocol = $Item.InterSiteTransportProtocol
                                                                    $reportTranslate.GetAbrADSite.SiteLinksCol = $SiteArray -join '; '
                                                                    $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion = $Item.ProtectedFromAccidentalDeletion
                                                                    $reportTranslate.GetAbrADSite.Description = $Item.Description
                                                                }
                                                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                                                if ($HealthCheck.Site.BestPractice) {
                                                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.Description
                                                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion
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
                                                                if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) -or (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' })))) {
                                                                    Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                                                    BlankLine
                                                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.Description) -eq '--' }) {
                                                                        Paragraph {
                                                                            Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                            Text $reportTranslate.GetAbrADSite.DescBP
                                                                        }
                                                                        BlankLine
                                                                    }
                                                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ProtectedFromAccidentalDeletion) -eq $reportTranslate.GetAbrADSite.No }) {
                                                                        Paragraph {
                                                                            Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                                                            Text $reportTranslate.GetAbrADSite.SiteLinkBridgesProtectedBP
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
                                                $reportTranslate.GetAbrADSite.DCName = $DC.split('.', 2)[0]
                                                $reportTranslate.GetAbrADSite.ReplicationStatus = switch ($Replication.State) {
                                                    0 { $reportTranslate.GetAbrADSite.StatusUninitialized }
                                                    1 { $reportTranslate.GetAbrADSite.StatusInitialized }
                                                    2 { $reportTranslate.GetAbrADSite.StatusInitialSync }
                                                    3 { $reportTranslate.GetAbrADSite.StatusAutoRecovery }
                                                    4 { $reportTranslate.GetAbrADSite.StatusNormal }
                                                    5 { $reportTranslate.GetAbrADSite.StatusInErrorState }
                                                    6 { $reportTranslate.GetAbrADSite.StatusDisabled }
                                                    7 { $reportTranslate.GetAbrADSite.StatusUnknown }
                                                    default { $reportTranslate.GetAbrADSite.StatusOffline }
                                                }
                                                $reportTranslate.GetAbrADSite.Domain = $Domain
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "Sysvol Replication Item Section: $($_.Exception.Message)"
                                        }

                                        if ($HealthCheck.Site.BestPractice) {
                                            $ReplicationStatusError = @(
                                                $reportTranslate.GetAbrADSite.StatusUninitialized,
                                                $reportTranslate.GetAbrADSite.StatusAutoRecovery,
                                                $reportTranslate.GetAbrADSite.StatusInErrorState,
                                                $reportTranslate.GetAbrADSite.StatusDisabled,
                                                $reportTranslate.GetAbrADSite.StatusUnknown
                                            )
                                            $ReplicationStatusWarn = @(
                                                $reportTranslate.GetAbrADSite.StatusInitialized,
                                                $reportTranslate.GetAbrADSite.StatusInitialSync
                                            )
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ReplicationStatus) -eq $reportTranslate.GetAbrADSite.StatusNormal } | Set-Style -Style OK -Property $reportTranslate.GetAbrADSite.ReplicationStatus
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ReplicationStatus) -in $ReplicationStatusError } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADSite.ReplicationStatus
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ReplicationStatus) -in $ReplicationStatusWarn } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADSite.ReplicationStatus
                                        }
                                    }
                                } else {
                                    try {
                                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADSite.DCName = $DC.split('.', 2)[0]
                                            $reportTranslate.GetAbrADSite.ReplicationStatus = switch ($Replication.State) {
                                                0 { $reportTranslate.GetAbrADSite.StatusUninitialized }
                                                1 { $reportTranslate.GetAbrADSite.StatusInitialized }
                                                2 { $reportTranslate.GetAbrADSite.StatusInitialSync }
                                                3 { $reportTranslate.GetAbrADSite.StatusAutoRecovery }
                                                4 { $reportTranslate.GetAbrADSite.StatusNormal }
                                                5 { $reportTranslate.GetAbrADSite.StatusInErrorState }
                                                6 { $reportTranslate.GetAbrADSite.StatusDisabled }
                                                7 { $reportTranslate.GetAbrADSite.StatusUnknown }
                                                default { $reportTranslate.GetAbrADSite.StatusOffline }
                                            }
                                            $reportTranslate.GetAbrADSite.Domain = $Domain
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DNS IP Configuration Item)"
                                    }
                                }
                            }
                        }
                        if ($OutObj) {
                            Section -Style Heading4 $reportTranslate.GetAbrADSite.SysvolReplication {
                                $TableParams = @{
                                    Name = "Sysvol Replication - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 33, 33, 34
                                }

                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }

                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADSite.Domain | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADSite.ReplicationStatus) -in $ReplicationStatusError }))) {
                                    Paragraph $reportTranslate.GetAbrADSite.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADSite.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADSite.SysvolBP
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
