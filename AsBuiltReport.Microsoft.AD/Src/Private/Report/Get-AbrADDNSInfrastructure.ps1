function Get-AbrADDNSInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Infrastructure information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string[]]$DCs
    )

    begin {
        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADDNSInfrastructure.Collecting, $Domain.DNSRoot))
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DNS Infrastructure'
    }

    process {
        try {
            if ($DCs) {
                Section -Style Heading3 $reportTranslate.GetAbrADDNSInfrastructure.InfrastructureSummary {
                    Paragraph $reportTranslate.GetAbrADDNSInfrastructure.InfrastructureSummaryParagraph
                    BlankLine
                    $OutObj = [System.Collections.Generic.List[object]]::new()
                    foreach ($DC in $DCs) {
                        if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                            try {
                                $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                $DNSSetting = Get-DnsServerSetting -CimSession $DCCimSession -ComputerName $DC
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADDNSInfrastructure.DCName = $($DC.ToString().ToUpper().Split('.')[0])
                                    $reportTranslate.GetAbrADDNSInfrastructure.BuildNumber = $DNSSetting.BuildNumber
                                    $reportTranslate.GetAbrADDNSInfrastructure.IPv6 = ($DNSSetting.EnableIPv6)
                                    $reportTranslate.GetAbrADDNSInfrastructure.DnsSec = ($DNSSetting.EnableDnsSec)
                                    $reportTranslate.GetAbrADDNSInfrastructure.ReadOnlyDC = ($DNSSetting.IsReadOnlyDC)
                                    $reportTranslate.GetAbrADDNSInfrastructure.ListeningIP = $DNSSetting.ListeningIPAddress
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorInfrastructureSummarySection) $($_.Exception.Message)"
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDNSInfrastructure.InfrastructureSummary) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 10, 9, 10, 11, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.DCName | Table @TableParams
                    #---------------------------------------------------------------------------------------------#
                    #                            DNS Aplication Partitions Section                                #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.AppDirectoryPartition {
                                Paragraph $reportTranslate.GetAbrADDNSInfrastructure.AppDirectoryPartitionParagraph
                                BlankLine
                                foreach ($DC in $DCs) {
                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                        try {
                                            Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                                $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                                $DNSSetting = Get-DnsServerDirectoryPartition -CimSession $DCCimSession -ComputerName $DC
                                                foreach ($Partition in $DNSSetting) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            $reportTranslate.GetAbrADDNSInfrastructure.Name = $Partition.DirectoryPartitionName
                                                            $reportTranslate.GetAbrADDNSInfrastructure.State = switch ($Partition.State) {
                                                                $Null { '--' }
                                                                0 { 'DNS_DP_OKAY' }
                                                                1 { 'DNS_DP_STATE_REPL_INCOMING' }
                                                                2 { 'DNS_DP_STATE_REPL_OUTGOING' }
                                                                3 { 'DNS_DP_STATE_UNKNOWN' }
                                                                default { $Partition.State }
                                                            }
                                                            $reportTranslate.GetAbrADDNSInfrastructure.Flags = $Partition.Flags
                                                            $reportTranslate.GetAbrADDNSInfrastructure.ZoneCount = $Partition.ZoneCount
                                                        }
                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                    } catch {
                                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorDirectoryPartitionsItemSection) $($_.Exception.Message)"
                                                    }
                                                }
                                                $TableParams = @{
                                                    Name = "$($reportTranslate.GetAbrADDNSInfrastructure.DirectoryPartitions) - $($DC.ToString().ToUpper().Split('.')[0])"
                                                    List = $false
                                                    ColumnWidths = 40, 25, 25, 10
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.Name | Table @TableParams
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorDirectoryPartitionsTableSection) $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorDirectoryPartitionsSection) $($_.Exception.Message)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS RRL Section                                             #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.ResponseRateLimiting {
                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                foreach ($DC in $DCs) {
                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                        try {
                                            $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                            $DNSSetting = Get-DnsServerResponseRateLimiting -CimSession $DCCimSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDNSInfrastructure.DCName = $($DC.ToString().ToUpper().Split('.')[0])
                                                $reportTranslate.GetAbrADDNSInfrastructure.Status = $DNSSetting.Mode
                                                $reportTranslate.GetAbrADDNSInfrastructure.ResponsesPerSec = $DNSSetting.ResponsesPerSec
                                                $reportTranslate.GetAbrADDNSInfrastructure.ErrorsPerSec = $DNSSetting.ErrorsPerSec
                                                $reportTranslate.GetAbrADDNSInfrastructure.WindowInSec = $DNSSetting.WindowInSec
                                                $reportTranslate.GetAbrADDNSInfrastructure.LeakRate = $DNSSetting.LeakRate
                                                $reportTranslate.GetAbrADDNSInfrastructure.TruncateRate = $DNSSetting.TruncateRate

                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorRRLItem) $($_.Exception.Message)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDNSInfrastructure.ResponseRateLimitingTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 30, 10, 12, 12, 12, 12, 12
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.DCName | Table @TableParams
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorRRLTable) $($_.Exception.Message)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Scanvenging Section                                     #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.ScavengingOptions {
                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                foreach ($DC in $DCs) {
                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                        try {
                                            $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                            $DNSSetting = Get-DnsServerScavenging -CimSession $DCCimSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDNSInfrastructure.DCName = $($DC.ToString().ToUpper().Split('.')[0])
                                                $reportTranslate.GetAbrADDNSInfrastructure.NoRefreshInterval = $DNSSetting.NoRefreshInterval
                                                $reportTranslate.GetAbrADDNSInfrastructure.RefreshInterval = $DNSSetting.RefreshInterval
                                                $reportTranslate.GetAbrADDNSInfrastructure.ScavengingInterval = $DNSSetting.ScavengingInterval
                                                $reportTranslate.GetAbrADDNSInfrastructure.LastScavengeTime = switch ($DNSSetting.LastScavengeTime) {
                                                    '' { '--'; break }
                                                    $Null { '--'; break }
                                                    default { ($DNSSetting.LastScavengeTime.ToString('MM/dd/yyyy')) }
                                                }
                                                $reportTranslate.GetAbrADDNSInfrastructure.ScavengingState = switch ($DNSSetting.ScavengingState) {
                                                    'True' { $reportTranslate.GetAbrADDNSInfrastructure.Enabled }
                                                    'False' { $reportTranslate.GetAbrADDNSInfrastructure.Disabled }
                                                    default { $DNSSetting.ScavengingState }
                                                }
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorScavengingItem) $($_.Exception.Message)"
                                        }
                                    }
                                }

                                if ($HealthCheck.DNS.Zones) {
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.ScavengingState) -eq $reportTranslate.GetAbrADDNSInfrastructure.Disabled } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.ScavengingState
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDNSInfrastructure.ScavengingTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 15, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.DCName | Table @TableParams
                                if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.ScavengingState) -eq $reportTranslate.GetAbrADDNSInfrastructure.Disabled })) {
                                    Paragraph $reportTranslate.GetAbrADDNSInfrastructure.HealthCheck -Bold -Underline
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.ScavengingBP
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorScavengingTable) $($_.Exception.Message)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Forwarder Section                                       #
                    #---------------------------------------------------------------------------------------------#
                    try {
                        Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.ForwarderOptions {
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            foreach ($DC in $DCs) {
                                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                    try {
                                        $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                        $DNSSetting = Get-DnsServerForwarder -CimSession $DCCimSession -ComputerName $DC
                                        $Recursion = Get-DnsServerRecursion -CimSession $DCCimSession -ComputerName $DC | Select-Object -ExpandProperty Enable
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDNSInfrastructure.DCName = $($DC.ToString().ToUpper().Split('.')[0])
                                            $reportTranslate.GetAbrADDNSInfrastructure.IPAddress = $DNSSetting.IPAddress.IPAddressToString
                                            $reportTranslate.GetAbrADDNSInfrastructure.Timeout = ("$($DNSSetting.Timeout)/s")
                                            $reportTranslate.GetAbrADDNSInfrastructure.UseRootHint = ($DNSSetting.UseRootHint)
                                            $reportTranslate.GetAbrADDNSInfrastructure.UseRecursion = ($Recursion)
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorForwarderItem) $($_.Exception.Message)"
                                    }
                                }
                            }

                            if ($HealthCheck.DNS.BestPractice) {
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress).Count -gt 2 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.IPAddress
                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress).Count -lt 2 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.IPAddress
                            }

                            $TableParams = @{
                                Name = "$($reportTranslate.GetAbrADDNSInfrastructure.ForwardersTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 35, 15, 15, 15, 20
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.DCName | Table @TableParams
                            if ($HealthCheck.DNS.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress) -gt 2 }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress).Count -lt 2 }))) {
                                Paragraph $reportTranslate.GetAbrADDNSInfrastructure.HealthCheck -Bold -Underline
                                BlankLine
                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress) -gt 2 }) {

                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.ForwarderMaxBP
                                    }
                                    BlankLine
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.Reference -Bold
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.ForwarderRefURL -Color blue
                                    }
                                    BlankLine
                                }
                                if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPAddress).Count -lt 2 }) {
                                    Paragraph {
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.BestPractice -Bold
                                        Text $reportTranslate.GetAbrADDNSInfrastructure.ForwarderMinBP
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorForwarderTable) $($_.Exception.Message)"
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Root Hints Section                                      #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.RootHints {
                                Paragraph ([string]::Format($reportTranslate.GetAbrADDNSInfrastructure.RootHintsParagraph, $Domain.DNSRoot))
                                BlankLine
                                foreach ($DC in $DCs) {
                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                        try {
                                            Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                                $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                                $DNSSetting = Get-DnsServerRootHint -CimSession $DCCimSession -ComputerName $DC -ErrorAction SilentlyContinue | Select-Object @{Name = 'Name'; E = { $_.NameServer.RecordData.Nameserver } }, @{ Name = 'IPv4Address'; E = { $_.IPAddress.RecordData.IPv4Address.IPAddressToString } }, @{ Name = 'IPv6Address'; E = { $_.IPAddress.RecordData.IPv6Address.IPAddressToString } }
                                                if ($DNSSetting) {
                                                    foreach ($Hints in $DNSSetting) {
                                                        try {
                                                            $inObj = [ordered] @{
                                                                $reportTranslate.GetAbrADDNSInfrastructure.Name = $Hints.Name
                                                                $reportTranslate.GetAbrADDNSInfrastructure.IPv4Address = switch ([string]::IsNullOrEmpty($Hints.IPv4Address)) {
                                                                    $true { '--' }
                                                                    $false { $Hints.IPv4Address -split ' ' }
                                                                    default { 'Unknown' }
                                                                }
                                                                $reportTranslate.GetAbrADDNSInfrastructure.IPv6Address = switch ([string]::IsNullOrEmpty($Hints.IPv6Address)) {
                                                                    $true { '--' }
                                                                    $false { $Hints.IPv6Address -split ' ' }
                                                                    default { 'Unknown' }
                                                                }
                                                            }
                                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                        } catch {
                                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                                        }
                                                    }
                                                } else {
                                                    $RootServers = @(
                                                        'a.root-servers.net',
                                                        'b.root-servers.net',
                                                        'c.root-servers.net',
                                                        'd.root-servers.net',
                                                        'e.root-servers.net',
                                                        'f.root-servers.net',
                                                        'g.root-servers.net',
                                                        'h.root-servers.net',
                                                        'i.root-servers.net',
                                                        'j.root-servers.net',
                                                        'k.root-servers.net',
                                                        'l.root-servers.net',
                                                        'm.root-servers.net'
                                                    )
                                                    foreach ($server in $RootServers) {
                                                        $inObj = [ordered] @{
                                                            $reportTranslate.GetAbrADDNSInfrastructure.Name = $server
                                                            $reportTranslate.GetAbrADDNSInfrastructure.IPv4Address = '--'
                                                            $reportTranslate.GetAbrADDNSInfrastructure.IPv6Address = '--'
                                                        }
                                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                                    }

                                                }

                                                if ($HealthCheck.DNS.BestPractice) {
                                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address) -eq '--' -and $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address) -eq '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.IPv4Address, $reportTranslate.GetAbrADDNSInfrastructure.IPv6Address
                                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address).Count -gt 1 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.IPv4Address
                                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address).Count -gt 1 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSInfrastructure.IPv6Address
                                                }

                                                $TableParams = @{
                                                    Name = "$($reportTranslate.GetAbrADDNSInfrastructure.RootHints) - $($DC.ToString().ToUpper().Split('.')[0])"
                                                    List = $false
                                                    ColumnWidths = 40, 30, 30
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.Name | Table @TableParams
                                                if ($HealthCheck.DNS.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address) -eq '--' -and $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address) -eq '--' }) -or (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address).Count -gt 1 }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address).Count -gt 1 })))) {
                                                    Paragraph $reportTranslate.GetAbrADDNSInfrastructure.HealthCheck -Bold -Underline
                                                    BlankLine
                                                    if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address) -eq '--' -and $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address) -eq '--' }) {
                                                        Paragraph {
                                                            Text $reportTranslate.GetAbrADDNSInfrastructure.CorrectiveActions -Bold
                                                            Text $reportTranslate.GetAbrADDNSInfrastructure.RootHintsMissingCA
                                                        }
                                                    }
                                                    if (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv4Address).Count -gt 1 }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSInfrastructure.IPv6Address).Count -gt 1 })) {
                                                        Paragraph {
                                                            Text $reportTranslate.GetAbrADDNSInfrastructure.CorrectiveActions -Bold
                                                            Text $reportTranslate.GetAbrADDNSInfrastructure.RootHintsDuplicateCA
                                                        }
                                                    }
                                                }
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorRootHintsTable) $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorRootHintsSection) $($_.Exception.Message)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Zone Scope Section                                      #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSInfrastructure.ZoneScopeRecursion {
                                $OutObj = [System.Collections.Generic.List[object]]::new()
                                foreach ($DC in $DCs) {
                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                        try {
                                            $DCCimSession = Get-ValidCIMSession -ComputerName $DC -SessionName "$($DC)_DNS" -CIMTable ([ref]$CIMTable)
                                            $DNSSetting = Get-DnsServerRecursionScope -CimSession $DCCimSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDNSInfrastructure.DCName = $($DC.ToString().ToUpper().Split('.')[0])
                                                $reportTranslate.GetAbrADDNSInfrastructure.ZoneName = switch ($DNSSetting.Name) {
                                                    '.' { $reportTranslate.GetAbrADDNSInfrastructure.ZoneScopeRoot }
                                                    default { $DNSSetting.Name }
                                                }
                                                $reportTranslate.GetAbrADDNSInfrastructure.Forwarder = $DNSSetting.Forwarder
                                                $reportTranslate.GetAbrADDNSInfrastructure.UseRecursion = ($DNSSetting.EnableRecursion)
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorZoneScopeRecursionItem) $($_.Exception.Message)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDNSInfrastructure.ZoneScopeRecursion) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 25, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSInfrastructure.DCName | Table @TableParams
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorZoneScopeRecursionTable) $($_.Exception.Message)"
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($reportTranslate.GetAbrADDNSInfrastructure.ErrorDNSInfrastructureSection) $($_.Exception.Message)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DNS Infrastructure'
    }

}
