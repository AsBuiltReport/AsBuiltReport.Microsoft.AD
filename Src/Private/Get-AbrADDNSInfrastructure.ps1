function Get-AbrADDNSInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Infrastructure information.
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
        Write-PscriboMessage "Discovering Active Directory Domain Name System Infrastructure information for $Domain"
    }

    process {
        try {
            $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object {$_ -notin ($using:Options).Exclude.DCs}}
            if ($DCs) {
                Section -Style Heading4 "Infrastructure Summary" {
                    Paragraph "The following section provides a summary of the DNS Infrastructure configuration."
                    BlankLine
                    $OutObj = @()
                    foreach ($DC in $DCs) {
                        if  (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                            Write-PscriboMessage "Collecting Domain Name System Infrastructure information from '$($DC)'."
                            try {
                                $DNSSetting = Get-DnsServerSetting -CimSession $TempCIMSession -ComputerName $DC
                                $inObj = [ordered] @{
                                    'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                    'Build Number' = ConvertTo-EmptyToFiller $DNSSetting.BuildNumber
                                    'IPv6' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $DNSSetting.EnableIPv6)
                                    'DnsSec' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $DNSSetting.EnableDnsSec)
                                    'ReadOnly DC' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $DNSSetting.IsReadOnlyDC)
                                    'Listening IP' = $DNSSetting.ListeningIPAddress
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "DNS Infrastructure Summary Section: $($_.Exception.Message)"
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Infrastructure Summary - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 10, 9, 10, 11, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                    #---------------------------------------------------------------------------------------------#
                    #                            DNS Aplication Partitions Section                                #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading5 "Application Directory Partition" {
                                Paragraph "The following section provides Directory Partition information."
                                BlankLine
                                foreach ($DC in $DCs) {
                                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                        Section -ExcludeFromTOC -Style NOTOCHeading6 $($DC.ToString().ToUpper().Split(".")[0]) {
                                            $OutObj = @()
                                            Write-PscriboMessage "Collecting Directory Partition information from $($DC)."
                                            try {
                                                $DNSSetting = Get-DnsServerDirectoryPartition -CimSession $TempCIMSession -ComputerName $DC
                                                foreach ($Partition in $DNSSetting) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            'Name' = $Partition.DirectoryPartitionName
                                                            'State' = Switch ($Partition.State) {
                                                                $Null {'--'}
                                                                0 {'DNS_DP_OKAY'}
                                                                1 {'DNS_DP_STATE_REPL_INCOMING'}
                                                                2 {'DNS_DP_STATE_REPL_OUTGOING'}
                                                                3 {'DNS_DP_STATE_UNKNOWN'}
                                                                default {$Partition.State}
                                                            }
                                                            'Flags' = $Partition.Flags
                                                            'Zone Count' = $Partition.ZoneCount
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    catch {
                                                        Write-PscriboMessage -IsWarning "Directory Partitions Item Section: $($_.Exception.Message)"
                                                    }
                                                }
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning "Directory Partitions Table Section: $($_.Exception.Message)"
                                            }

                                            $TableParams = @{
                                                Name = "Directory Partitions - $($DC.ToString().ToUpper().Split(".")[0])"
                                                List = $false
                                                ColumnWidths = 40, 25, 25, 10
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "Directory Partitions Section: $($_.Exception.Message)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS RRL Section                                             #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading5 "Response Rate Limiting (RRL)" {
                                $OutObj = @()
                                foreach ($DC in $DCs) {
                                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                        Write-PscriboMessage "Collecting Response Rate Limiting (RRL) information from $($DC)."
                                        try {
                                            $DNSSetting = Get-DnsServerResponseRateLimiting -CimSession $TempCIMSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                                'Status' = ConvertTo-EmptyToFiller $DNSSetting.Mode
                                                'Responses Per Sec' = ConvertTo-EmptyToFiller $DNSSetting.ResponsesPerSec
                                                'Errors Per Sec' = ConvertTo-EmptyToFiller $DNSSetting.ErrorsPerSec
                                                'Window In Sec' = ConvertTo-EmptyToFiller $DNSSetting.WindowInSec
                                                'Leak Rate' = ConvertTo-EmptyToFiller $DNSSetting.LeakRate
                                                'Truncate Rate' = ConvertTo-EmptyToFiller $DNSSetting.TruncateRate

                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Response Rate Limiting (RRL) Item)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "Response Rate Limiting - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 30, 10, 12, 12, 12, 12, 12
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Response Rate Limiting (RRL) Table)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Scanvenging Section                                     #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading5 "Scavenging Options" {
                                $OutObj = @()
                                foreach ($DC in $DCs) {
                                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                        Write-PscriboMessage "Collecting Scavenging Options information from $($DC)."
                                        try {
                                            $DNSSetting = Get-DnsServerScavenging -CimSession $TempCIMSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                                'NoRefresh Interval' = ConvertTo-EmptyToFiller $DNSSetting.NoRefreshInterval
                                                'Refresh Interval' = ConvertTo-EmptyToFiller $DNSSetting.RefreshInterval
                                                'Scavenging Interval' = ConvertTo-EmptyToFiller $DNSSetting.ScavengingInterval
                                                'Last Scavenge Time' = Switch ($DNSSetting.LastScavengeTime) {
                                                    "" {"--"; break}
                                                    $Null {"--"; break}
                                                    default {ConvertTo-EmptyToFiller ($DNSSetting.LastScavengeTime.ToString("MM/dd/yyyy"))}
                                                }
                                                'Scavenging State' = Switch ($DNSSetting.ScavengingState) {
                                                    "True" {"Enabled"}
                                                    "False" {"Disabled"}
                                                    default {ConvertTo-EmptyToFiller $DNSSetting.ScavengingState}
                                                }
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Scavenging Item)"
                                        }
                                    }
                                }

                                if ($HealthCheck.DNS.Zones) {
                                    $OutObj | Where-Object { $_.'Scavenging State' -eq 'Disabled'} | Set-Style -Style Warning -Property 'Scavenging State'
                                }

                                $TableParams = @{
                                    Name = "Scavenging - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 15, 15, 15, 15, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                                if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.'Scavenging State' -eq 'Disabled'})) {
                                    Paragraph "Health Check:" -Italic -Bold -Underline
                                    BlankLine
                                    Paragraph "Best Practices: Microsoft recommends to enable aging/scavenging on all DNS servers. However, with AD-integrated zones ensure to enable DNS scavenging on one DC at main site. The results will be replicated to other DCs." -Italic -Bold
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Scavenging Table)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Forwarder Section                                       #
                    #---------------------------------------------------------------------------------------------#
                    try {
                        Section -Style Heading5 "Forwarder Options" {
                            $OutObj = @()
                            foreach ($DC in $DCs) {
                                if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                    Write-PscriboMessage "Collecting Forwarder Options information from $($DC)."
                                    try {
                                        $DNSSetting = Get-DnsServerForwarder -CimSession $TempCIMSession -ComputerName $DC
                                        $Recursion = Get-DnsServerRecursion -CimSession $TempCIMSession -ComputerName $DC | Select-Object -ExpandProperty Enable
                                        $inObj = [ordered] @{
                                            'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                            'IP Address' = $DNSSetting.IPAddress
                                            'Timeout' = ("$($DNSSetting.Timeout)/s")
                                            'Use Root Hint' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $DNSSetting.UseRootHint)
                                            'Use Recursion' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Recursion)
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Forwarder Item)"
                                    }
                                }
                            }
                            $TableParams = @{
                                Name = "Forwarders - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 35, 15, 15, 15, 20
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Forwarder Table)"
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Root Hints Section                                      #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading5 "Root Hints" {
                                Paragraph "The following section provides Root Hints information."
                                foreach ($DC in $DCs) {
                                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                        Section -ExcludeFromTOC -Style NOTOCHeading6 $($DC.ToString().ToUpper().Split(".")[0]) {
                                            $OutObj = @()
                                            Write-PscriboMessage "Collecting Root Hint information from $($DC)."
                                            try {
                                                $DNSSetting = Get-DnsServerRootHint -CimSession $TempCIMSession -ComputerName $DC | Select-Object @{Name="Name"; E={$_.NameServer.RecordData.Nameserver}},@{Name="IPAddress"; E={$_.IPAddress.RecordData.IPv6Address.IPAddressToString,$_.IPAddress.RecordData.IPv4Address.IPAddressToString} }
                                                foreach ($Hints in $DNSSetting) {
                                                    try {
                                                        $inObj = [ordered] @{
                                                            'Name' = $Hints.Name
                                                            'IP Address' = (($Hints.IPAddress).Where({ $_ -ne $Null })) -join ", "
                                                        }
                                                        $OutObj += [pscustomobject]$inobj
                                                    }
                                                    catch {
                                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                                    }
                                                }
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Root Hints Item)"
                                            }

                                            $TableParams = @{
                                                Name = "Root Hints - $($Domain.ToString().ToUpper())"
                                                List = $false
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Root Hints Table)"
                        }
                    }
                    #---------------------------------------------------------------------------------------------#
                    #                                 DNS Zone Scope Section                                      #
                    #---------------------------------------------------------------------------------------------#
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Section -Style Heading5 "Zone Scope Recursion" {
                                $OutObj = @()
                                foreach ($DC in $DCs) {
                                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                        Write-PscriboMessage "Collecting Zone Scope Recursion information from $($DC)."
                                        try {
                                            $DNSSetting = Get-DnsServerRecursionScope -CimSession $TempCIMSession -ComputerName $DC
                                            $inObj = [ordered] @{
                                                'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                                'Zone Name' = Switch ($DNSSetting.Name) {
                                                    "." {"Root"}
                                                    default {ConvertTo-EmptyToFiller $DNSSetting.Name}
                                                }
                                                'Forwarder' = $DNSSetting.Forwarder
                                                'Use Recursion' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $DNSSetting.EnableRecursion)
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Recursion Item)"
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "Zone Scope Recursion - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 35, 25, 20, 20
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Recursion Table)"
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DNS Infrastructure Section)"
        }
    }

    end {}

}