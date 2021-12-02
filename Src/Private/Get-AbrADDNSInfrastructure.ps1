function Get-AbrADDNSInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Infrastructure information.
    .DESCRIPTION

    .NOTES
        Version:        0.5.0
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
            $Domain,
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory Domain Name System Infrastructure information for $Domain"
    }

    process {
        try {
            Section -Style Heading5 "Infrastructure Summary" {
                Paragraph "The following section provides a summary of the DNS Infrastructure configuration."
                BlankLine
                if ($Domain) {
                    $OutObj = @()
                    foreach ($Item in $Domain) {
                        $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                        foreach ($DC in $DCs) {
                            Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                            try {
                                $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerSetting -ComputerName $using:DC}
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
                                Write-PscriboMessage -IsWarning " $($_.Exception.Message) (Infrastructure Summary)"
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "DNS Infrastructure Setting Information."
                        List = $false
                        ColumnWidths = 30, 10, 9, 10, 11, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }

                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Domain Controller DNS IP Configuration" {
                        Paragraph "The following section provides information of the DNS IP Configuration."
                        BlankLine
                        if ($Domain) {
                            $OutObj = @()
                            $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                            if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                            foreach ($DC in $DCs) {
                                $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                                Write-PscriboMessage "Collecting DNS IP Configuration information from '$($DC)'."
                                try {
                                    $DNSSettings = Invoke-Command -Session $DCPssSession {Get-NetAdapter | Get-DnsClientServerAddress -AddressFamily IPv4}
                                    foreach ($DNSSetting in $DNSSettings) {
                                        $inObj = [ordered] @{
                                            'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                            'Interface' = $DNSSetting.InterfaceAlias
                                            'DNS IP 1' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[0]
                                            'DNS IP 2' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[1]
                                            'DNS IP 3' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[2]
                                            'DNS IP 4' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[3]
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DNS IP Configuration)"
                                }
                            }

                            if ($HealthCheck.DNS.DP) {
                                $OutObj | Where-Object { $_.'DNS IP 1' -eq "127.0.0.1"} | Set-Style -Style Warning -Property 'DNS IP 1'
                            }

                            $TableParams = @{
                                Name = "DNS IP Configuration information."
                                List = $false
                                ColumnWidths = 20, 20, 15, 15, 15, 15
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Application Directory Partition" {
                        Paragraph "The following section provides a summary of the DNS Application Directory Partition information."
                        BlankLine
                        if ($Domain) {
                            foreach ($Item in $Domain) {
                                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                                foreach ($DC in $DCs) {
                                    Section -Style Heading7 "$($DC.ToString().ToUpper().Split(".")[0]) Directory Partition" {
                                        Paragraph "The following section provides $($DC.ToString().ToUpper().Split(".")[0]) Directory Partition information."
                                        BlankLine
                                        $OutObj = @()
                                        Write-PscriboMessage "Collecting Domain Name System Directory Partition information on '$($DC)'."
                                        try {
                                            $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerDirectoryPartition -ComputerName $using:DC}
                                            foreach ($Partition in $DNSSetting) {
                                                $inObj = [ordered] @{
                                                    'Name' = $Partition.DirectoryPartitionName
                                                    'State' = ConvertTo-EmptyToFiller $Partition.State
                                                    'Flags' = $Partition.Flags
                                                    'Zone Count' = $Partition.ZoneCount
                                                }
                                                $OutObj += [pscustomobject]$inobj
                                            }
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Directory Partitions Summary)"
                                        }
                                        if ($HealthCheck.DNS.DP) {
                                            $OutObj | Where-Object { $_.'State' -ne 0 -and $_.'State' -ne "-"} | Set-Style -Style Warning -Property 'Name','State','Flags','Zone Count'
                                        }

                                        $TableParams = @{
                                            Name = "DNS Directory Partitions information."
                                            List = $false
                                            ColumnWidths = 50, 15, 25, 10
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Sort-Object -Property Name | Table @TableParams
                                    }
                                }
                            }
                        }
                    }
                }
                
                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Response Rate Limiting (RRL)" {
                        Paragraph "The following section provides a summary of the DNS Response Rate Limiting configuration."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            foreach ($Item in $Domain) {
                                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                                foreach ($DC in $DCs) {
                                    Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                                    try {
                                        $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerResponseRateLimiting -ComputerName $using:DC}
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
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Response Rate Limiting (RRL) Summary)"
                                    }
                                }
                            }

                            $TableParams = @{
                                Name = "DNS Response Rate Limiting configuration."
                                List = $false
                                ColumnWidths = 30, 10, 12, 12, 12, 12, 12
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Scavenging Options" {
                        Paragraph "The following section provides a summary of the DNS Scavenging configuration."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            foreach ($Item in $Domain) {
                                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                                foreach ($DC in $DCs) {
                                    Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                                    try {
                                        $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerScavenging -ComputerName $using:DC}
                                        $inObj = [ordered] @{
                                            'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                            'NoRefresh Interval' = ConvertTo-EmptyToFiller $DNSSetting.NoRefreshInterval
                                            'Refresh Interval' = ConvertTo-EmptyToFiller $DNSSetting.RefreshInterval
                                            'Scavenging Interval' = ConvertTo-EmptyToFiller $DNSSetting.ScavengingInterval
                                            'Last Scavenge Time' = Switch ($DNSSetting.LastScavengeTime) {
                                                "" {"-"; break}
                                                $Null {"-"; break}
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
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Scavenging Summary)"
                                    }
                                }
                            }

                            $TableParams = @{
                                Name = "DNS Scavenging configuration."
                                List = $false
                                ColumnWidths = 25, 15, 15, 15, 15, 15
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }

                Section -Style Heading6 "Forwarder Options" {
                    Paragraph "The following section provides a summary of the DNS Forwarder configuration."
                    BlankLine
                    $OutObj = @()
                    if ($Domain) {
                        foreach ($Item in $Domain) {
                            $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                            if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                            foreach ($DC in $DCs) {
                                Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)' (Forwarder Summary)."
                                try {
                                    $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerForwarder -ComputerName $using:DC}
                                    $Recursion = Invoke-Command -Session $Session {Get-DnsServerRecursion -ComputerName $using:DC | Select-Object -ExpandProperty Enable}
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
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Forwarder Summary)"
                                }
                            }
                        }

                        $TableParams = @{
                            Name = "DNS Infrastructure Forwarder configuration."
                            List = $false
                            ColumnWidths = 35, 15, 15, 15, 20
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }
                        $OutObj | Table @TableParams
                    }
                }
                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Root Hints" {
                        Paragraph "The following section provides a summary of the DNS Root Hints information."
                        BlankLine
                        if ($Domain) {
                            foreach ($Item in $Domain) {
                                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                                foreach ($DC in $DCs) {
                                    Section -Style Heading7 "$($DC.ToString().ToUpper().Split(".")[0]) Root Hints" {
                                        Paragraph "The following section provides $($DC.ToString().ToUpper().Split(".")[0]) Root Hints information."
                                        BlankLine
                                        $OutObj = @()
                                        Write-PscriboMessage "Collecting Domain Name System Root Hint information on '$($DC)'."
                                        try {
                                            $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerRootHint -ComputerName $using:DC | Select-Object @{Name="Name"; E={$_.NameServer.RecordData.Nameserver}},@{Name="IPAddress"; E={$_.IPAddress.RecordData.IPv6Address.IPAddressToString,$_.IPAddress.RecordData.IPv4Address.IPAddressToString} }}
                                            foreach ($Hints in $DNSSetting) {
                                                $inObj = [ordered] @{
                                                    'Name' = $Hints.Name
                                                    'IP Address' = (($Hints.IPAddress).Where({ $_ -ne $Null })) -join ", "
                                                }
                                                $OutObj += [pscustomobject]$inobj
                                            }
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Root Hints Summary)"
                                        }

                                        $TableParams = @{
                                            Name = "DNS Root Hints information."
                                            List = $false
                                            ColumnWidths = 50, 50
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Sort-Object -Property Name | Table @TableParams
                                    }
                                }
                            }
                        }
                    }
                }
                if ($InfoLevel.DNS -ge 2) {
                    Section -Style Heading6 "Zone Scope Recursion" {
                        Paragraph "The following section provides a summary of the DNS Zone Scope Recursion configuration."
                        BlankLine
                        $OutObj = @()
                        if ($Domain) {
                            foreach ($Item in $Domain) {
                                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                                foreach ($DC in $DCs) {
                                    Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                                    try {
                                        $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerRecursionScope -ComputerName $using:DC}
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
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Recursion Summary)"
                                    }
                                }
                            }

                            $TableParams = @{
                                Name = "DNS Zone Scope Recursion configuration."
                                List = $false
                                ColumnWidths = 35, 25, 20, 20
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Global DNS Infrastructure)"
        }
    }

    end {}

}