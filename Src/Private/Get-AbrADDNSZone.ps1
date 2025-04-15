function Get-AbrADDNSZone {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Microsoft AD Domain Name System Zone information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.4
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
        [string]
        $DC
    )

    begin {
        Write-PScriboMessage "Collecting Actve Directory Domain Name System Zone information on $Domain."
    }

    process {
        try {
            if ($TempCIMSession) {
                $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like "False" -and $_.ZoneType -notlike "Forwarder" }
            }
            if ($DNSSetting) {
                Section -Style Heading3 "$($DC.ToString().ToUpper().Split(".")[0]) DNS Zones" {
                    $OutObj = @()
                    foreach ($Zones in $DNSSetting) {
                        try {
                            $inObj = [ordered] @{
                                'Zone Name' = $Zones.ZoneName
                                'Zone Type' = $Zones.ZoneType
                                'Replication Scope' = $Zones.ReplicationScope
                                'Dynamic Update' = $Zones.DynamicUpdate
                                'DS Integrated' = ($Zones.IsDsIntegrated)
                                'Read Only' = ($Zones.IsReadOnly)
                                'Signed' = ($Zones.IsSigned)
                            }
                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Name System Zone Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "Zones - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Zone Name' | Table @TableParams
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like "False" -and ($_.ZoneName -ne "_msdcs.pharmax.local" -and $_.ZoneName -ne "TrustAnchors") -and ($_.ZoneType -like "Primary" -or $_.ZoneType -like "Secondary") } | Select-Object -ExpandProperty ZoneName
                            if ($DNSSetting) {
                                $OutObj = @()
                                foreach ($Zone in $DNSSetting) {
                                    try {
                                        $Delegations = Get-DnsServerZoneDelegation -CimSession $TempCIMSession -Name $Zone -ComputerName $DC
                                        if ($Delegations) {
                                            foreach ($Delegation in $Delegations) {
                                                try {
                                                    $inObj = [ordered] @{
                                                        'Zone Name' = $Delegation.ZoneName
                                                        'Child Zone' = $Delegation.ChildZoneName
                                                        'Name Server' = $Delegation.NameServer.RecordData.NameServer
                                                        'IP Address' = $Delegation.IPaddress.RecordData.IPv4Address.ToString()
                                                    }
                                                    $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                                } catch {
                                                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                                                }
                                            }
                                        } else {
                                            Write-PScriboMessage "DNS Zones $($Zone) Section: No Zone Delegation information found, Disabling this section."
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Delegation Item)"
                                    }
                                }
                            } else {
                                Write-PScriboMessage "DNS Zones Section: No Zone Delegation information found in $DC, Disabling this section."
                            }

                            if ($OutObj) {
                                Section -Style Heading4 "Zone Delegation" {

                                    $TableParams = @{
                                        Name = "Zone Delegations - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 25, 32, 18
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Zone Name' | Table @TableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Delegation Table)"
                        }
                    }

                    if ($InfoLevel.DNS -ge 2) {
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                        try {
                            $DNSSetting = $Null
                            if ($DCPssSession) {
                                $DNSSetting = Invoke-Command -Session $DCPssSession { Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\*" | Get-ItemProperty | Where-Object { $_ -match 'SecondaryServers' } }
                            } else {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning "DNS Zones Transfers Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            if ($DNSSetting) {
                                Section -Style Heading4 "Zone Transfers" {
                                    $OutObj = @()
                                    foreach ($Zone in $DNSSetting) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Zone Name' = $Zone.PSChildName
                                                'Secondary Servers' = ($Zone.SecondaryServers -join ", ")
                                                'Notify Servers' = $Zone.NotifyServers
                                                'Secure Secondaries' = Switch ($Zone.SecureSecondaries) {
                                                    "0" { "Send zone transfers to all secondary servers that request them." }
                                                    "1" { "Send zone transfers only to name servers that are authoritative for the zone." }
                                                    "2" { "Send zone transfers only to servers you specify in Secondary Servers." }
                                                    "3" { "Do not send zone transfers." }
                                                    default { $Zone.SecureSecondaries }
                                                }
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)

                                            if ($HealthCheck.DNS.Zones) {
                                                $OutObj | Where-Object { $_.'Secure Secondaries' -eq "Send zone transfers to all secondary servers that request them." } | Set-Style -Style Warning -Property 'Secure Secondaries'
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Transfers Item)"
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "Zone Transfers - $($Zone.PSChildName)"
                                        List = $false
                                        ColumnWidths = 25, 20, 20, 35
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                    if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.'Secure Secondaries' -eq "Send zone transfers to all secondary servers that request them." })) {
                                        Paragraph "Health Check:" -Italic -Bold
                                        BlankLine
                                        Paragraph {
                                            Text "Best Practices:" -Bold
                                            Text "Configure all DNS zones only to allow zone transfers from Trusted IP addresses. This ensures that only authorized DNS servers can receive zone data, reducing the risk of unauthorized access or data leakage. It is a best practice to specify the IP addresses of the secondary DNS servers that are allowed to receive zone transfers."
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage "DNS Zones Section: No Zone Transfer information found in $DC, Disabling this section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Transfers Table)"
                        }
                    }
                    try {
                        $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like "True" }
                        if ($DNSSetting) {
                            Section -Style Heading4 "Reverse Lookup Zone" {
                                $OutObj = @()
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Zone Name' = $Zones.ZoneName
                                            'Zone Type' = $Zones.ZoneType
                                            'Replication Scope' = $Zones.ReplicationScope
                                            'Dynamic Update' = $Zones.DynamicUpdate
                                            'DS Integrated' = ($Zones.IsDsIntegrated)
                                            'Read Only' = ($Zones.IsReadOnly)
                                            'Signed' = ($Zones.IsSigned)
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Reverse Lookup Zone Configuration Item)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Zones - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Zone Name' | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage "DNS Zones Section: No Reverse lookup zone information found in $DC, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Reverse Lookup Zone Configuration Table)"
                    }
                    try {
                        $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like "False" -and $_.ZoneType -like "Forwarder" }
                        if ($DNSSetting) {
                            Section -Style Heading4 "Conditional Forwarder" {
                                $OutObj = @()
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Zone Name' = $Zones.ZoneName
                                            'Zone Type' = $Zones.ZoneType
                                            'Replication Scope' = $Zones.ReplicationScope
                                            'Master Servers' = $Zones.MasterServers
                                            'DS Integrated' = $Zones.IsDsIntegrated
                                        }
                                        $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Conditional Forwarder Item)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Conditional Forwarders - $($Domain.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 20, 20, 20, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Zone Name' | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage "DNS Zones Section: No Conditional forwarder zone information found in $DC, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Conditional Forwarder Table)"
                    }
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like "False" -and $_.ZoneType -eq "Primary" } | Select-Object -ExpandProperty ZoneName
                            $Zones = Get-DnsServerZoneAging -CimSession $TempCIMSession -Name $DNSSetting -ComputerName $DC
                            if ($Zones) {
                                Section -Style Heading4 "Zone Scope Aging" {
                                    $OutObj = @()
                                    foreach ($Settings in $Zones) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Zone Name' = $Settings.ZoneName
                                                'Aging Enabled' = ($Settings.AgingEnabled)
                                                'Refresh Interval' = $Settings.RefreshInterval
                                                'NoRefresh Interval' = $Settings.NoRefreshInterval
                                                'Available For Scavenge' = Switch ($Settings.AvailForScavengeTime) {
                                                    "" { "--"; break }
                                                    $Null { "--"; break }
                                                    default { (($Settings.AvailForScavengeTime).ToUniversalTime().toString("r")); break }
                                                }
                                            }
                                            $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                                        } catch {
                                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Aging Item)"
                                        }
                                    }

                                    if ($HealthCheck.DNS.Aging) {
                                        $OutObj | Where-Object { $_.'Aging Enabled' -ne 'Yes' } | Set-Style -Style Warning -Property 'Aging Enabled'
                                    }

                                    $TableParams = @{
                                        Name = "Zone Aging Properties - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 10, 15, 15, 35
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Zone Name' | Table @TableParams
                                    if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.'Aging Enabled' -ne 'Yes' })) {
                                        Paragraph "Health Check:" -Bold -Underline
                                        Paragraph {
                                            Text "Best Practices:" -Bold
                                            Text "Microsoft recommends to enable aging/scavenging on all DNS servers. However, with AD-integrated zones ensure to enable DNS scavenging on one DC at main site. The results will be replicated to other DCs."
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage "DNS Zones Section: No Zone Aging property information found in $DC, Disabling this section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Aging Table)"
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Global DNS Zone Information)"
        }
    }

    end {}

}