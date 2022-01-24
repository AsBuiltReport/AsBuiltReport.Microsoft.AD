function Get-AbrADDNSZone {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Zone information.
    .DESCRIPTION

    .NOTES
        Version:        0.6.2
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
            [PSCredential]
            $Cred,
            [string]
            $DC
    )

    begin {
        Write-PscriboMessage "Discovering Actve Directory Domain Name System Zone information on $Domain."
    }

    process {
        try {
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -notlike "Forwarder"}}
            if ($DNSSetting) {
                Section -Style Heading5 "$($DC.ToString().ToUpper().Split(".")[0]) DNS Zone Configuration" {
                    $OutObj = @()
                    Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Zone)"
                    foreach ($Zones in $DNSSetting) {
                        try {
                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                            $inObj = [ordered] @{
                                'Zone Name' = ConvertTo-EmptyToFiller $Zones.ZoneName
                                'Zone Type' = ConvertTo-EmptyToFiller $Zones.ZoneType
                                'Replication Scope' = ConvertTo-EmptyToFiller $Zones.ReplicationScope
                                'Dynamic Update' = ConvertTo-EmptyToFiller $Zones.DynamicUpdate
                                'DS Integrated' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsDsIntegrated)
                                'Read Only' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsReadOnly)
                                'Signed' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsSigned)
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Name System Zone Item)"
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
                    $OutObj | Table @TableParams
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and ($_.ZoneName -ne "_msdcs.pharmax.local" -and $_.ZoneName -ne "TrustAnchors") -and ($_.ZoneType -like "Primary" -or $_.ZoneType -like "Secondary")} | Select-Object -ExpandProperty ZoneName }
                            if ($DNSSetting) {
                                $OutObj = @()
                                foreach ($Zone in $DNSSetting) {
                                    try {
                                        $Delegations = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneDelegation -Name $using:Zone}
                                        if ($Delegations) {
                                            foreach ($Delegation in $Delegations) {
                                                try {
                                                    Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Delegation.ZoneName)' on $DC"
                                                    $inObj = [ordered] @{
                                                        'Zone Name' = $Delegation.ZoneName
                                                        'Child Zone' = $Delegation.ChildZoneName
                                                        'Name Server' = $Delegation.NameServer.RecordData.NameServer
                                                        'IP Address' = $Delegation.IPaddress.RecordData.IPv4Address.ToString()
                                                    }
                                                    $OutObj += [pscustomobject]$inobj
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $($_.Exception.Message)
                                                }
                                            }
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Delegation Item)"
                                    }
                                }
                            }

                            if ($OutObj) {
                                Section -Style Heading6 "Zone Delegation" {

                                    $TableParams = @{
                                        Name = "Zone Delegations - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 25, 32, 18
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Delegation Table)"
                        }
                    }

                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\*" | Get-ItemProperty | Where-Object {$_ -match 'SecondaryServers'}}
                            if ($DNSSetting) {
                                Section -Style Heading6 "Zone Transfers" {
                                    $OutObj = @()
                                    foreach ($Zone in $DNSSetting) {
                                        try {
                                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zone.PSChildName)' on $DC"
                                            $inObj = [ordered] @{
                                                'Zone Name' = $Zone.PSChildName
                                                'Secondary Servers' = ConvertTo-EmptyToFiller ($Zone.SecondaryServers -join ", ")
                                                'Notify Servers' = ConvertTo-EmptyToFiller $Zone.NotifyServers
                                                'Secure Secondaries' = Switch ($Zone.SecureSecondaries) {
                                                    "0" {"Send zone transfers to all secondary servers that request them."}
                                                    "1" {"Send zone transfers only to name servers that are authoritative for the zone."}
                                                    "2" {"Send zone transfers only to servers you specify in Secondary Servers."}
                                                    "3" {"Do not send zone transfers."}
                                                    default {$Zone.SecureSecondaries}
                                                }
                                            }
                                            $OutObj = [pscustomobject]$inobj

                                            $TableParams = @{
                                                Name = "Zone Transfers - $($Zone.PSChildName)"
                                                List = $true
                                                ColumnWidths = 40, 60
                                            }
                                            if ($Report.ShowTableCaptions) {
                                                $TableParams['Caption'] = "- $($TableParams.Name)"
                                            }
                                            $OutObj | Table @TableParams
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Transfers Item)"
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Transfers Table)"
                        }
                    }
                    try {
                        $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "True"}}
                        if ($DNSSetting) {
                            Section -Style Heading6 "Reverse Lookup Zone Configuration" {
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC (Domain Name System Zone)"
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                                        $inObj = [ordered] @{
                                            'Zone Name' = ConvertTo-EmptyToFiller $Zones.ZoneName
                                            'Zone Type' = ConvertTo-EmptyToFiller $Zones.ZoneType
                                            'Replication Scope' = ConvertTo-EmptyToFiller $Zones.ReplicationScope
                                            'Dynamic Update' = ConvertTo-EmptyToFiller $Zones.DynamicUpdate
                                            'DS Integrated' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsDsIntegrated)
                                            'Read Only' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsReadOnly)
                                            'Signed' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Zones.IsSigned)
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Reverse Lookup Zone Configuration Item)"
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
                                $OutObj | Table @TableParams
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Reverse Lookup Zone Configuration Table)"
                    }
                    try {
                        $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -like "Forwarder"}}
                        if ($DNSSetting) {
                            Section -Style Heading5 "Conditional Forwarder" {
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Conditional Forwarder )"
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                                        $inObj = [ordered] @{
                                            'Zone Name' = $Zones.ZoneName
                                            'Zone Type' = $Zones.ZoneType
                                            'Replication Scope' = $Zones.ReplicationScope
                                            'Master Servers' = $Zones.MasterServers
                                            'DS Integrated' = $Zones.IsDsIntegrated
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Conditional Forwarder Item)"
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
                                $OutObj | Table @TableParams
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Conditional Forwarder Table)"
                    }
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Zone)"
                            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -eq "Primary"} | Select-Object -ExpandProperty ZoneName }
                            $Zones = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneAging -Name $using:DNSSetting}
                            if ($Zones) {
                                Section -Style Heading6 "Zone Scope Aging Properties" {
                                    $OutObj = @()
                                    foreach ($Settings in $Zones) {
                                        try {
                                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Settings.ZoneName)' on $DC"
                                            $inObj = [ordered] @{
                                                'Zone Name' = ConvertTo-EmptyToFiller $Settings.ZoneName
                                                'Aging Enabled' = ConvertTo-EmptyToFiller (ConvertTo-TextYN $Settings.AgingEnabled)
                                                'Refresh Interval' = ConvertTo-EmptyToFiller $Settings.RefreshInterval
                                                'NoRefresh Interval' = ConvertTo-EmptyToFiller $Settings.NoRefreshInterval
                                                'Available For Scavenge' = Switch ($Settings.AvailForScavengeTime) {
                                                    "" {"-"; break}
                                                    $Null {"-"; break}
                                                    default {(ConvertTo-EmptyToFiller ($Settings.AvailForScavengeTime).ToUniversalTime().toString("r")); break}
                                                }
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Aging Item)"
                                        }
                                    }

                                    if ($HealthCheck.DNS.Aging) {
                                        $OutObj | Where-Object { $_.'Aging Enabled' -ne 'Yes'} | Set-Style -Style Warning -Property 'Aging Enabled'
                                    }

                                    $TableParams = @{
                                        Name = "Zone Aging Properties - $($Domain.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 10, 15, 15, 35
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Zone Scope Aging Table)"
                        }
                    }
                }
            }
            Remove-PSSession -Session $DCPssSession
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Global DNS Zone Information)"
        }
    }

    end {}

}