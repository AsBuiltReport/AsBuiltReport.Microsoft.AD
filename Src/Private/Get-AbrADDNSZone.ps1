function Get-AbrADDNSZone {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Zone information.
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
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
        Section -Style Heading5 "Domain Name System Zone Configuration of $($DC.ToString().ToUpper().Split(".")[0])" {
            Paragraph "The following section provides a summary of the Domain Name System Zone Configuration information."
            BlankLine
            $OutObj = @()
            if ($DC) {
                try {
                    Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Zone)"
                    $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                    $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -notlike "Forwarder"}}
                    foreach ($Zones in $DNSSetting) {
                        Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                        $inObj = [ordered] @{
                            'Zone Name' = $Zones.ZoneName
                            'Zone Type' = $Zones.ZoneType
                            'Replication Scope' = $Zones.ReplicationScope
                            'Dynamic Update' = $Zones.DynamicUpdate
                            'DS Integrated' = ConvertTo-TextYN $Zones.IsDsIntegrated
                            'Read Only' = ConvertTo-TextYN $Zones.IsReadOnly
                            'Signed' = ConvertTo-TextYN $Zones.IsSigned
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    Remove-PSSession -Session $DCPssSession
                }
                catch {
                    Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                    Write-PscriboMessage -IsDebug $_.Exception.Message
                }

                $TableParams = @{
                    Name = "Domain Name System Zone Information."
                    List = $false
                    ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
            if ($InfoLevel.DNS -ge 2) {
                try {
                    $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                    Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Zone)"
                    $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ReplicationScope -eq "Domain"} | Select-Object -ExpandProperty ZoneName }
                    $Zones = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneDelegation -Name $using:DNSSetting}
                    Remove-PSSession -Session $DCPssSession
                    if ($Zones) {
                        Section -Style Heading6 "Zone Delegation of $($DC.ToString().ToUpper().Split(".")[0])" {
                            Paragraph "The following section provides a summary of the Domain Name System Zone Delegation information."
                            BlankLine
                            $OutObj = @()
                            if ($DC -and $DNSSetting -and $Zones) {
                                if ($Zones) {
                                    foreach ($Delegations in $Zones) {
                                        if ($Delegations) {
                                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Delegations.ZoneName)' on $DC"
                                            $inObj = [ordered] @{
                                                'Zone Name' = $Delegations.ZoneName
                                                'Child Zone' = $Delegations.ChildZoneName
                                                'Name Server' = $Delegations.NameServer.RecordData.NameServer
                                                'IP Address' = $Delegations.IPaddress.RecordData.IPv4Address.ToString()
                                            }
                                            $OutObj += [pscustomobject]$inobj
                                        }
                                    }
                                }

                                $TableParams = @{
                                    Name = "Domain Name System Zone Delegation Information."
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
                }
                catch {
                    Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                    Write-PscriboMessage -IsDebug $_.Exception.Message
                }
            }
            Section -Style Heading6 "Reverse Lookup Zone Configuration of $($DC.ToString().ToUpper().Split(".")[0])" {
                Paragraph "The following section provides a summary of the Domain Name System Reverse Lookup Zone Configuration information."
                BlankLine
                $OutObj = @()
                if ($DC) {
                    try {
                        Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC (Domain Name System Zone)"
                        $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                        $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "True"}}
                        foreach ($Zones in $DNSSetting) {
                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                            $inObj = [ordered] @{
                                'Zone Name' = $Zones.ZoneName
                                'Zone Type' = $Zones.ZoneType
                                'Replication Scope' = $Zones.ReplicationScope
                                'Dynamic Update' = $Zones.DynamicUpdate
                                'DS Integrated' = ConvertTo-TextYN $Zones.IsDsIntegrated
                                'Read Only' = ConvertTo-TextYN $Zones.IsReadOnly
                                'Signed' = ConvertTo-TextYN $Zones.IsSigned
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        Remove-PSSession -Session $DCPssSession
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }

                    $TableParams = @{
                        Name = "Domain Name System Zone Information."
                        List = $false
                        ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            Section -Style Heading5 "Conditional Forwarder information on $($DC.ToString().ToUpper().Split(".")[0])" {
                Paragraph "The following section provides a summary of the Domain Name System Conditional Forwarder information."
                BlankLine
                $OutObj = @()
                if ($DC) {
                    try {
                        Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Conditional Forwarder )"
                        $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                        $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -like "Forwarder"}}
                        foreach ($Zones in $DNSSetting) {
                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Zones.ZoneName)' on $DC"
                            $inObj = [ordered] @{
                                'Zone Name' = $Zones.ZoneName
                                'Zone Type' = $Zones.ZoneType
                                'Replication Scope' = $Zones.ReplicationScope
                                'Master Servers' = $Zones.MasterServers
                                'DS Integrated' = ConvertTo-TextYN $Zones.IsDsIntegrated
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        Remove-PSSession -Session $DCPssSession
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }

                    $TableParams = @{
                        Name = "Domain Name System Conditional Forwarder Information."
                        List = $false
                        ColumnWidths = 25, 20, 20, 20, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            if ($InfoLevel.DNS -ge 2) {
                Section -Style Heading6 "Zone Scope Aging properties of $($DC.ToString().ToUpper().Split(".")[0])" {
                    Paragraph "The following section provides a summary of the Domain Name System Zone Aging properties information."
                    BlankLine
                    $OutObj = @()
                    try {
                        $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                        Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC. (Domain Name System Zone)"
                        $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ZoneType -notlike "Forwarder"} | Select-Object -ExpandProperty ZoneName }
                        $Zones = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneAging -Name $using:DNSSetting}
                        foreach ($Settings in $Zones) {
                            Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Settings.ZoneName)' on $DC"
                            $inObj = [ordered] @{
                                'Zone Name' = $Settings.ZoneName
                                'Aging Enabled' = ConvertTo-TextYN $Settings.AgingEnabled
                                'Refresh Interval' = $Settings.RefreshInterval
                                'NoRefresh Interval' = $Settings.NoRefreshInterval
                                'Available For Scavenge' = Switch ($Settings.AvailForScavengeTime) {
                                    "" {"-"; break}
                                    $Null {"-"; break}
                                    default {($Settings.AvailForScavengeTime).ToUniversalTime().toString("r"); break}
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        Remove-PSSession -Session $DCPssSession
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }

                    if ($HealthCheck.DNS.Aging) {
                        $OutObj | Where-Object { $_.'Aging Enabled' -ne 'Yes'} | Set-Style -Style Warning -Property 'Aging Enabled'
                    }

                    $TableParams = @{
                        Name = "Domain Name System Zone Aging properties Information."
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
    }

    end {}

}