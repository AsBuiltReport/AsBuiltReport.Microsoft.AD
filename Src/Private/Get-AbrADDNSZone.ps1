function Get-AbrADDNSZone {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Zone information.
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
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
        Section -Style Heading4 "Domain Name System Zone Configuration of $($DC.ToString().ToUpper().Split(".")[0])" {
            Paragraph "The following section provides a summary of the Domain Name System Zone Configuration information."
            BlankLine
            $OutObj = @()
            if ($DC) {
                Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC"
                $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False"}}
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
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC"
            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False" -and $_.ReplicationScope -eq "Domain"} | Select-Object -ExpandProperty ZoneName }
            $Zones = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneDelegation -Name $using:DNSSetting}
            if ($Zones) {
                Section -Style Heading5 "Domain Name System Zone Delegation of $($DC.ToString().ToUpper().Split(".")[0])" {
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
                                        'IP Address' = $Delegations.IPaddress.RecordData.IPv4Address.IPAddressToString
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
            Section -Style Heading5 "Domain Name System Reverse Lookup Zone Configuration of $($DC.ToString().ToUpper().Split(".")[0])" {
                Paragraph "The following section provides a summary of the Domain Name System Reverse Lookup Zone Configuration information."
                BlankLine
                $OutObj = @()
                if ($DC) {
                    Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC"
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
        }
        Section -Style Heading4 "Domain Name System Zone Aging properties of $($DC.ToString().ToUpper().Split(".")[0])" {
            Paragraph "The following section provides a summary of the Domain Name System Zone Aging properties information."
            BlankLine
            $OutObj = @()
            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
            Write-PscriboMessage "Discovered Actve Directory Domain Controller: $DC"
            $DNSSetting = Invoke-Command -Session $DCPssSession {Get-DnsServerZone | Where-Object {$_.IsReverseLookupZone -like "False"} | Select-Object -ExpandProperty ZoneName }
            $Zones = Invoke-Command -Session $DCPssSession {Get-DnsServerZoneAging -Name $using:DNSSetting}
            foreach ($Settings in $Zones) {
                Write-PscriboMessage "Collecting Actve Directory DNS Zone: '$($Settings.ZoneName)' on $DC"
                $inObj = [ordered] @{
                    'Zone Name' = $Settings.ZoneName
                    'Aging Enabled' = ConvertTo-TextYN $Settings.AgingEnabled
                    'Refresh Interval' = $Settings.RefreshInterval
                    'NoRefresh Interval' = $Settings.NoRefreshInterval
                    'Available For Scavenge' = if ($Settings.AvailForScavengeTime) {($Settings.AvailForScavengeTime).ToUniversalTime().toString("r")}
                }
                $OutObj += [pscustomobject]$inobj
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

    end {}

}