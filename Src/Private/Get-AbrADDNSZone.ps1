function Get-AbrADDNSZone {
    <#
    .SYNOPSIS
        Used by As Built Report to retrieve Microsoft AD Domain Name System Zone information.
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
        $Domain,
        [string]
        $DC
    )

    begin {
        Write-PScriboMessage -Message ([string]::Format($reportTranslate.GetAbrADDNSZone.Collecting, $Domain.DNSRoot))
        Show-AbrDebugExecutionTime -Start -TitleMessage 'DNS Zones'
    }

    process {
        try {
            if ($TempCIMSession) {
                $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like 'False' -and $_.ZoneType -notlike 'Forwarder' }
            }
            if ($DNSSetting) {
                Section -Style Heading3 "$($DC.ToString().ToUpper().Split('.')[0]) $($reportTranslate.GetAbrADDNSZone.DNSZonesSuffix)" {
                    $OutObj = [System.Collections.ArrayList]::new()
                    foreach ($Zones in $DNSSetting) {
                        try {
                            $inObj = [ordered] @{
                                $reportTranslate.GetAbrADDNSZone.ZoneName = $Zones.ZoneName
                                $reportTranslate.GetAbrADDNSZone.ZoneType = $Zones.ZoneType
                                $reportTranslate.GetAbrADDNSZone.ReplicationScope = $Zones.ReplicationScope
                                $reportTranslate.GetAbrADDNSZone.DynamicUpdate = $Zones.DynamicUpdate
                                $reportTranslate.GetAbrADDNSZone.DSIntegrated = ($Zones.IsDsIntegrated)
                                $reportTranslate.GetAbrADDNSZone.ReadOnly = ($Zones.IsReadOnly)
                                $reportTranslate.GetAbrADDNSZone.Signed = ($Zones.IsSigned)
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Name System Zone Item)"
                        }
                    }

                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDNSZone.ZonesTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSZone.ZoneName | Table @TableParams
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like 'False' -and ($_.ZoneName -ne '_msdcs.pharmax.local' -and $_.ZoneName -ne 'TrustAnchors') -and ($_.ZoneType -like 'Primary' -or $_.ZoneType -like 'Secondary') } | Select-Object -ExpandProperty ZoneName
                            if ($DNSSetting) {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Zone in $DNSSetting) {
                                    try {
                                        $Delegations = Get-DnsServerZoneDelegation -CimSession $TempCIMSession -Name $Zone -ComputerName $DC
                                        if ($Delegations) {
                                            foreach ($Delegation in $Delegations) {
                                                try {
                                                    $inObj = [ordered] @{
                                                        $reportTranslate.GetAbrADDNSZone.ZoneName = $Delegation.ZoneName
                                                        $reportTranslate.GetAbrADDNSZone.ChildZone = $Delegation.ChildZoneName
                                                        $reportTranslate.GetAbrADDNSZone.NameServer = $Delegation.NameServer.RecordData.NameServer
                                                        $reportTranslate.GetAbrADDNSZone.IPAddress = $Delegation.IPaddress.RecordData.IPv4Address.ToString()
                                                    }
                                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                                } catch {
                                                    Write-PScriboMessage -IsWarning $($_.Exception.Message)
                                                }
                                            }
                                        } else {
                                            Write-PScriboMessage -Message "DNS Zones $($Zone) Section: No Zone Delegation information found, Disabling this section."
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Delegation Item)"
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message "DNS Zones Section: No Zone Delegation information found in $DC, Disabling this section."
                            }

                            if ($OutObj) {
                                Section -Style Heading4 $reportTranslate.GetAbrADDNSZone.ZoneDelegation {

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDNSZone.ZoneDelegation) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 25, 32, 18
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSZone.ZoneName | Table @TableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Delegation Table)"
                        }
                    }

                    if ($InfoLevel.DNS -ge 2) {
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                        try {
                            $DNSSetting = $Null
                            if ($DCPssSession) {
                                $DNSSetting = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\*' | Get-ItemProperty | Where-Object { $_ -match 'SecondaryServers' } }
                            } else {
                                if (-not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "DNS Zones Transfers Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            if ($DNSSetting) {
                                Section -Style Heading4 $reportTranslate.GetAbrADDNSZone.ZoneTransfers {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Zone in $DNSSetting) {
                                        try {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDNSZone.ZoneName = $Zone.PSChildName
                                                $reportTranslate.GetAbrADDNSZone.SecondaryServers = ($Zone.SecondaryServers -join ', ')
                                                $reportTranslate.GetAbrADDNSZone.NotifyServers = $Zone.NotifyServers
                                                $reportTranslate.GetAbrADDNSZone.SecureSecondaries = switch ($Zone.SecureSecondaries) {
                                                    '0' { $reportTranslate.GetAbrADDNSZone.SecureSecondariesAll }
                                                    '1' { $reportTranslate.GetAbrADDNSZone.SecureSecondariesAuth }
                                                    '2' { $reportTranslate.GetAbrADDNSZone.SecureSecondariesSpec }
                                                    '3' { $reportTranslate.GetAbrADDNSZone.SecureSecondariesNone }
                                                    default { $Zone.SecureSecondaries }
                                                }
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                            if ($HealthCheck.DNS.Zones) {
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSZone.SecureSecondaries) -eq $reportTranslate.GetAbrADDNSZone.SecureSecondariesAll } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSZone.SecureSecondaries
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Transfers Item)"
                                        }
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDNSZone.ZoneTransfers) - $($Zone.PSChildName)"
                                        List = $false
                                        ColumnWidths = 25, 20, 20, 35
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                    if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSZone.SecureSecondaries) -eq $reportTranslate.GetAbrADDNSZone.SecureSecondariesAll })) {
                                        Paragraph $reportTranslate.GetAbrADDNSZone.HealthCheck -Italic -Bold
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDNSZone.BestPractice -Bold
                                            Text $reportTranslate.GetAbrADDNSZone.ZoneTransferBP
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message "DNS Zones Section: No Zone Transfer information found in $DC, Disabling this section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Transfers Table)"
                        }
                    }
                    try {
                        $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like 'True' }
                        if ($DNSSetting) {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSZone.ReverseLookupZone {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDNSZone.ZoneName = $Zones.ZoneName
                                            $reportTranslate.GetAbrADDNSZone.ZoneType = $Zones.ZoneType
                                            $reportTranslate.GetAbrADDNSZone.ReplicationScope = $Zones.ReplicationScope
                                            $reportTranslate.GetAbrADDNSZone.DynamicUpdate = $Zones.DynamicUpdate
                                            $reportTranslate.GetAbrADDNSZone.DSIntegrated = ($Zones.IsDsIntegrated)
                                            $reportTranslate.GetAbrADDNSZone.ReadOnly = ($Zones.IsReadOnly)
                                            $reportTranslate.GetAbrADDNSZone.Signed = ($Zones.IsSigned)
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Reverse Lookup Zone Configuration Item)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDNSZone.ZonesTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 15, 12, 12, 12, 12, 12
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSZone.ZoneName | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage -Message "DNS Zones Section: No Reverse lookup zone information found in $DC, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Reverse Lookup Zone Configuration Table)"
                    }
                    try {
                        $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like 'False' -and $_.ZoneType -like 'Forwarder' }
                        if ($DNSSetting) {
                            Section -Style Heading4 $reportTranslate.GetAbrADDNSZone.ConditionalForwarder {
                                $OutObj = [System.Collections.ArrayList]::new()
                                foreach ($Zones in $DNSSetting) {
                                    try {
                                        $inObj = [ordered] @{
                                            $reportTranslate.GetAbrADDNSZone.ZoneName = $Zones.ZoneName
                                            $reportTranslate.GetAbrADDNSZone.ZoneType = $Zones.ZoneType
                                            $reportTranslate.GetAbrADDNSZone.ReplicationScope = $Zones.ReplicationScope
                                            $reportTranslate.GetAbrADDNSZone.MasterServers = $Zones.MasterServers
                                            $reportTranslate.GetAbrADDNSZone.DSIntegrated = $Zones.IsDsIntegrated
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Conditional Forwarder Item)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "$($reportTranslate.GetAbrADDNSZone.ConditionalForwardersTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                    List = $false
                                    ColumnWidths = 25, 20, 20, 20, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSZone.ZoneName | Table @TableParams
                            }
                        } else {
                            Write-PScriboMessage -Message "DNS Zones Section: No Conditional forwarder zone information found in $DC, Disabling this section."
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Conditional Forwarder Table)"
                    }
                    if ($InfoLevel.DNS -ge 2) {
                        try {
                            $DNSSetting = Get-DnsServerZone -CimSession $TempCIMSession -ComputerName $DC | Where-Object { $_.IsReverseLookupZone -like 'False' -and $_.ZoneType -eq 'Primary' } | Select-Object -ExpandProperty ZoneName
                            $Zones = Get-DnsServerZoneAging -CimSession $TempCIMSession -Name $DNSSetting -ComputerName $DC
                            if ($Zones) {
                                Section -Style Heading4 $reportTranslate.GetAbrADDNSZone.ZoneScopeAging {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Settings in $Zones) {
                                        try {
                                            $inObj = [ordered] @{
                                                $reportTranslate.GetAbrADDNSZone.ZoneName = $Settings.ZoneName
                                                $reportTranslate.GetAbrADDNSZone.AgingEnabled = ($Settings.AgingEnabled)
                                                $reportTranslate.GetAbrADDNSZone.RefreshInterval = $Settings.RefreshInterval
                                                $reportTranslate.GetAbrADDNSZone.NoRefreshInterval = $Settings.NoRefreshInterval
                                                $reportTranslate.GetAbrADDNSZone.AvailableForScavenge = switch ($Settings.AvailForScavengeTime) {
                                                    '' { '--'; break }
                                                    $Null { '--'; break }
                                                    default { (($Settings.AvailForScavengeTime).ToUniversalTime().toString('r')); break }
                                                }
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        } catch {
                                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Scope Aging Item)"
                                        }
                                    }

                                    if ($HealthCheck.DNS.Aging) {
                                        $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSZone.AgingEnabled) -ne $reportTranslate.GetAbrADDNSZone.Yes } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDNSZone.AgingEnabled
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDNSZone.ZoneAgingPropertiesTable) - $($Domain.DNSRoot.ToString().ToUpper())"
                                        List = $false
                                        ColumnWidths = 25, 10, 15, 15, 35
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDNSZone.ZoneName | Table @TableParams
                                    if ($HealthCheck.DNS.Zones -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDNSZone.AgingEnabled) -ne $reportTranslate.GetAbrADDNSZone.Yes })) {
                                        Paragraph $reportTranslate.GetAbrADDNSZone.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDNSZone.BestPractice -Bold
                                            Text $reportTranslate.GetAbrADDNSZone.ZoneAgingBP
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message "DNS Zones Section: No Zone Aging property information found in $DC, Disabling this section."
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Zone Scope Aging Table)"
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Global DNS Zone Information)"
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'DNS Zones'
    }

}