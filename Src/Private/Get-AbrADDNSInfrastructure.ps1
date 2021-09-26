function Get-AbrADDNSInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Name System Infrastructure information.
    .DESCRIPTION

    .NOTES
        Version:        0.3.0
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
        Section -Style Heading5 "Infrastructure Summary" {
            Paragraph "The following section provides a summary of the Domain Name System Infrastructure configuration."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                    if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                    foreach ($DC in $DCs) {
                        Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                        try {
                            $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerSetting -ComputerName $using:DC}
                            $inObj = [ordered] @{
                                'DC Name' = $($DNSSetting.ComputerName.ToString().ToUpper().Split(".")[0])
                                'Build Number' = $DNSSetting.BuildNumber
                                'IPv6' = ConvertTo-TextYN $DNSSetting.EnableIPv6
                                'DnsSec' = ConvertTo-TextYN $DNSSetting.EnableDnsSec
                                'ReadOnly DC' = ConvertTo-TextYN $DNSSetting.IsReadOnlyDC
                                'Listening IP' = $DNSSetting.ListeningIPAddress
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                            Write-PscriboMessage -IsDebug $_.Exception.Message
                        }
                    }
                }

                $TableParams = @{
                    Name = "Domain Name System Infrastructure Setting Information."
                    List = $false
                    ColumnWidths = 30, 10, 9, 10, 11, 30
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
            Section -Style Heading6 "Response Rate Limiting (RRL) Summary" {
                Paragraph "The following section provides a summary of the Domain Name System Response Rate Limiting configuration."
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
                                    'Status' = $DNSSetting.Mode
                                    'Responses Per Sec' = $DNSSetting.ResponsesPerSec
                                    'Errors Per Sec' = $DNSSetting.ErrorsPerSec
                                    'Window In Sec' = $DNSSetting.WindowInSec
                                    'Leak Rate' = $DNSSetting.LeakRate
                                    'Truncate Rate' = $DNSSetting.TruncateRate

                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Name System Response Rate Limiting configuration."
                        List = $false
                        ColumnWidths = 30, 10, 12, 12, 12, 12, 12
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            Section -Style Heading6 "Scavenging Summary" {
                Paragraph "The following section provides a summary of the Domain Name System Scavenging configuration."
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
                                    'NoRefresh Interval' = $DNSSetting.NoRefreshInterval
                                    'Refresh Interval' = $DNSSetting.RefreshInterval
                                    'Scavenging Interval' = $DNSSetting.ScavengingInterval
                                    'Last Scavenge Time' = Switch ($DNSSetting.LastScavengeTime) {
                                        "" {"-"; break}
                                        $Null {"-"; break}
                                        default {$DNSSetting.LastScavengeTime.ToString("MM/dd/yyyy")}

                                    }
                                    'Scavenging State' = Switch ($DNSSetting.ScavengingState) {
                                        "True" {"Enabled"}
                                        "False" {"Disabled"}
                                        default {$DNSSetting.ScavengingState}
                                    }
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Name System Scavenging configuration."
                        List = $false
                        ColumnWidths = 25, 15, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            Section -Style Heading6 "Forwarder Summary" {
                Paragraph "The following section provides a summary of the Domain Name System Forwarder configuration."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        if ($DCs) {Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller on $Domain"}
                        foreach ($DC in $DCs) {
                            Write-PscriboMessage "Collecting Domain Name System Infrastructure information on '$($DC)'."
                            try {
                                $DNSSetting = Invoke-Command -Session $Session {Get-DnsServerForwarder -ComputerName $using:DC}
                                $Recursion = Invoke-Command -Session $Session {Get-DnsServerRecursion -ComputerName $using:DC | Select-Object -ExpandProperty Enable}
                                $inObj = [ordered] @{
                                    'DC Name' = $($DC.ToString().ToUpper().Split(".")[0])
                                    'IP Address' = $DNSSetting.IPAddress
                                    'Timeout' = "$($DNSSetting.Timeout)/s"
                                    'Use Root Hint' = ConvertTo-TextYN $DNSSetting.UseRootHint
                                    'Use Recursion' = ConvertTo-TextYN $Recursion
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Name System Infrastructure Forwarder configuration."
                        List = $false
                        ColumnWidths = 35, 15, 15, 15, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            Section -Style Heading6 "Zone Scope Recursion Summary" {
                Paragraph "The following section provides a summary of the Domain Name System Zone Scope Recursion configuration."
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
                                        default {$DNSSetting.Name}
                                    }
                                    'Forwarder' = $DNSSetting.Forwarder
                                    'Use Recursion' = ConvertTo-TextYN $DNSSetting.EnableRecursion
                                }
                                $OutObj += [pscustomobject]$inobj
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Name System Zone Scope Recursion configuration."
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

    end {}

}