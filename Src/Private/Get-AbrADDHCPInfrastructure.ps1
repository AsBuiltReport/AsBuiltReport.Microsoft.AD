function Get-AbrADDHCPInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers from Domain Controller
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
            $Session,
            [PSCredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading5 'DHCP Servers In Active Directory' {
            Paragraph "The following section provides a summary of the DHCP servers information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
                    if ($DHCPinDC) {Write-PScriboMessage "Discovered '$(($DHCPinDC | Measure-Object).Count)' DHCP Servers in forest $($Domain)."}
                    foreach ($DHCPServers in $DHCPinDC) {
                        Write-PScriboMessage "Collecting DHCP Server Setting information from $($DHCPServers.DnsName.split(".", 2)[0])"
                        $Setting = Invoke-Command -Session $Session { Get-DhcpServerSetting -ComputerName ($using:DHCPServers).DnsName }
                        $inObj = [ordered] @{
                            'DC Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                            'IP Address' =  $DHCPServers.IPAddress
                            'Domain Name' = $DHCPServers.DnsName.Split(".", 2)[1]
                            'Domain Joined' = ConvertTo-TextYN $Setting.IsDomainJoined
                            'Authorized' = ConvertTo-TextYN $Setting.IsAuthorized
                            'Conflict Detection Attempts' = $Setting.ConflictDetectionAttempts
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (DHCP Servers In Active Directory)"

                    }
                }

            if ($HealthCheck.DHCP.BP) {
                $OutObj | Where-Object { $_.'Conflict Detection Attempts' -eq 0} | Set-Style -Style Warning -Property 'Conflict Detection Attempts'
                $OutObj | Where-Object { $_.'Authorized' -eq 'No'} | Set-Style -Style Warning -Property 'Authorized'
            }

            $TableParams = @{
                Name = "DHCP Servers In Active Directory - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 20, 15, 20, 15, 15 ,15
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams

            Section -Style Heading6 'Service Database' {
                Paragraph "The following section provides a summary of the DHCP servers service database information on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    try {
                        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain)."
                        $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
                        if ($DHCPinDC) {Write-PScriboMessage "Discovered '$(($DHCPinDC | Measure-Object).Count)' DHCP Servers in forest $($Domain)."}
                        foreach ($DHCPServers in $DHCPinDC) {
                            Write-PScriboMessage "Collecting DHCP Server database information from $($DHCPServers.DnsName.split(".", 2)[0])"
                            $Setting = Invoke-Command -Session $Session { Get-DhcpServerDatabase -ComputerName ($using:DHCPServers).DnsName }
                            $inObj = [ordered] @{
                                'DC Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                                'File Path' =  ConvertTo-EmptyToFiller $Setting.FileName
                                'Backup Path' = ConvertTo-EmptyToFiller $Setting.BackupPath
                                'Backup Interval' = switch ($Setting.BackupInterval) {
                                    "" {"-"; break}
                                    $NULL {"-"; break}
                                    default {"$($Setting.BackupInterval) min"}
                                }
                                'Logging Enabled' =  Switch ($Setting.LoggingEnabled) {
                                    ""  {"-"; break}
                                    $Null   {"-"; break}
                                    default {ConvertTo-TextYN $Setting.LoggingEnabled}
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                    catch {

                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Service Database)"

                    }
                }

                $TableParams = @{
                    Name = "DHCP Servers Database - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 20, 28, 28, 12, 12
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }

            Section -Style Heading6 'Dynamic DNS credentials' {
                Paragraph "The following section provides a summary of the DHCP Servers Dynamic DNS registration credentials information on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    try {
                        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain)."
                        $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
                        if ($DHCPinDC) {Write-PScriboMessage "Discovered '$(($DHCPinDC | Measure-Object).Count)' DHCP Servers in forest $($Domain)."}
                        foreach ($DHCPServers in $DHCPinDC) {
                            Write-PScriboMessage "Collecting DHCP Server Dynamic DNS Credentials information from $($DHCPServers.DnsName.split(".", 2)[0])"
                            $Setting = Invoke-Command -Session $Session { Get-DhcpServerDnsCredential -ComputerName ($using:DHCPServers).DnsName }
                            $inObj = [ordered] @{
                                'DC Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                                'User Name' =  ConvertTo-EmptyToFiller $Setting.UserName
                                'Domain Name' = ConvertTo-EmptyToFiller $Setting.DomainName
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }
                    catch {

                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Dynamic DNS credentials)"

                    }
                }
                if ($HealthCheck.DHCP.BP) {
                    $OutObj | Where-Object { $_.'User Name' -eq "-"} | Set-Style -Style Warning -Property 'User Name','Domain Name'
                }

                $TableParams = @{
                    Name = "DHCP Servers Dynamic DNS Credentials - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 30, 30, 40
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
    }

    end {}

}