function Get-AbrADDHCPInfrastructure {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers from Domain Controller
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
            $Session,
            [PSCredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading4 'DHCP Servers In Active Directory Summary' {
            Paragraph "The following section provides a summary of the DHCP servers information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
                    if ($DHCPinDC) {Write-PScriboMessage "Discovered '$(($DHCPinDC | Measure-Object).Count)' DHCP Servers in forest $($Domain)."}
                    foreach ($DHCPServers in $DHCPinDC) {
                        Write-PScriboMessage "Collecting DHCP Server information from $($DHCPServers.DnsName.split(".", 2)[0])"
                        $Setting = Invoke-Command -Session $Session { Get-DhcpServerSetting -ComputerName ($using:DHCPServers).DnsName }
                        $inObj = [ordered] @{
                            'Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                            'IP Address' =  $DHCPServers.IPAddress
                            'Domain Name' = $DHCPServers.DnsName.Split(".", 2)[1]
                            'Domain Joined' =  Switch ($Setting.IsDomainJoined) {
                                ""  {"-"; break}
                                $Null   {"-"; break}
                                default {ConvertTo-TextYN $Setting.IsDomainJoined}
                            }
                            'Authorized' =  Switch ($Setting.IsAuthorized) {
                                ""  {"-"; break}
                                $Null   {"-"; break}
                                default {ConvertTo-TextYN $Setting.IsAuthorized}
                            }
                            'Conflict Detection Attempts' = Switch ($Setting.ConflictDetectionAttempts) {
                                ""  {"-"; break}
                                $Null   {"-"; break}
                                default {ConvertTo-TextYN $Setting.ConflictDetectionAttempts}
                            }
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PScriboMessage -IsWarning "Error: Retreiving $Domain Dhcp Servers."
                    Write-PScriboMessage -IsDebug $_.Exception.Message
                    }
                }

            $TableParams = @{
                Name = "DHCP Servers In Active Directory Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 20, 15, 20, 15, 15 ,15
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        Section -Style Heading5 'DHCP Servers Database Summary' {
            Paragraph "The following section provides a summary of the DHCP Servers Database information on $($Domain.ToString().ToUpper())."
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
                            'Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                            'File Path' =  $Setting.FileName
                            'Backup Path' = $Setting.BackupPath
                            'Backup Interval' = $Setting.BackupInterval
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
                    Write-PScriboMessage -IsWarning "Error: Retreiving Dhcp Servers Database on $($DHCPServers.DnsName)."
                    Write-PScriboMessage -IsDebug $_.Exception.Message
                    }
                }

            $TableParams = @{
                Name = "DHCP Servers Database Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 20, 28, 28, 12, 12
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}