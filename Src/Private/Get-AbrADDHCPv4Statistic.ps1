function Get-AbrADDHCPv4Statistic {
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
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading5 'DHCP Servers IPv4 Statistics Summary' {
            Paragraph "The following section provides a summary of the DHCP servers IPv4 Statistics information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
                    if ($DHCPinDC) {Write-PScriboMessage "Discovered '$(($DHCPinDC | Measure-Object).Count)' DHCP Servers in forest $($Domain)."}
                    foreach ($DHCPServers in $DHCPinDC) {
                        Write-PScriboMessage "Collecting DHCP Server IPv4 Statistics from $($DHCPServers.DnsName.split(".", 2)[0])"
                        $Setting = Invoke-Command -Session $Session { Get-DhcpServerv4Statistics -ComputerName ($using:DHCPServers).DnsName }
                        $inObj = [ordered] @{
                            'DC Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                            'Total Scopes' = ConvertTo-EmptyToFiller $Setting.TotalScopes
                            'Total Addresses' = ConvertTo-EmptyToFiller $Setting.TotalAddresses
                            'Addresses In Use' = ConvertTo-EmptyToFiller $Setting.AddressesInUse
                            'Addresses Available' = ConvertTo-EmptyToFiller $Setting.AddressesAvailable
                            'Percentage In Use' = ConvertTo-EmptyToFiller $Setting.PercentageInUse
                            'Percentage Available' = ConvertTo-EmptyToFiller $Setting.PercentageAvailable
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }

                catch {
                    Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Statistics from $(($DHCPServers).DnsName)."
                    Write-PScriboMessage -IsDebug $_.Exception.Message
                    }
                }

            if ($HealthCheck.DHCP.Statistics) {
                $OutObj | Where-Object { $_.'Percentage Available' -lt '5'} | Set-Style -Style Warning -Property 'Percentage Available','Percentage In Use'
            }

            $TableParams = @{
                Name = "DHCP Server IPv4 Statistics Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 20, 13, 13, 13, 14 ,13, 14
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}