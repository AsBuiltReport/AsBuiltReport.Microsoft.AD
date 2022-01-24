function Get-AbrADDHCPv6Statistic {
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
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        try  {
            $DHCPinDC = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} }
            if ($DHCPinDC) {
                Section -Style Heading6 'IPv6 Service Statistics' {
                    $OutObj = @()
                    foreach ($DHCPServers in $DHCPinDC) {
                        try {
                            Write-PScriboMessage "Collecting DHCP Server IPv6 Statistics from $($DHCPServers.DnsName.split(".", 2)[0])"
                            $Setting = Invoke-Command -Session $Session { Get-DhcpServerv6Statistics -ComputerName ($using:DHCPServers).DnsName }
                            $inObj = [ordered] @{
                                'DC Name' = $DHCPServers.DnsName.Split(".", 2)[0]
                                'Total Scopes' = ConvertTo-EmptyToFiller $Setting.TotalScopes
                                'Total Addresses' = ConvertTo-EmptyToFiller $Setting.TotalAddresses
                                'Addresses In Use' = ConvertTo-EmptyToFiller $Setting.AddressesInUse
                                'Addresses Available' = ConvertTo-EmptyToFiller $Setting.AddressesAvailable
                                'Percentage In Use' = ConvertTo-EmptyToFiller ([math]::Round($Setting.PercentageInUse, 0))
                                'Percentage Available' = ConvertTo-EmptyToFiller ([math]::Round($Setting.PercentageAvailable, 0))
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Service Statistics Item)"
                        }
                    }

                    if ($HealthCheck.DHCP.Statistics) {
                        $OutObj | Where-Object { $_.'Percentage In Use' -gt 95} | Set-Style -Style Warning -Property 'Percentage Available','Percentage In Use'
                    }
                    $TableParams = @{
                        Name = "DHCP Server IPv6 Statistics - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 13, 13, 13, 14 ,13, 14
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Service Statistics Table)"
        }
    }

    end {}

}