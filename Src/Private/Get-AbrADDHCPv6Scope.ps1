function Get-AbrADDHCPv6Scope {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory DHCP Servers Scopes.
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
            [string]
            $Server
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6Scope -ComputerName $using:Server}
        if ($DHCPScopes) {
            Section -Style Heading6 "$($Server.ToUpper().split(".", 2)[0]) IPv6 Scopes" {
                Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope Configuration."
                BlankLine
                $OutObj = @()
                foreach ($Scope in $DHCPScopes) {
                    try {
                        Write-PscriboMessage "Collecting DHCP Server IPv6 $($Scope.ScopeId) Scope from $($Server.split(".", 2)[0])"
                        $inObj = [ordered] @{
                            'Scope Id' = "$($Scope.Prefix)/$($Scope.PrefixLength)"
                            'Scope Name' = $Scope.Name
                            'Lease Duration' = Switch ($Scope.PreferredLifetime) {
                                "10675199.02:48:05.4775807" {"Unlimited"}
                                default {$Scope.PreferredLifetime}
                            }
                            'State' = $Scope.State
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope Item)"
                    }
                }

                $TableParams = @{
                    Name = "IPv6 Scopes - $($Server.split(".", 2).ToUpper()[0])"
                    List = $false
                    ColumnWidths = 30, 30, 20, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'Scope Id' | Table @TableParams
                try {
                    $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6ScopeStatistics -ComputerName $using:Server}
                    if ($DHCPScopes) {
                        Section -Style Heading6 "IPv6 Scope Statistics" {
                            $OutObj = @()
                            foreach ($Scope in $DHCPScopes) {
                                try {
                                    Write-PscriboMessage "Collecting DHCP Server IPv6 $($Scope.ScopeId) scope statistics from $($Server.split(".", 2)[0])"
                                    $inObj = [ordered] @{
                                        'Scope Id' = $Scope.Prefix
                                        'Free IP' = $Scope.AddressesFree
                                        'In Use IP' = $Scope.AddressesInUse
                                        'Percentage In Use' = [math]::Round($Scope.PercentageInUse, 0)
                                        'Reserved IP' = $Scope.ReservedAddress
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope Statistics Item)"
                                }
                            }
                            if ($HealthCheck.DHCP.Statistics) {
                                $OutObj | Where-Object { $_.'Percentage In Use' -gt '95'} | Set-Style -Style Warning -Property 'Percentage In Use'
                            }

                            $TableParams = @{
                                Name = "IPv6 Scope Statistics -  $($Server.split(".", 2).ToUpper()[0])"
                                List = $false
                                ColumnWidths = 20, 20, 20, 20, 20
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Sort-Object -Property 'Scope Id' | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope Statistics Table)"
                }
                try {
                    $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6Binding -ComputerName $using:Server}
                    if ($DHCPScopes) {
                        Section -Style Heading6 "IPv6 Network Interface Binding" {
                            $OutObj = @()
                            foreach ($Scope in $DHCPScopes) {
                                try {
                                Write-PscriboMessage "Collecting DHCP Server IPv6 $($Scope.InterfaceAlias) binding from $($Server.split(".", 2)[0])"
                                    $inObj = [ordered] @{
                                        'Interface Alias' = $Scope.InterfaceAlias
                                        'IP Address' = $Scope.IPAddress
                                        'State' = Switch ($Scope.BindingState) {
                                            ""  {"-"; break}
                                            $Null  {"-"; break}
                                            "True"  {"Enabled"}
                                            "False"  {"Disabled"}
                                            default {$Scope.BindingState}
                                        }
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Network Interface binding item)"
                                }
                            }

                            $TableParams = @{
                                Name = "IPv6 Network Interface binding - $($Server.split(".", 2).ToUpper()[0])"
                                List = $false
                                ColumnWidths = 30, 40, 30
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Network Interface binding table)"
                }
            }
        }
    }

    end {}

}