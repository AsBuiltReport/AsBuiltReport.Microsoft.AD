function Get-AbrADDHCPv6Scope {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory DHCP Servers Scopes.
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
            $Session,
            [string]
            $Server
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading6 "IPv6 Scope Summary on $($Server.ToUpper().split(".", 2)[0])" {
            Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope information."
            BlankLine
            $OutObj = @()
            if ($Server -and $Domain) {
                try {
                    $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6Scope -ComputerName $using:Server}
                    Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' DHCP SCopes in $($Server)."
                    foreach ($Scope in $DHCPScopes) {
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
                }
                catch {
                    Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv6 Scopes from $($Server.split(".", 2)[0])."
                    Write-PScriboMessage -IsDebug $_.Exception.Message
                }
            }

            $TableParams = @{
                Name = "IPv6 Scopes Information - $($Server.split(".", 2).ToUpper()[0])"
                List = $false
                ColumnWidths = 30, 30, 20, 20
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
            try {
                Section -Style Heading6 "IPv6 Scope Statistics Summary on $($Server.ToUpper().split(".", 2)[0])" {
                    Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope Statistics information."
                    BlankLine
                    $OutObj = @()
                    if ($Server -and $Domain) {
                        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6ScopeStatistics -ComputerName $using:Server}
                        Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' scopes in $($Server)."
                        foreach ($Scope in $DHCPScopes) {
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
                    }

                    if ($HealthCheck.DHCP.Statistics) {
                        $OutObj | Where-Object { $_.'Percentage In Use' -gt '95'} | Set-Style -Style Warning -Property 'Percentage In Use'
                    }

                    $TableParams = @{
                        Name = "IPv6 Scope Statistics Information - $($Server.split(".", 2).ToUpper()[0])"
                        List = $false
                        ColumnWidths = 20, 20, 20, 20, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv6 Scope Statistics from $($Server.split(".", 2).ToUpper()[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
            try {
                Section -Style Heading6 "IPv6 Network Interface binding Summary on $($Server.ToUpper().split(".", 2)[0])" {
                    Paragraph "The following section provides a summary of the IPv6 Network Interface binding."
                    BlankLine
                    $OutObj = @()
                    if ($Server -and $Domain) {
                        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv6Binding -ComputerName $using:Server}
                        Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' bindings in $($Server)."
                        foreach ($Scope in $DHCPScopes) {
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
                    }

                    $TableParams = @{
                        Name = "IPv6 Network Interface binding Information - $($Server.split(".", 2).ToUpper()[0])"
                        List = $false
                        ColumnWidths = 30, 40, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv6 interface binding from $($Server.split(".", 2).ToUpper()[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
        }
    }

    end {}

}