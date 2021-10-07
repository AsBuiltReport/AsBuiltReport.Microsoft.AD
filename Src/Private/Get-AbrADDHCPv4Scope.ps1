function Get-AbrADDHCPv4Scope {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft Active Directory DHCP Servers Scopes.
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
            $Session,
            [string]
            $Server
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory DHCP Servers information on $($Domain.ToString().ToUpper())."
    }

    process {
        Section -Style Heading6 "IPv4 Scope Summary on $($Server.ToUpper().split(".", 2)[0])" {
            Paragraph "The following section provides a summary of the DHCP servers IPv4 Scope information."
            BlankLine
            $OutObj = @()
            if ($Server -and $Domain) {
                try {
                    $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv4Scope -ComputerName $using:Server}
                    Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' DHCP SCopes in $($Server)."
                    foreach ($Scope in $DHCPScopes) {
                        Write-PscriboMessage "Collecting DHCP Server IPv4 $($Scope.ScopeId) Scope from $($Server.split(".", 2)[0])"
                        $SubnetMask = Convert-IpAddressToMaskLength $Scope.SubnetMask
                        $inObj = [ordered] @{
                            'Scope Id' = "$($Scope.ScopeId)/$($SubnetMask)"
                            'Scope Name' = $Scope.Name
                            'Scope Range' = "$($Scope.StartRange) - $($Scope.EndRange)"
                            'Lease Duration' = Switch ($Scope.LeaseDuration) {
                                "10675199.02:48:05.4775807" {"Unlimited"}
                                default {$Scope.LeaseDuration}
                            }
                            'State' = $Scope.State
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }
                catch {
                    Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scopes from $($Server.split(".", 2)[0])."
                    Write-PScriboMessage -IsDebug $_.Exception.Message
                }
            }

            $TableParams = @{
                Name = "IPv4 Scopes Information - $($Server.split(".", 2).ToUpper()[0])"
                List = $false
                ColumnWidths = 20, 20, 35, 15, 10
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
            try {
                Section -Style Heading6 "IPv4 Scope Statistics Summary on $($Server.ToUpper().split(".", 2)[0])" {
                    Paragraph "The following section provides a summary of the DHCP servers IPv4 Scope Statistics information."
                    BlankLine
                    $OutObj = @()
                    if ($Server -and $Domain) {
                        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv4ScopeStatistics -ComputerName $using:Server}
                        Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' scopes in $($Server)."
                        foreach ($Scope in $DHCPScopes) {
                            Write-PscriboMessage "Collecting DHCP Server IPv4 $($Scope.ScopeId) scope statistics from $($Server.split(".", 2)[0])"
                            $inObj = [ordered] @{
                                'Scope Id' = $Scope.ScopeId
                                'Free IP' = $Scope.Free
                                'In Use IP' = $Scope.InUse
                                'Percentage In Use' = [math]::Round($Scope.PercentageInUse, 0)
                                'Reserved IP' = $Scope.Reserved
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }

                    if ($HealthCheck.DHCP.Statistics) {
                        $OutObj | Where-Object { $_.'Percentage In Use' -gt '95'} | Set-Style -Style Warning -Property 'Percentage In Use'
                    }

                    $TableParams = @{
                        Name = "IPv4 Scope Statistics Information - $($Server.split(".", 2).ToUpper()[0])"
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
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scope Statistics from $($Server.split(".", 2).ToUpper()[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
            try {
                Section -Style Heading6 "IPv4 Scope Failover Summary on $($Server.ToUpper().split(".", 2)[0])" {
                    Paragraph "The following section provides a summary of the DHCP servers IPv4 Scope Failover information."
                    BlankLine
                    $OutObj = @()
                    if ($Server -and $Domain) {
                        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv4Failover -ComputerName $using:Server}
                        Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' failover setting in $($Server)."
                        foreach ($Scope in $DHCPScopes) {
                            Write-PscriboMessage "Collecting DHCP Server IPv4 $($Scope.ScopeId) scope failover setting from $($Server.split(".", 2)[0])"
                            $inObj = [ordered] @{
                                'DHCP Server' = $Server
                                'Partner DHCP Server' = $Scope.PartnerServer
                                'Mode' = $Scope.Mode
                                'LoadBalance Percent' = ConvertTo-EmptyToFiller ([math]::Round($Scope.LoadBalancePercent, 0))
                                'Server Role' = ConvertTo-EmptyToFiller $Scope.ServerRole
                                'Reserve Percent' = ConvertTo-EmptyToFiller ([math]::Round($Scope.ReservePercent, 0))
                                'Max Client Lead Time' = ConvertTo-EmptyToFiller $Scope.MaxClientLeadTime
                                'State Switch Interval' = ConvertTo-EmptyToFiller $Scope.StateSwitchInterval
                                'Scope Ids' = $Scope.ScopeId
                                'State' = $Scope.State
                                'Auto State Transition' = ConvertTo-TextYN $Scope.AutoStateTransition
                                'Authetication Enable' = ConvertTo-TextYN $Scope.EnableAuth
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    }

                    if ($HealthCheck.DHCP.BP) {
                        $OutObj | Where-Object { $_.'Authetication Enable' -eq 'No'} | Set-Style -Style Warning -Property 'Authetication Enable'
                    }

                    $TableParams = @{
                        Name = "IPv4 Scope Failover Cofiguration Information - $($Server.split(".", 2).ToUpper()[0])"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scope Failover Setting from $($Server.split(".", 2).ToUpper()[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
            try {
                Section -Style Heading6 "IPv4 Network Interface binding Summary on $($Server.ToUpper().split(".", 2)[0])" {
                    Paragraph "The following section provides a summary of the IPv4 Network Interface binding."
                    BlankLine
                    $OutObj = @()
                    if ($Server -and $Domain) {
                        $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv4Binding -ComputerName $using:Server}
                        Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' bindings in $($Server)."
                        foreach ($Scope in $DHCPScopes) {
                            Write-PscriboMessage "Collecting DHCP Server IPv4 $($Scope.InterfaceAlias) binding from $($Server.split(".", 2)[0])"
                            $SubnetMask = Convert-IpAddressToMaskLength $Scope.SubnetMask
                            $inObj = [ordered] @{
                                'Interface Alias' = $Scope.InterfaceAlias
                                'IP Address' = $Scope.IPAddress
                                'Subnet Mask' = $Scope.SubnetMask
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
                        Name = "IPv4 Network Interface binding Information - $($Server.split(".", 2).ToUpper()[0])"
                        List = $false
                        ColumnWidths = 25, 25, 25, 25
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
            catch {
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 interface binding from $($Server.split(".", 2).ToUpper()[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
        }
    }

    end {}

}