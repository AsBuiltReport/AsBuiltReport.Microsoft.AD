function Get-AbrADDHCPv6ScopeServerSetting {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers IPv6 Scopes Server Options from DHCP Servers
    .DESCRIPTION

    .NOTES
        Version:        0.6.3
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
            [string]
            $Server
    )

    begin {
        Write-PscriboMessage "Discovering DHCP Servers IPv6 Scope Server Options information on $($Server.ToUpper().split(".", 2)[0])."
    }

    process {
        $OutObj = @()
        $DHCPScopeOptions = Get-DhcpServerv6OptionValue -CimSession $TempCIMSession -ComputerName $Server
        if ($DHCPScopeOptions) {
            Section -Style Heading5 "$($DHCPServer.ToUpper().split(".", 2)[0]) IPv6 Scope Server Options" {
                Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope Server Options information."
                BlankLine
                Write-PScriboMessage "Discovered '$(($DHCPScopeOptions | Measure-Object).Count)' DHCP scopes server opions on $($Server)."
                foreach ($Option in $DHCPScopeOptions) {
                    try {
                        Write-PscriboMessage "Collecting DHCP Server IPv6 Scope Server Option value $($Option.OptionId) from $($Server.split(".", 2)[0])"
                        $inObj = [ordered] @{
                            'Name' = $Option.Name
                            'Option Id' = $Option.OptionId
                            'Type' = ConvertTo-EmptyToFiller $Option.Type
                            'Value' = $Option.Value
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope Server Option Item)"
                    }
                }

                $TableParams = @{
                    Name = "IPv6 Scopes Server Options - $($Server.split(".", 2).ToUpper()[0])"
                    List = $false
                    ColumnWidths = 40, 15, 20, 25
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'Option Id' | Table @TableParams
                try {
                    $DHCPScopeOptions = Get-DhcpServerv6DnsSetting -CimSession $TempCIMSession -ComputerName $Server
                    if ($DHCPScopeOptions) {
                        Section -Style Heading6 "Scope DNS Settings" {
                            $OutObj = @()
                            foreach ($Option in $DHCPScopeOptions) {
                                try {
                                    Write-PscriboMessage "Collecting DHCP Server IPv6 Scope DNS Setting value from $($Server)."
                                    $inObj = [ordered] @{
                                        'Dynamic Updates' = $Option.DynamicUpdates
                                        'Name Protection' = ConvertTo-EmptyToFiller $Option.NameProtection
                                        'Delete Dns RR On Lease Expiry' = ConvertTo-EmptyToFiller $Option.DeleteDnsRROnLeaseExpiry
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope DNS Setting Item)"
                                }
                            }

                            $TableParams = @{
                                Name = "IPv6 Scopes DNS Setting - $($Server.split(".", 2)[0])"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope DNS Setting Table)"
                }
            }
        }
    }

    end {}

}