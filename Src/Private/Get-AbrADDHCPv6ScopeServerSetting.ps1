function Get-AbrADDHCPv6ScopeServerSetting {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers IPv6 Scopes Server Options from DHCP Servers
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
        Write-PscriboMessage "Discovering DHCP Servers IPv6 Scope Server Options information on $($Server.ToUpper().split(".", 2)[0])."
    }

    process {
        $OutObj = @()
        if ($Server) {
            try {
                $DHCPScopeOptions = Invoke-Command -Session $Session { Get-DhcpServerv6OptionValue -ComputerName $using:Server}
                Write-PScriboMessage "Discovered '$(($DHCPScopeOptions | Measure-Object).Count)' DHCP scopes server opions on $($Server)."
                foreach ($Option in $DHCPScopeOptions) {
                    Write-PscriboMessage "Collecting DHCP Server IPv6 Scope Server Option value $($Option.OptionId) from $($Server.split(".", 2)[0])"
                    $inObj = [ordered] @{
                        'Name' = $Option.Name
                        'Option Id' = $Option.OptionId
                        'Type' = ConvertTo-EmptyToFiller $Option.Type
                        'Value' = $Option.Value
                    }
                    $OutObj += [pscustomobject]$inobj
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope Server Option)"
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
        $OutObj | Table @TableParams
        try {
            Section -Style Heading6 "Scope DNS Settings" {
                Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope DNS Setting information."
                BlankLine
                $OutObj = @()
                if ($Server) {
                    $DHCPScopeOptions = Invoke-Command -Session $Session { Get-DhcpServerv6DnsSetting -ComputerName $using:Server}
                    Write-PScriboMessage "Discovered '$(($DHCPScopeOptions | Measure-Object).Count)' DHCP scopes dns setting from $($Server)."
                    foreach ($Option in $DHCPScopeOptions) {
                        Write-PscriboMessage "Collecting DHCP Server IPv6 Scope DNS Setting value from $($Server)."
                        $inObj = [ordered] @{
                            'Dynamic Updates' = $Option.DynamicUpdates
                            'Name Protection' = ConvertTo-EmptyToFiller $Option.NameProtection
                            'Delete Dns RR On Lease Expiry' = ConvertTo-EmptyToFiller $Option.DeleteDnsRROnLeaseExpiry
                        }
                        $OutObj += [pscustomobject]$inobj
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
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Scope DNS Setting)"
        }
    }

    end {}

}