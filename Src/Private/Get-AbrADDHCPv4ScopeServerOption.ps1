function Get-AbrADDHCPv4ScopeServerOption {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers Scopes Server Options from DHCP Servers
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
        Write-PscriboMessage "Discovering DHCP Servers Scope Server Options information on $($Server.ToUpper().split(".", 2)[0])."
    }

    process {
        $OutObj = @()
        if ($Server) {
            try {
                $DHCPScopeOptions = Invoke-Command -Session $Session { Get-DhcpServerv4OptionValue -ComputerName $using:Server}
                Write-PScriboMessage "Discovered '$(($DHCPScopeOptions | Measure-Object).Count)' DHCP scopes server opions on $($Server)."
                foreach ($Option in $DHCPScopeOptions) {
                    Write-PscriboMessage "Collecting DHCP Server IPv4 Scope Server Option value $($Option.OptionId) from $($Server.split(".", 2)[0])"
                    $inObj = [ordered] @{
                        'Name' = $Option.Name
                        'Option Id' = $Option.OptionId
                        'Value' = $Option.Value
                        'Policy Name' = ConvertTo-EmptyToFiller $Option.PolicyName
                    }
                    $OutObj += [pscustomobject]$inobj
                }
            }
            catch {
                Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scope Server Options from $($Server.split(".", 2)[0])."
                Write-PScriboMessage -IsDebug $_.Exception.Message
            }
        }

        $TableParams = @{
            Name = "IPv4 Scopes Server Options Information - $($Server.split(".", 2).ToUpper()[0])"
            List = $false
            ColumnWidths = 40, 15, 20, 25
        }
        if ($Report.ShowTableCaptions) {
            $TableParams['Caption'] = "- $($TableParams.Name)"
        }
        $OutObj | Table @TableParams
    }

    end {}

}