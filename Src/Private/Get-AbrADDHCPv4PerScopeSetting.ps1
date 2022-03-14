function Get-AbrADDHCPv4PerScopeSetting {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers Scopes Server Options from DHCP Servers
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
            $Server,
            $Scope
    )

    begin {
        Write-PscriboMessage "Discovering DHCP Servers Scope Server Options information on $($Server.ToUpper().split(".", 2)[0])."
    }

    process {
        $DHCPScopeOptions = Get-DhcpServerv4OptionValue -CimSession $TempCIMSession -ComputerName $Server -ScopeId $Scope
        if ($DHCPScopeOptions) {
            Section -Style Heading6 "$Scope" {
                $OutObj = @()
                foreach ($Option in $DHCPScopeOptions) {
                    try {
                        Write-PscriboMessage "Collecting DHCP Server IPv4 Scope Server Option value $($Option.OptionId) from $($Server.split(".", 2)[0])"
                        $inObj = [ordered] @{
                            'Name' = $Option.Name
                            'Option Id' = $Option.OptionId
                            'Value' = $Option.Value
                            'Policy Name' = ConvertTo-EmptyToFiller $Option.PolicyName
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Scope Options Item)"
                    }
                }

                $TableParams = @{
                    Name = "IPv4 Scopes Options - $Scope"
                    List = $false
                    ColumnWidths = 40, 15, 20, 25
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'Option Id' | Table @TableParams
            }
        }
    }

    end {}

}