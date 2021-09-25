function Get-AbrADDHCPv4Scope {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD DHCP Servers Scopes from Domain Controller
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
        try {
            Section -Style Heading5 "DHCP Servers IPv4 Scope Summary on $($Server.ToUpper().split(".", 2)[0])" {
                Paragraph "The following section provides a summary of the DHCP servers IPv4 Scope information."
                BlankLine
                $OutObj = @()
                if ($Server -and $Domain) {
                    $DHCPScopes = Invoke-Command -Session $Session { Get-DhcpServerv4Scope -ComputerName $using:Server}
                    Write-PScriboMessage "Discovered '$(($DHCPScopes | Measure-Object).Count)' DHCP SCopes in $($Server)."
                    foreach ($Scope in $DHCPScopes) {
                        Write-PscriboMessage "Collecting DHCP Server IPv4 $($Scope.ScopeId) Scope from $($Server.split(".", 2)[0])"
                        $SubnetMask = Convert-IpAddressToMaskLength $Scope.SubnetMask
                        $inObj = [ordered] @{
                            'Scope Id' = "$($Scope.ScopeId)/$($SubnetMask)"
                            'Scope Name' = $Scope.Name
                            'Scope Range' = "$($Scope.StartRange) - $($Scope.EndRange)"
                            'Lease Duration' = $Scope.LeaseDuration
                            'State' = $Scope.State
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                }

                if ($HealthCheck.DHCP.Statistics) {
                    $OutObj | Where-Object { $_.'Percentage Available' -lt '5'} | Set-Style -Style Warning -Property 'Percentage Available','Percentage In Use'
                }

                $TableParams = @{
                    Name = "DHCP Server IPv4 Scopes Information - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 20, 20, 35, 15, 10
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        catch {
            Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scopes from $($Server)."
            Write-PScriboMessage -IsDebug $_.Exception.Message
        }
    }

    end {}

}