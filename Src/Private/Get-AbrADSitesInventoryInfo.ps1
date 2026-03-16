function Get-AbrADSitesInventoryInfo {
    <#
    .SYNOPSIS
        Function to extract microsoft active directory sites information.
    .DESCRIPTION
        Build a diagram of the configuration of Microsoft Active Directory to a supported formats using Psgraph.
    .NOTES
        Version:        0.9.11
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .LINK
        https://github.com/rebelinux/Diagrammer.Microsoft.AD
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]

    param()

    begin {
    }

    process {
        Write-Verbose -Message ($reportTranslate.NewADDiagram.buildingSites -f $($ForestRoot))
        try {
            $Sites = Invoke-CommandWithTimeout -Session $DiagramTempPssSession -ScriptBlock { Get-ADReplicationSite -Filter * -Properties * }

            $SitesInfo = [System.Collections.ArrayList]::new()
            if ($Sites) {
                foreach ($Site in $Sites) {
                    $TempSitesInfo = [PSCustomObject]@{
                        Name = $Site.Name
                        Label = $Site.Name
                        Subnets = & {
                            $SubnetTable = [System.Collections.ArrayList]::new()
                            $SubnetArray = [System.Collections.ArrayList]::new()
                            $Subnets = $Site.Subnets
                            foreach ($Object in $Subnets) {
                                $SubnetName = Invoke-CommandWithTimeout -Session $DiagramTempPssSession -ScriptBlock { Get-ADReplicationSubnet $using:Object }
                                $SubnetArray.Add($SubnetName.Name) | Out-Null
                            }

                            # Used for Debug
                            # $SubnetArray = @("192.168.5.0/24","192.168.4.0/24","192.168.3.0/24","192.168.7.0/24","192.168.9.0/24","192.168.10.0/24","192.168.1.0/24","192.168.19.0/24")

                            $SubnetTable.Add(
                                [PSCustomObject]@{
                                    Name = Remove-SpecialCharacter -String "$($Site.Name)SubNets" -SpecialChars '\-. '
                                    Label = (Add-HtmlTable -Name SubnetTable -ImagesObj $Images -Rows $SubnetArray -ColumnSize 3 -ALIGN 'Center' -IconDebug $IconDebug)
                                    SubnetArray = $SubnetArray
                                }
                            ) | Out-Null

                            $SubnetTable
                        }
                        DomainControllers = & {
                            $DCsTable = [System.Collections.ArrayList]::new()
                            $DCsArray = [System.Collections.ArrayList]::new()
                            $DCs = try { Get-ADObjectSearch -DN "CN=Servers,$($Site.DistinguishedName)" -Filter { objectClass -eq 'Server' } -Properties 'DNSHostName' -SelectPrty 'DNSHostName', 'Name' -Session $DiagramTempPssSession } catch { Out-Null }
                            foreach ($Object in $DCs) {
                                $DCsArray.Add($Object.DNSHostName) | Out-Null
                            }

                            # Used for Debug
                            # $DCsArray = @("Server-dc-01v","Server-dc-02v","Server-dc-03v","Server-dc-04v","Server-dc-05v","Server-dc-06v","Server-dc-07v","Server-dc-08v","Server-dc-09v","DC-Server-01v","DC-Server-02v","DC-Server-03v","DC-Server-04v")

                            $DCsTable.Add([PSCustomObject]@{
                                    Name = Remove-SpecialCharacter -String "$($Site.Name)DCs" -SpecialChars '\-. '
                                    Label = (Add-HtmlTable -Name DCsTable -Rows $DCsArray -ColumnSize 3 -ALIGN 'Center' -ImagesObj $Images -IconDebug $IconDebug)
                                    DCsArray = $DCsArray
                                }) | Out-Null

                            $DCsTable
                        }

                        SitesObj = $Site
                    }
                    $SitesInfo.Add($TempSitesInfo) | Out-Null
                }
            }

            $SitesInfo
        } catch {
            Write-Verbose $_.Exception.Message
        }
    }
    end {}
}