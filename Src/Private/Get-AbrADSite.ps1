function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
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
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory Sites information of forest $ForestInfo"
    }

    process {
        Section -Style Heading3 'Domain Site Summary' {
            Paragraph "The following section provides a summary of the Active Directory Sites."
            BlankLine
            $Data =  Invoke-Command -Session $Session {Get-ADReplicationSite -Filter * -Properties *}
            $OutObj = @()
            if ($Data) {
                Write-PscriboMessage "Discovered Active Directory Sites information of forest $ForestInfo"
                foreach ($Item in $Data) {
                    try {
                        Write-PscriboMessage "Collecting '$($Item.Name)' Site"
                        $SubnetArray = @()
                        $Subnets = $Item.Subnets
                        foreach ($Object in $Subnets) {
                            $SubnetName =  Invoke-Command -Session $Session {Get-ADReplicationSubnet $using:Object}
                            $SubnetArray += $SubnetName.Name
                        }
                        $inObj = [ordered] @{
                            'Site Name' = $Item.Name
                            'Description' = ConvertTo-EmptyToFiller $Item.Description
                            'Creation Date' = ($Item.createTimeStamp).ToUniversalTime().toString("r")
                            'Subnets' = $SubnetArray
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Site)"
                        continue
                    }
                }

                $TableParams = @{
                    Name = "Domain Site Information - $($ForestInfo)"
                    List = $false
                    ColumnWidths = 25, 30, 25, 20
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        Section -Style Heading4 'Site Links Summary' {
            Paragraph "The following section provides a summary of the Active Directory Site Link information."
            BlankLine
            $Data =  Invoke-Command -Session $Session {Get-ADReplicationSiteLink -Filter * -Properties *}
            $OutObj = @()
            if ($Data) {
                Write-PscriboMessage "Discovered Active Directory Sites Link information of forest $ForestInfo"
                foreach ($Item in $Data) {
                    try {
                        Write-PscriboMessage "Collecting '$($Item.Name)' Site Link"
                        $SiteArray = @()
                        $Sites = $Item.siteList
                        foreach ($Object in $Sites) {
                            $SiteName =  Invoke-Command -Session $Session {Get-ADReplicationSite -Identity $using:Object}
                            $SiteArray += $SiteName.Name
                        }
                        $inObj = [ordered] @{
                            'Site Link Name' = $Item.Name
                            'Cost' = $Item.Cost
                            'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                            'Transport Protocol' = $Item.InterSiteTransportProtocol
                            'Sites' = $SiteArray
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Links)"
                        continue
                    }
                }

                $TableParams = @{
                    Name = "Site Links Information - $($ForestInfo)"
                    List = $false
                    ColumnWidths = 30, 15, 15, 15, 25
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }

    }

    end {}

}