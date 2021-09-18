function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.2.0
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (

    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Sites information."
    }

    process {
        $Data = Get-ADReplicationSite -Filter * -Properties *
        $OutObj = @()
        if ($Data) {
            foreach ($Item in $Data) {
                $SubnetArray = @()
                $Subnets = $Item.Subnets
                foreach ($Object in $Subnets) {
                    $SubnetName = Get-ADReplicationSubnet $Object
                    $SubnetArray += $SubnetName.Name
                }
                $inObj = [ordered] @{
                    'Site Name' = $Item.Name
                    'Description' = $Item.Description
                    'Creation Date' = ($Item.createTimeStamp).ToUniversalTime().toString("r")
                    'Subnets' = $SubnetArray -join ", "
                }
                $OutObj += [pscustomobject]$inobj
            }

            $TableParams = @{
                Name = "AD Domain Controller Summary Information - $($ForestInfo)"
                List = $false
                ColumnWidths = 25, 30, 25, 20
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        Section -Style Heading4 'Site Links Summary' {
            Paragraph "The following section provides a summary of the Active Directory Site Link information."
            BlankLine
            $Data = Get-ADReplicationSiteLink -Filter * -Properties *
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    $SiteArray = @()
                    $Sites = $Item.siteList
                    foreach ($Object in $Sites) {
                        $SiteName = Get-ADReplicationSite -Identity $Object
                        $SiteArray += $SiteName.Name
                    }
                    $inObj = [ordered] @{
                        'Site Link Name' = $Item.Name
                        'Cost' = $Item.Cost
                        'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                        'Transport Protocol' = $Item.InterSiteTransportProtocol
                        'Sites' = $SiteArray -join ", "
                    }
                    $OutObj += [pscustomobject]$inobj
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