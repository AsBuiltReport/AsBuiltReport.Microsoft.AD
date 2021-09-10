function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.1.0
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
        $Data = Get-ADReplicationSite -Filter *
        $OutObj = @()
        if ($Data) {
            foreach ($Item in $Data) {
                $inObj = [ordered] @{
                    'Site Name' = $Item.Name
                    'Distinguished Name' = $Item.DistinguishedName
                    'Description' = $Item.Description
                }
                $OutObj += [pscustomobject]$inobj
            }

            $TableParams = @{
                Name = "AD Domain Controller Summary Information - $($ForestInfo)"
                List = $false
                ColumnWidths = 30, 35, 35
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}