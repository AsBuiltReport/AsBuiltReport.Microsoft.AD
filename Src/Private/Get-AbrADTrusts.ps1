function Get-AbrADTrusts {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Trust from Domain Controller
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
        Write-PscriboMessage "Collecting AD Forest information."
    }

    process {
        Section -Style Heading5 'Active Directory Trust Summary' {
            Paragraph "The following section provides a summary of Active Directory Trust information on $($ForestInfo)."
            BlankLine
            $Data =  Get-ADTrust -Server (Get-ADForest).DomainNamingMaster -Filter *
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    $inObj = [ordered] @{
                        'Name' = $Item.Name
                        'Distinguished Name' =  $Item.DistinguishedName
                        'Source' = $Item.Source
                        'Target' = $Item.Target
                        'Direction' = $Item.Direction
                        'IntraForest' = ConvertTo-TextYN $Item.IntraForest
                        'Selective Authentication' = $Item.SelectiveAuthentication
                        'SID Filtering Forest Aware' = $Item.SIDFilteringForestAware
                        'SID Filtering Quarantined' = $Item.SIDFilteringQuarantined
                        'Trust Type' = $Item.TrustType
                        'Uplevel Only' = $Item.UplevelOnly
                    }
                    $OutObj += [pscustomobject]$inobj
                }

                $TableParams = @{
                    Name = "Active Directory Trusts Information - $($ForestInfo)"
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

    end {}

}