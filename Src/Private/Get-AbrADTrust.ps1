function Get-AbrADTrust {
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
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD Trust information."
    }

    process {
        Section -Style Heading5 'Trust Summary' {
            Paragraph "The following section provides a summary of Active Directory Trust information on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                $GlobalCatalog = Get-ADDomainController -Discover -Service GlobalCatalog
                $Trust = Get-ADTrust -Identity $Domain -Server "$($GlobalCatalog.name):3268"
                $inObj = [ordered] @{
                    'Name' = $Trust.Name
                    'Distinguished Name' =  $Trust.DistinguishedName
                    'Source' = $Trust.Source
                    'Target' = $Trust.Target
                    'Direction' = $Trust.Direction
                    'IntraForest' = ConvertTo-TextYN $Trust.IntraForest
                    'Selective Authentication' = ConvertTo-TextYN $Trust.SelectiveAuthentication
                    'SID Filtering Forest Aware' = ConvertTo-TextYN $Trust.SIDFilteringForestAware
                    'SID Filtering Quarantined' = ConvertTo-TextYN $Trust.SIDFilteringQuarantined
                    'Trust Type' = $Trust.TrustType
                    'Uplevel Only' = ConvertTo-TextYN $Trust.UplevelOnly
                }
                $OutObj += [pscustomobject]$inobj
            }

            $TableParams = @{
                Name = "Active Directory Trusts Information - $($Domain.ToString().ToUpper())"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
    }

    end {}

}