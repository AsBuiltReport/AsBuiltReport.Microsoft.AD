function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
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
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory Sites information of forest $ForestInfo"
    }

    process {
        try {
            $Site =  Invoke-Command -Session $Session {Get-ADReplicationSite -Filter * -Properties *}
            if ($Site) {
                Section -Style Heading3 'Domain Sites' {
                    Paragraph "The following section provides a summary of the Active Directory Sites."
                    BlankLine
                    $OutObj = @()
                    Write-PscriboMessage "Discovered Active Directory Sites information of forest $ForestInfo"
                    foreach ($Item in $Site) {
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
                                'Subnets' = Switch (($SubnetArray).count) {
                                    0 {"-"}
                                    default {$SubnetArray}
                                }
                                'Creation Date' = $Item.createTimeStamp.ToShortDateString()
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Site)"
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
                    try {
                        $Subnet = Invoke-Command -Session $Session {Get-ADReplicationSubnet -Filter * -Properties *}
                        if ($Subnet) {
                            Section -Style Heading4 'Site Subnets' {
                                Paragraph "The following section provides a summary of the Active Directory Site Subnets information."
                                BlankLine
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Active Directory Sites Subnets information of forest $ForestInfo"
                                foreach ($Item in $Subnet) {
                                    try {
                                        Write-PscriboMessage "Collecting $($Item.Name) Site Subnet."
                                        $inObj = [ordered] @{
                                            'Subnet' = $Item.Name
                                            'Description' = ConvertTo-EmptyToFiller $Item.Description
                                            'Sites' = Get-ADObject $Item.Site | Select-Object -ExpandProperty Name
                                            'Creation Date' = $Item.Created.ToShortDateString()
                                        }
                                        $OutObj += [pscustomobject]$inObj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Site Subnets Information - $($ForestInfo)"
                                    List = $false
                                    ColumnWidths = 20, 30, 35, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Table @TableParams
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                    }
                    try {
                        $Link =  Invoke-Command -Session $Session {Get-ADReplicationSiteLink -Filter * -Properties *}
                        if ($Link) {
                            Section -Style Heading4 'Site Links' {
                                Paragraph "The following section provides a summary of the Active Directory Site Link information."
                                BlankLine
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Active Directory Sites Link information of forest $ForestInfo"
                                foreach ($Item in $Link) {
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
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Site Global)"
        }
    }

    end {}

}