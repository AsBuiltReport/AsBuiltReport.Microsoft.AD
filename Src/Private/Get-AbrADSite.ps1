function Get-AbrADSite {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Sites information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.13
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
        Write-PscriboMessage "Discovering Active Directory Sites information of forest $ForestInfo"
    }

    process {
        try {
            $Site =  Invoke-Command -Session $TempPssSession {Get-ADReplicationSite -Filter * -Properties *}
            if ($Site) {
                Section -Style Heading3 'Sites' {
                    $OutObj = @()
                    Write-PscriboMessage "Discovered Active Directory Sites information of forest $ForestInfo"
                    foreach ($Item in $Site) {
                        try {
                            Write-PscriboMessage "Collecting '$($Item.Name)' Site"
                            $SubnetArray = @()
                            $Subnets = $Item.Subnets
                            foreach ($Object in $Subnets) {
                                $SubnetName =  Invoke-Command -Session $TempPssSession {Get-ADReplicationSubnet $using:Object}
                                $SubnetArray += $SubnetName.Name
                            }
                            $inObj = [ordered] @{
                                'Site Name' = $Item.Name
                                'Description' = ConvertTo-EmptyToFiller $Item.Description
                                'Subnets' = Switch (($SubnetArray).count) {
                                    0 {"--"}
                                    default {$SubnetArray}
                                }
                                'Creation Date' = $Item.createTimeStamp.ToShortDateString()
                            }
                            $OutObj += [pscustomobject]$inobj

                            if ($HealthCheck.Site.BestPractice) {
                                $OutObj | Where-Object { $_.'Subnets' -eq '--'} | Set-Style -Style Warning -Property 'Subnets'
                                $OutObj | Where-Object { $_.'Description' -eq '--'} | Set-Style -Style Warning -Property 'Description'
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Site)"
                        }
                    }

                    $TableParams = @{
                        Name = "Sites - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 25, 30, 25, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Site Name' | Table @TableParams
                    if ($HealthCheck.Site.BestPractice -and (($OutObj | Where-Object { $_.'Subnets' -eq '--'}) -or ($OutObj | Where-Object { $_.'Description' -eq '--'}))) {
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        BlankLine
                        if ($OutObj | Where-Object { $_.'Subnets' -eq '--'}) {
                            Paragraph "Corrective Actions: Ensure Sites have an associated subnet. If subnets are not associated with AD Sites users in the AD Sites might choose a remote domain controller for authentication which in turn might result in excessive use of a remote domain controller." -Italic -Bold
                        }
                        if ($OutObj | Where-Object { $_.'Description' -eq '--'}) {
                            Paragraph "Best Practice: It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment." -Italic -Bold
                        }
                    }
                    try {
                        $Subnet = Invoke-Command -Session $TempPssSession {Get-ADReplicationSubnet -Filter * -Properties *}
                        if ($Subnet) {
                            Section -Style Heading4 'Site Subnets' {
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

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.'Description' -eq '--'} | Set-Style -Style Warning -Property 'Description'
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                                    }
                                }

                                $TableParams = @{
                                    Name = "Site Subnets - $($ForestInfo)"
                                    List = $false
                                    ColumnWidths = 20, 30, 35, 15
                                }
                                if ($Report.ShowTableCaptions) {
                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                }
                                $OutObj | Sort-Object -Property 'Subnet' | Table @TableParams
                                if ($HealthCheck.Site.BestPractice -and ($OutObj | Where-Object { $_.'Description' -eq '--'})) {
                                    Paragraph "Health Check:" -Italic -Bold -Underline
                                    BlankLine
                                    Paragraph "Best Practice: It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment." -Italic -Bold
                                }
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Subnets)"
                    }
                    try {
                        $Link = Invoke-Command -Session $TempPssSession {Get-ADReplicationSiteLink -Filter * -Properties *}
                        if ($Link) {
                            Section -Style Heading4 'Site Links' {
                                $OutObj = @()
                                Write-PscriboMessage "Discovered Active Directory Sites Link information of forest $ForestInfo"
                                foreach ($Item in $Link) {
                                    try {
                                        Write-PscriboMessage "Collecting '$($Item.Name)' Site Link"
                                        $SiteArray = @()
                                        $Sites = $Item.siteList
                                        foreach ($Object in $Sites) {
                                            $SiteName =  Invoke-Command -Session $TempPssSession {Get-ADReplicationSite -Identity $using:Object}
                                            $SiteArray += $SiteName.Name
                                        }
                                        $inObj = [ordered] @{
                                            'Site Link Name' = $Item.Name
                                            'Cost' = $Item.Cost
                                            'Replication Frequency' = "$($Item.ReplicationFrequencyInMinutes) min"
                                            'Transport Protocol' = $Item.InterSiteTransportProtocol
                                            'Options' = Switch ($Item.Options) {
                                                $null {'Change Notification is Disabled'}
                                                '0' {'Change Notification is Disabled'}
                                                '1' {'Change Notification is Enabled with Compression'}
                                                '2' {'Force sync in opposite direction at end of sync'}
                                                '3' {'Change Notification is Enabled with Compression and Force sync in opposite direction at end of sync'}
                                                '4' {'Disable compression of Change Notification messages'}
                                                '5' {'Change Notification is Enabled without Compression'}
                                                '6' {'Force sync in opposite direction at end of sync and Disable compression of Change Notification messages'}
                                                '7' {'Change Notification is Enabled without Compression and Force sync in opposite direction at end of sync'}
                                                Default {"Unknown siteLink option: $($Item.Options)"}
                                            }
                                            'Sites' = $SiteArray -join "; "
                                            'Protected From Accidental Deletion' = ConvertTo-TextYN $Item.ProtectedFromAccidentalDeletion
                                            'Description' = ConvertTo-EmptyToFiller $Item.Description
                                        }
                                        $OutObj = [pscustomobject]$inobj

                                        if ($HealthCheck.Site.BestPractice) {
                                            $OutObj | Where-Object { $_.'Description' -eq '--'} | Set-Style -Style Warning -Property 'Description'
                                            $OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' } | Set-Style -Style Warning -Property 'Options'
                                            $OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No'} | Set-Style -Style Warning -Property 'Protected From Accidental Deletion'
                                        }

                                        $TableParams = @{
                                            Name = "Site Links - $($Item.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Sort-Object -Property 'Site Link Name' | Table @TableParams
                                        if ($HealthCheck.Site.BestPractice -and ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No'}) -or (($OutObj | Where-Object { $_.'Description' -eq '--'}) -or ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' }))) {
                                            Paragraph "Health Check:" -Italic -Bold -Underline
                                            BlankLine
                                            if ($OutObj | Where-Object { $_.'Description' -eq '--'}) {
                                                Paragraph "Best Practice: It is a general rule of good practice to establish well-defined descriptions. This helps to speed up the fault identification process, as well as enabling better documentation of the environment." -Italic -Bold
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Options' -eq 'Change Notification is Disabled' -or $Null -eq 'Options' }) {
                                                Paragraph "Best Practice: Enabling change notification treats an INTER-site replication connection like an INTRA-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an Option number value of 5 (Change Notification is Enabled without Compression)." -Italic -Bold
                                                BlankLine
                                            }
                                            if ($OutObj | Where-Object { $_.'Protected From Accidental Deletion' -eq 'No'}) {
                                                Paragraph "Best Practice: If Site Links in your Actie Directory domain are not protected from accidental deletion your enviroment can experience disruptions that maight be cause by accidental bulk deletion of object." -Italic -Bold
                                                BlankLine
                                            }
                                            BlankLine
                                        }

                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Site Links)"
                                    }
                                }
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