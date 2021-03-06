function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.2
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
        Write-PscriboMessage "Discovering Active Directory forest information."
    }

    process {
        try {
            $Data = Invoke-Command -Session $TempPssSession {Get-ADForest}
            $ForestInfo =  $Data.RootDomain.toUpper()
            Write-PscriboMessage "Discovered Active Directory information of forest $ForestInfo."
            $DomainDN = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity (Get-ADForest | Select-Object -ExpandProperty RootDomain )).DistinguishedName}
            $TombstoneLifetime = Invoke-Command -Session $TempPssSession {Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$using:DomainDN" -Properties tombstoneLifetime | Select-Object -ExpandProperty tombstoneLifetime}
            $ADVersion = Invoke-Command -Session $TempPssSession {Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion}
            If ($ADVersion -eq '88') {$server = 'Windows Server 2019'}
            ElseIf ($ADVersion -eq '87') {$server = 'Windows Server 2016'}
            ElseIf ($ADVersion -eq '69') {$server = 'Windows Server 2012 R2'}
            ElseIf ($ADVersion -eq '56') {$server = 'Windows Server 2012'}
            ElseIf ($ADVersion -eq '47') {$server = 'Windows Server 2008 R2'}
            ElseIf ($ADVersion -eq '44') {$server = 'Windows Server 2008'}
            ElseIf ($ADVersion -eq '31') {$server = 'Windows Server 2003 R2'}
            ElseIf ($ADVersion -eq '30') {$server = 'Windows Server 2003'}
            $OutObj = @()
            if ($Data) {
                Write-PscriboMessage "Collecting Active Directory information of forest $ForestInfo."
                foreach ($Item in $Data) {
                    try {
                        $inObj = [ordered] @{
                            'Forest Name' = $Item.RootDomain
                            'Forest Functional Level' = $Item.ForestMode
                            'Schema Version' = "ObjectVersion $ADVersion, Correspond to $server"
                            'Tombstone Lifetime (days)' = $TombstoneLifetime
                            'Domains' = $Item.Domains -join '; '
                            'Global Catalogs' = $Item.GlobalCatalogs -join '; '
                            'Domains Count' = $Item.Domains.Count
                            'Global Catalogs Count' = $Item.GlobalCatalogs.Count
                            'Sites Count' = $Item.Sites.Count
                            'Application Partitions' = $Item.ApplicationPartitions
                            'PartitionsContainer' = [string]$Item.PartitionsContainer
                            'SPN Suffixes' = ConvertTo-EmptyToFiller $Item.SPNSuffixes
                            'UPN Suffixes' = ConvertTo-EmptyToFiller $Item.UPNSuffixes
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                    }
                }

                $TableParams = @{
                    Name = "Forest Summary - $($ForestInfo)"
                    List = $true
                    ColumnWidths = 40, 60
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
        try {
            Section -Style Heading5 'Optional Features' {
                Write-PscriboMessage "Discovering Optional Features enabled on forest $ForestInfo."
                $Data = Invoke-Command -Session $TempPssSession {Get-ADOptionalFeature -Filter *}
                $OutObj = @()
                if ($Data) {
                    Write-PscriboMessage "Discovered Optional Features enabled on forest $ForestInfo."
                    foreach ($Item in $Data) {
                        try {
                            Write-PscriboMessage "Collecting Optional Features '$($Item.Name)'"
                            $inObj = [ordered] @{
                                'Name' = $Item.Name
                                'Required Forest Mode' = $Item.RequiredForestMode
                                'Enabled' = Switch (($Item.EnabledScopes).count) {
                                    0 {'No'}
                                    default {'Yes'}
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }

                    $TableParams = @{
                        Name = "Optional Features - $($ForestInfo)"
                        List = $false
                        ColumnWidths = 40, 30, 30
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }
    }

    end {}

}