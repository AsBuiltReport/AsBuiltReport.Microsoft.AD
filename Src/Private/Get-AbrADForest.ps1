function Get-AbrADForest {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD information from Domain Controller
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
        [Parameter (
            Position = 0,
            Mandatory)]
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory forest information."
    }

    process {
        $Data = Invoke-Command -Session $Session {Get-ADForest}
        $ForestInfo =  $Data.RootDomain.toUpper()
        Write-PscriboMessage "Discovered Active Directory information of forest $ForestInfo."
        $ADVersion = Invoke-Command -Session $Session {Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object -ExpandProperty objectVersion}
        If ($ADVersion -eq '88') {$server = 'Windows Server 2019'}
        ElseIf ($ADVersion -eq '87') {$server = 'Windows Server 2016'}
        ElseIf ($ADVersion -eq '69') {$server = 'Windows Server 2012 R2'}
        ElseIf ($ADVersion -eq '56') {$server = 'Windows Server 2012'}
        ElseIf ($ADVersion -eq '47') {$server = 'Windows Server 2008 R2'}
        ElseIf ($ADVersion -eq '44') {$server = 'Windows Server 2008'}
        ElseIf ($ADVersion -eq '31') {$server = 'Windows Server 2003 R2'}
        ElseIf ($ADVersion -eq '30') {$server = 'Windows Server 2003'}
        $OutObj = @()
        $OutObj = @()
        if ($Data) {
            Write-PscriboMessage "Collecting Active Directory information of forest $ForestInfo."
            foreach ($Item in $Data) {
                $inObj = [ordered] @{
                    'Forest Name' = $Item.RootDomain
                    'Forest Functional Level' = $Item.ForestMode
                    'Schema Version' = "ObjectVersion $ADVersion, Correspond to $server"
                    'Domains' = $Item.Domains -join '; '
                    'Global Catalogs' = $Item.GlobalCatalogs -join '; '
                    'Application Partitions' = $Item.ApplicationPartitions
                    'PartitionsContainer' = [string]$Item.PartitionsContainer
                    'SPN Suffixes' = $Item.SPNSuffixes
                    'UPN Suffixes' = $Item.UPNSuffixes
                }
                $OutObj += [pscustomobject]$inobj
            }

            $TableParams = @{
                Name = "AD Forest Summary Information - $($ForestInfo)"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        Section -Style Heading5 'Optional Features Summary' {
            Paragraph "The following section provides a summary of the enabled Optional Features."
            BlankLine
            Write-PscriboMessage "Discovering Optional Features enabled on forest $ForestInfo."
            $Data = Invoke-Command -Session $Session {Get-ADOptionalFeature -Filter *}
            $OutObj = @()
            if ($Data) {
                Write-PscriboMessage "Discovered Optional Features enabled on forest $ForestInfo."
                foreach ($Item in $Data) {
                    Write-PscriboMessage "Collecting Optional Features '$($Item.Name)'"
                    $Forest = Invoke-Command -Session $Session {Get-ADForest}
                    $inObj = [ordered] @{
                        'Name' = $Item.Name
                        'Required Forest Mode' = $Item.RequiredForestMode
                        'Forest' = $Forest.RootDomain.toUpper()
                    }
                    $OutObj += [pscustomobject]$inobj
                }

                $TableParams = @{
                    Name = "Active Directory Enabled Optional Features Information - $($ForestInfo)"
                    List = $false
                    ColumnWidths = 40, 30, 30
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