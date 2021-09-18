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
    )

    begin {
        Write-PscriboMessage "Collecting AD Forest information."
    }

    process {
        $Data = Get-ADForest
        $ForestInfo =  $Data.RootDomain.toUpper()
        $ADVersion = Get-ADObject (Get-ADRootDSE).schemaNamingContext -property objectVersion | Select-Object objectVersion
        $ADnumber = $ADVersion -replace "@{objectVersion=","" -replace "}",""
        If ($ADnumber -eq '88') {$server = 'Windows Server 2019'}
        ElseIf ($ADnumber -eq '87') {$server = 'Windows Server 2016'}
        ElseIf ($ADnumber -eq '69') {$server = 'Windows Server 2012 R2'}
        ElseIf ($ADnumber -eq '56') {$server = 'Windows Server 2012'}
        ElseIf ($ADnumber -eq '47') {$server = 'Windows Server 2008 R2'}
        ElseIf ($ADnumber -eq '44') {$server = 'Windows Server 2008'}
        ElseIf ($ADnumber -eq '31') {$server = 'Windows Server 2003 R2'}
        ElseIf ($ADnumber -eq '30') {$server = 'Windows Server 2003'}
        $OutObj = @()
        if ($Data) {
            foreach ($Item in $Data) {
                $inObj = [ordered] @{
                    'Forest Name' = $Item.RootDomain
                    'Forest Functional Level' = $Item.ForestMode
                    'Schema Version' = "ObjectVersion $ADnumber, Correspond to $server"
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
            $Data = Get-ADOptionalFeature -Filter *
            $OutObj = @()
            if ($Data) {
                foreach ($Item in $Data) {
                    $Forest = Get-ADForest
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