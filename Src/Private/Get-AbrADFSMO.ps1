function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
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
        Write-PscriboMessage "Collecting AD FSMO information."
    }

    process {
        $DomainData = Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
        $ForestData = Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster
        $OutObj = @()
        if ($Data) {
            $inObj = [ordered] @{
                'Infrastructure Master Server' = $DomainData.InfrastructureMaster
                'RID Master Server' = $DomainData.RIDMaster
                'PDC Emulator Name' = $DomainData.PDCEmulator
                'Domain Naming Master Server' = $ForestData.DomainNamingMaster
                'Schema Master Server' = $ForestData.SchemaMaster
            }
            $OutObj += [pscustomobject]$inobj

            $TableParams = @{
                Name = "AD FSMO Server Information - $($ForestInfo)"
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