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
        [Parameter (
            Position = 0,
            Mandatory)]
            [string]
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD FSMO information."
    }

    process {
        Section -Style Heading4 'Active Directory FSMO Information' {
            Paragraph "The following section provides a summary of the Active Directory FSMO for Domain $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                $DomainData = Get-ADDomain $Domain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
                $ForestData = Get-ADForest $Domain | Select-Object DomainNamingMaster, SchemaMaster
                $inObj = [ordered] @{
                    'Infrastructure Master Server' = $DomainData.InfrastructureMaster
                    'RID Master Server' = $DomainData.RIDMaster
                    'PDC Emulator Name' = $DomainData.PDCEmulator
                    'Domain Naming Master Server' = $ForestData.DomainNamingMaster
                    'Schema Master Server' = $ForestData.SchemaMaster
                }
                $OutObj += [pscustomobject]$inobj

                $TableParams = @{
                    Name = "AD FSMO Server Information - $($Domain)"
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