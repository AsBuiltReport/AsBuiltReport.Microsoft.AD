function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.4.0
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
            $Domain,
            $Session
    )

    begin {
        Write-PscriboMessage "Discovering Active Directory FSMO information of domain $ForestInfo."
    }

    process {
        Section -Style Heading5 'Flexible Single Master Operations (FSMO) Information' {
            Paragraph "The following section provides a summary of the Active Directory FSMO for Domain $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                try {
                    $DomainData = Invoke-Command -Session $Session {Get-ADDomain $using:Domain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator}
                    $ForestData = Invoke-Command -Session $Session {Get-ADForest $using:Domain | Select-Object DomainNamingMaster, SchemaMaster}
                    Write-PscriboMessage "Discovered Active Directory FSMO information of domain $Domain."
                    $inObj = [ordered] @{
                        'Infrastructure Master Server' = $DomainData.InfrastructureMaster
                        'RID Master Server' = $DomainData.RIDMaster
                        'PDC Emulator Name' = $DomainData.PDCEmulator
                        'Domain Naming Master Server' = $ForestData.DomainNamingMaster
                        'Schema Master Server' = $ForestData.SchemaMaster
                    }
                    $OutObj += [pscustomobject]$inobj
                }
                catch {
                    Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Flexible Single Master Operations)"
                }

                $TableParams = @{
                    Name = "FSMO Server Information - $($Domain)"
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