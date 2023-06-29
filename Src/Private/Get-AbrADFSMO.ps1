function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.7.14
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
        Write-PscriboMessage "Discovering Active Directory FSMO information of domain $ForestInfo."
    }

    process {
        try {
            $DomainData = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator}
            $ForestData = Invoke-Command -Session $TempPssSession {Get-ADForest $using:Domain | Select-Object DomainNamingMaster, SchemaMaster}
            if ($DomainData -and $ForestData) {
                $DC = Invoke-Command -Session $TempPssSession {(Get-ADDomain -Identity $using:Domain).ReplicaDirectoryServers | Select-Object -First 1}
                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                Section -Style Heading4 'FSMO Roles' {
                    $IsInfraMasterGC = (Invoke-Command -Session $DCPssSession {Get-ADDomainController -Identity ($using:DomainData).InfrastructureMaster}).IsGlobalCatalog
                    $OutObj = @()
                    try {
                        Write-PscriboMessage "Discovered Active Directory FSMO information of domain $Domain."
                        $inObj = [ordered] @{
                            'Infrastructure Master' = $DomainData.InfrastructureMaster
                            'RID Master' = $DomainData.RIDMaster
                            'PDC Emulator Name' = $DomainData.PDCEmulator
                            'Domain Naming Master' = $ForestData.DomainNamingMaster
                            'Schema Master' = $ForestData.SchemaMaster
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Flexible Single Master Operations)"
                    }

                    if ($HealthCheck.Domain.BestPractice) {
                        if ($IsInfraMasterGC) {
                            $OutObj | Set-Style -Style Warning -Property 'Infrastructure Master'
                        }
                    }

                    $TableParams = @{
                        Name = "FSMO Roles - $($Domain)"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                    if ($HealthCheck.DomainController.BestPractice -and ($IsInfraMasterGC)) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "The infrastructure master role in the domain $($Domain.ToString().ToUpper()) should be held by a domain controller that is not a global catalog server. This issue does not affect forests that have a single domain."
                        }
                        BlankLine
                        Paragraph {
                            Text "Reference:" -Bold
                            Text "http://go.microsoft.com/fwlink/?LinkId=168841"
                        }
                    }
                }
                if ($DCPssSession) {
                    Remove-PSSession -Session $DCPssSession
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Flexible Single Master Operations)"
        }
    }
    end {}

}