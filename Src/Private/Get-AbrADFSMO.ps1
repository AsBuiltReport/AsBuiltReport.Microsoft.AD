function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.2
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
        Write-PScriboMessage "Collecting Active Directory FSMO information of domain $Domain."
    }

    process {
        try {
            $DomainData = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator }
            $ForestData = Invoke-Command -Session $TempPssSession { Get-ADForest $using:Domain | Select-Object DomainNamingMaster, SchemaMaster }
            if ($DomainData -and $ForestData) {
                if ($DC = Get-ValidDCfromDomain -Domain $Domain) {
                    if ($DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName 'FSMORoles') {
                        Section -Style Heading3 'FSMO Roles' {
                            $IsInfraMasterGC = (Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-ADDomainController -Identity ($using:DomainData).InfrastructureMaster }).IsGlobalCatalog
                            $OutObj = @()
                            try {
                                $inObj = [ordered] @{
                                    'Infrastructure Master' = $DomainData.InfrastructureMaster
                                    'PDC Emulator Name' = $DomainData.PDCEmulator
                                    'RID Master' = $DomainData.RIDMaster
                                    'Domain Naming Master' = $ForestData.DomainNamingMaster
                                    'Schema Master' = $ForestData.SchemaMaster
                                }
                                $OutObj += [pscustomobject](ConvertTo-HashToYN $inObj)
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Flexible Single Master Operations)"
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
                                    Text "The infrastructure master role in the domain $($Domain.ToString().ToUpper()) should be held by a domain controller that is not a global catalog server. The infrastructure master is responsible for updating references from objects in its domain to objects in other domains. If the infrastructure master runs on a global catalog server, it will not function properly because the global catalog holds a partial replica of every object in the forest, and it will not update the references. This issue does not affect forests that have a single domain. "
                                }
                                BlankLine
                                Paragraph {
                                    Text "Reference:" -Bold
                                    Text "http://go.microsoft.com/fwlink/?LinkId=168841"
                                }
                            }
                            Remove-PSSession -Session $DCPssSession
                        }
                    } else {
                        if (-Not $_.Exception.MessageId) {
                            $ErrorMessage = $_.FullyQualifiedErrorId
                        } else { $ErrorMessage = $_.Exception.MessageId }
                        Write-PScriboMessage -IsWarning "FSMO Roles Section: New-PSSession: Unable to connect to $($Domain): $ErrorMessage"
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Flexible Single Master Operations)"
        }
    }
    end {}

}