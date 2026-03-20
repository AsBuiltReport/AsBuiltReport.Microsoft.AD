function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.9
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        [string]$ValidDCFromDomain
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrADFSMO.Collecting -f $Domain.DNSRoot)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD FSMO Roles'
    }

    process {
        try {
            $DomainData = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain ($using:Domain).DNSRoot | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator }
            $ForestData = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest ($using:Domain).DNSRoot | Select-Object DomainNamingMaster, SchemaMaster }
            if ($DomainData -and $ForestData) {
                if ($ValidDCFromDomain) {
                    if ($DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)) {
                        Section -Style Heading3 $reportTranslate.GetAbrADFSMO.SectionTitle {
                            $IsInfraMasterGC = (Invoke-CommandWithTimeout -Session $DCPssSession -ErrorAction Stop -ScriptBlock { Get-ADDomainController -Identity ($using:DomainData).InfrastructureMaster }).IsGlobalCatalog
                            $OutObj = [System.Collections.Generic.List[object]]::new()
                            try {
                                $inObj = [ordered] @{
                                    $reportTranslate.GetAbrADFSMO.InfrastructureMaster = $DomainData.InfrastructureMaster
                                    $reportTranslate.GetAbrADFSMO.PDCEmulator = $DomainData.PDCEmulator
                                    $reportTranslate.GetAbrADFSMO.RIDMaster = $DomainData.RIDMaster
                                    $reportTranslate.GetAbrADFSMO.DomainNamingMaster = $ForestData.DomainNamingMaster
                                    $reportTranslate.GetAbrADFSMO.SchemaMaster = $ForestData.SchemaMaster
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj))
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Flexible Single Master Operations)"
                            }

                            if ($HealthCheck.Domain.BestPractice) {
                                if ($IsInfraMasterGC) {
                                    $OutObj | Set-Style -Style Warning -Property $reportTranslate.GetAbrADFSMO.InfrastructureMaster
                                }
                            }

                            $TableParams = @{
                                Name = "FSMO Roles - $($Domain.DNSRoot)"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $OutObj | Table @TableParams
                            if ($HealthCheck.DomainController.BestPractice -and ($IsInfraMasterGC)) {
                                Paragraph $reportTranslate.GetAbrADFSMO.HealthCheck -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADFSMO.BestPractice -Bold
                                    Text ($reportTranslate.GetAbrADFSMO.InfraMasterBP -f $Domain.DNSRoot.ToString().ToUpper())
                                }
                                BlankLine
                                Paragraph {
                                    Text $reportTranslate.GetAbrADFSMO.Reference -Bold
                                    Text $reportTranslate.GetAbrADFSMO.InfraMasterRef
                                }
                            }
                        }
                    } else {
                        if (-not $_.Exception.MessageId) {
                            $ErrorMessage = $_.FullyQualifiedErrorId
                        } else { $ErrorMessage = $_.Exception.MessageId }
                        Write-PScriboMessage -IsWarning -Message "FSMO Roles Section: New-PSSession: Unable to connect to $($Domain.DNSRoot): $ErrorMessage"
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Flexible Single Master Operations)"
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'AD FSMO Roles'
    }

}