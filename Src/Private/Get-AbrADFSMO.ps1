function Get-AbrADFSMO {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Flexible Single Master Operations information from Domain Controller
    .DESCRIPTION

    .NOTES
        Version:        0.9.8
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
        Write-PScriboMessage -Message "Collecting Active Directory FSMO information of domain $($Domain.DNSRoot)."
        Show-AbrDebugExecutionTime -Start -TitleMessage 'AD FSMO Roles'
    }

    process {
        try {
            $DomainData = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain ($using:Domain).DNSRoot | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator }
            $ForestData = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest ($using:Domain).DNSRoot | Select-Object DomainNamingMaster, SchemaMaster }
            if ($DomainData -and $ForestData) {
                if ($ValidDCFromDomain) {
                    if ($DCPssSession = Get-ValidPSSession -ComputerName $ValidDCFromDomain -SessionName $($ValidDCFromDomain) -PSSTable ([ref]$PSSTable)) {
                        Section -Style Heading3 'FSMO Roles' {
                            $IsInfraMasterGC = (Invoke-CommandWithTimeout -Session $DCPssSession -ErrorAction Stop -ScriptBlock { Get-ADDomainController -Identity ($using:DomainData).InfrastructureMaster }).IsGlobalCatalog
                            $OutObj = [System.Collections.ArrayList]::new()
                            try {
                                $inObj = [ordered] @{
                                    'Infrastructure Master' = $DomainData.InfrastructureMaster
                                    'PDC Emulator Name' = $DomainData.PDCEmulator
                                    'RID Master' = $DomainData.RIDMaster
                                    'Domain Naming Master' = $ForestData.DomainNamingMaster
                                    'Schema Master' = $ForestData.SchemaMaster
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Flexible Single Master Operations)"
                            }

                            if ($HealthCheck.Domain.BestPractice) {
                                if ($IsInfraMasterGC) {
                                    $OutObj | Set-Style -Style Warning -Property 'Infrastructure Master'
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
                                Paragraph 'Health Check:' -Bold -Underline
                                BlankLine
                                Paragraph {
                                    Text 'Best Practice:' -Bold
                                    Text "The infrastructure master role in the domain $($Domain.DNSRoot.ToString().ToUpper()) should be held by a domain controller that is not a global catalog server. The infrastructure master is responsible for updating references from objects in its domain to objects in other domains. If the infrastructure master runs on a global catalog server, it will not function properly because the global catalog holds a partial replica of every object in the forest, and it will not update the references. This issue does not affect forests that have a single domain. "
                                }
                                BlankLine
                                Paragraph {
                                    Text 'Reference:' -Bold
                                    Text 'http://go.microsoft.com/fwlink/?LinkId=168841'
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