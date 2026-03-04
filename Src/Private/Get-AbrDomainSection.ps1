function Get-AbrDomainSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Domain Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.11
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [ref]$DomainStatus
    )

    begin {
        Write-PScriboMessage -Message ($reportTranslate.GetAbrDomainSection.Collecting -f $ForestInfo)
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Domain Section'
    }

    process {
        if ($InfoLevel.Domain -ge 1) {
            $DomainObj = foreach ($Domain in ($OrderedDomains | Where-Object { $_ -notin $Options.Exclude.Domains })) {
                if ($Domain -and ($Domain -notin $DomainStatus.Value.Name)) {
                    if ($ValidDC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                        # Define Filter option for Domain variable
                        try {
                            if ($DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain }) {
                                Write-Host "  - Collecting Domain information from $Domain."
                                $DCs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } } | Sort-Object
                                Section -Style Heading2 "$($DomainInfo.DNSRoot.ToString().ToUpper())" {
                                    Paragraph $reportTranslate.GetAbrDomainSection.Paragraph
                                    BlankLine
                                    Get-AbrADDomain -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADFSMO -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADTrust -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADAuthenticationPolicy -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADHardening -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADDomainObject -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    if ($HealthCheck.Domain.Backup -or $HealthCheck.Domain.DFS -or $HealthCheck.Domain.SPN -or $HealthCheck.Domain.Security -or $HealthCheck.Domain.DuplicateObject) {
                                        Section -Style Heading3 $reportTranslate.GetAbrDomainSection.HealthChecks {
                                            Get-AbrADDomainLastBackup -Domain $DomainInfo
                                            Get-AbrADDFSHealth -Domain $DomainInfo -DCs $DCs -ValidDcFromDomain $ValidDC
                                            if ($DomainInfo -like $ADSystem.RootDomain) {
                                                Get-AbrADDuplicateSPN -Domain $ADSystem.RootDomain
                                            }
                                            Get-AbrADSecurityAssessment -Domain $DomainInfo
                                            Get-AbrADKerberosAudit -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                            Get-AbrADDuplicateObject -Domain $DomainInfo
                                        }
                                    }
                                    Section -Style Heading3 $reportTranslate.GetAbrDomainSection.DomainControllersSection {
                                        if ($Options.ShowDefinitionInfo) {
                                            Paragraph $reportTranslate.GetAbrDomainSection.DCDefinitionText
                                            BlankLine
                                        }
                                        if (-not $Options.ShowDefinitionInfo) {
                                            if ($InfoLevel.Domain -ge 2) {
                                                Paragraph $reportTranslate.GetAbrDomainSection.DCParagraphDetail
                                                BlankLine
                                            } else {
                                                Paragraph $reportTranslate.GetAbrDomainSection.DCParagraphSummary
                                                BlankLine
                                            }
                                        }

                                        if ($DCs) {

                                            Get-AbrADDomainController -Domain $DomainInfo -Dcs $DCs

                                            if ($InfoLevel.Domain -ge 2) {
                                                $RolesObj = foreach ($DC in $DCs) {
                                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                                        Get-AbrADDCRoleFeature -DC $DC
                                                    } else {
                                                        Write-PScriboMessage -IsWarning -Message "Unable to connect to $DC. Removing it from the $($DomainInfo.DNSRoot) report."
                                                    }
                                                }
                                                if ($RolesObj) {
                                                    Section -Style Heading4 $reportTranslate.GetAbrDomainSection.RolesSection {
                                                        Paragraph ($reportTranslate.GetAbrDomainSection.RolesParagraph -f $DomainInfo.DNSRoot)
                                                        $RolesObj
                                                    }
                                                }
                                            }
                                            if ($HealthCheck.DomainController.Diagnostic) {
                                                try {
                                                    $DCDiagObj = foreach ($DC in $DCs) {
                                                        if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                                            Get-AbrADDCDiag -Domain $Domain -DC $DC
                                                        }
                                                    }
                                                    if ($DCDiagObj) {
                                                        Section -Style Heading4 $reportTranslate.GetAbrDomainSection.DCDiagSection {
                                                            Paragraph $reportTranslate.GetAbrDomainSection.DCDiagParagraph
                                                            BlankLine
                                                            $DCDiagObj
                                                        }
                                                    }
                                                } catch {
                                                    Write-PScriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. ('DCDiag Information)"
                                                    Write-PScriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }
                                            try {
                                                $ADInfraServices = foreach ($DC in $DCs) {
                                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                                        Get-AbrADInfrastructureService -DC $DC
                                                    }
                                                }
                                                if ($ADInfraServices) {
                                                    Section -Style Heading4 $reportTranslate.GetAbrDomainSection.InfraServicesSection {
                                                        Paragraph $reportTranslate.GetAbrDomainSection.InfraServicesParagraph
                                                        $ADInfraServices
                                                    }
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. (ADInfrastructureService)"
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                    Get-AbrADSiteReplication -Domain $DomainInfo -ValidDcFromDomain $ValidDC -DCs $DCs
                                    Get-AbrADGPO -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADOU -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                }
                            } else {
                                Write-PScriboMessage -Message "$($DomainInfo.DNSRoot) disabled in Exclude.Domain variable"
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Active Directory Domain)"
                        }
                    } else {
                        $DomainStatus.Value.Add(
                            @{
                                Name = $Domain
                                Status = 'Offline'
                            }
                        ) | Out-Null
                        Write-PScriboMessage -IsWarning -Message ($reportTranslate.GetAbrDomainSection.NoDCAvailable -f $Domain)
                    }
                }
            }
            if ($DomainObj) {
                Section -Style Heading1 $reportTranslate.GetAbrDomainSection.SectionTitle {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrDomainSection.DefinitionText
                        BlankLine
                    }
                    if (-not $Options.ShowDefinitionInfo) {
                        Paragraph $reportTranslate.GetAbrDomainSection.ParagraphDetail
                        BlankLine
                    }
                    $DomainObj
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Domain Section'
    }
}
