function Get-AbrDomainSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Domain Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.5
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
        Write-PScriboMessage -Message "Collecting Domain information from $ForestInfo."
        Show-AbrDebugExecutionTime -Start -TitleMessage "Domain Section"
    }

    process {
        if ($InfoLevel.Domain -ge 1) {
            $DomainObj = foreach ($Domain in [string[]]($OrderedDomains | Where-Object { $_ -notin $Options.Exclude.Domains })) {
                if ($Domain -and ($Domain -notin $DomainStatus.Value.Name)) {
                    if ($ValidDC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                        # Define Filter option for Domain variable
                        try {
                            if ($DomainInfo = Invoke-Command -Session $TempPssSession { Get-ADDomain -Identity $using:Domain }) {
                                $DCs = Invoke-Command -Session $TempPssSession { Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } } | Sort-Object

                                Section -Style Heading2 "$($DomainInfo.DNSRoot.ToString().ToUpper())" {
                                    Paragraph "The following section provides a summary of the Active Directory Domain Information."
                                    BlankLine
                                    Get-AbrADDomain -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADFSMO -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADTrust -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADHardening -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    Get-AbrADDomainObject -Domain $DomainInfo -ValidDcFromDomain $ValidDC
                                    if ($HealthCheck.Domain.Backup -or $HealthCheck.Domain.DFS -or $HealthCheck.Domain.SPN -or $HealthCheck.Domain.Security -or $HealthCheck.Domain.DuplicateObject) {
                                        Section -Style Heading3 'Health Checks' {
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
                                    Section -Style Heading3 'Domain Controllers' {
                                        if ($Options.ShowDefinitionInfo) {
                                            Paragraph "A domain controller (DC) is a server computer that responds to security authentication requests within a computer network domain. It is a network server that is responsible for allowing host access to domain resources. It authenticates users, stores user account information and enforces security policy for a domain."
                                            BlankLine
                                        }
                                        if (-Not $Options.ShowDefinitionInfo) {
                                            if ($InfoLevel.Domain -ge 2) {
                                                Paragraph "The following section provides detailed information about Active Directory domain controllers."
                                                BlankLine
                                            } else {
                                                Paragraph "The following section provides an overview of Active Directory domain controllers."
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
                                                    Section -Style Heading4 "Roles" {
                                                        Paragraph "The following section provides a summary of installed role & features on $($DomainInfo.DNSRoot) DCs."
                                                        $RolesObj
                                                    }
                                                }
                                            }
                                            try {
                                                $ADInfraServices = foreach ($DC in $DCs) {
                                                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                                        Get-AbrADInfrastructureService -DC $DC
                                                    }
                                                }
                                                if ($ADInfraServices) {
                                                    Section -Style Heading4 "Infrastructure Services" {
                                                        Paragraph "The following section provides a summary of the Domain Controller Infrastructure services status."
                                                        $ADInfraServices
                                                    }
                                                }
                                            } catch {
                                                Write-PScriboMessage -IsWarning -Message "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. (ADInfrastructureService)"
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                    Get-AbrADSiteReplication -Domain $DomainInfo -ValidDcFromDomain $ValidDC
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
                        $DomainStatus.Value += @{
                            Name = $Domain
                            Status = 'Offline'
                        }
                        Write-PScriboMessage -IsWarning -Message "Unable to get an available DC in $($Domain) domain. Removing it from the report."
                    }
                }
            }
            if ($DomainObj) {
                Section -Style Heading1 "AD Domain Configuration" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user, a group, or a hardware component such as a computer or printer. Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain, or an alternate version (which may end in .local)."
                        BlankLine
                    }
                    if (-Not $Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory domain information."
                        BlankLine
                    }
                    $DomainObj
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "Domain Section"
    }
}
