function Get-AbrDomainSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD Domain Section.
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
    )

    begin {
        Write-PScriboMessage "Collecting Domain information from $ForestInfo."
    }

    process {
        if ($InfoLevel.Domain -ge 1) {
            Section -Style Heading1 "AD Domain Configuration" {
                if ($Options.ShowDefinitionInfo) {
                    Paragraph "An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user, a group, or a hardware component such as a computer or printer. Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain, or an alternate version (which may end in .local)."
                    BlankLine
                }
                if (-Not $Options.ShowDefinitionInfo) {
                    Paragraph "The following section provides a summary of the Active Directory domain information."
                    BlankLine
                }

                foreach ($Domain in $OrderedDomains.split(" ")) {
                    if ($Domain) {
                        # Define Filter option for Domain variable
                        if ($Options.Include.Domains) {
                            $DomainFilterOption = $Domain -in $Options.Include.Domains

                        } else {
                            $DomainFilterOption = $Domain -notin $Options.Exclude.Domains
                        }
                        try {
                            if (( $DomainFilterOption ) -and (Invoke-Command -Session $TempPssSession { Get-ADDomain -Identity $using:Domain })) {
                                Section -Style Heading2 "$($Domain.ToString().ToUpper())" {
                                    Paragraph "The following section provides a summary of the Active Directory Domain Information."
                                    BlankLine
                                    Get-AbrADDomain -Domain $Domain
                                    Get-AbrADFSMO -Domain $Domain
                                    Get-AbrADTrust -Domain $Domain
                                    Get-AbrADDomainObject -Domain $Domain
                                    if ($HealthCheck.Domain.Backup -or $HealthCheck.Domain.DFS -or $HealthCheck.Domain.SPN -or $HealthCheck.Domain.Security -or $HealthCheck.Domain.DuplicateObject) {
                                        Section -Style Heading3 'Health Checks' {
                                            Get-AbrADDomainLastBackup -Domain $Domain
                                            Get-AbrADDFSHealth -Domain $Domain
                                            if ($Domain -like $ADSystem.RootDomain) {
                                                Get-AbrADDuplicateSPN -Domain $ADSystem.RootDomain
                                            }
                                            Get-AbrADSecurityAssessment -Domain $Domain
                                            Get-AbrADKerberosAudit -Domain $Domain
                                            Get-AbrADDuplicateObject -Domain $Domain
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
                                        $DCs = Invoke-Command -Session $TempPssSession { Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } } | Sort-Object

                                        if ($DCs) {

                                            Get-AbrADDomainController -Domain $Domain -Dcs $DCs

                                            if ($InfoLevel.Domain -ge 2) {
                                                $RolesObj = foreach ($DC in $DCs) {
                                                    $DCStatus = Get-DCWinRMState -ComputerName $DC
                                                    if (-Not $DCStatus) {
                                                        Write-PScriboMessage -IsWarning "Unable to connect to $DC. Removing it from the $Domain report."
                                                    }
                                                    if ($DCStatus) {
                                                        Get-AbrADDCRoleFeature -DC $DC
                                                    }
                                                }
                                                if ($RolesObj) {
                                                    Section -Style Heading4 "Roles" {
                                                        Paragraph "The following section provides a summary of installed role & features on $Domain DCs."
                                                        $RolesObj
                                                    }
                                                }
                                            }
                                            if ($HealthCheck.DomainController.Diagnostic) {
                                                try {
                                                    $DCDiagObj = foreach ($DC in $DCs) {
                                                        if (Get-DCWinRMState -ComputerName $DC) {
                                                            Get-AbrADDCDiag -Domain $Domain -DC $DC
                                                        }
                                                    }
                                                    if ($DCDiagObj) {
                                                        Section -Style Heading4 'DC Diagnostic' {
                                                            Paragraph "The following section provides a summary of the Active Directory DC Diagnostic."
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
                                                    if (Get-DCWinRMState -ComputerName $DC) {
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
                                                Write-PScriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. (ADInfrastructureService)"
                                                Write-PScriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                    Get-AbrADSiteReplication -Domain $Domain
                                    Get-AbrADGPO -Domain $Domain
                                    Get-AbrADOU -Domain $Domain
                                }
                            } else {
                                Write-PScriboMessage "$($Domain) disabled in Exclude.Domain variable"
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Active Directory Domain)"
                        }
                    }
                }
            }
        }
    }
    end {}
}
