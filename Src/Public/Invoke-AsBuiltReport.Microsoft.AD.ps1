function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.2.0
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD
    #>

	# Do not remove or add to these parameters
    param (
        [String[]] $Target,
        [PSCredential] $Credential
    )

    # Import Report Configuration
    $Report = $ReportConfig.Report
    $InfoLevel = $ReportConfig.InfoLevel
    $Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $TextInfo = (Get-Culture).TextInfo

	# Update/rename the $System variable and build out your code within the ForEach loop. The ForEach loop enables AsBuiltReport to generate an as built configuration against multiple defined targets.

    #region foreach loop
    #---------------------------------------------------------------------------------------------#
    #                                 Connection Section                                          #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {
        Try {
            Write-PScriboMessage "Connecting to Domain Controller Server '$System'."
            $TempPssSession = New-PSSession $System -Credential $Credential -Authentication Default
            $ADSystem = Invoke-Command -Session $TempPssSession { Get-ADForest -ErrorAction Stop}
        } Catch {
            Write-Verbose "Unable to connect to the Domain Controller: $System"
            throw
        }
        $global:ForestInfo =  $ADSystem.RootDomain.toUpper()
        #---------------------------------------------------------------------------------------------#
        #                                 Forest Section                                              #
        #---------------------------------------------------------------------------------------------#
        Section -Style Heading1 "Report for Active Directory Forest $($ForestInfo.toUpper())" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -gt 0) {
                try {
                    Section -Style Heading2 "Forest Information."  {
                        Get-AbrADForest -Session $TempPssSession
                        Get-AbrADSite -Session $TempPssSession
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "Error: Unable to retreive Forest: $ForestInfo information."
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                    continue
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 Domain Section                                              #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.Domain -gt 0) {
                foreach ($Domain in (Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                    try {
                        if (Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain}) {
                            Section -Style Heading3 "Active Directory Information for domain $($Domain.ToString().ToUpper())" {
                                Paragraph "The following section provides a summary of the AD Domain Information."
                                BlankLine
                                Get-AbrADDomain -Domain $Domain -Session $TempPssSession
                                Get-AbrADFSMO -Domain $Domain -Session $TempPssSession
                                Get-AbrADTrust -Domain $Domain -Session $TempPssSession -Cred $Credential
                                Section -Style Heading4 'Domain Controller Information' {
                                    Paragraph "The following section provides a summary of the Active Directory Domain Controller."
                                    BlankLine
                                    Get-AbrADDomainController -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    if ($HealthCheck.DomainController.Diagnostic) {
                                        try {
                                            Section -Style Heading4 'DCDiag Information' {
                                                Paragraph "The following section provides a summary of the Active Directory DC Diagnostic."
                                                BlankLine
                                                $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                                foreach ($DC in $DCs){
                                                    Get-AbrADDCDiag -Domain $Domain -Session $TempPssSession -DC $DC
                                                }
                                            }
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. ('DCDiag Information)"
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
                                            continue
                                        }
                                    }
                                    try {
                                        $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                        foreach ($DC in $DCs){
                                            Get-AbrADInfrastructureService -DC $DC -Cred $Credential
                                        }
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. (ADInfrastructureService)"
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
                                        continue
                                    }
                                    Get-AbrADSiteReplication -Domain $Domain -Session $TempPssSession
                                    Get-AbrADGPO -Domain $Domain -Session $TempPssSession
                                    Get-AbrADOU -Domain $Domain -Session $TempPssSession
                                }
                            }
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                        continue
                    }
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DNS Section                                                 #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DNS -gt 0) {
                foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                    try {
                        if (Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop}) {
                            Section -Style Heading3 "Domain Name System Information for domain $($Domain.ToString().ToUpper())" {
                                Paragraph "The following section provides a summary of the Domain Name System Information."
                                BlankLine
                                Get-AbrADDNSInfrastructure -Domain $Domain -Session $TempPssSession
                            }
                        }
                        $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        foreach ($DC in $DCs){
                            Get-AbrADDNSZone -Domain $Domain -DC $DC -Cred $Credential
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                        continue
                    }
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DHCP Section                                                 #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DHCP -gt 0) {
                foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                    try {
                        Section -Style Heading3 "DHCP Server Summary on Active Directory $($ForestInfo.toUpper())" {
                            Paragraph "The following section provides a summary of the Dynamic Host Configuration Protocol"
                            BlankLine
                            Get-AbrADDHCPInfrastructure -Domain $Domain -Session $TempPssSession
                        }
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                        continue
                    }
                }
            }
        }#endregion AD Section
        Write-PscriboMessage "Clearing PSSession $($TempPssSession.Id)"
        Remove-PSSession -Session $TempPssSession
	}#endregion foreach loop
}