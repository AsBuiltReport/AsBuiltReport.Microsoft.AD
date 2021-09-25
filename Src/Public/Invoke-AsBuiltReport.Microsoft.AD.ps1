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
                        Paragraph "The Active Directory framework that holds the objects can be viewed at a number of levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are accessible."
                        BlankLine
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
                Section -Style Heading3 "Active Directory Domain summary for forest $($ForestInfo.toUpper())" {
                    Paragraph "An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user or a group or it can be a hardware component, such as a computer or printer.Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain or an alternate version (which may end in .local)."
                    BlankLine
                    foreach ($Domain in (Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        try {
                            if (Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain}) {
                                Section -Style Heading4 "Active Directory Information for domain $($Domain.ToString().ToUpper())" {
                                    Paragraph "The following section provides a summary of the AD Domain Information."
                                    BlankLine
                                    Get-AbrADDomain -Domain $Domain -Session $TempPssSession
                                    Get-AbrADFSMO -Domain $Domain -Session $TempPssSession
                                    Get-AbrADTrust -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    Section -Style Heading5 'Domain Controller Information' {
                                        Paragraph "The following section provides a summary of the Active Directory Domain Controller."
                                        BlankLine
                                        Get-AbrADDomainController -Domain $Domain -Session $TempPssSession -Cred $Credential
                                        if ($HealthCheck.DomainController.Diagnostic) {
                                            try {
                                                Section -Style Heading6 'DCDiag Information' {
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
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DNS Section                                                 #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DNS -gt 0) {
                Section -Style Heading3 "Domain Name System summary for forest $($ForestInfo.toUpper())" {
                    Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                    BlankLine
                    foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        try {
                            if (Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop}) {
                                Section -Style Heading4 "Domain Name System Information for domain $($Domain.ToString().ToUpper())" {
                                    Paragraph "The following section provides a configuration summary of the Domain Name System."
                                    BlankLine
                                    Get-AbrADDNSInfrastructure -Domain $Domain -Session $TempPssSession
                                    $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                    foreach ($DC in $DCs){
                                        Get-AbrADDNSZone -Domain $Domain -DC $DC -Cred $Credential
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
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DHCP Section                                                #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DHCP -gt 0) {
                Section -Style Heading3 "Dynamic Host Configuration Protocol summary for forest $($ForestInfo.toUpper())" {
                    Paragraph "The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol (IP) networks for automatically assigning IP addresses and other communication parameters to devices connected to the network using a client/server architecture."
                    BlankLine
                    foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        try {
                            Section -Style Heading4 "Dynamic Host Configuration Protocol information for domain $($Domain.ToString().ToUpper())" {
                                Paragraph "The following section provides a configuration summary of the Dynamic Host Configuration Protocol."
                                BlankLine
                                Get-AbrADDHCPInfrastructure -Domain $Domain -Session $TempPssSession
                                Get-AbrADDHCPv4Statistic -Domain $Domain -Session $TempPssSession
                                Get-AbrADDHCPv6Statistic -Domain $Domain -Session $TempPssSession
                                $DomainDHCPs = Invoke-Command -Session $Session { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} | Select-Object -ExpandProperty DnsName}
                                foreach ($DHCPServer in $DomainDHCPs){
                                    try {
                                        Get-AbrADDHCPv4Scope -Domain $Domain -Server $DHCPServer -Session $TempPssSession
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning $_.Exception.Message
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
            }
        }#endregion AD Section
        Write-PscriboMessage "Clearing PSSession $($TempPssSession.Id)"
        Remove-PSSession -Session $TempPssSession
	}#endregion foreach loop
}