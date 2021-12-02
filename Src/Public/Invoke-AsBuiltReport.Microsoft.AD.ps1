function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.5.0
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
        Section -Style Heading1 "$($ForestInfo.toUpper()) Active Directory Report" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 "Forest Information."  {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph "The Active Directory framework that holds the objects can be viewed at a number of levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are accessible."
                            BlankLine
                        }
                        if (!$Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a summary of the Active Directory Forest Information."
                            BlankLine
                        }
                        try {
                            Get-AbrADForest -Session $TempPssSession
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADSite -Session $TempPssSession
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning "Error: Unable to retreive Forest: $ForestInfo information."
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 Domain Section                                              #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.Domain -ge 1) {
                Section -Style Heading3 "Active Directory Domain Information" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user or a group or it can be a hardware component, such as a computer or printer.Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain or an alternate version (which may end in .local)."
                        BlankLine
                    }
                    if (!$Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory Domain Information."
                        BlankLine
                    }
                    foreach ($Domain in (Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        try {
                            if (Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain}) {
                                Section -Style Heading4 "$($Domain.ToString().ToUpper()) Domain Configuration" {
                                    Paragraph "The following section provides a summary of the Active Directory Domain Information."
                                    BlankLine
                                    Get-AbrADDomain -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    Get-AbrADFSMO -Domain $Domain -Session $TempPssSession
                                    Get-AbrADTrust -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    Get-AbrADDomainObject -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    Section -Style Heading5 'Domain Controller Summary' {
                                        if ($Options.ShowDefinitionInfo) {
                                            Paragraph "A domain controller (DC) is a server computer that responds to security authentication requests within a computer network domain. It is a network server that is responsible for allowing host access to domain resources. It authenticates users, stores user account information and enforces security policy for a domain."
                                            BlankLine
                                        }
                                        if (!$Options.ShowDefinitionInfo) {
                                            Paragraph "The following section provides a summary of the Active Directory Domain Controllers."
                                            BlankLine
                                        }
                                        Get-AbrADDomainController -Domain $Domain -Session $TempPssSession -Cred $Credential
                                        $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                        if ($InfoLevel.Domain -ge 3) {
                                            foreach ($DC in $DCs){
                                                Get-AbrADDCRoleFeature -DC $DC -Cred $Credential
                                            }
                                        }
                                        if ($HealthCheck.DomainController.Diagnostic) {
                                            try {
                                                Section -Style Heading6 'DC Diagnostic' {
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
                                        Get-AbrADGPO -Domain $Domain -Session $TempPssSession -Cred $Credential
                                        Get-AbrADOU -Domain $Domain -Session $TempPssSession -Cred $Credential
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Active Directory Domain)"
                            continue
                        }
                    }
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DNS Section                                                 #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DNS -ge 1) {
                Section -Style Heading3 "Domain Name System Summary" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                        BlankLine
                    }
                    if (!$Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory DNS Infrastructure Information."
                        BlankLine
                    }
                    foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        try {
                            if (Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop}) {
                                Section -Style Heading4 "$($Domain.ToString().ToUpper()) DNS Configuration" {
                                    Paragraph "The following section provides a configuration summary of the DNS service."
                                    BlankLine
                                    Get-AbrADDNSInfrastructure -Domain $Domain -Session $TempPssSession
                                    if ($InfoLevel.DNS -ge 2) {
                                        $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
                                        foreach ($DC in $DCs){
                                            Get-AbrADDNSZone -Domain $Domain -DC $DC -Cred $Credential
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Name System Information)"
                            continue
                        }
                    }
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DHCP Section                                                #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DHCP -ge 1) {
                Section -Style Heading3 "Dynamic Host Configuration Protocol Summary" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "The Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on Internet Protocol (IP) networks for automatically assigning IP addresses and other communication parameters to devices connected to the network using a client/server architecture."
                        BlankLine
                    }
                    if (!$Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory DHCP Infrastructure Information."
                        BlankLine
                    }
                    foreach ($Domain in ( Invoke-Command -Session $TempPssSession {Get-ADForest | Select-Object -ExpandProperty Domains | Sort-Object -Descending})) {
                        Section -Style Heading4 "$($Domain.ToString().ToUpper()) Domain DHCP Configuration" {
                            Paragraph "The following section provides a summary of the Dynamic Host Configuration Protocol."
                            BlankLine
                            Get-AbrADDHCPInfrastructure -Domain $Domain -Session $TempPssSession
                            Section -Style Heading5 "IPv4 Scope Summary" {
                                Paragraph "The following section provides a IPv4 configuration summary of the Dynamic Host Configuration Protocol."
                                BlankLine
                                try {
                                    Get-AbrADDHCPv4Statistic -Domain $Domain -Session $TempPssSession
                                }
                                catch {
                                    Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Statistics from  $($Domain.ToString().ToUpper())."
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv4 DHCP Server Statistics)"
                                }
                                $DomainDHCPs = Invoke-Command -Session $TempPssSession { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} | Select-Object -ExpandProperty DnsName}
                                foreach ($DHCPServer in $DomainDHCPs){
                                    try {
                                        Get-AbrADDHCPv4Scope -Domain $Domain -Server $DHCPServer -Session $TempPssSession
                                    }
                                    catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv4 DHCP Server Scope information)"
                                    }
                                    if ($InfoLevel.DHCP -ge 2) {
                                        try {
                                            Section -Style Heading6 "$($DHCPServer.ToUpper().split(".", 2)[0]) IPv4 Scope Server Options" {
                                                Paragraph "The following section provides a summary of the DHCP servers IPv4 Scope Server Options information."
                                                BlankLine
                                                Get-AbrADDHCPv4ScopeServerSetting -Domain $Domain -Server $DHCPServer -Session $TempPssSession
                                                $DHCPScopes = Invoke-Command -Session $TempPssSession { Get-DhcpServerv4Scope -ComputerName $using:DHCPServer | Select-Object -ExpandProperty ScopeId}
                                                foreach ($Scope in $DHCPScopes) {
                                                    try {
                                                        Get-AbrADDHCPv4PerScopeSetting -Domain $Domain -Server $DHCPServer -Session $TempPssSession -Scope $Scope
                                                    }
                                                    catch {
                                                        Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv4 Scope configuration from $($DHCPServerr.split(".", 2)[0])."
                                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv4 DHCP Server Scope configuration)"
                                                    }
                                                }
                                            }
                                        }
                                        catch {
                                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv4 DHCP Scope Server Options)"
                                        }
                                    }
                                }
                            }
                            Section -Style Heading5 "IPv6 Scope Configuration" {
                                Paragraph "The following section provides a IPv6 configuration summary of the Dynamic Host Configuration Protocol."
                                BlankLine
                                try {
                                    Get-AbrADDHCPv6Statistic -Domain $Domain -Session $TempPssSession
                                }
                                catch {
                                    Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv6 Statistics from $($Domain.ToString().ToUpper())."
                                    Write-PScriboMessage -IsDebug  "$($_.Exception.Message) (IPv6 DHCP Server IPv6 Statistics)"
                                }
                                $DomainDHCPs = Invoke-Command -Session $TempPssSession { Get-DhcpServerInDC | Where-Object {$_.DnsName.split(".", 2)[1]  -eq $using:Domain} | Select-Object -ExpandProperty DnsName}
                                foreach ($DHCPServer in $DomainDHCPs){
                                    try {
                                        Get-AbrADDHCPv6Scope -Domain $Domain -Server $DHCPServer -Session $TempPssSession
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (IPv6 DHCP Scope Information)"
                                    }
                                    if ($InfoLevel.DHCP -ge 2) {
                                        try {
                                            Section -Style Heading6 "$($DHCPServer.ToUpper().split(".", 2)[0]) IPv6 Scope Server Options" {
                                                Paragraph "The following section provides a summary of the DHCP servers IPv6 Scope Server Options information."
                                                BlankLine
                                                Get-AbrADDHCPv6ScopeServerSetting -Domain $Domain -Server $DHCPServer -Session $TempPssSession
                                                $DHCPScopes = Invoke-Command -Session $TempPssSession { Get-DhcpServerv6Scope -ComputerName $using:DHCPServer | Select-Object -ExpandProperty Prefix}
                                                foreach ($Scope in $DHCPScopes) {
                                                    try {
                                                        Get-AbrADDHCPv6PerScopeSetting -Domain $Domain -Server $DHCPServer -Session $TempPssSession -Scope $Scope
                                                    }
                                                    catch {
                                                        Write-PScriboMessage -IsWarning "Error: Retreiving DHCP Server IPv6 Scope configuration from $($DHCPServerr.split(".", 2)[0])."
                                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv6 Per DHCP Scope configuration)"
                                                    }
                                                }
                                            }
                                        }
                                        catch {
                                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (IPv6 DHCP Scope Server Options)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            #---------------------------------------------------------------------------------------------#
            #                                 Certificate Authority Section                               #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.CA -ge 1) {
                try {
                    Section -Style Heading3 "Certificate Authority Summary" {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph 'In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.'
                            BlankLine
                        }
                        if (!$Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a summary of the Active Directory PKI Infrastructure Information."
                            BlankLine
                        }
                        try {
                            Get-AbrADCASummary
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        if ($InfoLevel.CA -ge 2) {
                            try {
                                Get-AbrADCARoot
                                Get-AbrADCASubordinate
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }
                        try {
                            Get-AbrADCASecurity
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADCACryptographyConfig
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        if ($InfoLevel.CA -ge 2) {
                            try {
                                Get-AbrADCAAIA
                                Get-AbrADCACRLSetting
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }
                        if ($InfoLevel.CA -ge 2) {
                            try {
                                Get-AbrADCATemplate
                            }
                            catch {
                                Write-PscriboMessage -IsWarning $_.Exception.Message
                            }
                        }
                        try {
                            Get-AbrADCAKeyRecoveryAgent
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                    }
                }
                catch {
                    Write-PscriboMessage -IsWarning $_.Exception.Message
                    continue
                }
            }
        }#endregion AD Section
        Write-PscriboMessage "Clearing PowerShell Session $($TempPssSession.Id)"
        Remove-PSSession -Session $TempPssSession
	}#endregion foreach loop
}