function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.7.11
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

    Write-PScriboMessage -IsWarning "Please refer to the AsBuiltReport.Microsoft.AD github website for more detailed information about this project."
    Write-PScriboMessage -IsWarning "Do not forget to update your report configuration file after each new release."
    Write-PScriboMessage -IsWarning "Documentation: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD"
    Write-PScriboMessage -IsWarning "Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues"

    Try {
        $InstalledVersion = Get-Module -ListAvailable -Name AsBuiltReport.Microsoft.AD -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version

        if ($InstalledVersion) {
            Write-PScriboMessage -IsWarning "AsBuiltReport.Microsoft.AD $($InstalledVersion.ToString()) is currently installed."
            $LatestVersion = Find-Module -Name AsBuiltReport.Microsoft.AD -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
            if ($LatestVersion -gt $InstalledVersion) {
                Write-PScriboMessage -IsWarning "AsBuiltReport.Microsoft.AD $($LatestVersion.ToString()) is available."
                Write-PScriboMessage -IsWarning "Run 'Update-Module -Name AsBuiltReport.Microsoft.AD -Force' to install the latest version."
            }
        }
    } Catch {
            Write-PscriboMessage -IsWarning $_.Exception.Message
        }

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        throw "The requested operation requires elevation: Run PowerShell console as administrator"
    }


    #Validate Required Modules and Features
    $OSType = (Get-ComputerInfo).OsProductType
    if ($OSType -eq 'WorkStation') {
        Get-RequiredFeature -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.CertificateServices.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.Dns.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.DHCP.Tools~~~~0.0.1.0' -OSType $OSType

    }
    if ($OSType -eq 'Server' -or $OSType -eq 'DomainController') {
        Get-RequiredFeature -Name RSAT-AD-PowerShell -OSType $OSType
        Get-RequiredFeature -Name RSAT-ADCS -OSType $OSType
        Get-RequiredFeature -Name RSAT-ADCS-mgmt -OSType $OSType
        Get-RequiredFeature -Name RSAT-DNS-Server -OSType $OSType
        Get-RequiredFeature -Name RSAT-DHCP -OSType $OSType
        Get-RequiredFeature -Name GPMC -OSType $OSType
    }

    Get-RequiredModule -Name PSPKI -Version '3.7.2'


    # Import Report Configuration
    $Global:Report = $ReportConfig.Report
    $Global:InfoLevel = $ReportConfig.InfoLevel
    $Global:Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $TextInfo = (Get-Culture).TextInfo

    #---------------------------------------------------------------------------------------------#
    #                                 Connection Section                                          #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {

        Try {
            Write-PScriboMessage "Connecting to Domain Controller Server '$System'."
            $script:TempPssSession = New-PSSession $System -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop
            $script:TempCIMSession = New-CIMSession $System -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop
            $ADSystem = Invoke-Command -Session $TempPssSession { Get-ADForest -ErrorAction Stop}
        } Catch {
            throw "Unable to connect to the Domain Controller: $System"
        }

        $script:ForestInfo =  $ADSystem.RootDomain.toUpper()
        [array]$RootDomains = $ADSystem.RootDomain
        [array]$ChildDomains = $ADSystem.Domains | Where-Object {$_ -ne $RootDomains}
        [string]$OrderedDomains = $RootDomains + $ChildDomains

        #---------------------------------------------------------------------------------------------#
        #                                 Forest Section                                              #
        #---------------------------------------------------------------------------------------------#
        Section -Style Heading1 "$($ForestInfo.toUpper())" {
            Paragraph "The following section provides a summary of the Active Directory Infrastructure configuration for $($ForestInfo)."
            BlankLine
            Write-PScriboMessage "Forest InfoLevel set at $($InfoLevel.Forest)."
            if ($InfoLevel.Forest -ge 1) {
                try {
                    Section -Style Heading2 "Forest Configuration."  {
                        if ($Options.ShowDefinitionInfo) {
                            Paragraph "The Active Directory framework that holds the objects can be viewed at a number of levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are accessible."
                            BlankLine
                        }
                        if (!$Options.ShowDefinitionInfo) {
                            Paragraph "The following section provides a summary of the Active Directory Forest Information."
                            BlankLine
                        }
                        try {
                            Get-AbrADForest
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                        }
                        try {
                            Get-AbrADSite
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
                Section -Style Heading2 "AD Domain Configuration" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user or a group or it can be a hardware component, such as a computer or printer.Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain or an alternate version (which may end in .local)."
                        BlankLine
                    }
                    if (!$Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory Domain Information."
                        BlankLine
                    }

                    foreach ($Domain in $OrderedDomains.split(" ")) {
                        if ($Domain) {
                            try {
                                if (($Domain -notin $Options.Exclude.Domains ) -and (Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain})) {
                                    Section -Style Heading3 "$($Domain.ToString().ToUpper())" {
                                        Paragraph "The following section provides a summary of the Active Directory Domain Information."
                                        BlankLine
                                        Get-AbrADDomain -Domain $Domain
                                        Get-AbrADFSMO -Domain $Domain
                                        Get-AbrADTrust -Domain $Domain
                                        Get-AbrADDomainObject -Domain $Domain
                                        if ($HealthCheck.Domain.Backup -or $HealthCheck.Domain.DFS -or $HealthCheck.Domain.SPN -or $HealthCheck.Domain.Security -or $HealthCheck.Domain.DuplicateObject) {
                                            Section -Style Heading4 'Health Checks' {
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
                                        Section -Style Heading4 'Domain Controllers' {
                                            if ($Options.ShowDefinitionInfo) {
                                                Paragraph "A domain controller (DC) is a server computer that responds to security authentication requests within a computer network domain. It is a network server that is responsible for allowing host access to domain resources. It authenticates users, stores user account information and enforces security policy for a domain."
                                                BlankLine
                                            }
                                            if (!$Options.ShowDefinitionInfo) {
                                                Paragraph "The following section provides a summary of the Active Directory Domain Controllers."
                                                BlankLine
                                            }
                                            $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs}}

                                            if ($DCs) {

                                                Get-AbrADDomainController -Domain $Domain -Dcs $DCs

                                                if ($InfoLevel.Domain -ge 2) {
                                                    Section -Style Heading5 "Roles" {
                                                        Paragraph "The following section provides a summary of the Domain Controller Role & Features information."
                                                        foreach ($DC in $DCs){
                                                            $DCStatus = Test-Connection -ComputerName $DC -Quiet -Count 1
                                                            if ($DCStatus -eq $false) {
                                                                Write-PScriboMessage -IsWarning "Unable to connect to $DC. Removing it from the $Domain report"
                                                            }
                                                            if ($DC -notin $Options.Exclude.DCs -and $DCStatus) {
                                                                Get-AbrADDCRoleFeature -DC $DC
                                                            }
                                                        }
                                                    }
                                                }
                                                if ($HealthCheck.DomainController.Diagnostic) {
                                                    try {
                                                        Section -Style Heading5 'DC Diagnostic' {
                                                            Paragraph "The following section provides a summary of the Active Directory DC Diagnostic."
                                                            BlankLine
                                                            foreach ($DC in $DCs){
                                                                if ($DC -notin $Options.Exclude.DCs -and (Test-Connection -ComputerName $DC -Quiet -Count 1)) {
                                                                    Get-AbrADDCDiag -Domain $Domain -DC $DC
                                                                }
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
                                                    Section -Style Heading5 "Infrastructure Services Status" {
                                                        Paragraph "The following section provides a summary of the Domain Controller Infrastructure services status."
                                                        foreach ($DC in $DCs){
                                                            if ($DC -notin $Options.Exclude.DCs -and (Test-Connection -ComputerName $DC -Quiet -Count 1)) {
                                                                Get-AbrADInfrastructureService -DC $DC
                                                            }
                                                        }
                                                    }
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation. (ADInfrastructureService)"
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                    continue
                                                }
                                            }
                                            Get-AbrADSiteReplication -Domain $Domain
                                            Get-AbrADGPO -Domain $Domain
                                            Get-AbrADOU -Domain $Domain
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
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DNS Section                                                 #
            #---------------------------------------------------------------------------------------------#
            if ($InfoLevel.DNS -ge 1) {
                Section -Style Heading2 "DNS Configuration" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                        BlankLine
                    }
                    if (!$Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory DNS Infrastructure Information."
                        BlankLine
                    }
                    foreach ($Domain in $OrderedDomains.split(" ")) {
                        if ($Domain) {
                            try {
                                if (($Domain -notin $Options.Exclude.Domains) -and (Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop})) {
                                    Section -Style Heading3 "$($Domain.ToString().ToUpper())" {
                                        Paragraph "The following section provides a configuration summary of the DNS service."
                                        BlankLine
                                        Get-AbrADDNSInfrastructure -Domain $Domain
                                        $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs}}
                                        foreach ($DC in $DCs){
                                            if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                                                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                                                Get-AbrADDNSZone -Domain $Domain -DC $DC
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
            }
            #---------------------------------------------------------------------------------------------#
            #                                 DHCP Section                                                #
            #---------------------------------------------------------------------------------------------#

            Try {
                $Global:DHCPinDomain = Get-DhcpServerInDC -CimSession $TempCIMSession
            } Catch {
                throw "Unable to get DHCP discovery from $System"
            }

            if ($InfoLevel.DHCP -ge 1 -and $DHCPinDomain ) {
                Section -Style Heading1 "DHCP Configuration" {
                    foreach ($Domain in ($OrderedDomains.split(" "))) {
                        if ($Domain -notin $Options.Exclude.Domains) {
                            try {
                                $DomainInfo = Invoke-Command -Session $TempPssSession {Get-ADDomain $using:Domain -ErrorAction Stop}
                                if ($DomainInfo) {
                                    Get-AbrDHCPReport -Domain $DomainInfo
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning "Unable to retreive $($Domain) information. Removing Domain from report"
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
                    $CurrentMachineADDomain = Get-ComputerADDomain -ErrorAction SilentlyContinue
                } catch {
                    Write-PscriboMessage -IsWarning 'Unable to determine current AD Domain'
                    Write-PscriboMessage -IsWarning $_.Exception.Message

                }
                if ($CurrentMachineADDomain.Name -in $ADSystem.Domains) {
                    Write-PScriboMessage "Current PC Domain $($CurrentMachineADDomain.Name) is in the Forrest Domain list of $($ADSystem.Name). Enabling Certificate Authority section"
                    try {
                        Write-PScriboMessage "Collecting Certification Authority information from $($System.split(".")[0])"
                        $Global:CAs = Get-CertificationAuthority -Enterprise
                    }
                    catch {
                        Write-PscriboMessage -IsWarning $_.Exception.Message
                    }

                    if ($CAs) {
                        try {
                            Section -Style Heading2 "CA Configuration" {
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
                                foreach ($CA in ($CAs | Where-Object {$_.IsAccessible -notlike 'False'}).ComputerName) {
                                    $CAObject = Get-CertificationAuthority -Enterprise -ComputerName $CA
                                    if ($CAObject) {
                                        Section -Style Heading3 "$($CAObject.DisplayName) Details" {
                                            try {
                                                Get-AbrADCASecurity -CA $CAObject
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                            try {
                                                Get-AbrADCACryptographyConfig -CA $CAObject
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                            if ($InfoLevel.CA -ge 2) {
                                                try {
                                                    Get-AbrADCAAIA -CA $CAObject
                                                    Get-AbrADCACRLSetting -CA $CAObject
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }
                                            if ($InfoLevel.CA -ge 2) {
                                                try {
                                                    Get-AbrADCATemplate -CA $CAObject
                                                }
                                                catch {
                                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                                }
                                            }
                                            try {
                                                Get-AbrADCAKeyRecoveryAgent -CA $CAObject
                                            }
                                            catch {
                                                Write-PscriboMessage -IsWarning $_.Exception.Message
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning $_.Exception.Message
                            continue
                        }
                    }
                } else {Write-PScriboMessage -IsWarning "Current PC Domain $($CurrentMachineADDomain.Name) is not in the Forrest Domain list of $($ADSystem.Name). Disabling Certificate Authority section"
            }
            }
        }#endregion AD Section
        Write-PscriboMessage "Clearing PowerShell Session $($TempPssSession.Id)"
        Remove-PSSession -Session $TempPssSession
        Write-PscriboMessage "Clearing CIM Session $($TempCIMSession.Id)"
        Remove-CIMSession -CimSession $TempCIMSession
	}#endregion foreach loop
}
