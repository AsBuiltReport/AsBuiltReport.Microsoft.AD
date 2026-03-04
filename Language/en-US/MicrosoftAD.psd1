# culture = 'en-US'
@{
    # InvokeAsBuiltReportMicrosoftAD
    InvokeAsBuiltReportMicrosoftAD = ConvertFrom-StringData @'
    PwshISE = This script cannot be run inside the PowerShell ISE. Please execute it from the PowerShell Command Window.
    ReportModuleInfo3 = - Documentation: https://github.com/AsBuiltReport/AsBuiltReport.{0}
    ReportModuleInfo2 = - Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.{0}/issues
    ReportModuleInfo1 = - Do not forget to update your report configuration file after each new version release: https://www.asbuiltreport.com/user-guide/new-asbuiltreportconfig/
    ReportModuleInfo4 = - To sponsor this project, please visit:
    ReportModuleInfo5 = https://ko-fi.com/F1F8DEV80
    ReportModuleInfo6 = - Getting dependency information:
    ProjectWebsite = - Please refer to the AsBuiltReport.Microsoft.AD github website for more detailed information about this project.
    CommunityProject = - AsBuiltReport is a community-maintained open source project. It has no sponsorship, endorsement, or affiliation with any technology vendors, their employees, or affiliates.
    DISCLAIMER = This report combines automated data analysis with professional observations. While these findings offer expert insight, this assessment is not exhaustive. All recommendations should be reviewed and implemented by qualified personnel. The author(s) assume no liability for any damages-including lost profits, business interruptions, or financial losses-arising from the use of this report or its recommendations.
'@

    # InvokeAsBuiltReportMicrosoftAD
    ConvertToTextYN = ConvertFrom-StringData @'
    Yes = Yes
    No = No
'@

    # Get-AbrForestSection
    GetAbrForestSection = ConvertFrom-StringData @'
    Collecting = Collecting Forest information from {0}.
    Paragraph = This section provides a comprehensive overview of the Active Directory infrastructure and configuration for the {0} forest.
    Heading = Forest Configuration
    DefinitionText = The Active Directory framework that holds the objects can be viewed at several levels. The forest, tree, and domain are the logical divisions in an Active Directory network. At the top of the structure is the forest, which is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, computers, groups, and other objects are contained.
    ParagraphDetail = The following section provides a detailed summary of the Active Directory Forest infrastructure and configuration.
    ErrorForest = Error: Unable to retrieve Forest: {0} information.
'@

    # Get-AbrADForest
    GetAbrADForest = ConvertFrom-StringData @'
    InfoLevel  = {0} InfoLevel set at {1}.
    Collecting  = Collecting Active Directory forest information.
    ParagraphDetail = The following sections detail the forest information.
    ParagraphSummary = The following table summarises the forest information.
    Heading = Forest Information

    ForestName = Forest Name
    ForestFunctionalLevel = Forest Functional Level
    SchemaVersion = Schema Version
    SchemaVersionValue = ObjectVersion {0}, Correspond to {1}
    TombstoneLifetime = Tombstone Lifetime (days)
    Domains = Domains
    GlobalCatalogs = Global Catalogs
    DomainsCount = Domains Count
    GlobalCatalogsCount = Global Catalogs Count
    SitesCount = Sites Count
    ApplicationPartitions = Application Partitions
    PartitionsContainer = Partitions Container
    SPNSuffixes = SPN Suffixes
    UPNSuffixes = UPN Suffixes
    AnonymousAccess = Anonymous Access (dsHeuristics)
    AnonymousAccessEnabled = Enabled
    AnonymousAccessDisabled = Disabled

    ForestDiagram = Forest Diagram
    CASection = Certificate Authority
    CADefinition = In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.
    CAParagraph = The following section provides an overview of the Public Key Infrastructure (PKI) configuration deployed within the Active Directory environment.
    CARootSection = Certificate Authority Root(s)
    CAIssuerSection = Certificate Authority Issuer(s)
    CAName = Name
    CADistinguishedName = Distinguished Name
    CADnsName = DNS Name
    MultipleRootCABP = In most PKI (Public Key Infrastructure) implementations, it is not typical to have multiple Root CAs (Certificate Authorities). The Root CA is the top-most authority in a PKI hierarchy and is responsible for issuing certificates to subordinate CAs and end entities. Having multiple Root CAs can complicate the trust relationships and management of certificates. It is recommended to conduct a detailed review of the current PKI infrastructure and Root CA requirements to ensure proper security and management practices are followed.
    OptionalFeatures = Optional Features
    OFName = Name
    OFRequiredForestMode = Required Forest Mode
    OFEnabled = Enabled
    OFEnabledYes = Yes
    OFEnabledNo = No

    HealthCheck = Health Check:
    BestPractice = Best Practice:
    Reference = Reference:
    AnonAccessBP = Anonymous access to Active Directory forest data above the rootDSE level must be disabled. This is to ensure that unauthorized users cannot access sensitive directory information, which could potentially be exploited for malicious purposes.
    AnonAccessRef = https://www.stigviewer.com/stig/active_directory_forest/2016-02-19/finding/V-8555
    TombstoneBP = Set the Tombstone Lifetime to a minimum of 180 days to ensure that deleted objects are retained for a sufficient period before being permanently removed from the directory. This allows for recovery of accidentally deleted objects and helps in maintaining the integrity of the Active Directory environment.
    RecycleBinBP = Accidental deletion of Active Directory objects is a common issue for AD DS users. Enabling the Recycle Bin feature allows for the recovery of these accidentally deleted objects, helping to maintain the integrity and continuity of the Active Directory environment.
    RecycleBinRef = https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944
'@
    NewADDiagram = ConvertFrom-StringData @'
    genMain = Please wait while the {0} diagram is being generated
    gereratingDiag = Generating {0} diagram
    diagramSignature = No diagram signature specified
    genDiagramSignature = Generating Signature SubGraph
    genDiagramMain =  Generating Main SubGraph
    osType = {0} is required to run the Diagrammer.Microsoft.AD. Run 'Install-WindowsFeature -Name '{0}'' to install the required modules. https://github.com/rebelinux/Diagrammer.Microsoft.AD
    outputfolderpatherror = OutputFolderPath {0} is not a valid folder path.
    runasadmin = The requested operation requires elevation: Run PowerShell console as administrator
    signaturerequirements = New-AbrADDiagram: AuthorName and CompanyName must be defined if the Signature option is specified
    psSessionClear = Clearing PowerShell Session {0}
    psSessionSetup = Setting PowerShell Session for {0}
    unableToConnect = Unable to connect to {0} Domain Controller Server.
    InfoProject = - Please refer to the Diagrammer.Microsoft.AD github website for more detailed information about this project.
    InfoDocumentation = - Documentation: https://github.com/rebelinux/Diagrammer.Microsoft.AD
    InfoIssues = - Issues or bug reporting: https://github.com/rebelinux/Diagrammer.Microsoft.AD/issues
    InfoCommunity = - This project is community maintained and has no sponsorship from Microsoft, its employees or any of its affiliates.
    InfoVersion = - {0} v{1} is currently installed.
    WarningUpdate =   - {0} v{1} update is available.
    WarningUpdateCommand =   - Run 'Update-Module -Name {0} -Force' to install the latest version.

    forestgraphlabel = Active Directory Forest Architecture
    domaingraphlabel = Active Directory Domain Architecture
    emptyForest = No Forest Infrastructure available to diagram
    fDomainNaming = Domain Naming
    fSchema = Schema
    fFuncLevel = Functional Level
    fInfrastructure = Infrastructure
    fPDC = PDC Emulator
    fRID = RID
    fSchemaVersion = Schema Version
    fForestRoot = Forest Root
    fForestRootInfo = Forest Root Information
    fForestRootLabel = Forest Root
    fChildDomains = Child Domains
    fNoChildDomains = No Child Domains

    connectingDomain = Collecting Microsoft AD Domain information from {0}.
    connectingForest = Collecting Microsoft AD Forest information from {0}.
    forestRootInfo = Forest Root Information

    DiagramLabel = Child Domains
    contiguous = Contiguous
    noncontiguous = Non Contiguous
    osTypelast = Unable to validate if {0} is installed.
    DiagramDummyLabel = Child Domains
    NoChildDomain = No Child Domains
    funcLevel = <B>Func Level</B>: {0}
    schemaVersion = <B>Schema Ver</B>: {0}
    infrastructure = <B>Infrastructure:</B> {0}
    rID = <B>RID:</B> {0}
    pdcEmulator= <B>PDC Emulator:</B> {0}
    schema = <B>Schema:</B> {0}
    domainNaming = <B>Domain Naming:</B> {0}
    fsmoRoles = FSMO Roles
    MicrosoftLogo = Microsoft Logo

    SitesDiagramDummyLabel = Sites
    sitesgraphlabel = Active Directory Site Topology
    sitesinventorygraphlabel = Active Directory Site Inventory
    NoSites = No Site Topology
    NoSiteSubnet = No Site Subnets
    siteLinkCost = Site Link Cost
    siteLinkFrequency = Site Link Frequency
    siteLinkFrequencyMinutes = minutes
    siteLinkName = Site Link
    siteLinkNameInterSiteTP = Site Link Protocol
    NoSiteDC = No Site Domain Controllers
    emptySites = No Site topology available to diagram
    connectingSites = Collecting Microsoft AD Sites information from {0}.
    buildingSites = Building Microsoft AD Sites diagram from {0}.

    NoTrusts = No Trusts Topology
    emptyTrusts = No Trust topology available to diagram
    connectingSTrusts = Collecting Microsoft AD Trusts information from {0}.
    genDiagTrust = Generating Trusts Diagram
    trustsDiagramLabel = Active Directory Domains and Trusts
    buildingTrusts = Building Microsoft AD Trust diagram from {0}.
    trustDirection = Direction
    trustType = Flavor
    TrustAttributes = Type
    AuthenticationLevel = Authentication
    TrustRelationships = Trust Relationships

    Base64Output = Displaying Base64 string
    DiagramOutput = '{0}' diagram file '{1}' has been saved to '{2}'

    caDiagramLabel = Active Directory Certificate Authority
    caStdRootCA = Standalone Root CA
    caEntRootCA = Enterprise Root CA
    caEntSubCA = Enterprise Subordinate CA
    caEnterpriseCA = Enterprise CA
    caStandaloneCA = Standalone CA
    caSubordinateCA = Subordinate CA
    NoCA = No Certificate Authority Infrastructure
    caNotBefore = Not Before
    caNotAfter = Not After
    caType = Type
    caRootCaIssuer = Root CA Issuer
    caDnsName = Dns Name

    DomainControllers = Domain Controllers
    Sites = Sites
    Subnets = Subnets

    replicationDiagramLabel = Active Directory Replication Topology
    NoReplication = No Replication Topology
    emptyReplication = No Replication topology available to diagram
    connectingReplication = Collecting Microsoft AD Replication information from {0}.
    buildingReplication = Building Microsoft AD Replication diagram from {0}.
    replTransportProtocol = Protocol
    replAutoGenerated = Auto Generated
    replEnabled = Enabled
    replYes = Yes
    replNo = No
    replUnknownSite = Unknown Site
'@
    # Get-AbrADExchange
    GetAbrADExchange = ConvertFrom-StringData @'
    Collecting = Collecting AD Exchange information of {0}.
    Heading = Exchange Infrastructure
    Paragraph = The following section provides a comprehensive overview of the Exchange infrastructure deployed in the Active Directory environment.
    Name = Name
    DnsName = DNS Name
    ServerRoles = Server Roles
    Version = Version
'@

    # Get-AbrADSCCM
    GetAbrADSCCM = ConvertFrom-StringData @'
    Collecting = Collecting AD SCCM information of {0}.
    Heading = SCCM Infrastructure
    Paragraph = The following section provides a summary of the System Center Configuration Manager (SCCM) infrastructure registered in Active Directory.
    Name = Name
    ManagementPoint = Management Point
    SiteCode = Site Code
    Version = Version
'@

    # Get-AbrDHCPinAD
    GetAbrDHCPinAD = ConvertFrom-StringData @'
    Collecting = Collecting AD DHCP Servers information of {0}.
    Heading = DHCP Infrastructure
    Paragraph = The following section provides an overview of the DHCP servers registered in Active Directory.
    ServerName = Server Name
    IsDomainController = Is Domain Controller?
    Yes = Yes
    No = No
    Unknown = Unknown
'@

    # Get-AbrADSite
    GetAbrADSite = ConvertFrom-StringData @'
    Collecting = Collecting Active Directory Sites information of forest {0}.
    Replication = Replication
    ReplicationParagraph1 = Replication is the process by which Active Directory objects are transferred and synchronized between domain controllers within the domain and forest, ensuring consistency across the infrastructure.
    ReplicationParagraph2 = The following section provides detailed information about Active Directory replication and its associated relationships.
    SiteInventoryDiagram = Site Inventory Diagram
    SiteTopologyDiagram = Site Topology Diagram
    Sites = Sites
    SiteName = Site Name
    Description = Description
    SubnetsCol = Subnets
    DomainControllers = Domain Controllers
    NoSubnetAssigned = No subnet assigned
    NoDCAssigned = No DC assigned
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    DescBP = It is a good practice to establish well-defined descriptions. This helps to speed up the fault identification process and enables better documentation of the environment.
    SiteSubnetBP = Ensure Sites have an associated subnet. If subnets are not associated with AD Sites users in the AD Sites might choose a remote domain controller for authentication which in turn might result in excessive use of a remote domain controller.
    SiteDCBP = It is important to ensure that each site has at least one assigned domain controller. Missing domain controllers can lead to authentication delays and potential service disruptions for users in the site.
    ConnectionObjects = Connection Objects
    Name = Name
    FromServer = From Server
    ToServer = To Server
    FromSite = From Site
    AutoGenerated = <automatically generated>
    ConnectionObjectsBP = By default, the replication topology is managed automatically and optimizes existing connections. However, manual connections created by an administrator are not modified or optimized. Verify that all topology information is entered for Site Links and delete all manual connection objects.
    SiteSubnets = Site Subnets
    Subnet = Subnet
    NoSiteAssigned = No site assigned
    SubnetSiteBP = Ensure Subnet have an associated site. If subnets are not associated with AD Sites, users in the AD Sites might choose a remote domain controller for authentication. This can lead to increased latency and potential performance issues for users authenticating against a domain controller that is not local to their site.
    MissingSubnets = Missing Subnets in AD
    MissingSubnetsTable = Missing Subnets
    MissingSubnetsParagraph = The following table lists the NO_CLIENT_SITE entries found in the netlogon.log file on each Domain Controller in the forest. These entries indicate client IP addresses that could not be mapped to an Active Directory site.
    DC = DC
    IP = IP
    MissingSubnetsBP = Ensure that all subnets at each site are properly defined. Missing subnets can cause clients to not use the site's local Domain Controllers.
    InterSiteTransports = Inter-Site Transports
    InterSiteTransportsParagraph = Site links in Active Directory represent the inter-site connectivity and method used to transfer replication traffic. There are two transport protocols that can be used for replication via site links. The default protocol used in site link is IP, and it performs synchronous replication between available domain controllers. The SMTP method can be used when the link between sites is not reliable.
    BridgeAllSiteLinks = Bridge All Site Links
    IgnoreSchedules = Ignore Schedules
    Yes = Yes
    No = No
    Unknown = Unknown
    IPSection = IP
    SiteLinks = Site Links
    SiteLinkName = Site Link Name
    Cost = Cost
    ReplicationFrequency = Replication Frequency
    TransportProtocol = Transport Protocol
    Options = Options
    ChangeNotificationDisabled = Change Notification is Disabled
    Option0 = (0) Change Notification is Disabled
    Option1 = (1) Change Notification is Enabled with Compression
    Option2 = (2) Force sync in opposite direction at end of sync
    Option3 = (3) Change Notification is Enabled with Compression and Force sync in opposite direction at end of sync
    Option4 = (4) Disable compression of Change Notification messages
    Option5 = (5) Change Notification is Enabled without Compression
    Option6 = (6) Force sync in opposite direction at end of sync and Disable compression of Change Notification messages
    Option7 = (7) Change Notification is Enabled without Compression and Force sync in opposite direction at end of sync
    ProtectedFromAccidentalDeletion = Protected From Accidental Deletion
    SiteLinkChangeNotifBP = Enabling change notification treats an inter-site replication connection like an intra-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an option number value of 5 (Change Notification is Enabled without Compression).
    SiteLinkProtectedBP = If the Site Links in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.
    SiteLinkBridges = Site Link Bridges
    SiteLinkBridgesName = Site Link Bridges Name
    SiteLinksCol = Site Links
    SiteLinkBridgesProtectedBP = If the Site Links Bridges in your Active Directory are not protected from accidental deletion, your environment can experience disruptions that might be caused by accidental bulk deletion of objects.
    SMTPSection = SMTP
    SMTPParagraph = SMTP replication is used for sites that cannot use the others, but as a general rule, it should never be used. It is reserved when network connections are not always available, therefore, you can schedule replication.
    SMTPChangeNotifBP = Enabling change notification treats an INTER-site replication connection like an INTRA-site connection. Replication between sites with change notification is almost instant. Microsoft recommends using an Option number value of 5 (Change Notification is Enabled without Compression).
    SysvolReplication = Sysvol Replication
    DCName = DC Name
    ReplicationStatus = Replication Status
    Domain = Domain
    StatusUninitialized = Uninitialized
    StatusInitialized = Initialized
    StatusInitialSync = Initial synchronization
    StatusAutoRecovery = Auto recovery
    StatusNormal = Normal
    StatusInErrorState = In error state
    StatusDisabled = Disabled
    StatusUnknown = Unknown
    StatusOffline = Offline
    SysvolBP = SYSVOL is a special directory that resides on each domain controller (DC) within a domain. The directory comprises folders that store Group Policy objects (GPOs) and logon scripts that clients need to access and synchronize between DCs. For these logon scripts and GPOs to function properly, SYSVOL should be replicated accurately and rapidly throughout the domain. Ensure that proper SYSVOL replication is in place to ensure identical GPO/SYSVOL content for the domain controller across all Active Directory domains.
'@

    # Get-AbrDNSSection
    GetAbrDNSSection = ConvertFrom-StringData @'
    Collecting = Collecting DNS server information from {0}.
    CollectingDomain = Collecting DNS information from {0}.
    DomainParagraph = The following section provides a comprehensive summary of the DNS service configuration and settings for this domain.
    ExcludedDomain = {0} disabled in Exclude.Domain variable
    NoDCAvailable = Unable to get an available DC in {0} domain. Removing domain from the DNS section.
    Heading = DNS Configuration
    DefinitionParagraph = The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols.
    Paragraph = The following section provides a comprehensive overview of the DNS infrastructure configuration and settings within the Active Directory environment.
'@

    # Get-AbrADDNSInfrastructure
    GetAbrADDNSInfrastructure = ConvertFrom-StringData @'
    Collecting = Collecting Active Directory Domain Name System Infrastructure information for {0}
    InfrastructureSummary = Infrastructure Summary
    InfrastructureSummaryParagraph = This section provides a comprehensive overview of the DNS infrastructure configuration for the domain.
    AppDirectoryPartition = Application Directory Partition
    AppDirectoryPartitionParagraph = This section provides detailed information about the Application Directory Partitions configured on each DNS server in the domain.
    ResponseRateLimiting = Response Rate Limiting (RRL)
    ResponseRateLimitingTable = Response Rate Limiting
    ScavengingOptions = Scavenging Options
    ScavengingTable = Scavenging
    ForwarderOptions = Forwarder Options
    ForwardersTable = Forwarders
    RootHints = Root Hints
    RootHintsParagraph = This section provides detailed information about the Root Hints configuration for each DNS server in the {0} domain.
    ZoneScopeRecursion = Zone Scope Recursion
    DirectoryPartitions = Directory Partitions
    DCName = DC Name
    BuildNumber = Build Number
    IPv6 = IPv6
    DnsSec = DnsSec
    ReadOnlyDC = ReadOnly DC
    ListeningIP = Listening IP
    Name = Name
    State = State
    Flags = Flags
    ZoneCount = Zone Count
    Status = Status
    ResponsesPerSec = Responses Per Sec
    ErrorsPerSec = Errors Per Sec
    WindowInSec = Window In Sec
    LeakRate = Leak Rate
    TruncateRate = Truncate Rate
    NoRefreshInterval = NoRefresh Interval
    RefreshInterval = Refresh Interval
    ScavengingInterval = Scavenging Interval
    LastScavengeTime = Last Scavenge Time
    ScavengingState = Scavenging State
    IPAddress = IP Address
    Timeout = Timeout
    UseRootHint = Use Root Hint
    UseRecursion = Use Recursion
    IPv4Address = IPv4 Address
    IPv6Address = IPv6 Address
    ZoneName = Zone Name
    Forwarder = Forwarder
    Enabled = Enabled
    Disabled = Disabled
    ZoneScopeRoot = Root
    HealthCheck = Health Check:
    BestPractice = Best Practices:
    CorrectiveActions = Corrective Actions:
    Reference = Reference:
    ScavengingBP = Microsoft recommends to enable aging/scavenging on all DNS servers. However, with AD-integrated zones ensure to enable DNS scavenging on one DC at main site. The results will be replicated to other DCs.
    ForwarderMaxBP = Configure the servers to use no more than two external DNS servers as Forwarders. Using more than two forwarders can lead to increased resolution times and potential issues with DNS query load balancing. It is recommended to use two reliable and geographically diverse DNS servers to ensure redundancy and optimal performance.
    ForwarderRefURL = https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/forwarders-resolution-timeouts
    ForwarderMinBP = For redundancy reason, more than one forwarding server should be configured
    RootHintsMissingCA = A default installation of the DNS server role should have root hints unless the server has a root zone - .(root). If the server has a root zone then delete it. If the server doesn't have a root zone and there are no root servers listed on the Root Hints tab of the DNS server properties then the server may be missing the cache.dns file in the %systemroot%\\system32\\dns directory, which is where the list of root servers is loaded from.
    RootHintsDuplicateCA = Duplicate IP Address found in the table of the DNS root hints servers. The DNS console does not show the duplicate Root Hint servers; you can only see them using the DNS PowerShell cmdlets. While there is a dnscmd utility to replace the Root Hints file, Using PowerShell is the best way to remediate this issue.
'@

    # Get-AbrADDNSZone
    GetAbrADDNSZone = ConvertFrom-StringData @'
    Collecting = Collecting Active Directory Domain Name System Zone information on {0}.
    DNSZonesSuffix = DNS Zones
    ZoneDelegation = Zone Delegation
    ZoneTransfers = Zone Transfers
    ReverseLookupZone = Reverse Lookup Zone
    ConditionalForwarder = Conditional Forwarder
    ZoneScopeAging = Zone Scope Aging
    ZonesTable = Zones
    ZoneDelegationsTable = Zone Delegations
    ConditionalForwardersTable = Conditional Forwarders
    ZoneAgingPropertiesTable = Zone Aging Properties
    ZoneName = Zone Name
    ZoneType = Zone Type
    ReplicationScope = Replication Scope
    DynamicUpdate = Dynamic Update
    DSIntegrated = DS Integrated
    ReadOnly = Read Only
    Signed = Signed
    ChildZone = Child Zone
    NameServer = Name Server
    IPAddress = IP Address
    SecondaryServers = Secondary Servers
    NotifyServers = Notify Servers
    SecureSecondaries = Secure Secondaries
    MasterServers = Master Servers
    AgingEnabled = Aging Enabled
    RefreshInterval = Refresh Interval
    NoRefreshInterval = NoRefresh Interval
    AvailableForScavenge = Available For Scavenge
    SecureSecondariesAll = Send zone transfers to all secondary servers that request them.
    SecureSecondariesAuth = Send zone transfers only to name servers that are authoritative for the zone.
    SecureSecondariesSpec = Send zone transfers only to servers you specify in Secondary Servers.
    SecureSecondariesNone = Do not send zone transfers.
    Yes = Yes
    HealthCheck = Health Check:
    BestPractice = Best Practices:
    ZoneTransferBP = Configure all DNS zones only to allow zone transfers from Trusted IP addresses. This ensures that only authorized DNS servers can receive zone data, reducing the risk of unauthorized access or data leakage. It is a best practice to specify the IP addresses of the secondary DNS servers that are allowed to receive zone transfers.
    ZoneAgingBP = Microsoft recommends to enable aging/scavenging on all DNS servers. However, with AD-integrated zones ensure to enable DNS scavenging on one DC at main site. The results will be replicated to other DCs.
'@

    # Get-AbrPKISection
    GetAbrPKISection = ConvertFrom-StringData @'
    Collecting = Collecting PKI infrastructure information from {0}.
    UnableDomain = Unable to determine current AD Domain
    DomainInForest = Current PC Domain {0} is in the Forest Domain list of {1}. Enabling Certificate Authority section
    Heading = PKI Configuration
    DefinitionParagraph = In cryptography, a certificate authority or certification authority (CA) is an entity that issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate. This allows others (relying parties) to rely upon signatures or on assertions made about the private key that corresponds to the certified public key. A CA acts as a trusted third party trusted both by the subject (owner) of the certificate and by the party relying upon the certificate. The format of these certificates is specified by the X.509 or EMV standard.
    Paragraph = The following section provides a comprehensive overview of the Active Directory Public Key Infrastructure (PKI) configuration and its components.
    DetailsSuffix = Details
    DomainNotInForest = Current PC Domain {0} is not in the Forest Domain list of {1}. Disabling Certificate Authority section
'@

    # Get-AbrADCASummary
    GetAbrADCASummary = ConvertFrom-StringData @'
    Collecting = Collecting Certification Authority information.
    CAName = CA Name
    ServerName = Server Name
    Type = Type
    Status = Status
    TableName = Certification Authority
'@

    # Get-AbrADCARoot
    GetAbrADCARoot = ConvertFrom-StringData @'
    Collecting = Collecting AD Certification Authority Per Domain information.
    Heading = Enterprise Root Certificate Authority
    Paragraph = The following section provides detailed information about the Enterprise Root Certificate Authority (CA) configuration and operational status.
    CAName = CA Name
    ServerName = Server Name
    Type = Type
    ConfigString = Config String
    OperatingSystem = Operating System
    Certificate = Certificate
    Auditing = Auditing
    Status = Status
    AuditingNotConfigured = Not Configured
    Auditing1 = Start and stop Active Directory® Certificate Services (1)
    Auditing2 = Back up and restore the CA database (2)
    Auditing4 = Issue and manage certificate requests (4)
    Auditing8 = Revoke certificates and publish CRLs (8)
    Auditing16 = Change CA security settings (16)
    Auditing32 = Change CA security settings (32)
    Auditing64 = Change CA configuration (64)
    AuditingFull = Auditing is fully enabled (127)
    AuditingUnknown = Unknown
    TableName = Enterprise Root CA
    HealthCheck = Health Check:
    SecurityBestPractice = Security Best Practice:
    AuditingBP = Auditing should be fully enabled for the Certification Authority to ensure that all relevant events are logged for security monitoring and incident response purposes. This includes events related to certificate issuance, revocation, and changes to CA configuration.
'@

    # Get-AbrADCASubordinate
    GetAbrADCASubordinate = ConvertFrom-StringData @'
    Collecting = Collecting AD Certification Authority Per Domain information.
    Heading = Enterprise Subordinate Certificate Authority
    Paragraph = The following section provides detailed information about Enterprise Subordinate Certification Authorities within the domain.
    CAName = CA Name
    ServerName = Server Name
    Type = Type
    ConfigString = Config String
    OperatingSystem = Operating System
    Certificate = Certificate
    Auditing = Auditing
    Status = Status
    AuditingNotConfigured = Not Configured
    Auditing1 = Start and stop Active Directory® Certificate Services (1)
    Auditing2 = Back up and restore the CA database (2)
    Auditing4 = Issue and manage certificate requests (4)
    Auditing8 = Revoke certificates and publish CRLs (8)
    Auditing16 = Change CA security settings (16)
    Auditing32 = Change CA security settings (32)
    Auditing64 = Change CA configuration (64)
    AuditingFull = Auditing is fully enabled (127)
    AuditingUnknown = Unknown
    TableName = Enterprise Subordinate CA
    HealthCheck = Health Check:
    SecurityBestPractice = Security Best Practice:
    AuditingBP = Auditing should be fully enabled for the Certification Authority to ensure that all relevant events are logged for security monitoring and incident response purposes. This includes events related to certificate issuance, revocation, and changes to CA configuration.
'@

    # Get-AbrADCASecurity
    GetAbrADCASecurity = ConvertFrom-StringData @'
    Collecting = Collecting AD Certification Authority Security information.
    CertValidityPeriod = Certificate Validity Period
    CertValidityPeriodParagraph = The following section provides certificate validity period configuration for the Certification Authority.
    CertValidityPeriodTable = Certificate Validity Period
    CAName = CA Name
    ServerName = Server Name
    ValidityPeriod = Validity Period
    ACL = Access Control List (ACL)
    ACLTable = Access Control List
    DCName = DC Name
    Owner = Owner
    Group = Group
    AccessRights = Access Rights
    AccessRightsTable = Access Rights
    Identity = Identity
    AccessControlType = Access Control Type
    Rights = Rights
'@

    # Get-AbrADCACryptographyConfig
    GetAbrADCACryptographyConfig = ConvertFrom-StringData @'
    Collecting = Collecting CA Certification Authority Cryptography Config information.
    Heading = Cryptography Configuration
    Paragraph = The following section provides detailed information about the cryptography configuration settings for the Certification Authority, including algorithms, providers, and key specifications.
    CAName = CA Name
    ServerName = Server Name
    PublicKeyAlgorithm = PublicKey Algorithm
    HashingAlgorithm = Hashing Algorithm
    ProviderName = Provider Name
    AlternateSignatureAlgorithm = Alternate Signature Algorithm
    ProviderIsCNG = Provider Is CNG
    TableName = Cryptography Configuration
'@

    # Get-AbrADCAAIA
    GetAbrADCAAIA = ConvertFrom-StringData @'
    Collecting = Collecting AD CA Authority Information Access information on {0}.
    Heading = Authority Information Access (AIA)
    Paragraph = This section provides the Authority Information Access (AIA) configuration for the Certification Authority, which specifies where certificates and certificate revocation information can be retrieved.
    RegURI = Reg URI
    ConfigURI = Config URI
    Flags = Flags
    ServerPublish = Server Publish
    IncludeToExtension = Include To Extension
    OCSP = OCSP
    TableName = Authority Information Access
'@

    # Get-AbrADCACRLSetting
    GetAbrADCACRLSetting = ConvertFrom-StringData @'
    CollectingVP = Collecting AD CA CRL Validity Period information on {0}.
    CollectingCDP = Collecting AD CA CRL Distribution Point information on {0}.
    CollectingHealth = Collecting AIA and CDP Health Status from {0}.
    CRLHeading = Certificate Revocation List (CRL)
    CRLParagraph = This section provides detailed information about the Certificate Revocation List (CRL) distribution settings and health status for the Certification Authority.
    CRLValidityPeriod = CRL Validity Period
    CRLValidityPeriodTable = CRL Validity Period
    CAName = CA Name
    BaseCRL = Base CRL
    BaseCRLOverlap = Base CRL Overlap
    DeltaCRL = Delta CRL
    DeltaCRLOverlap = Delta CRL Overlap
    ServerName = Server Name
    CRLFlags = CRL Flags
    CRLFlagsSettings = CRL Flags Settings
    CRLFlagsTable = CRL Flags
    CRLDistributionPoint = CRL Distribution Point
    CRLDistributionPointParagraph = This section provides detailed information about the Certificate Revocation List (CRL) Distribution Points configured on the Certification Authority, including URI locations and publication settings.
    RegURI = Reg URI
    ConfigURI = Config URI
    UrlScheme = Url Scheme
    ProjectedURI = ProjectedURI
    Flags = Flags
    CRLPublish = CRL Publish
    DeltaCRLPublish = Delta CRL Publish
    AddToCertCDP = Add To Cert CDP
    AddToFreshestCRL = Add To Freshest CRL
    AddToCrlCDP = Add To Crl cdp
    CRLDistributionPointTable = CRL Distribution Point
    AIACDPHealth = AIA and CDP Health Status
    AIACDPHealthParagraph = This section provides a comprehensive health check of the Certification Authority by verifying the CA certificate chain status and validating the accessibility of all Certificate Revocation List (CDP) and Authority Information Access (AIA) URLs for each certificate in the chain.
    Childs = Childs
    Health = Health
    OK = OK
    CAHealthTable = Certification Authority Health
'@

    # Get-AbrADCATemplate
    GetAbrADCATemplate = ConvertFrom-StringData @'
    Collecting = Collecting AD Certification Authority Templates information from {0}.
    Heading = Certificate Template Summary
    Paragraph = The following section lists certificate templates assigned to the Certification Authority. The CA can only issue certificates based on these assigned templates.
    TemplateName = Template Name
    SchemaVersion = Schema Version
    SupportedCA = Supported CA
    Autoenrollment = Autoenrollment
    IssuedTemplateTable = Issued Certificate Template
    IssuedTemplateACLs = Issued Certificate Template ACLs
    IssuedTemplateACLsParagraph = The following section provides the Access Control List (ACL) for certificate templates assigned to the Certification Authority.
    Identity = Identity
    AccessControlType = Access Control Type
    Rights = Rights
    Inherited = Inherited
    TemplateACLTable = Certificate Template ACL
    ADTemplates = Certificate Template In Active Directory
    ADTemplatesParagraph = The following section lists all certificate templates registered in Active Directory, regardless of whether they are assigned to any Certification Authority.
    ADTemplatesTable = Certificate Template in AD
'@

    # Get-AbrADCAKeyRecoveryAgent
    GetAbrADCAKeyRecoveryAgent = ConvertFrom-StringData @'
    Collecting = Collecting AD Certification Authority Key Recovery Agent information.
    Heading = Key Recovery Agent Certificate
    Paragraph = This section provides details about the Key Recovery Agent certificate, which encrypts users' certificate private keys for storage in the CA database. If a user loses access to their certificate private key, the Key Recovery Agent can recover it when key archival was configured for the certificate.
    CAName = CA Name
    ServerName = Server Name
    Certificate = Certificate
    TableName = Key Recovery Agent Certificate
'@

    # Get-AbrDomainSection
    GetAbrDomainSection = ConvertFrom-StringData @'
    Collecting = Collecting Domain information from {0}.
    Paragraph = This section provides a comprehensive overview of the Active Directory domain configuration, including key settings and critical details.
    SectionTitle = AD Domain Configuration
    DefinitionText = An Active Directory domain is a collection of objects within a Microsoft Active Directory network. An object can be a single user, a group, or a hardware component such as a computer or printer. Each domain holds a database containing object identity information. Active Directory domains can be identified using a DNS name, which can be the same as an organization's public domain name, a sub-domain, or an alternate version (which may end in .local).
    ParagraphDetail = The following section provides a comprehensive overview of the Active Directory domain configuration, including critical settings and key operational details.
    HealthChecks = Health Checks
    DomainControllersSection = Domain Controllers
    DCDefinitionText = A domain controller (DC) is a server computer that responds to security authentication requests within a computer network domain. It is a network server that is responsible for allowing host access to domain resources. It authenticates users, stores user account information and enforces security policy for a domain.
    DCParagraphDetail = The following section presents an in-depth overview of the Active Directory domain controllers, including their configuration and key details.
    DCParagraphSummary = The following section provides a summary of the configuration and key details of the Active Directory domain controllers.
    RolesSection = Roles
    RolesParagraph = The following section provides a detailed overview of the installed roles and features on domain controllers in {0}.
    DCDiagSection = DC Diagnostic
    DCDiagParagraph = The following section provides a summary of the Active Directory DC Diagnostic.
    InfraServicesSection = Infrastructure Services
    InfraServicesParagraph = The following section provides a detailed overview of the status and configuration of infrastructure services on the domain controllers.
    NoDCAvailable = Unable to get an available DC in {0} domain. Removing domain from the Domain section.
'@

    # Get-AbrADDomain
    GetAbrADDomain = ConvertFrom-StringData @'
    Collecting = Collecting AD Domain information on forest {0}.
    DomainName = Domain Name
    NetBIOSName = NetBIOS Name
    DomainSID = Domain SID
    DomainFunctionalLevel = Domain Functional Level
    Domains = Domains
    Forest = Forest
    ParentDomain = Parent Domain
    ReplicaDirectoryServers = Replica Directory Servers
    ChildDomains = Child Domains
    DomainPath = Domain Path
    ComputersContainer = Computers Container
    DomainControllersContainer = Domain Controllers Container
    SystemsContainer = Systems Container
    UsersContainer = Users Container
    DeletedObjectsContainer = Deleted Objects Container
    ForeignSecurityPrincipalsContainer = Foreign Security Principals Container
    LostAndFoundContainer = Lost And Found Container
    QuotasContainer = Quotas Container
    ReadOnlyReplicaDirectoryServers = ReadOnly Replica Directory Servers
    MachineAccountQuota = ms-DS-MachineAccountQuota
    RIDIssuedAvailable = RID Issued/Available
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    Reference = Reference:
    RIDBestPractice = The RID Issued percentage exceeds 80%. It is recommended to evaluate the utilization of RIDs to prevent potential exhaustion and ensure the stability of the domain. The Relative Identifier (RID) is a crucial component in the SID (Security Identifier) for objects within the domain. Exhaustion of the RID pool can lead to the inability to create new security principals, such as user or computer accounts. Regular monitoring and proactive management of the RID pool are essential to maintain domain health and avoid disruptions.
    RIDReference = https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/managing-rid-pool-depletion/ba-p/399736
'@

    # Get-AbrADFSMO
    GetAbrADFSMO = ConvertFrom-StringData @'
    Collecting = Collecting Active Directory FSMO information of domain {0}.
    SectionTitle = FSMO Roles
    InfrastructureMaster = Infrastructure Master
    PDCEmulator = PDC Emulator Name
    RIDMaster = RID Master
    DomainNamingMaster = Domain Naming Master
    SchemaMaster = Schema Master
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    Reference = Reference:
    InfraMasterBP = The infrastructure master role in the domain {0} should be held by a domain controller that is not a global catalog server. The infrastructure master is responsible for updating references from objects in its domain to objects in other domains. If the infrastructure master runs on a global catalog server, it will not function properly because the global catalog holds a partial replica of every object in the forest, and it will not update the references. This issue does not affect forests that have a single domain.
    InfraMasterRef = http://go.microsoft.com/fwlink/?LinkId=168841
'@

    # Get-AbrADTrust
    GetAbrADTrust = ConvertFrom-StringData @'
    Collecting = Collecting AD Trust information of {0}.
    SectionTitle = Domain and Trusts
    Name = Name
    Path = Path
    Source = Source
    Target = Target
    TrustType = Trust Type
    TrustTypeDownlevel = Downlevel (NT domain)
    TrustTypeUplevel = Uplevel (Active Directory)
    TrustTypeMIT = MIT (Kerberos Realm Trust )
    TrustTypeDCE = DCE
    TrustAttributes = Trust Attributes
    TrustAttrNonTransitive = Non-Transitive
    TrustAttrUplevel = Uplevel clients only (Windows 2000 or newer
    TrustAttrQuarantine = Quarantined Domain (External)
    TrustAttrForest = Forest Trust
    TrustAttrCrossOrg = Cross-Organizational Trust (Selective Authentication)
    TrustAttrIntraForest = Intra-Forest Trust (trust within the forest)
    TrustAttrInterForest = Inter-Forest Trust (trust with another forest)
    TrustDirection = Trust Direction
    TrustDirDisabled = Disabled (The trust relationship exists but has been disabled)
    TrustDirInbound = Inbound (Trusting domain)
    TrustDirOutbound = Outbound (Trusted domain)
    TrustDirBidirectional = Bidirectional (two-way trust)
    IntraForest = Intra Forest
    SelectiveAuthentication = Selective Authentication
    SIDFilteringForestAware = SID Filtering Forest Aware
    SIDFilteringQuarantined = SID Filtering Quarantined
    TGTDelegation = TGT Delegation
    KerberosAESEncryption = Kerberos AES Encryption
    KerberosRC4Encryption = Kerberos RC4 Encryption
    UplevelOnly = Uplevel Only
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    AESBP = Ensure that AES Kerberos encryption is enabled on all Active Directory trusts. RC4 encryption is considered weak and vulnerable to various attacks. Enabling AES encryption on trusts enhances Kerberos security and aligns with modern security standards. Reference: https://techcommunity.microsoft.com/t5/itops-talk-blog/tough-questions-answered-can-i-disable-rc4-etype-for-kerberos-on/ba-p/382718
    TrustDiagramSection = Domain and Trusts Diagram
'@

    # Get-AbrADAuthenticationPolicy
    GetAbrADAuthenticationPolicy = ConvertFrom-StringData @'
    Collecting = Collecting AD Authentication Policy and Silo information from {0}.
    SectionTitle = Authentication Policies and Silos
    SectionParagraph = The following section provides an overview of Authentication Policy Silos and Authentication Policies configured in the domain. Authentication Policy Silos restrict where accounts can sign in and apply authentication policies to control the Kerberos ticket-granting ticket (TGT) lifetime for privileged accounts.
    SilosSection = Authentication Policy Silos
    SilosParagraph = The following table provides a summary of Authentication Policy Silos configured in domain {0}.
    SiloName = Name
    SiloEnforce = Enforce
    SiloDescription = Description
    UserAuthPolicy = User Authentication Policy
    ServiceAuthPolicy = Service Authentication Policy
    ComputerAuthPolicy = Computer Authentication Policy
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    SiloBP = Authentication Policy Silos should be set to Enforce mode to actively restrict where privileged accounts can authenticate. Silos in audit mode only log events without enforcing restrictions.
    SiloMembersSection = Silo Members
    SiloMembersParagraph = The following table lists the accounts assigned to Authentication Policy Silos in domain {0}.
    SiloMemberSiloName = Silo Name
    SiloMemberName = Member Name
    ObjectClass = Object Class
    DistinguishedName = Distinguished Name
    PoliciesSection = Authentication Policies
    PoliciesParagraph = The following table provides a summary of Authentication Policies configured in domain {0}.
    PolicyName = Name
    PolicyEnforce = Enforce
    PolicyDescription = Description
    UserTGTLifetime = User TGT Lifetime (mins)
    ServiceTGTLifetime = Service TGT Lifetime (mins)
    ComputerTGTLifetime = Computer TGT Lifetime (mins)
    PolicyBP = Authentication Policies should be set to Enforce mode to actively restrict Kerberos TGT lifetimes and account sign-in. Policies in audit mode only log events without enforcing restrictions.
'@

    # Get-AbrADHardening
    GetAbrADHardening = ConvertFrom-StringData @'
    Collecting = Collecting AD Hardening information from {0}.
    SectionTitle = Active Directory Hardening
    SectionParagraph = The following section provides an overview of critical Active Directory security hardening settings, including authentication protocols, SMB configurations, and LDAP security enforcement mechanisms.
    NTLMv1Config = NTLMv1 configuration
    SMBv1Status = SMBv1 status
    EnforcingSMBSigning = Enforcing SMB Signing
    EnforcingLDAPSigning = Enforcing LDAP Signing
    EnforcingLDAPChannelBinding = Enforcing LDAP Channel Binding
    NTLMv1Level0 = Send LM & NTLM responses
    NTLMv1Level1 = Send LM & NTLM - use NTLMv2 session security if negotiated
    NTLMv1Level2 = Send NTLM response only
    NTLMv1Level3 = Send NTLMv2 response only
    NTLMv1Level4 = Send NTLMv2 response only\refuse LM
    NTLMv1Level5 = Send NTLMv2 response only\refuse LM & NTLM
    NTLMv1Unknown = Unknown
    NTLMv1Default = Send NTLMv2 response only
    SMBv1Enabled = Installed\Enabled
    SMBv1Disabled = Uninstalled\Disabled
    SMBv1Removed = Removed
    SMBSigningDisable = Disable
    SMBSigningEnable = Enable
    SMBSigningUnknown = Unknown
    SMBSigningDefault = Not Configured/Disabled
    LDAPSigningNone = None
    LDAPSigningRequired = Require Signing
    LDAPSigningUnknown = Unknown
    LDAPSigningDefault = None
    LDAPCBNever = Never
    LDAPCBWhenSupported = When supported
    LDAPCBAlways = Always
    LDAPCBUnknown = Unknown
    LDAPCBDefault = Not Configured/Disabled
    HealthCheck = Health Check:
    BestPractice = Best Practice:
    SMBSigningBP = Enforcing SMB Signing: SMB signing is a security feature that helps protect against man-in-the-middle attacks by ensuring the authenticity and integrity of SMB communications.
    SMBv1BP = SMBv1 status is enabled: SMBv1 is an outdated protocol that is vulnerable to several security issues. It is recommended to disable SMBv1 on all systems to enhance security and reduce the risk of exploitation. SMBv1 has been deprecated and replaced by SMBv2 and SMBv3, which offer improved security features.
    LDAPSigningBP = Enforcing LDAP Signing is not configured: LDAP signing is a security feature that helps protect the integrity and confidentiality of LDAP communications by requiring LDAP data signing.
    LDAPCBBindingBP = Enforcing LDAP Channel Binding is not configured: LDAP channel binding is a security feature that helps protect against man-in-the-middle attacks by ensuring the authenticity and integrity of LDAP communications.
    NTLMv1BP = Disable NTLMv1: NTLMv1 is an outdated authentication protocol that is vulnerable to several security issues. It is recommended to disable NTLMv1 on all systems to enhance security and reduce the risk of exploitation. NTLMv1 has been deprecated and replaced by NTLMv2, which offers improved security features.
'@

}