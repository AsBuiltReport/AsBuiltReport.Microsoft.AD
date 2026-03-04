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
    DnsName = Dns Name
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

}