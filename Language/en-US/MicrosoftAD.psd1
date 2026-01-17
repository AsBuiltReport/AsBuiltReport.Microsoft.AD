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
'@
}