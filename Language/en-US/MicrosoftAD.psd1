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
    DISCLAIMER = The information in this report has been gathered through automation and direct observation. The recommendations and conclusions are based on industry best practices, technical expertise, and empirical data. While comprehensive, this assessment may not cover all possible scenarios or configurations. Implementation of these recommendations should be carried out by qualified personnel with the appropriate knowledge and experience. The author(s) assume no responsibility for any damages, including but not limited to loss of business profits, business interruption, loss of data, or other financial losses resulting from the use of or reliance on this report.
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
}