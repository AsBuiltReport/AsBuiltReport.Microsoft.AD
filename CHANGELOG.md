# :arrows_clockwise: Microsoft AD As Built Report Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

##### This project is community maintained and has no sponsorship from Microsoft, its employees or any of its affiliates.

## [0.9.4] - Unreleased

### Changed

- Increase AsBuiltReport.Core to v1.4.3
- Increase Diagrammer.Core minimum requirement
- Increase Diagrammer.Microsoft.AD minumum requirement

### Fixed

- Fix issue with WinRM connection setup in Domain Controller section

### Removed

- Remove DCDiag section as it is not functioning properly

## [0.9.3] - 2025-02-21

### Added

- Add Site Inventory diagram to the Replication section
- Add Certificate Authority diagram


### Changed

- Move Circular Group Membership section to $InfoLevel.Domain level 4
- Increase AsBuiltReport.Core to v1.4.2
- Increase Diagrammer.Core minimum requirement
- Increase Diagrammer.Microsoft.AD minumum requirement

### Fixed

- Fix error message during DC discovery and WinRM connection
- Fix Get-WinADLastBackup cmdlet not returning AD partitions when the report generation machine is not part of the same domain or forest as the target domain controller
- Fix Certificate Authority section displaying content when no data is available
- Fix DHCP Infrastructure section not identifying if the server is a Domain Controller
- Fix Enterprise Root Certificate Authority section not displaying table descriptions

## [0.9.2] - 2025-01-14

### Added

- Add support for WinRM over SSL
- Add option to set the WinRM tcp port used for PSSession connection setup

### Changed

- Increase Diagrammer.Core minimum requirement
- Increase AsBuiltReport.Core to v1.4.1
- Improve DC selection logic
- Improve HealthCheck best practice recommendations (@Copilot)

### Fixed

- Fix [#190](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/190)
- Fix [#191](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/191)
- Fix ConvertTo-HashToYN cmdlet not generating an ordereddictionary output

### Removed

- Remove dependabot action (Not supported in Abr Organization)

## [0.9.1] - 2024-11-15

### Added

- Improve detection of empty fields in tables
- Improve detection of true/false elements in tables
- Update GitHub release workflow to add post to Bluesky social platform

### Changed

- Increase Diagrammer.Core minimum requirement
- Increase Diagrammer.Microsoft.AD minumum requirement

## [0.9.0] - 2024-10-13

### Added

- Initial support for Server 2025
- Add Dependabot action

### Changed

- Increase Diagrammer.Core minimum requirement
- Increase Diagrammer.Microsoft.AD minumum requirement
- Improve detection of Domain Controller availability (Test-WSMan)

## [0.8.2] - 2024-06-15

### Added

- Add Diagrammer.Core to the module RequiredModules list
- Add Health Check to detect circular group membership
- Add Health Check to find SMBv1 status in Active Directory DCs
- Add Health Check to find groups with AdminCount set to 1
- Add Health Check to find empty groups
- Add Health Check to find Computers with password-not-required attribute set
- Add basic DHCP Infrastructure information

### Changed

- Improve the code to better handle errors
- Update the Eomm/why-don-t-you-tweet action to v2.0.0
- Increase the default InfoLevel for the Forest and Domain section (InfoLevel 2)
- Enable DNS section by default (InfoLevel 1)

### Fixed

- Fix [#160](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/160)
- Fix [#168](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/168)
- Fix [#171](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/171)
- Fix [#172](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/172)
- Fix [#174](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/174)
- Fix the ip address is not displayed in the DC Network Settings section. [#176](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/176)
- Fix for Zone Transfer section displaying an empty table. [#178](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/178)
- Fix [#180](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/180)

## [0.8.1] - 2024-05-16

### Added

- Site Topology diagram
- Domain and Trust diagram
- Foreign Security Principals section

### Changed

- Remove Graphviz install check code
- Code cleanup
- Improve script logging
- Increase Diagrammer.Microsoft.AD module version requirements v0.2.3
- Increase AsBuiltReport.Core module version requirements v1.4.0
- Change charts default font to Segoe Ui
- Improved Forest diagram

### Fixed

- Improve error handling on Forest diagram section
- Fix issues with Diagrammer.Microsoft.AD module
- Fix DNS section not getting data when there are unavailable DC servers
- Fix [#154](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/154)
- Fix [#153](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/153)
- Fix [#152](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/152)
- Fix [#151](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/151)
- Fix [#150](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/150)

### Removed

- Removed EnableDiagrams option
- Removed EnableCharts option

## [0.8.0] - 2024-01-24

### Added

- Added initial diagram support:
  - Forest Diagram
- Added disclaimer section if the EnableHealthCheck option is used.

### Fixed

- Fix [#137](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/137)
- Fix [#138](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/138)
- Fix [#143](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/143)

## [0.7.15] - 2023-10-03

### Changed

- Improved verbose logging
- Improved PKI Section

## [0.7.14] - 2023-07-25

### Fixed

- Resolve [#113](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/113)
- Resolve [#116](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/116)
- Resolve [#117](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/117)
- Resolve [#118](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/118)
- Resolve [#119](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/119)
- Resolve [#120](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/120)
- Resolve [#121](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/121)
- Resolve [#123](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/123)
- Resolve [#124](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/124)
- Resolve [#125](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/125)
- Resolve [#126](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/126)
- Resolve [#128](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/128)

## [0.7.13] - 2023-06-22

### Added

- Added Option "Include.Domains" to allow only a list of Active Directory Domain to document
  - Include Domains in AD services
  - Include Domains in DNS services
- Added Site Connection Objects section

### Changed

- Major improvements to health check recommendations

### Fixed

- Fix HealthCheck sections not working after v0.7.12
- Fix [#84](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/84)
- Fix [#98](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/98)
- Fix [#99](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/99)
- Fix [#100](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/100)
- Fix [#101](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/101)
- Fix [#102](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/102)
- Fix [#103](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/103)
- Fix [#104](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/104)
- Fix [#105](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/105)
- Fix [#106](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/106)
- Fix [#107](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/107)
- Fix [#108](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/108)
- Fix [#109](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/109)
- Fix [#110](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/110)
- Fix Node.js 12 actions are deprecated warning message
- Fix the code to ensure that PSRemoting sessions are removed when they are no longer needed.

## [0.7.12] - 2023-05-23

### Changed

- Removed DHCP section (migrated to AsBuiltReport.Microsoft.DHCP)
- Disabled DNS & CA section by default

## [0.7.11] - 2023-03-09

### Added

- Added section for Local Administrator Password Solution.

### Changed

- Improved bug and feature request templates
- Changed default logo from Microsoft to the AsBuiltReport logo due to licensing requirements
- Changed default report style font to 'Segoe Ui' to align with Microsoft guidelines
- Changed Required Modules to AsBuiltReport.Core v1.3.0
- Changed Infolevel 1 table structure on the following section:
  - Hardware Inventory
  - Fined Grained Password Policies
  - Group Managed Service Accounts (GMSA)
  - Sites Replication Connection
  - Domain and Trusts

### Fixed

- [#81](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/81)
### Added

- Added section for Local Administrator Password Solution.

### Changed

- Improved bug and feature request templates
- Changed default logo from Microsoft to the AsBuiltReport logo due to licensing requirements
- Changed default report style font to 'Segoe Ui' to align with Microsoft guidelines
- Changed Required Modules to AsBuiltReport.Core v1.3.0
- Changed Infolevel 1 table structure on the following section:
  - Hardware Inventory
  - Fined Grained Password Policies
  - Group Managed Service Accounts (GMSA)
  - Sites Replication Connection
  - Domain and Trusts

### Fixed

- [#81](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/81)

## [0.7.10] - 2022-10-28

### Fixed

- Fix issue [#83](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/83) (Error running report if multiple version are installed together)

## [0.7.9] - 2022-10-09

### Added

- Added charts to the Domain object count sub-sections

### Changed

- Split the Domain object count section.
  - Computers Object count
  - User object count
  - Domain Controller count

### Fixed

- close [#69](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/69)
- close [#74](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/74)
- close [#75](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/75)
- close [#76](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/76)
- close [#77](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/77)
- close [#78](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/78)

## [0.7.8] - 2022-10-04

### Added

- Added Simple Chart support

### Fixed

- close [#67](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/67)
- close [#68](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/68)
- close [#71](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/71)

## [0.7.7] - 2022-09-07

### Added

- Add table to show the pending/missing Windows updates (Health Check)

### Changed

- Improve domain controller dcdiag table

### Fixed

- close [#57](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/57)
- close [#59](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/59)
- close [#60](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/60)
- close [#61](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/61)
- close [#62](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/62)

## [0.7.6] - 2022-09-04

### Changed

- Improve report table of content

### Fixed

- close [#52](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/52)

## [0.7.5] - 2022-08-06

### Added

- Added SYSVOL/NETLOGON folder content status
  - Added Health Check for malicious/unessential file extensions
- Added Domain Controller SRV Records Status
  - Added Health Check for SRV Records Status
- Added Health Check for Unsupported Operating System findings in the Active Directory Domain

### Changed

- Allowed the Forest Root Domain to be the fisrt Domain in the report
- Improved Sites Replication (repadmin) section

## [0.7.4] - 2022-07-29

### Changed

- Access well known groups via SID to include international names and expand them to localized group names.
- Removed PSSharedGoods/PSWriteColor module dependency

### Fixed

- Fixes [#42](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/42)

## [0.7.3] - 2022-05-13

### Added

- Improved validation of module dependencies
- Added Option "Exclude.Domains" to allow Active Directory Domain exclusions
  - Exclude Domains in AD Services
  - Exclude Domains in DNS Services
  - Exclude Domains in DHCP Services
- Added Option "Exclude.DCs" to allow Active Directory Domain Controller exclusions
  - Exclude DCs in AD Services
  - Exclude DCs in DNS Services
  - Exclude DCs in DHCP Services
- Added Test-Connection test to verify DC connectivity.

## [0.7.2] - 2022-04-25

### Added

- Improved AD user/group object stats
  - Added Privileged Group count information
- Improved AD computer object stats
  - Added Operating System Count information
- Added RID Pool Issued/Available information
- Added Domain,Site and Global Catalog count information

### Fixed

- Fix report module dependencies. Closes #35

## [0.7.1] - 2022-03-14

### Added

- Added Kerberos Audit section.
  - Added Health Check condition and explanatione

### Fixed

- Fix release workflows to include PSSharedGoods module.

## [0.7.0] - 2022-03-14

### Added

- Implemented health check explanations.
- Added Health Check:
  - Search for Duplicate Object.
  - Search for Duplicate SID.
  - DFS Health Status
  - Search for Account Security Issues.
- Added Naming Context Backup information.

### Changed

- Improve Health Check content.
- Added enabled status on Forest Optional Features section.

### Fixed

- Fix DNS section issues.
- Sort "Organizational Unit" section by path. Closes #27

## [0.6.3] - 2022-01-30

### Changed

- More Code refactoring to improve performance.
- Migrated DNS/DHCP Server section to use CIM sessions.
- Changed authentication parameter of CIM/PSRemote from kerberos to negotiate.
- Added variable to control CIM/PSRemote authentication method (PSDefaultAuthentication)
- Changed report main text color.

### Fixed

- Fix for more table caption error messages.
- Fix section heading hierarchy

## [0.6.2] - 2022-01-24

### Changed

- Code refactoring to improve performance.
- Implement more try/catch to better handle terminating errors.
- Update ReadMe to include Known limitations.
- Improve Sections title text.
- Improve table sorting.

### Fixed

- Fix for table caption error messages.

## [0.6.1] - 2021-12-07

### Added

- Added Sample HTML Report Link to README file.
- Added DHCP/DNS Powershell module installation instructions. Closes #18

### Fixed

- Improved the code to better detect whether a DHCP/CA infrastructure is in place. Closes #17
- Fix missing comma in JSON File. Closes #16

## [0.6.0] - 2021-12-02

### Added

- Added more CA Sections (Need More Testing)
  - Added CRL Repository
  - Added AIA Information
  - Added Security Section
  - Added Template Information
  - Added Key Recovery Agent Information
  - Added Cryptography Configuration Information

### Changed

- The spelling of the section title has been revised.
- Enabled CA InfoLevels Option.

## [0.5.0] - 2021-10-29

### Added

- Added ShowDefinitionInfo Option (Allows the user to choose whether to enable AD term explanations.)
- Explanation of the ShowDefinitionInfo option has been added to the ReadMe file.
- Added Dynamic DNS Credentials Health Check.
- Added updated HTML Sample Report.

### Changed

- The spelling of the section title has been revised.
- Moved DNS Zone section to InfoLevel 2.
- Moved Role and Feature section to InfoLevel 3.
- Removed Unused InfoLevels (CA & Security).

### Fixed

- Fix try/catch error messages (globally)
- Fix try/catch logic on the DNS Section (Fix [#11](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/11))

## [0.4.0] - 2021-10-08

### Added

- Added Installed Roles and Features to the DC Section.
- Added Fined Grained Password Policies to the Domain Section (fix issue #6).
- Added Log and SysVol Path to NTDS Table (fix issue #6).
- Added More Active Directory Object Count (fix issue #9).
- Added Tombstone Lifetime to the Forest Section.
- Added Enforced Group Policy Objects (fix issue #9).
- Added GPO Logon/Logoff Startup/Shutdown Script Support (fix issue #9).
- Added GPO Blocked Inheritance (fix issue #9).
- Added DHCP IPv4 per Scope Option information.
- Added DHCP IPv6 per Scope Option information.
  - Added DHCP Scope Statistics information.
  - Added DHCP Scope DNS Setting information.
- Added More Health Checks.
  - Added GPO Health Check.
  - Added GMSA Health Check.
  - Added Dcdiag Health Check.
  - Added more DHCP IPv4/IPv6 Health Checks.
- Added DNS Conditional Forwarder to DNS Section (fix issue #6).

### Changed

- Added more Heading definitions.
- Disable Certificate Authority until is Completed.
- Added function to translate from DN to Name or CanonicalName
- Implement InfoLevel 2 and 3 Report Option.
  - Added Domain InfoLevel 2/3 Option.
  - Added DNS InfoLevel 2 Option.
  - Added DHCP InfoLevel 2 Option.
- Updated Sample Report

### Fixed

- Fix more PSSession exhaustion.
- Remove the PSPKI module from ReadMe file.
- Fix more Heading Index issues.
- Fix for better verbose loggin.

## [0.3.0] - 2021-09-26

### Added

- Added Active Directory DHCP summary information.
  - Added DHCP Database information.
  - Added DHCP Dynamic DNS information.
- Added per Domain DHCP IPv4 Scope information.
  - Added DHCP Scope Failover configuration information.
  - Added DHCP Scope Statistics information.
  - Added DHCP Scope Interface Binding information.
  - Added DHCP Scope Delegation configuration information.
- Added per Domain DHCP IPv6 Scope information.
  - Added DHCP Scope Failover configuration information.
  - Added DHCP Scope Statistics information.
  - Added DHCP Scope Interface Binding information.
  - Added DHCP health check.

### Changed

- Added more Heading definitions.
- Added funtion to convert from subnetmask to dotted notation.
- Added a function to convert empty culumns to "-" (less switch cases).

### Fixed

- Fix for PSSession exhaustion.
- Fix for DNS Zone Delegation IPaddress variable
- Fix for unhandle null values.
- Enhanced error message catching.
- Fix for heading hierarchy.
- Fix Forest schema version code.
- Fix ActiveDirectory RequiredModule error (Fix [#3](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues/3)).

## [0.2.0] - 2021-09-10

### Added

- Added Active Directory DNS summary information.
  - Added DNS Forwarder summary information.
  - Added DNS Recursion configuration information.
  - Added DNS RRL configuration information.
  - Added DNS Zone Reverse Lookup configuration information.
    - Added DNS Zone Scavenging/Aging configuration information.
    - Added DNS Zone Delegation configuration information.
  - Added more health checks.

### Changed

- Improved per Domain configuration information.
- Improved per Domain Controller configuration information.
- Introduced the ability to use a shared PSsession.
- Merged the functions used within the reports into a single file (SharedUtilsFunctions).

### Fixed

- Enhanced the logic of detecting a unavailable Domain or DC.
- Enhanced verbose/degug logging.
- Added more try/catch code to improve error diagnostic.

## [0.1.0] - 2021-08-10

### Added

- Added Active Directory Forest summary information.
  - Added Forest Optional Features Summary.
  - Added Domain Site summary information.
    - Added Domain Site Link summary information.
- Added Active Directory Domain summary Infomation.
  - Added Object Count summary Information.
  - Added Default Domain Password Policy Summary Information.
  - Added Group Managed Service Accounts (GMSA) Summary Information.
  - Added Flexible Single Master Operations (FSMO) Information.
  - Added Trust Summary information.
- Added Domain Controller Information.
  - Added Domain Controller Hardware Summary.
  - Added Domain Controller NTDS Summary.
  - Added Domain Controller Time Source Summary.
  - Added Domain Controller Infrastructure Services Status.
  - Added Site Replication Summary.
  - Added Site Replication Failure Summary.
  - Added Group Policy Objects Summary.
  - Added Organizational Unit summary.
  - Added Domain Site summary information
    - Added Domain Site Link summary information
- Added Active Directory Domain summary Infomation
  - Added Object Count summary Information
  - Added Default Domain Password Policy Summary Information
  - Added Group Managed Service Accounts (GMSA) Summary Information
  - Added Flexible Single Master Operations (FSMO) Information
  - Added Trust Summary information
- Added Domain Controller Information
  - Added Domain Controller Hardware Summary
  - Added Domain Controller NTDS Summary
  - Added Domain Controller Time Source Summary
  - Added Domain Controller Infrastructure Services Status
  - Added Site Replication Summary
  - Added Site Replication Failure Summary
  - Added Group Policy Objects Summary
  - Added Organizational Unit summary
