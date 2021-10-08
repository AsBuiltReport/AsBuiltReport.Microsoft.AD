# :arrows_counterclockwise: Microsoft AD As Built Report Changelog

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
