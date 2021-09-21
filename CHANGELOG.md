# :arrows_counterclockwise: Microsoft AD As Built Report Changelog

## [0.2.0] - 2021-09-10

### Added

- Added Active Directory DNS summary information
  - Added DNS Forwarder summary information
  - Added Added DNS Recursion configuration information
  - Added Added DNS RRL configuration information
  - Added Added DNS Zone Reverse Lookup configuration information
    - Added Added DNS Zone Scavenging/Aging configuration information
    - Added Added DNS Zone Delegation configuration information
  - Added more health checks

### Changed

- Improved per Domain configuration information
- Improved per Domain Controller configuration information
- Introduced the ability to use a shared PSsession
- Merged the functions used within the reports into a single file (SharedUtilsFunctions)

### Fixed

- Enhanced the logic of detecting a unavailable Domain or DC.
- Enhanced verbose/degug logging
- Added more try/catch code to improve error diagnostic

## [0.1.0] - 2021-08-10

### Added

- Added Active Directory Forest summary information
  - Added Forest Optional Features Summary
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
