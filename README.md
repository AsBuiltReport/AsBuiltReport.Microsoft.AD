<!-- ********** DO NOT EDIT THESE LINKS ********** -->
<p align="center">
    <a href="https://www.asbuiltreport.com/" alt="AsBuiltReport"></a>
            <img src='https://avatars.githubusercontent.com/u/42958564' width="8%" height="8%" /></a>
</p>
<p align="center">
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Microsoft.AD/" alt="PowerShell Gallery Version">
        <img src="https://img.shields.io/powershellgallery/v/AsBuiltReport.Microsoft.AD.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Microsoft.AD/" alt="PS Gallery Downloads">
        <img src="https://img.shields.io/powershellgallery/dt/AsBuiltReport.Microsoft.AD.svg" /></a>
    <a href="https://www.powershellgallery.com/packages/AsBuiltReport.Microsoft.AD/" alt="PS Platform">
        <img src="https://img.shields.io/powershellgallery/p/AsBuiltReport.Microsoft.AD.svg" /></a>
</p>
<p align="center">
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/graphs/commit-activity" alt="GitHub Last Commit">
        <img src="https://img.shields.io/github/last-commit/AsBuiltReport/AsBuiltReport.Microsoft.AD/master.svg" /></a>
    <a href="https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/master/LICENSE" alt="GitHub License">
        <img src="https://img.shields.io/github/license/AsBuiltReport/AsBuiltReport.Microsoft.AD.svg" /></a>
    <a href="https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/graphs/contributors" alt="GitHub Contributors">
        <img src="https://img.shields.io/github/contributors/AsBuiltReport/AsBuiltReport.Microsoft.AD.svg"/></a>
</p>
<p align="center">
    <a href="https://twitter.com/AsBuiltReport" alt="Twitter">
            <img src="https://img.shields.io/twitter/follow/AsBuiltReport.svg?style=social"/></a>
</p>
<!-- ********** DO NOT EDIT THESE LINKS ********** -->

> [!WARNING]
> This report contains information gathered through automation and observations. All opinions, recommendations, and conclusions are based on professional insight and expertise, though this assessment is not exhaustive. Implementation of recommendations should be reviewed and executed by qualified personnel. The author(s) assume no liability for any damages—including lost profits, business interruption, or financial loss—arising from the use of this report or its recommendations.

#### This project is community maintained and has no sponsorship from Microsoft, its employees or any of its affiliates.

# Microsoft AD As Built Report

Microsoft AD As Built Report is a PowerShell module which works in conjunction with [AsBuiltReport.Core](https://github.com/AsBuiltReport/AsBuiltReport.Core).

[AsBuiltReport](https://github.com/AsBuiltReport/AsBuiltReport) is an open-sourced community project which utilizes PowerShell to produce as-built documentation in multiple document formats for multiple vendors and technologies.

Please refer to the AsBuiltReport [website](https://www.asbuiltreport.com) for more detailed information about this project.

# :books: Sample Reports

## Sample Report - Default Style with EnableHealthCheck

Sample Microsoft AD As Built report HTML file: [Sample Microsoft AD As-Built Report.html](https://htmlpreview.github.io/?https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/dev/Samples/Sample%20Microsoft%20AD%20As%20Built%20Report.html)

# :beginner: Getting Started

Below are the instructions on how to install, configure and generate a Microsoft AD As Built report.

## :floppy_disk: Supported Versions
<!-- ********** Update supported AD versions ********** -->
The Microsoft AD As Built Report supports the following Active Directory versions;

- 2016, 2019, 2022 & 2025

### PowerShell

This report is compatible with the following PowerShell versions;

<!-- ********** Update supported PowerShell versions ********** -->
| Windows PowerShell 5.1 |    PowerShell 7    |
| :--------------------: | :----------------: |
|   :white_check_mark:   | :white_check_mark: |

## :wrench: System Requirements
<!-- ********** Update system requirements ********** -->
PowerShell 5.1, and the following PowerShell modules are required for generating a Microsoft AD As Built report.

- [AsBuiltReport.Core Module](https://github.com/AsBuiltReport/AsBuiltReport.Core)
- [AsBuiltReport.Microsoft.AD Module](https://www.powershellgallery.com/packages/AsBuiltReport.Microsoft.AD/)
- [PScribo Module](https://github.com/iainbrighton/PScribo)
- [PSGraph Module](https://github.com/KevinMarquette/PSGraph)
- [Diagrammer.Core Module](https://github.com/rebelinux/Diagrammer.Core)
- [Diagrammer.Microsoft.AD Module](https://github.com/rebelinux/Diagrammer.Microsoft.AD)
- [PScriboCharts Module](https://github.com/iainbrighton/PScriboCharts)
- [ActiveDirectory Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2019-ps)
- [ADCSAdministration Module](https://learn.microsoft.com/en-us/powershell/module/adcsadministration/?view=windowsserver2019-ps)
- [PSPKI Module](https://www.powershellgallery.com/packages/PSPKI/3.7.2)
- [GroupPolicy Module](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2019-ps)
- [DnsServer Module](https://docs.microsoft.com/en-us/powershell/module/dnsserver/?view=windowsserver2019-ps)

### Linux & macOS

This report does not support Linux or Mac due to the fact that the ActiveDirectory/GroupPolicy modules are dependent on the .NET Framework. Until Microsoft migrates these modules to native PowerShell Core, only PowerShell >= (5.x, 7) will be supported on Windows.

### :closed_lock_with_key: Required Privileges

A Microsoft AD As Built Report can be generated with Active Directory Enterprise Forest level privileges. Since this report relies extensively on the WinRM component, you should make sure that it is enabled and configured. [Reference](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)

Due to a limitation of the WinRM component, a domain-joined machine is needed, also it is required to use the FQDN of the DC instead of it's IP address.
[Reference](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting?view=powershell-7.1#how-to-use-an-ip-address-in-a-remote-command)

## :package: Module Installation

### PowerShell v5.x running on a Domain Controller server
<!-- ********** Add installation for any additional PowerShell module(s) ********** -->
```powershell
Install-Module -Name PSPKI
Install-Module -Name PSGraph
Install-Module -Name Diagrammer.Core
Install-Module -Name Diagrammer.Microsoft.AD
Install-Module -Name AsBuiltReport.Microsoft.AD
Install-WindowsFeature -Name RSAT-AD-PowerShell
Install-WindowsFeature -Name RSAT-ADCS,RSAT-ADCS-mgmt
Install-WindowsFeature -Name RSAT-DNS-Server
Install-WindowsFeature -Name GPMC
```

### PowerShell v5.x running on Windows 10 client computer
<!-- ********** Add installation for any additional PowerShell module(s) ********** -->
```powershell
Install-Module -Name PSPKI
Install-Module -Name PSGraph
Install-Module -Name Diagrammer.Core
Install-Module -Name Diagrammer.Microsoft.AD
Install-Module -Name AsBuiltReport.Microsoft.AD
Add-WindowsCapability -online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
Add-WindowsCapability -Online -Name 'Rsat.CertificateServices.Tools~~~~0.0.1.0'
Add-WindowsCapability -online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
Add-WindowsCapability –online –Name 'Rsat.Dns.Tools~~~~0.0.1.0'
```

### GitHub

If you are unable to use the PowerShell Gallery, you can still install the module manually. Ensure you repeat the following steps for the [system requirements](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD#wrench-system-requirements) also.

1. Download the code package / [latest release](https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/releases/latest) zip from GitHub
2. Extract the zip file
3. Copy the folder `AsBuiltReport.Microsoft.AD` to a path that is set in `$env:PSModulePath`.
4. Open a PowerShell terminal window and unblock the downloaded files with

    ```powershell
    $path = (Get-Module -Name AsBuiltReport.Microsoft.AD -ListAvailable).ModuleBase; Unblock-File -Path $path\*.psd1; Unblock-File -Path $path\Src\Public\*.ps1; Unblock-File -Path $path\Src\Private\*.ps1
    ```

5. Close and reopen the PowerShell terminal window.

_Note: You are not limited to installing the module to those example paths, you can add a new entry to the environment variable PSModulePath if you want to use another path._

## :pencil2: Configuration

The Microsoft AD As Built Report utilises a JSON file to allow configuration of report information, options, detail and healthchecks.

A Microsoft AD report configuration file can be generated by executing the following command;

```powershell
New-AsBuiltReportConfig -Report Microsoft.AD -FolderPath <User specified folder> -Filename <Optional>
```

Executing this command will copy the default Microsoft AD report JSON configuration to a user specified folder.

All report settings can then be configured via the JSON file.

The following provides information of how to configure each schema within the report's JSON file.

### Report

The **Report** schema provides configuration of the Microsoft AD report information.

| Sub-Schema          | Setting      | Default                      | Description                                                  |
| ------------------- | ------------ | ---------------------------- | ------------------------------------------------------------ |
| Name                | User defined | Microsoft AD As Built Report | The name of the As Built Report                              |
| Version             | User defined | 1.0                          | The report version                                           |
| Status              | User defined | Released                     | The report release status                                    |
| ShowCoverPageImage  | true / false | true                         | Toggle to enable/disable the display of the cover page image |
| ShowTableOfContents | true / false | true                         | Toggle to enable/disable table of contents                   |
| ShowHeaderFooter    | true / false | true                         | Toggle to enable/disable document headers & footers          |
| ShowTableCaptions   | true / false | true                         | Toggle to enable/disable table captions/numbering            |

### Options

The **Options** schema allows certain options within the report to be toggled on or off.

| Sub-Schema              | Setting            | Default   | Description                                                                   |
| ----------------------- | ------------------ | --------- | ----------------------------------------------------------------------------- |
| DiagramTheme            | string             | White     | Set the diagram theme (Black/White/Neon)                                      |
| DiagramType             | true / false       | true      | Toggle to enable/disable the export of individual diagram diagrams            |
| DiagramWaterMark        | string             | empty     | Set the diagram watermark                                                     |
| EnableDiagrams          | true / false       | false     | Toggle to enable/disable infrastructure diagrams                              |
| EnableDiagramsDebug     | true / false       | false     | Toggle to enable/disable diagram debug option                                 |
| EnableDiagramSignature  | true / false       | false     | Toggle to enable/disable diagram signature (bottom right corner)              |
| EnableHardwareInventory | true / false       | false     | Toggle to enable/disable hardware information                                 |
| ExportDiagrams          | true / false       | true      | Toggle to enable/disable diagram export option                                |
| ExportDiagramsFormat    | string array       | pdf       | Set the format used to export the infrastructure diagram (dot, png, pdf, svg) |
| Exclude.DCs             | Array List         | Empty     | Allow to filter on AD Domain Controller Server FQDN.                          |
| Exclude.Domains         | Array List         | Empty     | Allow to filter on AD Domain FQDN                                             |
| Include.DCs             | Array List         | Empty     | Allow only a list of Active Directory Domain FQDN to document.                |
| Include.Domains         | Array List         | Empty     | Allow only a list of Active Directory Domain Controller FQDN to document.     |
| JobsTimeOut             | Int                | 900       | Allow to set the timeout (in seconds) for remote jobs execution               |
| PSDefaultAuthentication | Negotiate/Kerberos | Negotiate | Allow to set the value of the PSRemoting authentication method.               |
|                         |                    |           | For Workgroup authentication Negotiate value is required.                     |
| ShowDefinitionInfo      | true/false         | False     | Toggle to enable/disable Microsoft AD term explanations                       |
| SignatureAuthorName     | string             | empty     | Set the signature author name                                                 |
| SignatureCompanyName    | string             | empty     | Set the signature company name                                                |
| WinRMFallbackToNoSSL    | Bool               | True      | Allow to fallback to WINRM without SSL                                        |
| WinRMPort               | Int                | 5985      | Allow to set tcp port for WinRM                                               |
| WinRMSSL                | Bool               | True      | Allow to enable SSL for WINRM connection                                      |
| WinRMSSLPort            | Int                | 5986      | Allow to set tcp port for WinRM over SSL                                      |


### InfoLevel

The **InfoLevel** schema allows configuration of each section of the report at a granular level. The following sections can be set.

There are 4 levels (0-3) of detail granularity for each section as follows;

| Setting | InfoLevel    | Description                                                                                         |
| :-----: | ------------ | --------------------------------------------------------------------------------------------------- |
|    0    | Disabled     | Does not collect or display any information                                                         |
|    1    | Enabled      | Provides summarized information for a collection of objects                                         |
|    2    | Adv Summary  | Provides condensed, detailed information for a collection of objects                                |
|    3    | Detailed     | Provides detailed information for individual objects                                                |
|    4    | Adv Detailed | Provides detailed information for individual objects, as well as information for associated objects |


The table below outlines the default and maximum **InfoLevel** settings for each section.

| Sub-Schema | Default Setting | Maximum Setting |
| ---------- | :-------------: | :-------------: |
| Forest     |        2        |        1        |
| Domain     |        2        |        4        |
| DNS        |        1        |        2        |
| CA         |        0        |        3        |

### Healthcheck

The **Healthcheck** schema is used to toggle health checks on or off.

## :computer: Examples

There are a few examples listed below on running the AsBuiltReport script against a Microsoft Active Directory Domain Controller target. Refer to the `README.md` file in the main AsBuiltReport project repository for more examples.

```powershell

# Generate a Microsoft Active Directory As Built Report for Domain Controller Server 'admin-dc-01v.contoso.local' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Append timestamp to report filename. Save reports to 'C:\Users\Jon\Documents'
PS C:\> New-AsBuiltReport -Report Microsoft.AD -Target 'admin-dc-01v.contoso.local' -Username 'administrator@contoso.local' -Password 'P@ssw0rd' -Format Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -Timestamp

# Generate a Microsoft Active Directory As Built Report for Domain Controller Server 'admin-dc-01v.contoso.local' using specified credentials and report configuration file. Export report to Text, HTML & DOCX formats. Use default report style. Save reports to 'C:\Users\Jon\Documents'. Display verbose messages to the console.
PS C:\> New-AsBuiltReport -Report Microsoft.AD -Target 'admin-dc-01v.contoso.local' -Username 'administrator@contoso.local' -Password 'P@ssw0rd' -Format Text,Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -ReportConfigFilePath 'C:\Users\Jon\AsBuiltReport\AsBuiltReport.Microsoft.AD.json' -Verbose

# Generate a Microsoft Active Directory As Built Report for Domain Controller Server 'admin-dc-01v.contoso.local' using stored credentials. Export report to HTML & Text formats. Use default report style. Highlight environment issues within the report. Save reports to 'C:\Users\Jon\Documents'.
PS C:\> $Creds = Get-Credential
PS C:\> New-AsBuiltReport -Report Microsoft.AD -Target 'admin-dc-01v.contoso.local' -Credential $Creds -Format Html,Text -OutputFolderPath 'C:\Users\Jon\Documents' -EnableHealthCheck

# Generate a Microsoft Active Directory As Built Report for Domain Controller Server 'admin-dc-01v.contoso.local' using specified credentials. Export report to HTML & DOCX formats. Use default report style. Reports are saved to the user profile folder by default. Attach and send reports via e-mail.
PS C:\> New-AsBuiltReport -Report Microsoft.AD -Target 'admin-dc-01v.contoso.local' -Username 'administrator@contoso.local' -Password 'P@ssw0rd' -Format Html,Word -OutputFolderPath 'C:\Users\Jon\Documents' -SendEmail
```

## :x: Known Issues

- This project uses the PScribo module to generate the documents. I have identified that the EvotecIT "PSWriteWord" project uses the same cmdlet. For this report to be generated successfully the PSWriteWord module must be uninstalled.
- Issues with WinRM when using the IP address instead of the "Fully Qualified Domain Name".
- This project relies heavily on the remote connection function through WinRM. For this reason the use of a Windows 10 client is specifically used as a jumpbox.
- The report provides the ability to extract the configuration of the DNS services. In order to obtain this information it is required that the servers running these services have powershell modules installed for each service (RSAT-DNS-Server & RSAT-AD-PowerShell).
- This report assumes that the DNS Server service is running on the same server where Domain Controller is running (Cohost).
- In some cases when trying to update the report, an error similar to this is generated:
  - "PackageManagement\Install-Package : Authenticode issuer 'CN="xyz, INC.", O="xyz, INC.", L=San Jose, S=California on the previusly-installed module 'PSPKI'. If you still want to install or update, use -SkipPublisherCheck parameter."
  - The expected workaround is to add the '-SkipPublisherCheck' to the install module 'Update-Module -Name PSPKI -Force -SkipPublisherCheck'
- Issues when running the report against Windows Server 2012 and 2012 R2.
  - Error: "Exception calling Save with 1 argument(s): hexadecimal value 0x00, is an invalid character."
