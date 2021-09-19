<!-- ********** DO NOT EDIT THESE LINKS ********** -->
<p align="center">
    <a href="https://www.asbuiltreport.com/" alt="AsBuiltReport"></a>
            <img src='https://raw.githubusercontent.com/AsBuiltReport/AsBuiltReport/master/AsBuiltReport.png' width="8%" height="8%" /></a>
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

# Microsoft AD As Built Report

Microsoft AD As Built Report is a PowerShell module which works in conjunction with [AsBuiltReport.Core](https://github.com/AsBuiltReport/AsBuiltReport.Core).

[AsBuiltReport](https://github.com/AsBuiltReport/AsBuiltReport) is an open-sourced community project which utilises PowerShell to produce as-built documentation in multiple document formats for multiple vendors and technologies.

Please refer to the AsBuiltReport [website](https://www.asbuiltreport.com) for more detailed information about this project.

# :beginner: Getting Started

Below are the instructions on how to install, configure and generate a Microsoft AD As Built report.

## :floppy_disk: Supported Versions
<!-- ********** Update supported AD versions ********** -->
The Microsoft AD As Built Report supports the following AD versions;

- 2008, 2008 R2, 2012, 2016, 2019

### PowerShell

This report is compatible with the following PowerShell versions;

<!-- ********** Update supported PowerShell versions ********** -->
| Windows PowerShell 5.1 |     PowerShell 7    |
|:----------------------:|:--------------------:|
|   :white_check_mark:   | :white_check_mark: |

## :wrench: System Requirements
<!-- ********** Update system requirements ********** -->
PowerShell 5.1 or PowerShell 7, and the following PowerShell modules are required for generating a Microsoft AD As Built report.

- [AsBuiltReport.Microsoft.AD Module](https://www.powershellgallery.com/packages/AsBuiltReport.Microsoft.AD/)
- [ActiveDirectory Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2019-ps)
- [PSPKI Module](https://www.powershellgallery.com/packages/PSPKI/3.7.2)
- [GroupPolicy Module](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2019-ps)

### Linux & macOS

* .NET Core is required for cover page image support on Linux and macOS operating systems.
  - [Installing .NET Core for macOS](https://docs.microsoft.com/en-us/dotnet/core/install/macos)
  - [Installing .NET Core for Linux](https://docs.microsoft.com/en-us/dotnet/core/install/linux)

❗ If you are unable to install .NET Core, you must set `ShowCoverPageImage` to `False` in the report JSON configuration file.

### :closed_lock_with_key: Required Privileges
<!-- ********** Define required privileges ********** -->
<!-- ********** Try to follow best practices to define least privileges ********** -->

## :package: Module Installation

### PowerShell v5.x on if running in a DC server
<!-- ********** Add installation for any additional PowerShell module(s) ********** -->
```powershell
install-module AsBuiltReport.Microsoft.AD
install-module PSPKI
Install-WindowsFeature RSAT-AD-PowerShell
Install-WindowsFeature GPMC
```

### PowerShell v5.x on if running in Windows 10 Client Machine
<!-- ********** Add installation for any additional PowerShell module(s) ********** -->
```powershell
install-module AsBuiltReport.Microsoft.AD
install-module PSPKI
Add-WindowsCapability -online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
Add-WindowsCapability -online -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
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

| Sub-Schema          | Setting      | Default                        | Description                                                  |
|---------------------|--------------|--------------------------------|--------------------------------------------------------------|
| Name                | User defined | Microsoft AD As Built Report | The name of the As Built Report                              |
| Version             | User defined | 1.0                            | The report version                                           |
| Status              | User defined | Released                       | The report release status                                    |
| ShowCoverPageImage  | true / false | true                           | Toggle to enable/disable the display of the cover page image |
| ShowTableOfContents | true / false | true                           | Toggle to enable/disable table of contents                   |
| ShowHeaderFooter    | true / false | true                           | Toggle to enable/disable document headers & footers          |
| ShowTableCaptions   | true / false | true                           | Toggle to enable/disable table captions/numbering            |

### Options

The **Options** schema allows certain options within the report to be toggled on or off.

### InfoLevel

The **InfoLevel** schema allows configuration of each section of the report at a granular level. The following sections can be set.

There are 6 levels (0-5) of detail granularity for each section as follows;

| Setting | InfoLevel         | Description                                                                                                                                |
|:-------:|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
|    0    | Disabled          | Does not collect or display any information                                                                                                |
|    1    | Enabled / Summary | Provides summarised information for a collection of objects                                                                                |
|    2    | Adv Summary       | Provides condensed, detailed information for a collection of objects                                                                       |
|    3    | Detailed          | Provides detailed information for individual objects                                                                                       |
|    4    | Adv Detailed      | Provides detailed information for individual objects, as well as information for associated objects                                        |
|    5    | Comprehensive     | Provides comprehensive information for individual objects, such as advanced configuration settings                                         |

### Healthcheck

The **Healthcheck** schema is used to toggle health checks on or off.

## :computer: Examples

There is one example listed below on running the AsBuiltReport script against a Microsoft Active Directory Array target. Refer to the `README.md` file in the main AsBuiltReport project repository for more examples.

- The following creates a Microsoft Active Directory Array As-Built report in HTML & Word formats in the folder C:\scripts\.

```powershell
PS C:\>New-AsBuiltReport -Report Microsoft.AD -Target 10.10.30.20 -Credential (Get-Credential) -Format HTML,Word -OutputPath C:\scripts\
```

## :x: Known Issues
