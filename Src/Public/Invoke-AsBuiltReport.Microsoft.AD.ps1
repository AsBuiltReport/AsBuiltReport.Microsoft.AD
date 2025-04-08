function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.9.4
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

    #Requires -Version 5.1
    #Requires -PSEdition Desktop
    #Requires -RunAsAdministrator

    if ($psISE) {
        Write-Error -Message "This script cannot be run inside the PowerShell ISE. Please execute it from the PowerShell Command Window."
        break
    }

    Write-PScriboMessage -Plugin "Module" -IsWarning "Please refer to the AsBuiltReport.Microsoft.AD github website for more detailed information about this project."
    Write-PScriboMessage -Plugin "Module" -IsWarning "Do not forget to update your report configuration file after each new release."
    Write-PScriboMessage -Plugin "Module" -IsWarning "Documentation: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD"
    Write-PScriboMessage -Plugin "Module" -IsWarning "Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues"
    Write-PScriboMessage -Plugin "Module" -IsWarning "This project is community maintained and has no sponsorship from Microsoft, its employees or any of its affiliates."

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
        Write-PScriboMessage -IsWarning $_.Exception.Message
    }

    #Validate Required Modules and Features
    $OSType = (Get-ComputerInfo).OsProductType
    if ($OSType -eq 'WorkStation') {
        Get-RequiredFeature -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.CertificateServices.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0' -OSType $OSType
        Get-RequiredFeature -Name 'Rsat.Dns.Tools~~~~0.0.1.0' -OSType $OSType
    }
    if ($OSType -eq 'Server' -or $OSType -eq 'DomainController') {
        Get-RequiredFeature -Name RSAT-AD-PowerShell -OSType $OSType
        Get-RequiredFeature -Name RSAT-ADCS -OSType $OSType
        Get-RequiredFeature -Name RSAT-ADCS-mgmt -OSType $OSType
        Get-RequiredFeature -Name RSAT-DNS-Server -OSType $OSType
        Get-RequiredFeature -Name GPMC -OSType $OSType
    }

    Get-RequiredModule -Name PSPKI -Version '4.2.0'

    # Import Report Configuration
    $script:Report = $ReportConfig.Report
    $script:InfoLevel = $ReportConfig.InfoLevel
    $script:Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $script:TextInfo = (Get-Culture).TextInfo

    if ($Healthcheck) {
        Section -Style TOC -ExcludeFromTOC 'DISCLAIMER' {
            Paragraph "The information in this report has been gathered through automation and observations. Opinions, recommendations, and conclusions are provided based on insight, knowledge, training, and experience. This assessment is not exhaustive, but we have aimed to capture the most relevant opportunities for improvement. It is expected that the implementation of these recommendations will be reviewed and carried out by someone with the necessary knowledge, experience, or expertise. The author(s) shall not be liable for any damages (including, but not limited to, loss of business profits, business interruption, loss of business information, or other financial loss) arising from the use or inability to use these recommendations or the statements made in this documentation."
        }
        PageBreak
    }

    #---------------------------------------------------------------------------------------------#
    #                                 Connection Section                                          #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {

        if (Select-String -InputObject $System -Pattern "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$") {
            throw "Please use the Fully Qualified Domain Name (FQDN) instead of an IP address when connecting to the Domain Controller: $System"
        }

        if ($Options.WinRMSSL) {
            $WinRMType = "WinRM with SSL"
            $CIMType = "CIM with SSL"
        } else {
            $WinRMType = "WinRM"
            $CIMType = "CIM"
        }

        Try {
            $script:TempPssSession = Get-ValidPSSession -ComputerName $System -SessionName $System
        } Catch {
            throw "Failed to establish a PSSession ($WinRMType) with the Domain Controller '$System': $($_.Exception.Message)"
        }

        Try {
            # By default, SSL is not used with New-CimSession. WsMan encrypts all content that is transmitted over the network, even when using HTTP.
            $script:TempCIMSession = New-CimSession $System -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name "Global:TempCIMSession"
        } Catch {
            Write-PScriboMessage -IsWarning "Unable to establish a CimSession ($CIMType) with the Domain Controller '$System'."
        }

        Try {
            Write-PScriboMessage "Connecting to retrieve Forest information from Domain Controller '$System'."
            $script:ADSystem = Invoke-Command -Session $TempPssSession { Get-ADForest -ErrorAction Stop }
        } Catch {
            throw "Unable to retrieve Forest information from Domain Controller '$System'."
        }

        $script:ForestInfo = $ADSystem.RootDomain.toUpper()
        [array]$RootDomains = $ADSystem.RootDomain
        [array]$ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains }
        [string] $script:OrderedDomains = $RootDomains + $ChildDomains

        # Forest Section
        Get-AbrForestSection

        # Domain Section
        Get-AbrDomainSection

        # DNS Section
        Get-AbrDnsSection

        # PKI Section
        Get-AbrPKISection

        if ($TempPssSession) {
            # Remove used PSSession
            Write-PScriboMessage "Clearing PowerShell session with ID $($TempPssSession.Id)."
            Remove-PSSession -Session $TempPssSession
        }
        if ($DCPssSessions = Get-PSSession | Where-Object { $_.Runspace.ConnectionInfo.Credential.Username -eq $Credential.UserName }) {
            foreach ($DCPssSession in $DCPssSessions) {
                # Remove used PSSession
                Write-PScriboMessage "Clearing PowerShell session: $($DCPssSession.Id)."
                Remove-PSSession -Session $DCPssSession
            }
        }

        if ($TempCIMSession) {
            # Remove used CIMSession
            Write-PScriboMessage "Clearing CIM Session with ID $($TempCIMSession.Id)"
            Remove-CimSession -CimSession $TempCIMSession
        }
    }#endregion foreach loop
}
