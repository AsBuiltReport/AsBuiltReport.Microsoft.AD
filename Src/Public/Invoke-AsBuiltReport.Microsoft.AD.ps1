function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.8.1
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

    Write-PScriboMessage -IsWarning "Please refer to the AsBuiltReport.Microsoft.AD github website for more detailed information about this project."
    Write-PScriboMessage -IsWarning "Do not forget to update your report configuration file after each new release."
    Write-PScriboMessage -IsWarning "Documentation: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD"
    Write-PScriboMessage -IsWarning "Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues"

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

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

        throw "The requested operation requires elevation: Run PowerShell console as administrator"
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

    Get-RequiredModule -Name PSPKI -Version '3.7.2'

    # Import Report Configuration
    $script:Report = $ReportConfig.Report
    $script:InfoLevel = $ReportConfig.InfoLevel
    $script:Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $script:TextInfo = (Get-Culture).TextInfo

    #---------------------------------------------------------------------------------------------#
    #                                 Connection Section                                          #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {

        Try {
            Write-PScriboMessage "Connecting to Domain Controller Server '$System'."
            $script:TempPssSession = New-PSSession $System -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name "Global:TempPssSession"
            $script:TempCIMSession = New-CimSession $System -Credential $Credential -Authentication $Options.PSDefaultAuthentication -ErrorAction Stop -Name "Global:TempCIMSession"
            $script:ADSystem = Invoke-Command -Session $TempPssSession { Get-ADForest -ErrorAction Stop }
        } Catch {
            throw "Unable to connect to the Domain Controller: $System"
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

        # Remove used PSSession
        Write-PScriboMessage "Clearing PowerShell Session $($TempPssSession.Id)"
        Remove-PSSession -Session $TempPssSession

        # Remove used CIMSession
        Write-PScriboMessage "Clearing CIM Session $($TempCIMSession.Id)"
        Remove-CimSession -CimSession $TempCIMSession

    }#endregion foreach loop
}
