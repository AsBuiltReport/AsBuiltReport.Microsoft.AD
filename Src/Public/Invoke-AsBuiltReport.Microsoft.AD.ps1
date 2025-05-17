function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.9.5
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

    Write-Host "- Please refer to the AsBuiltReport.Microsoft.AD github website for more detailed information about this project." -ForegroundColor White
    Write-Host "- Do not forget to update your report configuration file after each new release." -ForegroundColor White
    Write-Host "- Documentation: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD" -ForegroundColor White
    Write-Host "- Issues or bug reporting: https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD/issues" -ForegroundColor White
    Write-Host "- This project is community maintained and has no sponsorship from Microsoft, its employees or any of its affiliates." -ForegroundColor White

    # Check the version of the dependency modules
    $ModuleArray = @('AsBuiltReport.Microsoft.AD', 'Diagrammer.Microsoft.AD', 'Diagrammer.Core', 'PSPKI')

    foreach ($Module in $ModuleArray) {
        Try {
            $InstalledVersion = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version

            if ($InstalledVersion) {
                Write-Host "- $Module module v$($InstalledVersion.ToString()) is currently installed."
                $LatestVersion = Find-Module -Name $Module -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
                if ($InstalledVersion -lt $LatestVersion) {
                    Write-Host "  - $Module module v$($LatestVersion.ToString()) is available." -ForegroundColor Red
                    Write-Host "  - Run 'Update-Module -Name $Module -Force' to install the latest version." -ForegroundColor Red
                }
            }
        } Catch {
            Write-PScriboMessage -IsWarning $_.Exception.Message
        }
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

        # WinRM Session variables
        $DCStatus = @()
        $DomainStatus = @()
        $CIMTable = @()
        $PSSTable = @()

        Try {
            $script:TempPssSession = Get-ValidPSSession -ComputerName $System -SessionName $System -PSSTable ([ref]$PSSTable)
        } Catch {
            throw "Failed to establish a PSSession ($WinRMType) with the Domain Controller '$System': $($_.Exception.Message)"
        }

        Try {
            # By default, SSL is not used with New-CimSession. WsMan encrypts all content that is transmitted over the network, even when using HTTP.
            $script:TempCIMSession = Get-ValidCIMSession -ComputerName $System -SessionName $System -CIMTable ([ref]$CIMTable)
        } Catch {
            Write-PScriboMessage -IsWarning -Message "Unable to establish a CimSession ($CIMType) with the Domain Controller '$System'."
        }

        Try {
            Write-PScriboMessage -Message "Connecting to retrieve Forest information from Domain Controller '$System'."
            $script:ADSystem = Invoke-Command -Session $TempPssSession { Get-ADForest -ErrorAction Stop }
        } Catch {
            throw "Unable to retrieve Forest information from Domain Controller '$System'."
        }

        $script:ForestInfo = $ADSystem.RootDomain.toUpper()
        [array]$RootDomains = $ADSystem.RootDomain
        if ($Options.Include.Domains) {
            [array]$ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains -and $_ -in $Options.Include.Domains }
        } else {
            [array]$ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains -and $_ -notin $Options.Exclude.Domains }
        }
        [array] $script:OrderedDomains = @($RootDomains, $ChildDomains)

        # Forest Section
        Get-AbrForestSection

        # Domain Section
        Get-AbrDomainSection -DomainStatus ([ref]$DomainStatus)

        # DNS Section
        Get-AbrDnsSection -DomainStatus ([ref]$DomainStatus)

        # PKI Section
        Get-AbrPKISection

        #---------------------------------------------------------------------------------------------#
        #                            Export Diagram Section                                           #
        #---------------------------------------------------------------------------------------------#

        if ($Options.ExportDiagrams) {
            $Options.DiagramType.PSobject.Properties | ForEach-Object { if ($_.Value) { Get-AbrDiagrammer -DiagramType $_.Name -PSSessionObject $TempPssSession } }
        }

        #---------------------------------------------------------------------------------------------#
        #                          Clean Connection Sessions Section                                  #
        #---------------------------------------------------------------------------------------------#
        if ($PSSTable) {
            foreach ($PSSession in ($PSSTable | Where-Object { $_.Status -ne 'Offline' })) {
                # Remove used CIMSession
                Write-PScriboMessage -Message "Clearing PSSession with ID $($PSSession.Id)"
                Remove-PSSession -Id $PSSession.id
            }
        }

        if ($CIMTable) {
            foreach ($CIMSession in ($CIMTable | Where-Object { $_.Status -ne 'Offline' })) {
                # Remove used CIMSession
                Write-PScriboMessage -Message "Clearing CIM Session with ID $($CIMSession.Id)"
                Remove-CimSession -Id $CIMSession.id
            }
        }

        #---------------------------------------------------------------------------------------------#
        #                           Connection Status Section                                         #
        #---------------------------------------------------------------------------------------------#

        $DCOffine = $DCStatus | Where-Object { $Null -ne $_.DCName -and $_.Status -eq 'Offline' } | Select-Object -Property @{N = 'Name'; E = { $_.DCName } }, @{N = 'WinRM Status'; E = { $_.Status } }, @{N = 'Ping Status'; E = { $_.PingStatus } }, @{N = 'Protocol'; E = { $_.Protocol } } | ForEach-Object { [pscustomobject]$_ }
        $DomainOffline = $DomainStatus | Where-Object { $Null -ne $_.Name -and $_.Status -eq 'Offline' }
        if ($DCOffine -or $DomainOffline) {
            Write-Host " "
            Write-Host "The following Systems could not be reached:`n"
            if ($DCOffine) {
                Write-Host "Domain Controllers"
                Write-Host "------------------"
                Write-Host " "
                Write-PSObject $DCOffine -MatchMethod Query, Query, Query, Query -Column 'WinRM Status', 'WinRM Status', 'Ping Status', 'Ping Status' -Value "'WinRM Status' -eq 'Offline'", "'WinRM Status' -eq 'Online'", "'Ping Status' -eq 'Offline'", "'Ping Status' -eq 'Online'" -ValueForeColor Red, Green, Red, Green
                Write-Host " "
            }
            if ($DomainOffline) {
                Write-Host "Domains"
                Write-Host "--------"
                Write-Host " "
                $DomainOffline | ForEach-Object {
                    Write-Host "$($_.Name)" -ForegroundColor Red
                }
                Write-Host " "
            }
        }
    }#endregion foreach loop
}