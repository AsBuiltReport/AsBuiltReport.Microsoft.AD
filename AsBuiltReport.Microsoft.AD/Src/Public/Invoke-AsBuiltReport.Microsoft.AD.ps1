function Invoke-AsBuiltReport.Microsoft.AD {
    <#
    .SYNOPSIS
        PowerShell script to document the configuration of Microsoft AD in Word/HTML/Text formats
    .DESCRIPTION
        Documents the configuration of Microsoft AD in Word/HTML/Text formats using PScribo.
    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
        Credits:        Iain Brighton (@iainbrighton) - PScribo module

    .LINK
        https://github.com/AsBuiltReport/AsBuiltReport.Microsoft.AD
    #>

    # Do not remove or add to these parameters
    [CmdletBinding()]
    param (
        [String[]] $Target,
        [PSCredential] $Credential
    )

    #Requires -RunAsAdministrator
    #Requires -Version 7.4

    if ($psISE) {
        Write-Error -Message $reportTranslate.InvokeAsBuiltReportMicrosoftAD.PwshISE
        break
    }

    Write-ReportModuleInfo -ModuleName 'Microsoft.AD'

    Write-Host "$($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ReportModuleInfo4) " -NoNewline
    Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.ReportModuleInfo5 -ForegroundColor Cyan
    Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.ReportModuleInfo6

    # Check the version of the dependency modules
    $ModuleArray = @('AsBuiltReport.Core', 'AsBuiltReport.Chart', 'AsBuiltReport.Diagram')

    foreach ($Module in $ModuleArray) {
        try {
            $InstalledVersion = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue | Sort-Object -Property Version -Descending | Select-Object -First 1 -ExpandProperty Version

            if ($InstalledVersion) {
                Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ModuleInstalled -f $Module, $InstalledVersion.ToString())
                $LatestVersion = Find-Module -Name $Module -Repository PSGallery -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
                if ($InstalledVersion -lt $LatestVersion) {
                    Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ModuleAvailable -f $Module, $LatestVersion.ToString()) -ForegroundColor Red
                    Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ModuleUpdate -f $Module) -ForegroundColor Red
                }
            }
        } catch {
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

    # Import Report Configuration
    $script:Report = $ReportConfig.Report
    $script:InfoLevel = $ReportConfig.InfoLevel
    $script:Options = $ReportConfig.Options

    # Used to set values to TitleCase where required
    $script:TextInfo = (Get-Culture).TextInfo
    $script:AbrCustomPalette = @(
        '#cfe4ff'
        '#bbd1ee'
        '#a7bfde'
        '#94acce'
        '#809bbe'
        '#6e89ae'
        '#5b789e'
        '#48678f'
        '#355780'
    )

    if ($Healthcheck) {
        Section -Style TOC -ExcludeFromTOC $reportTranslate.InvokeAsBuiltReportMicrosoftAD.DisclaimerSection {
            Paragraph $reportTranslate.InvokeAsBuiltReportMicrosoftAD.DISCLAIMER
        }
        PageBreak
    }

    #---------------------------------------------------------------------------------------------#
    #                                 Connection Section                                          #
    #---------------------------------------------------------------------------------------------#
    foreach ($System in $Target) {

        if (Select-String -InputObject $System -Pattern '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
            throw ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.IPAddressError -f $System)
        }

        if ($Options.WinRMSSL) {
            $WinRMType = 'WinRM with SSL'
            $CIMType = 'CIM with SSL'
        } else {
            $WinRMType = 'WinRM'
            $CIMType = 'CIM'
        }

        # WinRM Session variables
        $DCStatus = [System.Collections.Generic.List[object]]::new()
        $DomainStatus = [System.Collections.Generic.List[object]]::new()
        $CIMTable = [System.Collections.Generic.List[object]]::new()
        $PSSTable = [System.Collections.Generic.List[object]]::new()

        try {
            $script:TempPssSession = Get-ValidPSSession -ComputerName $System -SessionName $System -PSSTable ([ref]$PSSTable) -InitialForrestConnection $true
        } catch {
            throw ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.PSSessionError -f $WinRMType, $System, $_.Exception.Message)
        }

        try {
            # By default, SSL is not used with New-CimSession. WsMan encrypts all content that is transmitted over the network, even when using HTTP.
            $script:TempCIMSession = Get-ValidCIMSession -ComputerName $System -SessionName $System -CIMTable ([ref]$CIMTable)
        } catch {
            Write-PScriboMessage -IsWarning -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.CIMSessionError -f $CIMType, $System)
        }

        try {
            Write-PScriboMessage -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ConnectingForest -f $System)
            $script:ADSystem = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADForest -ErrorAction Stop }
        } catch {
            throw ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ForestError -f $System, $_.Exception.Message)
        }

        $script:ForestInfo = $ADSystem.RootDomain.toUpper()
        $RootDomains = $ADSystem.RootDomain
        $ChildDomains = [System.Collections.Generic.List[object]]::new()
        if ($Options.Include.Domains) {
            Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.IncludeDomainsEnabled -f ($Options.Include.Domains -join ', '))
            $ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains -and $_ -in $Options.Include.Domains }
        } elseif ($Options.Exclude.Domains) {
            Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ExcludeDomainsEnabled -f ($Options.Exclude.Domains -join ', '))
            $ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains -and $_ -notin $Options.Exclude.Domains }
        } else {
            $ChildDomains = $ADSystem.Domains | Where-Object { $_ -ne $RootDomains }
        }

        $script:OrderedDomains = [System.Collections.Generic.List[object]]::new()
        if (-not ($Options.Exclude.Domains -contains $RootDomains)) {
            $OrderedDomains.Add($RootDomains)
        }

        Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.GettingForestInfo -f $RootDomains)

        if ($ChildDomains) {
            $OrderedDomains.Add($ChildDomains)
            Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.DiscoveringChildDomains -f $RootDomains, ($OrderedDomains -join ', '))
        }

        # Set initial connection to childs domains to find out if there is an available DC to fulfill the requests
        foreach ($Domain in $OrderedDomains) {
            try {
                if (Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                    Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.DCAvailable -f $Domain)
                } else {
                    Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.DCUnavailable -f $Domain)
                    $DomainStatus.Add(
                        @{
                            Name = $Domain
                            Status = 'Offline'
                        }
                    )
                    $OrderedDomains = $OrderedDomains | Where-Object { $_ -ne $Domain }
                }
            } catch { $null }
        }
        Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.FinishingDomainList -f $RootDomains, ($OrderedDomains -join ', '))

        # Report Overview
        Get-AbrADReportBrief

        # Forest Section
        if ($InfoLevel.Forest -ge 1) {
            Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.WorkingOnForest
            Get-AbrForestSection
        }

        # Domain Section
        if ($InfoLevel.Domain -ge 1) {
            Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.WorkingOnDomain
            Get-AbrDomainSection -DomainStatus ([ref]$DomainStatus)
        }

        # DNS Section
        if ($InfoLevel.DNS -ge 1) {
            Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.WorkingOnDNS
            Get-AbrDnsSection -DomainStatus ([ref]$DomainStatus)
        }

        #---------------------------------------------------------------------------------------------#
        #                            Export Diagram Section                                           #
        #---------------------------------------------------------------------------------------------#

        if ($Options.ExportDiagrams) {
            Write-Host ' '
            Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.ExportDiagramsEnabled
            $Options.DiagramType.PSobject.Properties | ForEach-Object {
                if ($_.Value -and $_.Name -eq 'Trusts') {
                    foreach ($Domain in $OrderedDomains) {
                        try {
                            $ValidDC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)
                            if ($ValidDC) {
                                $DCPssSession = Get-ValidPSSession -ComputerName $ValidDC -SessionName $($ValidDC) -PSSTable ([ref]$PSSTable)
                                if ($DCPssSession) {
                                    Get-AbrDiagrammer -DiagramType $_.Name -PSSessionObject $DCPssSession -Domain $Domain -FileName "AsBuiltReport.Microsoft.AD-($($_.Name))-$($Domain)"
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.TrustsDiagramError -f $Domain, $_.Exception.Message)
                        }
                    }
                } elseif ($_.Value) {
                    try {
                        Get-AbrDiagrammer -DiagramType $_.Name -PSSessionObject $TempPssSession
                    } catch {
                        Write-PScriboMessage -IsWarning -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.DiagramExportError -f $_.Name, $_.Exception.Message)
                    }
                }
            }
        }

        #---------------------------------------------------------------------------------------------#
        #                          Clean Connection Sessions Section                                  #
        #---------------------------------------------------------------------------------------------#
        if ($PSSTable) {
            foreach ($PSSession in ($PSSTable | Where-Object { $_.Status -ne 'Offline' })) {
                # Remove used CIMSession
                Write-PScriboMessage -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ClearPSSession -f $PSSession.Id)
                Remove-PSSession -Id $PSSession.id
            }
        }

        if ($CIMTable) {
            foreach ($CIMSession in ($CIMTable | Where-Object { $_.Status -ne 'Offline' })) {
                # Remove used CIMSession
                Write-PScriboMessage -Message ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.ClearCIMSession -f $CIMSession.Id)
                Remove-CimSession -Id $CIMSession.id
            }
        }

        #---------------------------------------------------------------------------------------------#
        #                           Connection Status Section                                         #
        #---------------------------------------------------------------------------------------------#

        Write-Host ($reportTranslate.InvokeAsBuiltReportMicrosoftAD.FinishedReport -f $RootDomains)

        $DCOffine = $DCStatus | Where-Object { $Null -ne $_.DCName -and $_.Status -eq 'Offline' } | Select-Object -Property @{N = 'Name'; E = { $_.DCName } }, @{N = 'WinRM Status'; E = { $_.Status } }, @{N = 'Ping Status'; E = { $_.PingStatus } }, @{N = 'Protocol'; E = { $_.Protocol } } | ForEach-Object { [pscustomobject]$_ }
        $DomainOffline = $DomainStatus | Where-Object { $Null -ne $_.Name -and $_.Status -eq 'Offline' }
        if ($DCOffine -or $DomainOffline) {
            Write-Host ' '
            Write-Host "$($reportTranslate.InvokeAsBuiltReportMicrosoftAD.SystemsUnreachable)`n"
            if ($DCOffine) {
                Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.DomainControllers
                Write-Host '------------------'
                Write-Host ' '
                Write-AbrPSObject $DCOffine -MatchMethod Query, Query, Query, Query -Column 'WinRM Status', 'WinRM Status', 'Ping Status', 'Ping Status' -Value "'WinRM Status' -eq 'Offline'", "'WinRM Status' -eq 'Online'", "'Ping Status' -eq 'Offline'", "'Ping Status' -eq 'Online'" -ValueForeColor Red, Green, Red, Green
                Write-Host ' '
            }
            if ($DomainOffline) {
                Write-Host $reportTranslate.InvokeAsBuiltReportMicrosoftAD.Domains
                Write-Host '--------'
                Write-Host ' '
                $DomainOffline | ForEach-Object {
                    Write-Host "$($_.Name)" -ForegroundColor Red
                }
                Write-Host ' '
            }
        }
    }#endregion foreach loop
}