function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.12
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        $Domain,
        $DCs
    )

    begin {
        Write-PScriboMessage -Message $reportTranslate.GetAbrADDomainController.Collecting
        Show-AbrDebugExecutionTime -Start -TitleMessage 'Domain Controller Section'
    }

    process {
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            foreach ($DC in $DCs) {
                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                    $DCInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                    $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                    if ($DCPssSession ) {
                        $DCNetSettings = try { Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-NetIPAddress } } catch { Write-PScriboMessage -IsWarning -Message "Unable to get $DC network interfaces information" }
                    } else {
                        if (-not $_.Exception.MessageId) {
                            $ErrorMessage = $_.FullyQualifiedErrorId
                        } else { $ErrorMessage = $_.Exception.MessageId }
                        Write-PScriboMessage -IsWarning -Message "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                    }
                    try {
                        $inObj = [ordered] @{
                            $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                            $($reportTranslate.GetAbrADDomainController.Status) = $reportTranslate.GetAbrADDomainController.Online
                            $($reportTranslate.GetAbrADDomainController.Site) = switch ([string]::IsNullOrEmpty($DCInfo.Site)) {
                                $true { '--' }
                                $false { $DCInfo.Site }
                                default { 'Unknown' }
                            }
                            $($reportTranslate.GetAbrADDomainController.GlobalCatalog) = $DCInfo.IsGlobalCatalog
                            $($reportTranslate.GetAbrADDomainController.ReadOnly) = $DCInfo.IsReadOnly
                            $($reportTranslate.GetAbrADDomainController.IPAddress) = switch ([string]::IsNullOrEmpty($DCInfo.IPv4Address)) {
                                $true { '--' }
                                $false { $DCInfo.IPv4Address }
                                default { 'Unknown' }
                            }
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Item)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                            $($reportTranslate.GetAbrADDomainController.Status) = $reportTranslate.GetAbrADDomainController.Offline
                            $($reportTranslate.GetAbrADDomainController.Site) = '--'
                            $($reportTranslate.GetAbrADDomainController.GlobalCatalog) = '--'
                            $($reportTranslate.GetAbrADDomainController.ReadOnly) = '--'
                            $($reportTranslate.GetAbrADDomainController.IPAddress) = '--'
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Item)"
                    }
                }
            }
            if ($HealthCheck.DomainController.BestPractice) {
                if ($OutObj.Count -eq 1) {
                    $OutObj | Set-Style -Style Warning
                }
            }

            $TableParams = @{
                Name = "$($reportTranslate.GetAbrADDomainController.DomainControllerTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                List = $false
                ColumnWidths = 25, 12, 24, 10, 10, 19
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.DCName | Table @TableParams
            if ($HealthCheck.DomainController.BestPractice -and ($OutObj.Count -eq 1)) {
                Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                BlankLine
                Paragraph {
                    Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                    Text $reportTranslate.GetAbrADDomainController.DCBestPractice
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Table)"
        }
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            $inObj = [ordered] @{
                $($reportTranslate.GetAbrADDomainController.DomainControllerCount) = ($DomainController | Measure-Object).Count
                $($reportTranslate.GetAbrADDomainController.GlobalCatalog) = ($GC | Measure-Object).Count
            }
            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

            $TableParams = @{
                Name = "$($reportTranslate.GetAbrADDomainController.DomainControllerCountsTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            try {
                $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Category'
                $Chart = New-PieChart -Values $sampleData.Value -Labels $sampleData.Name -Title 'DC vs GC Distribution' -EnableLegend -LegendOrientation Horizontal -LegendAlignment UpperCenter -Width 600 -Height 400 -Format base64 -TitleFontSize 20 -TitleFontBold -EnableCustomColorPalette -CustomColorPalette $AbrCustomPalette -EnableChartBorder -ChartBorderStyle DenselyDashed -ChartBorderColor DarkBlue
            } catch {
                Write-PScriboMessage -IsWarning $_.Exception.Message
            }
            if ($OutObj) {
                if ($Chart) {
                    BlankLine
                    Image -Text $reportTranslate.GetAbrADDomainController.DCObjectChart -Align 'Center' -Percent 100 -Base64 $Chart
                }
                $OutObj | Table @TableParams
            }
        } catch {
            Write-PScriboMessage -IsWarning $($_.Exception.Message)
        }
        if ($InfoLevel.Domain -eq 2) {
            try {
                $DCConfiguration = foreach ($DC in $DCs) {
                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                        $DCInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                        $DCComputerObject = try { Invoke-CommandWithTimeout -Session $TempPssSession -ErrorAction Stop -ScriptBlock { Get-ADComputer ($using:DCInfo).ComputerObjectDN -Properties * -Server $using:DC } } catch { Out-Null }
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                        if ($DCPssSession) {
                            $DCNetSettings = try { Invoke-CommandWithTimeout -Session $DCPssSession -ErrorAction Stop -ScriptBlock { Get-NetIPAddress } } catch { Out-Null }
                            $DCNetSMBv1Setting = try { Invoke-CommandWithTimeout -Session $DCPssSession -ErrorAction Stop -ScriptBlock { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol } } catch { Out-Null }
                        } else {
                            if (-not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        try {
                            Section -Style Heading5 $DCInfo.Name {
                                try {
                                    Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADDomainController.GeneralInformationTitle {
                                        $OutObj = [System.Collections.ArrayList]::new()
                                        $inObj = [ordered] @{
                                            $($reportTranslate.GetAbrADDomainController.DCName) = $DCInfo.Hostname
                                            $($reportTranslate.GetAbrADDomainController.DomainName) = switch ([string]::IsNullOrEmpty($DCInfo.Domain)) {
                                                $true { '--' }
                                                $false { $DCInfo.Domain }
                                                default { 'Unknown' }
                                            }
                                            $($reportTranslate.GetAbrADDomainController.Site) = switch ([string]::IsNullOrEmpty($DCInfo.Site)) {
                                                $true { '--' }
                                                $false { $DCInfo.Site }
                                                default { 'Unknown' }
                                            }
                                            $($reportTranslate.GetAbrADDomainController.GlobalCatalog) = $DCInfo.IsGlobalCatalog
                                            $($reportTranslate.GetAbrADDomainController.ReadOnly) = $DCInfo.IsReadOnly
                                            $($reportTranslate.GetAbrADDomainController.OperationMasterRoles) = ($DCInfo.OperationMasterRoles -join ', ')
                                            $($reportTranslate.GetAbrADDomainController.Location) = $DCComputerObject.Location
                                            $($reportTranslate.GetAbrADDomainController.ComputerObjectSID) = $DCComputerObject.SID
                                            $($reportTranslate.GetAbrADDomainController.OperatingSystem) = $DCInfo.OperatingSystem
                                            $($reportTranslate.GetAbrADDomainController.SMB1Status) = $DCNetSMBv1Setting.State
                                            $($reportTranslate.GetAbrADDomainController.Description) = $DCComputerObject.Description
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.DomainController.BestPractice) {
                                            $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.SMB1Status) -eq $reportTranslate.GetAbrADDomainController.Enabled } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.SMB1Status
                                        }

                                        $TableParams = @{
                                            Name = "$($reportTranslate.GetAbrADDomainController.GeneralInfoTableName) - $($DCInfo.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                        if ($HealthCheck.DomainController.BestPractice -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.SMB1Status) -eq $reportTranslate.GetAbrADDomainController.Enabled })) {
                                            Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                                            BlankLine
                                            Paragraph {
                                                Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                                                Text $reportTranslate.GetAbrADDomainController.SMB1BestPractice
                                            }
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (General Information Section)"
                                }
                                try {
                                    Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADDomainController.PartitionsTitle {
                                        $OutObj = [System.Collections.ArrayList]::new()
                                        $inObj = [ordered] @{
                                            $($reportTranslate.GetAbrADDomainController.DefaultPartition) = $DCInfo.DefaultPartition
                                            $($reportTranslate.GetAbrADDomainController.Partitions) = $DCInfo.Partitions
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null


                                        $TableParams = @{
                                            Name = "$($reportTranslate.GetAbrADDomainController.PartitionsTableName) - $($DCInfo.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Partitions Section)"
                                }
                                try {
                                    if ($DCNetSettings) {
                                        Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADDomainController.NetworkingTitle {
                                            $OutObj = [System.Collections.ArrayList]::new()
                                            $inObj = [ordered] @{
                                                $($reportTranslate.GetAbrADDomainController.IPv4Addresses) = switch ([string]::IsNullOrEmpty((($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 2) -and $_.IPAddress -ne '127.0.0.1' }).IPv4Address))) {
                                                    $true { '--' }
                                                    $false { ($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 2) -and $_.IPAddress -ne '127.0.0.1' }).IPv4Address -join ', ' }
                                                    default { 'Unknown' }
                                                }
                                                $($reportTranslate.GetAbrADDomainController.IPv6Addresses) = switch ([string]::IsNullOrEmpty((($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv6' -or $_.AddressFamily -eq 23) -and $_.IPAddress -ne '::1' }).IPv6Address))) {
                                                    $true { '--' }
                                                    $false { ($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv6' -or $_.AddressFamily -eq 23) -and $_.IPAddress -ne '::1' }).IPv6Address -join ',' }
                                                    default { 'Unknown' }
                                                }
                                                $($reportTranslate.GetAbrADDomainController.LDAPPort) = $DCInfo.LdapPort
                                                $($reportTranslate.GetAbrADDomainController.LDAPSPort) = $DCInfo.SslPort
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                            if ($HealthCheck.DomainController.BestPractice) {
                                                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.IPv4Addresses).Split(',').Count -gt 1 } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainController.IPv4Addresses
                                            }
                                            if ($OutObj) {
                                                $TableParams = @{
                                                    Name = "$($reportTranslate.GetAbrADDomainController.NetworkingTableName) - $($DCInfo.Name)"
                                                    List = $true
                                                    ColumnWidths = 40, 60
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Table @TableParams
                                                if ($HealthCheck.DomainController.BestPractice -and ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.IPv4Addresses).Split(',').Count -gt 1 })) {
                                                    Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                                                    BlankLine
                                                    Paragraph {
                                                        Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                                                        Text $reportTranslate.GetAbrADDomainController.NetworkingBestPractice
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Networking Settings Section)"
                                }
                                try {
                                    $DCHWInfo = [System.Collections.ArrayList]::new()
                                    try {
                                        $CimSession = Get-ValidCIMSession -ComputerName $DC -SessionName $DC -CIMTable ([ref]$CIMTable)
                                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                                        if ($DCPssSession) {
                                            $HW = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ComputerInfo }
                                            $HWCPU = Get-CimInstance -Class Win32_Processor -CimSession $CimSession
                                        }

                                        if ($CimSession) {
                                            $License = Get-CimInstance -Query 'Select * from SoftwareLicensingProduct' -CimSession $CimSession | Where-Object { $_.LicenseStatus -eq 1 }
                                        }
                                        if ($HW) {
                                            $inObj = [ordered] @{
                                                $($reportTranslate.GetAbrADDomainController.Name) = $HW.CsName
                                                $($reportTranslate.GetAbrADDomainController.WindowsProductName) = $HW.WindowsProductName
                                                $($reportTranslate.GetAbrADDomainController.WindowsBuildNumber) = $HW.OsVersion
                                                $($reportTranslate.GetAbrADDomainController.ADDomain) = $HW.CsDomain
                                                $($reportTranslate.GetAbrADDomainController.WindowsInstallDate) = $HW.OsInstallDate
                                                $($reportTranslate.GetAbrADDomainController.TimeZone) = $HW.TimeZone
                                                $($reportTranslate.GetAbrADDomainController.LicenseType) = $License.ProductKeyChannel
                                                $($reportTranslate.GetAbrADDomainController.PartialProductKey) = $License.PartialProductKey
                                                $($reportTranslate.GetAbrADDomainController.Manufacturer) = $HW.CsManufacturer
                                                $($reportTranslate.GetAbrADDomainController.Model) = $HW.CsModel
                                                $($reportTranslate.GetAbrADDomainController.ProcessorModel) = $HWCPU[0].Name
                                                $($reportTranslate.GetAbrADDomainController.NumberOfProcessors) = ($HWCPU | Measure-Object).Count
                                                $($reportTranslate.GetAbrADDomainController.NumberOfCPUCores) = $HWCPU[0].NumberOfCores
                                                $($reportTranslate.GetAbrADDomainController.NumberOfLogicalCores) = $HWCPU[0].NumberOfLogicalProcessors
                                                $($reportTranslate.GetAbrADDomainController.PhysicalMemory) = & {
                                                    try {
                                                        ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
                                                    } catch { '0.00 GB' }
                                                }
                                            }
                                            $DCHWInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        }

                                        if ($HealthCheck.DomainController.Diagnostic) {
                                            if ($HW.CsTotalPhysicalMemory -lt 8589934592) {
                                                $DCHWInfo | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainController.PhysicalMemory
                                            }
                                        }
                                        if ($DCHWInfo) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading6 $reportTranslate.GetAbrADDomainController.HardwareInventoryTitle {
                                                $TableParams = @{
                                                    Name = "$($reportTranslate.GetAbrADDomainController.HardwareInventoryTableName) - $($DCHWInfo.$($reportTranslate.GetAbrADDomainController.Name).ToString().ToUpper())"
                                                    List = $true
                                                    ColumnWidths = 40, 60
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $DCHWInfo | Table @TableParams
                                                if ($HealthCheck.DomainController.Diagnostic) {
                                                    if ($HW.CsTotalPhysicalMemory -lt 8589934592) {
                                                        Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                                                        BlankLine
                                                        Paragraph {
                                                            Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                                                            Text $reportTranslate.GetAbrADDomainController.HWBestPractice
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Hardware Inventory Table)"
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Hardware Section)"
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Section)"
                        }
                    }
                }
                if ($DCConfiguration) {
                    Section -Style Heading4 $reportTranslate.GetAbrADDomainController.ConfigurationTitle {
                        $DCConfiguration
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Section)"
            }
        }
        #---------------------------------------------------------------------------------------------#
        #                                 DNS IP Section                                              #
        #---------------------------------------------------------------------------------------------#
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            $UnresolverDNS = [System.Collections.ArrayList]::new()
            foreach ($DC in $DCs) {
                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                    $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                    try {
                        if ($DCPssSession) {
                            $DCIPAddress = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { [System.Net.Dns]::GetHostAddresses($using:DC).IPAddressToString }
                            $DNSSettings = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-NetAdapter | Where-Object { $_.ifOperStatus -eq 'Up' } | Get-DnsClientServerAddress -AddressFamily IPv4 }
                            $PrimaryDNSSoA = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { (Get-DnsServerResourceRecord -RRType Soa -ZoneName ($using:Domain).DNSRoot).RecordData.PrimaryServer }
                        } else {
                            if (-not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "DNS IP Configuration Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        foreach ($DNSServer in $DNSSettings.ServerAddresses) {
                            if ($DCPssSession) {
                                $Unresolver = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Resolve-DnsName -Server $using:DNSServer -Name $using:PrimaryDNSSoA -DnsOnly -ErrorAction SilentlyContinue }
                            }
                            if ([string]::IsNullOrEmpty($Unresolver)) {
                                $UnresolverDNS.Add($DNSServer) | Out-Null
                            }
                        }
                        foreach ($DNSSetting in $DNSSettings) {
                            try {
                                $inObj = [ordered] @{
                                    $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                                    $($reportTranslate.GetAbrADDomainController.Interface) = $DNSSetting.InterfaceAlias
                                    $($reportTranslate.GetAbrADDomainController.PreferedDNS) = $DNSSetting.ServerAddresses[0]
                                    $($reportTranslate.GetAbrADDomainController.AlternateDNS) = $DNSSetting.ServerAddresses[1]
                                    $($reportTranslate.GetAbrADDomainController.DNS3) = $DNSSetting.ServerAddresses[2]
                                    $($reportTranslate.GetAbrADDomainController.DNS4) = $DNSSetting.ServerAddresses[3]
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($DC.ToString().ToUpper().Split('.')[0]) DNS IP Configuration Section: $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Domain Controller DNS IP Configuration Table Section: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                            $($reportTranslate.GetAbrADDomainController.Interface) = '--'
                            $($reportTranslate.GetAbrADDomainController.PreferedDNS) = '--'
                            $($reportTranslate.GetAbrADDomainController.AlternateDNS) = '--'
                            $($reportTranslate.GetAbrADDomainController.DNS3) = '--'
                            $($reportTranslate.GetAbrADDomainController.DNS4) = '--'
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DNS IP Configuration Item)"
                    }
                }
            }

            if ($HealthCheck.DomainController.BestPractice) {
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -eq '127.0.0.1' -or $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $DCIPAddress } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainController.PreferedDNS
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -eq '--' -and $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -ne '--' } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainController.AlternateDNS
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $UnresolverDNS } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.PreferedDNS
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -in $UnresolverDNS } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.AlternateDNS
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.DNS3) -in $UnresolverDNS } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.DNS3
                $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.DNS4) -in $UnresolverDNS } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.DNS4
            }

            if ($OutObj) {
                Section -Style Heading4 $reportTranslate.GetAbrADDomainController.DNSIPConfigTitle {
                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDomainController.DNSIPConfigTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 20, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.DCName | Table @TableParams
                    if ($HealthCheck.DomainController.BestPractice -and (($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -eq '127.0.0.1' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $DCIPAddress }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -eq '--' -and $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -ne '--' }) -or ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.DNS3) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.DNS4) -in $UnresolverDNS }))) {
                        Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                        BlankLine
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -eq '127.0.0.1' }) {
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainController.BestPractices -Bold
                                Text $reportTranslate.GetAbrADDomainController.DNSIPConfigBP1
                            }
                        }
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $DCIPAddress }) {
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainController.BestPractices -Bold
                                Text $reportTranslate.GetAbrADDomainController.DNSIPConfigBP2
                            }
                        }
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -eq '--' -and $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -ne '--' }) {
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainController.BestPractices -Bold
                                Text $reportTranslate.GetAbrADDomainController.DNSIPConfigBP3
                            }
                        }
                        if ($OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PreferedDNS) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.AlternateDNS) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.DNS3) -in $UnresolverDNS -or $_.$($reportTranslate.GetAbrADDomainController.DNS4) -in $UnresolverDNS }) {
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainController.CorrectiveActions -Bold
                                Text ($reportTranslate.GetAbrADDomainController.DNSIPConfigCA -f $Domain.DNSRoot.ToString().ToUpper(), ($UnresolverDNS -join ', '))
                            }
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "Domain Controller DNS IP Configuration Section: $($_.Exception.Message)"
        }

        try {
            $OutObj = [System.Collections.ArrayList]::new()
            foreach ($DC in $DCs) {
                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                    try {
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                        if ($DCPssSession) {
                            $NTDS = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'DSA Database File' }
                            $size = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { (Get-ItemProperty -Path $using:NTDS).Length }
                            $LogFiles = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'Database log files path' }
                            $SYSVOL = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters | Select-Object -ExpandProperty 'SysVol' }
                        } else {
                            if (-not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "NTDS Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        if ( $NTDS -and $size ) {
                            $inObj = [ordered] @{
                                $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                                $($reportTranslate.GetAbrADDomainController.DatabaseFile) = $NTDS
                                $($reportTranslate.GetAbrADDomainController.DatabaseSize) = ConvertTo-FileSizeString $size
                                $($reportTranslate.GetAbrADDomainController.LogPath) = $LogFiles
                                $($reportTranslate.GetAbrADDomainController.SysVolPath) = $SYSVOL
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            $($reportTranslate.GetAbrADDomainController.DCName) = $DC.ToString().ToUpper().Split('.')[0]
                            $($reportTranslate.GetAbrADDomainController.DatabaseFile) = '--'
                            $($reportTranslate.GetAbrADDomainController.DatabaseSize) = '--'
                            $($reportTranslate.GetAbrADDomainController.LogPath) = '--'
                            $($reportTranslate.GetAbrADDomainController.SysVolPath) = '--'
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 $reportTranslate.GetAbrADDomainController.NTDSTitle {
                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDomainController.NTDSTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 22, 14, 22, 22
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.DCName | Table @TableParams
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS section)"
        }
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            foreach ($DC in $DCs) {
                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                    try {
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                        if ($DCPssSession) {
                            $NtpServer = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'NtpServer' }
                            $SourceType = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'Type' }
                        } else {
                            if (-not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "Time Source Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        if ( $NtpServer -and $SourceType ) {
                            try {
                                $inObj = [ordered] @{
                                    $($reportTranslate.GetAbrADDomainController.Name) = $DC.ToString().ToUpper().Split('.')[0]
                                    $($reportTranslate.GetAbrADDomainController.TimeServer) = switch ($NtpServer) {
                                        'time.windows.com,0x8' { $reportTranslate.GetAbrADDomainController.DomainHierarchy }
                                        'time.windows.com' { $reportTranslate.GetAbrADDomainController.DomainHierarchy }
                                        '0x8' { $reportTranslate.GetAbrADDomainController.DomainHierarchy }
                                        default { $NtpServer }
                                    }
                                    $($reportTranslate.GetAbrADDomainController.Type) = switch ($SourceType) {
                                        'NTP' { $reportTranslate.GetAbrADDomainController.ManualNTP }
                                        'NT5DS' { $reportTranslate.GetAbrADDomainController.DOMHIER }
                                        default { $SourceType }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Time Source Item)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Time Source Table)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            $($reportTranslate.GetAbrADDomainController.Name) = $DC.ToString().ToUpper().Split('.')[0]
                            $($reportTranslate.GetAbrADDomainController.TimeServer) = '--'
                            $($reportTranslate.GetAbrADDomainController.Type) = '--'
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 $reportTranslate.GetAbrADDomainController.TimeSourceTitle {
                    $TableParams = @{
                        Name = "$($reportTranslate.GetAbrADDomainController.TimeSourceTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 50, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.Name | Table @TableParams
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Time Source)"
        }
        if ($HealthCheck.DomainController.Diagnostic) {
            try {
                $OutObj = [System.Collections.ArrayList]::new()
                foreach ($DC in $DCs) {
                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                        try {
                            $CimSession = Get-ValidCIMSession -ComputerName $DC -SessionName $DC -CIMTable ([ref]$CIMTable)
                            if ($CimSession -and ($Domain.DNSRoot -eq $ADSystem.RootDomain)) {
                                $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName "_msdcs.$($Domain.DNSRoot)" -RRType Srv
                                $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split('.')[0] }
                                if ($DC -in $Domain.PDCEmulator) {
                                    $PDC = $SRVRR | Where-Object { $_.Hostname -eq '_ldap._tcp.pdc' -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $PDC = 'NonPDC' }
                                if ($DC -in $ADSystem.GlobalCatalogs) {
                                    $GC = $SRVRR | Where-Object { $_.Hostname -eq '_ldap._tcp.gc' -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $GC = 'NonGC' }
                                $KDC = $SRVRR | Where-Object { $_.Hostname -eq '_kerberos._tcp.dc' -and $_.RecordData.DomainName -eq "$($DC)." }
                                $DCRR = $SRVRR | Where-Object { $_.Hostname -eq '_ldap._tcp.dc' -and $_.RecordData.DomainName -eq "$($DC)." }
                            } else {
                                if ($CimSession) {
                                    $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType Srv
                                    $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split('.')[0] }
                                    if ($DC -in $Domain.PDCEmulator) {
                                        $PDC = $SRVRR | Where-Object { $_.Hostname -eq '_ldap._tcp.pdc._msdcs' -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $PDC = 'NonPDC' }
                                    if ($DC -in $ADSystem.GlobalCatalogs) {
                                        $GC = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName "_msdcs.$($ADSystem.RootDomain)" -RRType Srv | Where-Object { $_.Hostname -eq '_ldap._tcp.gc' -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $GC = 'NonGC' }
                                    $KDC = $SRVRR | Where-Object { $_.Hostname -eq '_kerberos._tcp.dc._msdcs' -and $_.RecordData.DomainName -eq "$($DC)." }
                                    $DCRR = $SRVRR | Where-Object { $_.Hostname -eq '_ldap._tcp.dc._msdcs' -and $_.RecordData.DomainName -eq "$($DC)." }
                                }
                            }

                            if ( $SRVRR ) {
                                try {
                                    $inObj = [ordered] @{
                                        $($reportTranslate.GetAbrADDomainController.Name) = $DC.ToString().ToUpper().Split('.')[0]
                                        $($reportTranslate.GetAbrADDomainController.ARecord) = switch ([string]::IsNullOrEmpty($DCARR)) {
                                            $True { $reportTranslate.GetAbrADDomainController.Fail }
                                            default { $reportTranslate.GetAbrADDomainController.OK }
                                        }
                                        $($reportTranslate.GetAbrADDomainController.KDCSRV) = switch ([string]::IsNullOrEmpty($KDC)) {
                                            $True { $reportTranslate.GetAbrADDomainController.Fail }
                                            default { $reportTranslate.GetAbrADDomainController.OK }
                                        }
                                        $($reportTranslate.GetAbrADDomainController.PDCSRV) = switch ([string]::IsNullOrEmpty($PDC)) {
                                            $True { $reportTranslate.GetAbrADDomainController.Fail }
                                            $False {
                                                switch ($PDC) {
                                                    'NonPDC' { $reportTranslate.GetAbrADDomainController.NonPDC }
                                                    default { $reportTranslate.GetAbrADDomainController.OK }
                                                }
                                            }
                                        }
                                        $($reportTranslate.GetAbrADDomainController.GCSRV) = switch ([string]::IsNullOrEmpty($GC)) {
                                            $True { $reportTranslate.GetAbrADDomainController.Fail }
                                            $False {
                                                switch ($GC) {
                                                    'NonGC' { $reportTranslate.GetAbrADDomainController.NonGC }
                                                    default { $reportTranslate.GetAbrADDomainController.OK }
                                                }
                                            }
                                        }
                                        $($reportTranslate.GetAbrADDomainController.DCSRV) = switch ([string]::IsNullOrEmpty($DCRR)) {
                                            $True { $reportTranslate.GetAbrADDomainController.Fail }
                                            default { $reportTranslate.GetAbrADDomainController.OK }
                                        }
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning "$($_.Exception.Message) (SRV Records Status Item)"
                                }
                                if ($HealthCheck.DomainController.Diagnostic) {
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.ARecord) -eq $reportTranslate.GetAbrADDomainController.Fail } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.ARecord
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.KDCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.KDCSRV
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.PDCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.PDCSRV
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.GCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.GCSRV
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.GCSRV) -eq $reportTranslate.GetAbrADDomainController.NonGC } | Set-Style -Style Warning -Property $reportTranslate.GetAbrADDomainController.GCSRV
                                    $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.DCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail } | Set-Style -Style Critical -Property $reportTranslate.GetAbrADDomainController.DCSRV
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SRV Records Status Table)"
                        }
                    } else {
                        try {
                            Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                            $inObj = [ordered] @{
                                $($reportTranslate.GetAbrADDomainController.Name) = $DC.ToString().ToUpper().Split('.')[0]
                                $($reportTranslate.GetAbrADDomainController.ARecord) = '--'
                                $($reportTranslate.GetAbrADDomainController.KDCSRV) = '--'
                                $($reportTranslate.GetAbrADDomainController.PDCSRV) = '--'
                                $($reportTranslate.GetAbrADDomainController.GCSRV) = '--'
                                $($reportTranslate.GetAbrADDomainController.DCSRV) = '--'
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 $reportTranslate.GetAbrADDomainController.SRVRecordsTitle {
                        $TableParams = @{
                            Name = "$($reportTranslate.GetAbrADDomainController.SRVTableName) - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }

                        $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.Name | Table @TableParams
                        if ( $OutObj | Where-Object { $_.$($reportTranslate.GetAbrADDomainController.KDCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail -or $_.$($reportTranslate.GetAbrADDomainController.PDCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail -or $_.$($reportTranslate.GetAbrADDomainController.GCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail -or $_.$($reportTranslate.GetAbrADDomainController.DCSRV) -eq $reportTranslate.GetAbrADDomainController.Fail }) {
                            Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                                Text $reportTranslate.GetAbrADDomainController.SRVBestPractice
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SRV Records Status)"
            }
        }
        try {
            if ($HealthCheck.DomainController.BestPractice) {
                $OutObj = [System.Collections.ArrayList]::new()
                $OutObj = foreach ($DC in $DCs) {
                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                        try {
                            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                            if ($DCPssSession) {
                                $Shares = Invoke-CommandWithTimeout -Session $DCPssSession -ErrorAction Stop -ScriptBlock { Get-SmbShare | Where-Object { $_.Description -ne 'Default share' -and $_.Description -notmatch 'Remote' -and $_.Name -ne 'NETLOGON' -and $_.Name -ne 'SYSVOL' } }
                            } else {
                                if (-not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controllers File Shares Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            if ($Shares) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                                    $FSObj = [System.Collections.ArrayList]::new()
                                    foreach ($Share in $Shares) {
                                        $inObj = [ordered] @{
                                            $($reportTranslate.GetAbrADDomainController.Name) = $Share.Name
                                            $($reportTranslate.GetAbrADDomainController.Path) = $Share.Path
                                            $($reportTranslate.GetAbrADDomainController.Description) = $Share.Description
                                        }
                                        $FSObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    }

                                    if ($HealthCheck.DomainController.BestPractice) {
                                        $FSObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainController.FileSharesTableName) - $($DC.ToString().ToUpper().Split('.')[0])"
                                        List = $false
                                        ColumnWidths = 34, 33, 33
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }

                                    $FSObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.Name | Table @TableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (File Shares Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 $reportTranslate.GetAbrADDomainController.FileSharesTitle {
                        Paragraph $reportTranslate.GetAbrADDomainController.FileSharesParagraph
                        $OutObj
                        Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text $reportTranslate.GetAbrADDomainController.BestPractice -Bold
                            Text $reportTranslate.GetAbrADDomainController.FileSharesBestPractice
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (File Shares Table)"
        }
        if ($HealthCheck.DomainController.Software) {
            try {
                # Todo: Fix arraylist issue with foreach
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                        try {
                            $Software = [System.Collections.ArrayList]::new()
                            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                            if ($DCPssSession) {
                                $SoftwareX64 = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike 'Microsoft*' -and $_.DisplayName -notlike 'VMware*' -and $_.DisplayName -notlike 'Microsoft*') -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                                $SoftwareX86 = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike 'Microsoft*' -and $_.DisplayName -notlike 'VMware*' -and $_.DisplayName -notlike 'Microsoft*') -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                            } else {
                                if (-not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controller Installed Software Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }

                            if ($SoftwareX64) {
                                foreach ($item in $SoftwareX64) {
                                    $inObj = [ordered] @{
                                        'DisplayName' = $item.DisplayName
                                        'Publisher' = $item.Publisher
                                        'InstallDate' = $item.InstallDate
                                    }
                                    $Software.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                }
                            }
                            if ($SoftwareX86) {
                                foreach ($item in $SoftwareX86) {
                                    $inObj = [ordered] @{
                                        'DisplayName' = $item.DisplayName
                                        'Publisher' = $item.Publisher
                                        'InstallDate' = $item.InstallDate
                                    }
                                    $Software.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                }
                            }

                            if ( $Software ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($APP in $Software) {
                                        try {
                                            $inObj = [ordered] @{
                                                $($reportTranslate.GetAbrADDomainController.Name) = $APP.DisplayName
                                                $($reportTranslate.GetAbrADDomainController.Publisher) = $APP.Publisher
                                                $($reportTranslate.GetAbrADDomainController.InstallDate) = $APP.InstallDate
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                            if ($HealthCheck.DomainController.Software) {
                                                $OutObj | Set-Style -Style Warning
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }
                                    }
                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainController.InstalledSoftwareTableName) - $($DC.ToString().ToUpper().Split('.')[0])"
                                        List = $false
                                        ColumnWidths = 34, 33, 33
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.Name | Table @TableParams
                                    if ($HealthCheck.DomainController.Software) {
                                        Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDomainController.BestPractices -Bold
                                            Text $reportTranslate.GetAbrADDomainController.InstalledSoftwareBestPractices
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading4 $reportTranslate.GetAbrADDomainController.InstalledSoftwareTitle {
                        Paragraph ($reportTranslate.GetAbrADDomainController.InstalledSoftwareParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $DCObj
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Installed Software Section)"
            }
            try {
                # Todo: Fix arraylist issue with foreach
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                        try {
                            $Software = [System.Collections.ArrayList]::new()
                            $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                            if ($DCPssSession ) {
                                $Updates = Invoke-CommandWithTimeout -Session $DCPssSession -ScriptBlock { (New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search('IsHidden=0 and IsInstalled=0').Updates | Select-Object Title, KBArticleIDs }
                            } else {
                                if (-not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controller Pending Missing Patch Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }

                            if ( $Updates ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split('.')[0]) {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Update in $Updates) {
                                        try {
                                            $inObj = [ordered] @{
                                                $($reportTranslate.GetAbrADDomainController.KBArticle) = "KB$($Update.KBArticleIDs)"
                                                $($reportTranslate.GetAbrADDomainController.Name) = $Update.Title
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                            if ($HealthCheck.DomainController.Software) {
                                                $OutObj | Set-Style -Style Warning
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning $_.Exception.Message
                                        }
                                    }
                                    $TableParams = @{
                                        Name = "$($reportTranslate.GetAbrADDomainController.MissingUpdatesTableName) - $($DC.ToString().ToUpper().Split('.')[0])"
                                        List = $false
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property $reportTranslate.GetAbrADDomainController.Name | Table @TableParams
                                    if ($HealthCheck.DomainController.Software) {
                                        Paragraph $reportTranslate.GetAbrADDomainController.HealthCheck -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text $reportTranslate.GetAbrADDomainController.SecurityBestPractices -Bold
                                            Text $reportTranslate.GetAbrADDomainController.MissingUpdatesBestPractice
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading4 $reportTranslate.GetAbrADDomainController.MissingUpdatesTitle {
                        Paragraph ($reportTranslate.GetAbrADDomainController.MissingUpdatesParagraph -f $Domain.DNSRoot.ToString().ToUpper())
                        BlankLine
                        $DCObj
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Section)"
            }
        }
    }

    end {
        Show-AbrDebugExecutionTime -End -TitleMessage 'Domain Controller'
    }

}