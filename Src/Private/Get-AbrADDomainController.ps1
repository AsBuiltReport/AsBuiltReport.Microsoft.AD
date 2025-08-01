function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.9.6
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
        Write-PScriboMessage -Message "Collecting AD Domain Controller information."
        Show-AbrDebugExecutionTime -Start -TitleMessage "Domain Controller Section"
    }

    process {
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            foreach ($DC in $DCs) {
                if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                    $DCInfo = Invoke-Command -Session $TempPssSession { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                    $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)

                    if ($DCPssSession ) {
                        $DCNetSettings = try { Invoke-Command -Session $DCPssSession { Get-NetIPAddress } } catch { Write-PScriboMessage -IsWarning -Message "Unable to get $DC network interfaces information" }
                    } else {
                        if (-Not $_.Exception.MessageId) {
                            $ErrorMessage = $_.FullyQualifiedErrorId
                        } else { $ErrorMessage = $_.Exception.MessageId }
                        Write-PScriboMessage -IsWarning -Message "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                    }
                    try {
                        $inObj = [ordered] @{
                            'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                            'Status' = "Online"
                            'Site' = Switch ([string]::IsNullOrEmpty($DCInfo.Site)) {
                                $true { "--" }
                                $false { $DCInfo.Site }
                                default { "Unknown" }
                            }
                            'Global Catalog' = $DCInfo.IsGlobalCatalog
                            'Read Only' = $DCInfo.IsReadOnly
                            'IP Address' = Switch ([string]::IsNullOrEmpty($DCInfo.IPv4Address)) {
                                $true { "--" }
                                $false { $DCInfo.IPv4Address }
                                default { "Unknown" }
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
                            'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                            'Status' = "Offline"
                            'Site' = "--"
                            'Global Catalog' = "--"
                            'Read Only' = "--"
                            'IP Address' = "--"
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
                Name = "Domain Controller in Domain - $($Domain.DNSRoot.ToString().ToUpper())"
                List = $false
                ColumnWidths = 25, 12, 24, 10, 10, 19
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
            if ($HealthCheck.DomainController.BestPractice -and ($OutObj.Count -eq 1)) {
                Paragraph "Health Check:" -Bold -Underline
                BlankLine
                Paragraph {
                    Text "Best Practice:" -Bold
                    Text "All domains should have at least two functioning domain controllers for redundancy. In the event of a failure on the domain's only domain controller, users will not be able to log in to the domain or access domain resources. This ensures high availability and fault tolerance within the domain infrastructure."
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Table)"
        }
        try {
            $OutObj = [System.Collections.ArrayList]::new()
            $inObj = [ordered] @{
                'Domain Controller' = ($DomainController | Measure-Object).Count
                'Global Catalog' = ($GC | Measure-Object).Count
            }
            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

            $TableParams = @{
                Name = "Domain Controller Counts - $($Domain.DNSRoot.ToString().ToUpper())"
                List = $true
                ColumnWidths = 40, 60
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            try {
                # Chart Section
                $sampleData = $inObj.GetEnumerator() | Select-Object @{ Name = 'Name'; Expression = { $_.key } }, @{ Name = 'Value'; Expression = { $_.value } } | Sort-Object -Property 'Category'

                $chartFileItem = Get-PieChart -SampleData $sampleData -ChartName 'DomainControllerObject' -XField 'Name' -YField 'value' -ChartLegendName 'Category' -ChartTitleName 'DomainControllerObject' -ChartTitleText 'DC vs GC Distribution' -ReversePalette $True

            } catch {
                Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Controller Count Chart)"
            }
            if ($OutObj) {
                if ($chartFileItem) {
                    BlankLine
                    Image -Text 'Domain Controller Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
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
                        $DCInfo = Invoke-Command -Session $TempPssSession { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                        $DCComputerObject = try { Invoke-Command -Session $TempPssSession -ErrorAction Stop { Get-ADComputer ($using:DCInfo).ComputerObjectDN -Properties * -Server $using:DC } } catch { Out-Null }
                        $DCPssSession = Get-ValidPSSession -ComputerName $DC -SessionName $($DC) -PSSTable ([ref]$PSSTable)
                        if ($DCPssSession) {
                            $DCNetSettings = try { Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-NetIPAddress } } catch { Out-Null }
                            $DCNetSMBv1Setting = try { Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol } } catch { Out-Null }
                        } else {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        try {
                            Section -Style Heading5 $DCInfo.Name {
                                try {
                                    Section -ExcludeFromTOC -Style NOTOCHeading6 "General Information" {
                                        $OutObj = [System.Collections.ArrayList]::new()
                                        $inObj = [ordered] @{
                                            'DC Name' = $DCInfo.Hostname
                                            'Domain Name' = Switch ([string]::IsNullOrEmpty($DCInfo.Domain)) {
                                                $true { "--" }
                                                $false { $DCInfo.Domain }
                                                default { "Unknown" }
                                            }
                                            'Site' = Switch ([string]::IsNullOrEmpty($DCInfo.Site)) {
                                                $true { "--" }
                                                $false { $DCInfo.Site }
                                                default { "Unknown" }
                                            }
                                            'Global Catalog' = $DCInfo.IsGlobalCatalog
                                            'Read Only' = $DCInfo.IsReadOnly
                                            'Operation Master Roles' = ($DCInfo.OperationMasterRoles -join ', ')
                                            'Location' = $DCComputerObject.Location
                                            'Computer Object SID' = $DCComputerObject.SID
                                            'Operating System' = $DCInfo.OperatingSystem
                                            'SMB1 Status' = $DCNetSMBv1Setting.State
                                            'Description' = $DCComputerObject.Description
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                        if ($HealthCheck.DomainController.BestPractice) {
                                            $OutObj | Where-Object { $_.'SMB1 Status' -eq 'Enabled' } | Set-Style -Style Critical -Property 'SMB1 Status'
                                        }

                                        $TableParams = @{
                                            Name = "General Information - $($DCInfo.Name)"
                                            List = $true
                                            ColumnWidths = 40, 60
                                        }
                                        if ($Report.ShowTableCaptions) {
                                            $TableParams['Caption'] = "- $($TableParams.Name)"
                                        }
                                        $OutObj | Table @TableParams
                                        if ($HealthCheck.DomainController.BestPractice -and ($OutObj | Where-Object { $_.'SMB1 Status' -eq 'Enabled' })) {
                                            Paragraph "Health Check:" -Bold -Underline
                                            BlankLine
                                            Paragraph {
                                                Text "Best Practice:" -Bold
                                                Text "Disable SMBv1: SMBv1 is an outdated protocol that is vulnerable to several security issues. It is recommended to disable SMBv1 on all systems to enhance security and reduce the risk of exploitation. SMB v1 has been deprecated and replaced by SMB v2 and SMB v3, which offer improved performance and security features."
                                            }
                                        }
                                    }
                                } catch {
                                    Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (General Information Section)"
                                }
                                try {
                                    Section -ExcludeFromTOC -Style NOTOCHeading6 "Partitions" {
                                        $OutObj = [System.Collections.ArrayList]::new()
                                        $inObj = [ordered] @{
                                            'Default Partition' = $DCInfo.DefaultPartition
                                            'Partitions' = $DCInfo.Partitions
                                        }
                                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null


                                        $TableParams = @{
                                            Name = "Partitions - $($DCInfo.Name)"
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
                                        Section -ExcludeFromTOC -Style NOTOCHeading6 "Networking Settings" {
                                            $OutObj = [System.Collections.ArrayList]::new()
                                            $inObj = [ordered] @{
                                                'IPv4 Addresses' = Switch ([string]::IsNullOrEmpty((($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 2) -and $_.IPAddress -ne '127.0.0.1' }).IPv4Address))) {
                                                    $true { "--" }
                                                    $false { ($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv4' -or $_.AddressFamily -eq 2) -and $_.IPAddress -ne '127.0.0.1' }).IPv4Address -join ", " }
                                                    default { "Unknown" }
                                                }
                                                'IPv6 Addresses' = Switch ([string]::IsNullOrEmpty((($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv6' -or $_.AddressFamily -eq 23) -and $_.IPAddress -ne '::1' }).IPv6Address))) {
                                                    $true { "--" }
                                                    $false { ($DCNetSettings | Where-Object { ($_.AddressFamily -eq 'IPv6' -or $_.AddressFamily -eq 23) -and $_.IPAddress -ne '::1' }).IPv6Address -join "," }
                                                    default { "Unknown" }
                                                }
                                                "LDAP Port" = $DCInfo.LdapPort
                                                "LDAPS Port" = $DCInfo.SslPort
                                            }
                                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                            if ($HealthCheck.DomainController.BestPractice) {
                                                $OutObj | Where-Object { $_.'IPv4 Addresses'.Split(",").Count -gt 1 } | Set-Style -Style Warning -Property 'IPv4 Addresses'
                                            }
                                            if ($OutObj) {
                                                $TableParams = @{
                                                    Name = "Networking Settings - $($DCInfo.Name)"
                                                    List = $true
                                                    ColumnWidths = 40, 60
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $OutObj | Table @TableParams
                                                if ($HealthCheck.DomainController.BestPractice -and ($OutObj | Where-Object { $_.'IPv4 Addresses'.Split(",").Count -gt 1 })) {
                                                    Paragraph "Health Check:" -Bold -Underline
                                                    BlankLine
                                                    Paragraph {
                                                        Text "Best Practice:" -Bold
                                                        Text "On Domain Controllers with more than one NIC where each NIC is connected to separate Network, there's a possibility that the Host A DNS registration can occur for unwanted NICs. Avoid registering unwanted NICs in DNS on a multihomed domain controller."
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
                                            $HW = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ComputerInfo }
                                            $HWCPU = Get-CimInstance -Class Win32_Processor -CimSession $CimSession
                                        }

                                        if ($CimSession) {
                                            $License = Get-CimInstance -Query 'Select * from SoftwareLicensingProduct' -CimSession $CimSession | Where-Object { $_.LicenseStatus -eq 1 }
                                        }
                                        if ($HW) {
                                            $inObj = [ordered] @{
                                                'Name' = $HW.CsName
                                                'Windows Product Name' = $HW.WindowsProductName
                                                'Windows Build Number' = $HW.OsVersion
                                                'AD Domain' = $HW.CsDomain
                                                'Windows Installation Date' = $HW.OsInstallDate
                                                'Time Zone' = $HW.TimeZone
                                                'License Type' = $License.ProductKeyChannel
                                                'Partial Product Key' = $License.PartialProductKey
                                                'Manufacturer' = $HW.CsManufacturer
                                                'Model' = $HW.CsModel
                                                'Processor Model' = $HWCPU[0].Name
                                                'Number of Processors' = ($HWCPU | Measure-Object).Count
                                                'Number of CPU Cores' = $HWCPU[0].NumberOfCores
                                                'Number of Logical Cores' = $HWCPU[0].NumberOfLogicalProcessors
                                                'Physical Memory' = & {
                                                    try {
                                                        ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
                                                    } catch { '0.00 GB' }
                                                }
                                            }
                                            $DCHWInfo.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                        }

                                        if ($HealthCheck.DomainController.Diagnostic) {
                                            if ([int]([regex]::Matches($DCHWInfo.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                                                $DCHWInfo | Set-Style -Style Warning -Property 'Physical Memory'
                                            }
                                        }
                                        if ($DCHWInfo) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading6 'Hardware Inventory' {
                                                $TableParams = @{
                                                    Name = "Hardware Inventory - $($DCHWInfo.Name.ToString().ToUpper())"
                                                    List = $true
                                                    ColumnWidths = 40, 60
                                                }
                                                if ($Report.ShowTableCaptions) {
                                                    $TableParams['Caption'] = "- $($TableParams.Name)"
                                                }
                                                $DCHWInfo | Table @TableParams
                                                if ($HealthCheck.DomainController.Diagnostic) {
                                                    if ([int]([regex]::Matches($DCHWInfo.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                                                        Paragraph "Health Check:" -Bold -Underline
                                                        BlankLine
                                                        Paragraph {
                                                            Text "Best Practice:" -Bold
                                                            Text "Microsoft recommend putting enough RAM 8GB+ to load the entire DIT into memory, plus accommodate the operating system and other installed applications, such as anti-virus, backup software, monitoring, and so on. Insufficient memory can lead to performance issues and slow response times, which can affect the overall health and efficiency of the domain controller. Ensuring adequate memory helps maintain optimal performance and reliability of the Active Directory services."
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
                    Section -Style Heading4 'Configuration' {
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
                            $DCIPAddress = Invoke-Command -Session $DCPssSession { [System.Net.Dns]::GetHostAddresses($using:DC).IPAddressToString }
                            $DNSSettings = Invoke-Command -Session $DCPssSession { Get-NetAdapter | Where-Object { $_.ifOperStatus -eq "Up" } | Get-DnsClientServerAddress -AddressFamily IPv4 }
                            $PrimaryDNSSoA = Invoke-Command -Session $DCPssSession { (Get-DnsServerResourceRecord -RRType Soa -ZoneName ($using:Domain).DNSRoot).RecordData.PrimaryServer }
                        } else {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "DNS IP Configuration Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        foreach ($DNSServer in $DNSSettings.ServerAddresses) {
                            if ($DCPssSession) {
                                $Unresolver = Invoke-Command -Session $DCPssSession { Resolve-DnsName -Server $using:DNSServer -Name $using:PrimaryDNSSoA -DnsOnly -ErrorAction SilentlyContinue }
                            }
                            if ([string]::IsNullOrEmpty($Unresolver)) {
                                $UnresolverDNS.Add($DNSServer) | Out-Null
                            }
                        }
                        foreach ($DNSSetting in $DNSSettings) {
                            try {
                                $inObj = [ordered] @{
                                    'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                    'Interface' = $DNSSetting.InterfaceAlias
                                    'Prefered DNS' = $DNSSetting.ServerAddresses[0]
                                    'Alternate DNS' = $DNSSetting.ServerAddresses[1]
                                    'DNS 3' = $DNSSetting.ServerAddresses[2]
                                    'DNS 4' = $DNSSetting.ServerAddresses[3]
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning -Message "$($DC.ToString().ToUpper().Split(".")[0]) DNS IP Configuration Section: $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "Domain Controller DNS IP Configuration Table Section: $($_.Exception.Message)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                            'Interface' = '--'
                            'Prefered DNS' = '--'
                            'Alternate DNS' = '--'
                            'DNS 3' = '--'
                            'DNS 4' = '--'
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (DNS IP Configuration Item)"
                    }
                }
            }

            if ($HealthCheck.DomainController.BestPractice) {
                $OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" -or $_.'Prefered DNS' -in $DCIPAddress } | Set-Style -Style Warning -Property 'Prefered DNS'
                $OutObj | Where-Object { $_.'Alternate DNS' -eq "--" -and $_.'Prefered DNS' -ne '--' } | Set-Style -Style Warning -Property 'Alternate DNS'
                $OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'Prefered DNS'
                $OutObj | Where-Object { $_.'Alternate DNS' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'Alternate DNS'
                $OutObj | Where-Object { $_.'DNS 3' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 3'
                $OutObj | Where-Object { $_.'DNS 4' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 4'
            }

            if ($OutObj) {
                Section -Style Heading4 "DNS IP Configuration" {
                    $TableParams = @{
                        Name = "DNS IP Configuration - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 20, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                    if ($HealthCheck.DomainController.BestPractice -and (($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" }) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $DCIPAddress }) -or ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--" -and $_.'Prefered DNS' -ne '--' }) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS -or $_.'Alternate DNS' -in $UnresolverDNS -or $_.'DNS 3' -in $UnresolverDNS -or $_.'DNS 4' -in $UnresolverDNS }))) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" }) {
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "DNS configuration on network adapter should include the loopback address (127.0.0.1), but it should not be the first entry."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -in $DCIPAddress }) {
                            BlankLine
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "DNS configuration on the network adapter should not include the Domain Controller's own IP address as the first entry."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--" -and $_.'Prefered DNS' -ne '--' }) {
                            BlankLine
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "For redundancy reasons, the DNS configuration on the network adapter should include an Alternate DNS address. This ensures that if the primary DNS server becomes unavailable, the system can still resolve domain names using the alternate DNS server, maintaining network stability and connectivity."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS -or $_.'Alternate DNS' -in $UnresolverDNS -or $_.'DNS 3' -in $UnresolverDNS -or $_.'DNS 4' -in $UnresolverDNS }) {
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Network interfaces must be configured with DNS servers that can resolve names in the forest root domain. The following DNS server did not respond to the query for the forest root domain $($Domain.DNSRoot.ToString().ToUpper()): $(($UnresolverDNS -join ", "))"
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
                            $NTDS = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'DSA Database File' }
                            $size = Invoke-Command -Session $DCPssSession -ScriptBlock { (Get-ItemProperty -Path $using:NTDS).Length }
                            $LogFiles = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'Database log files path' }
                            $SYSVOL = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters | Select-Object -ExpandProperty 'SysVol' }
                        } else {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "NTDS Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        if ( $NTDS -and $size ) {
                            $inObj = [ordered] @{
                                'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                'Database File' = $NTDS
                                'Database Size' = ConvertTo-FileSizeString $size
                                'Log Path' = $LogFiles
                                'SysVol Path' = $SYSVOL
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
                            'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                            'Database File' = "--"
                            'Database Size' = "--"
                            'Log Path' = "--"
                            'SysVol Path' = "--"
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 'NTDS Information' {
                    $TableParams = @{
                        Name = "NTDS Database File Usage - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 22, 14, 22, 22
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
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
                            $NtpServer = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'NtpServer' }
                            $SourceType = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'Type' }
                        } else {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else { $ErrorMessage = $_.Exception.MessageId }
                            Write-PScriboMessage -IsWarning -Message "Time Source Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        if ( $NtpServer -and $SourceType ) {
                            try {
                                $inObj = [ordered] @{
                                    'Name' = $DC.ToString().ToUpper().Split(".")[0]
                                    'Time Server' = Switch ($NtpServer) {
                                        'time.windows.com,0x8' { "Domain Hierarchy" }
                                        'time.windows.com' { "Domain Hierarchy" }
                                        '0x8' { "Domain Hierarchy" }
                                        default { $NtpServer }
                                    }
                                    'Type' = Switch ($SourceType) {
                                        'NTP' { "MANUAL (NTP)" }
                                        'NT5DS' { "DOMHIER" }
                                        default { $SourceType }
                                    }
                                }
                                $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                            } catch {
                                Write-PScriboMessage -IsWarning  "$($_.Exception.Message) (Time Source Item)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Time Source Table)"
                    }
                } else {
                    try {
                        Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                        $inObj = [ordered] @{
                            'Name' = $DC.ToString().ToUpper().Split(".")[0]
                            'Time Server' = "--"
                            'Type' = "--"
                        }
                        $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                    } catch {
                        Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 'Time Source Information' {
                    $TableParams = @{
                        Name = "Time Source Configuration - $($Domain.DNSRoot.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 50, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
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
                                $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0] }
                                if ($DC -in $Domain.PDCEmulator) {
                                    $PDC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.pdc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $PDC = 'NonPDC' }
                                if ($DC -in $ADSystem.GlobalCatalogs) {
                                    $GC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $GC = 'NonGC' }
                                $KDC = $SRVRR | Where-Object { $_.Hostname -eq "_kerberos._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                $DCRR = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)." }
                            } else {
                                if ($CimSession) {
                                    $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType Srv
                                    $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain.DNSRoot -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0] }
                                    if ($DC -in $Domain.PDCEmulator) {
                                        $PDC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.pdc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $PDC = 'NonPDC' }
                                    if ($DC -in $ADSystem.GlobalCatalogs) {
                                        $GC = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName "_msdcs.$($ADSystem.RootDomain)" -RRType Srv | Where-Object { $_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $GC = 'NonGC' }
                                    $KDC = $SRVRR | Where-Object { $_.Hostname -eq "_kerberos._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    $DCRR = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                }
                            }

                            if ( $SRVRR ) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $DC.ToString().ToUpper().Split(".")[0]
                                        'A Record' = Switch ([string]::IsNullOrEmpty($DCARR)) {
                                            $True { 'Fail' }
                                            default { 'OK' }
                                        }
                                        'KDC SRV' = Switch ([string]::IsNullOrEmpty($KDC)) {
                                            $True { 'Fail' }
                                            default { 'OK' }
                                        }
                                        'PDC SRV' = Switch ([string]::IsNullOrEmpty($PDC)) {
                                            $True { 'Fail' }
                                            $False {
                                                Switch ($PDC) {
                                                    'NonPDC' { 'Non PDC' }
                                                    default { 'OK' }
                                                }
                                            }
                                        }
                                        'GC SRV' = Switch ([string]::IsNullOrEmpty($GC)) {
                                            $True { 'Fail' }
                                            $False {
                                                Switch ($GC) {
                                                    'NonGC' { 'Non GC' }
                                                    default { 'OK' }
                                                }
                                            }
                                        }
                                        'DC SRV' = Switch ([string]::IsNullOrEmpty($DCRR)) {
                                            $True { 'Fail' }
                                            default { 'OK' }
                                        }
                                    }
                                    $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                } catch {
                                    Write-PScriboMessage -IsWarning  "$($_.Exception.Message) (SRV Records Status Item)"
                                }
                                if ($HealthCheck.DomainController.Diagnostic) {
                                    $OutObj | Where-Object { $_.'A Record' -eq 'Fail' } | Set-Style -Style Critical -Property 'A Record'
                                    $OutObj | Where-Object { $_.'KDC SRV' -eq 'Fail' } | Set-Style -Style Critical -Property 'KDC SRV'
                                    $OutObj | Where-Object { $_.'PDC SRV' -eq 'Fail' } | Set-Style -Style Critical -Property 'PDC SRV'
                                    $OutObj | Where-Object { $_.'GC SRV' -eq 'Fail' } | Set-Style -Style Critical -Property 'GC SRV'
                                    $OutObj | Where-Object { $_.'GC SRV' -eq 'Non GC' } | Set-Style -Style Warning -Property 'GC SRV'
                                    $OutObj | Where-Object { $_.'DC SRV' -eq 'Fail' } | Set-Style -Style Critical -Property 'DC SRV'
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (SRV Records Status Table)"
                        }
                    } else {
                        try {
                            Write-PScriboMessage -Message "Unable to collect infromation from $DC."
                            $inObj = [ordered] @{
                                'Name' = $DC.ToString().ToUpper().Split(".")[0]
                                'A Record' = "--"
                                'KDC SRV' = "--"
                                'PDC SRV' = "--"
                                'GC SRV' = "--"
                                'DC SRV' = "--"
                            }
                            $OutObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (NTDS Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 'SRV Records Status' {
                        $TableParams = @{
                            Name = "SRV Records Status - $($Domain.DNSRoot.ToString().ToUpper())"
                            List = $false
                            ColumnWidths = 20, 16, 16, 16, 16, 16
                        }
                        if ($Report.ShowTableCaptions) {
                            $TableParams['Caption'] = "- $($TableParams.Name)"
                        }

                        $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                        if ( $OutObj | Where-Object { $_.'KDC SRV' -eq 'Fail' -or $_.'PDC SRV' -eq 'Fail' -or $_.'GC SRV' -eq 'Fail' -or $_.'DC SRV' -eq 'Fail' }) {
                            Paragraph "Health Check:" -Bold -Underline
                            BlankLine
                            Paragraph {
                                Text "Best Practice:" -Bold
                                Text "The SRV record is a Domain Name System (DNS) resource record. It's used to identify computers hosting specific services. SRV resource records are used to locate domain controllers for Active Directory. These records are essential for the proper functioning of Active Directory as they allow clients to locate domain controllers and other critical services within the network. Ensuring that these records are correctly configured and available is crucial for maintaining the health and accessibility of the Active Directory environment."
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
                                $Shares = Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-SmbShare | Where-Object { $_.Description -ne 'Default share' -and $_.Description -notmatch 'Remote' -and $_.Name -ne 'NETLOGON' -and $_.Name -ne 'SYSVOL' } }
                            } else {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controllers File Shares Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            if ($Shares) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $FSObj = [System.Collections.ArrayList]::new()
                                    foreach ($Share in $Shares) {
                                        $inObj = [ordered] @{
                                            'Name' = $Share.Name
                                            'Path' = $Share.Path
                                            'Description' = $Share.Description
                                        }
                                        $FSObj.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null
                                    }

                                    if ($HealthCheck.DomainController.BestPractice) {
                                        $FSObj | Set-Style -Style Warning
                                    }

                                    $TableParams = @{
                                        Name = "File Shares - $($DC.ToString().ToUpper().Split(".")[0])"
                                        List = $false
                                        ColumnWidths = 34, 33, 33
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }

                                    $FSObj | Sort-Object -Property 'Name' | Table @TableParams
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (File Shares Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 "File Shares" {
                        Paragraph "The following domain controllers have file shares other than the default administrative, NETLOGON, or SYSVOL shares."
                        $OutObj
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Only netlogon, sysvol and the default administrative shares should exist on a Domain Controller. If possible, non-default file shares should be moved to another server, preferably a dedicated file server. This helps to minimize the attack surface and ensures that the Domain Controller is dedicated to its primary role of managing security and authentication within the domain. Additionally, it reduces the risk of performance degradation and potential conflicts that can arise from running multiple services on a single server."
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
                                $SoftwareX64 = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                                $SoftwareX86 = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                            } else {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controller Installed Software Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }

                            If ($SoftwareX64) {
                                foreach ($item in $SoftwareX64) {
                                    $inObj = [ordered] @{
                                        'DisplayName' = $item.DisplayName
                                        'Publisher' = $item.Publisher
                                        'InstallDate' = $item.InstallDate
                                    }
                                    $Software.Add([pscustomobject](ConvertTo-HashToYN $inObj)) | Out-Null

                                }
                            }
                            If ($SoftwareX86) {
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
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($APP in $Software) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Name' = $APP.DisplayName
                                                'Publisher' = $APP.Publisher
                                                'Install Date' = $APP.InstallDate
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
                                        Name = "Installed Software - $($DC.ToString().ToUpper().Split(".")[0])"
                                        List = $false
                                        ColumnWidths = 34, 33, 33
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                    if ($HealthCheck.DomainController.Software) {
                                        Paragraph "Health Check:" -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text "Best Practices:" -Bold
                                            Text "Do not run other software or services on a Domain Controller. Running additional software or services on a Domain Controller can introduce security vulnerabilities, increase the attack surface, and potentially degrade the performance of critical domain services. It is recommended to keep Domain Controllers dedicated to their primary role of managing security and authentication within the domain. If additional services are required, consider deploying them on separate, dedicated servers."
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
                    Section -Style Heading4 'Installed Software' {
                        Paragraph "This section summarizes non-Microsoft and non-default software installed on Domain Controllers in the $($Domain.DNSRoot.ToString().ToUpper()) domain."
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
                                $Updates = Invoke-Command -Session $DCPssSession -ScriptBlock { (New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title, KBArticleIDs }
                            } else {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else { $ErrorMessage = $_.Exception.MessageId }
                                Write-PScriboMessage -IsWarning -Message "Domain Controller Pending Missing Patch Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }

                            if ( $Updates ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $OutObj = [System.Collections.ArrayList]::new()
                                    foreach ($Update in $Updates) {
                                        try {
                                            $inObj = [ordered] @{
                                                'KB Article' = "KB$($Update.KBArticleIDs)"
                                                'Name' = $Update.Title
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
                                        Name = "Missing Windows Updates - $($DC.ToString().ToUpper().Split(".")[0])"
                                        List = $false
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                    if ($HealthCheck.DomainController.Software) {
                                        Paragraph "Health Check:" -Bold -Underline
                                        BlankLine
                                        Paragraph {
                                            Text "Security Best Practices:" -Bold
                                            Text "It is critical to install security updates to protect your systems from malicious attacks. Regularly applying updates ensures that your systems are safeguarded against newly discovered vulnerabilities. Additionally, installing software updates provides access to new features and improvements, enhancing overall system performance and stability. Neglecting updates can leave your systems exposed to potential threats and exploitation. Therefore, it is in your best interest to maintain an up-to-date environment by promptly installing all recommended updates."
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
                    Section -Style Heading4 'Missing Windows Updates' {
                        Paragraph "Below is a summary of pending or missing Windows updates detected on Domain Controllers in the $($Domain.DNSRoot.ToString().ToUpper()) domain."
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
        Show-AbrDebugExecutionTime -End -TitleMessage "Domain Controller"
    }

}