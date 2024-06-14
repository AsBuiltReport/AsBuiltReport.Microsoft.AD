function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.8.2
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [Parameter (
            Position = 0,
            Mandatory)]
        [string]
        $Domain,
        $DCs
    )

    begin {
        Write-PScriboMessage "Collecting AD Domain Controller information."
    }

    process {
        try {
            $OutObj = @()
            $inObj = [ordered] @{
                'Domain Controller' = ($DomainController | Measure-Object).Count
                'Global Catalog' = ($GC | Measure-Object).Count
            }
            $OutObj += [pscustomobject]$inobj

            $TableParams = @{
                Name = "Domain Controller Counts - $($Domain.ToString().ToUpper())"
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
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Count Chart)"
            }
            if ($OutObj) {
                if ($chartFileItem) {
                    Image -Text 'Domain Controller Object - Diagram' -Align 'Center' -Percent 100 -Base64 $chartFileItem
                }
                $OutObj | Table @TableParams
            }
        } catch {
            Write-PScriboMessage -IsWarning $($_.Exception.Message)
        }
        if ($InfoLevel.Domain -eq 1) {
            try {
                $OutObj = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        $DCInfo = Invoke-Command -Session $TempPssSession { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                        $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DCNetSettings' -ErrorAction Stop } catch {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else {$ErrorMessage = $_.Exception.MessageId}
                            Write-PScriboMessage -IsWarning "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DCNetSettings'
                        if ($DCPssSession ) {
                            $DCNetSettings = try { Invoke-Command -Session $DCPssSession { Get-NetIPAddress } } catch { Write-PScriboMessage -IsWarning "Unable to get $DC network interfaces information" }
                            Remove-PSSession -Session $DCPssSession
                        }
                        try {
                            $inObj = [ordered] @{
                                'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
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
                                'Global Catalog' = ConvertTo-TextYN $DCInfo.IsGlobalCatalog
                                'Read Only' = ConvertTo-TextYN $DCInfo.IsReadOnly
                                'IP Address' = Switch ([string]::IsNullOrEmpty($DCInfo.IPv4Address)) {
                                    $true { "--" }
                                    $false { $DCInfo.IPv4Address }
                                    default { "Unknown" }
                                }
                            }
                            $OutObj += [pscustomobject]$inobj
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Item)"
                        }
                    } else {
                        try {
                            Write-PScriboMessage "Unable to collect infromation from $DC."
                            $inObj = [ordered] @{
                                'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                'Domain Name' = "Unable to Connect"
                                'Site' = "--"
                                'Global Catalog' = "--"
                                'Read Only' = "--"
                                'IP Address' = "--"
                            }
                            $OutObj += [pscustomobject]$inobj
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Item)"
                        }
                    }
                }
                if ($HealthCheck.DomainController.BestPractice) {
                    if ($OutObj.Count -eq 1) {
                        $OutObj | Set-Style -Style Warning
                    }
                }

                $TableParams = @{
                    Name = "Domain Controllers - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 25, 25, 15, 10, 10, 15
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
                        Text "All domains should have at least two functioning domain controllers for redundancy. In the event of a failure on the domain's only domain controller, users will not be able to log in to the domain or access domain resources."
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Table)"
            }
        } else {
            try {
                $OutObj = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        $DCInfo = Invoke-Command -Session $TempPssSession { Get-ADDomainController -Identity $using:DC -Server $using:DC }
                        $DCComputerObject = try { Invoke-Command -Session $TempPssSession -ErrorAction Stop { Get-ADComputer ($using:DCInfo).ComputerObjectDN -Properties * -Server $using:DC } } catch { Out-Null }
                        $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DCNetSettings' -ErrorAction Stop } catch {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else {$ErrorMessage = $_.Exception.MessageId}
                            Write-PScriboMessage -IsWarning "DC Net Settings Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DCNetSettings'
                        if ($DCPssSession) {
                            $DCNetSettings = try { Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-NetIPAddress } } catch { Out-Null }
                            $DCNetSMBv1Setting = try { Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol } } catch { Out-Null }
                            Remove-PSSession -Session $DCPssSession
                        }
                        if ($InfoLevel.Domain -eq 1) {
                            try {
                                $inObj = [ordered] @{
                                    'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
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
                                    'Global Catalog' = ConvertTo-TextYN $DCInfo.IsGlobalCatalog
                                    'Read Only' = ConvertTo-TextYN $DCInfo.IsReadOnly
                                    'IP Address' = Switch ([string]::IsNullOrEmpty($DCInfo.IPv4Address)) {
                                        $true { "--" }
                                        $false { $DCInfo.IPv4Address }
                                        default { "Unknown" }
                                    }
                                }
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Item)"
                            }
                            if ($HealthCheck.DomainController.BestPractice) {
                                if ($OutObj.Count -eq 1) {
                                    $OutObj | Set-Style -Style Warning
                                }
                            }

                            $TableParams = @{
                                Name = "Domain Controllers - $($Domain.ToString().ToUpper())"
                                List = $false
                                ColumnWidths = 25, 25, 15, 10, 10, 15
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
                                    Text "All domains should have at least two functioning domain controllers for redundancy. In the event of a failure on the domain's only domain controller, users will not be able to log in to the domain or access domain resources."
                                }
                            }
                        } else {
                            try {
                                Section -Style Heading4 $DCInfo.Name {
                                    try {
                                        Section -ExcludeFromTOC -Style NOTOCHeading5 "General Information" {
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
                                                'Global Catalog' = ConvertTo-TextYN $DCInfo.IsGlobalCatalog
                                                'Read Only' = ConvertTo-TextYN $DCInfo.IsReadOnly
                                                'Operation Master Roles' = ConvertTo-EmptyToFiller ($DCInfo.OperationMasterRoles -join ', ')
                                                'Location' = ConvertTo-EmptyToFiller $DCComputerObject.Location
                                                'Computer Object SID' = $DCComputerObject.SID
                                                'Operating System' = $DCInfo.OperatingSystem
                                                'SMB1 Status' = $DCNetSMBv1Setting.State
                                                'Description' = ConvertTo-EmptyToFiller $DCComputerObject.Description
                                            }
                                            $OutObj = [pscustomobject]$inobj

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
                                                    Text "Disable SMB v1: SMB v1 is an outdated protocol that is vulnerable to several security issues. It is recommended to disable SMBv1 on all systems."
                                                }
                                            }
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (General Information Section)"
                                    }
                                    try {
                                        Section -ExcludeFromTOC -Style NOTOCHeading5 "Partitions" {
                                            $inObj = [ordered] @{
                                                'Default Partition' = $DCInfo.DefaultPartition
                                                'Partitions' = $DCInfo.Partitions
                                            }
                                            $OutObj = [pscustomobject]$inobj


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
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Partitions Section)"
                                    }
                                    try {
                                        if ($DCNetSettings) {
                                            Section -ExcludeFromTOC -Style NOTOCHeading5 "Networking Settings" {
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
                                                    "SSL Port" = $DCInfo.SslPort
                                                }
                                                $OutObj = [pscustomobject]$inobj

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
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Networking Settings Section)"
                                    }
                                    try {
                                        $DCHWInfo = @()
                                        try {
                                            $CimSession = try { New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerHardware' -ErrorAction Stop } catch { Write-PScriboMessage -IsWarning "Hardware Inventory Section: New-CimSession: Unable to connect to $($DC): $($_.Exception.MessageId)" }
                                            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerHardware' -ErrorAction Stop } catch {
                                                if (-Not $_.Exception.MessageId) {
                                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                                } else {$ErrorMessage = $_.Exception.MessageId}
                                                Write-PScriboMessage -IsWarning "Domain Controller Hardware Inventory Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                                            }
                                            # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerHardware'
                                            if ($DCPssSession) {
                                                $HW = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ComputerInfo }
                                                $HWCPU = Get-CimInstance -Class Win32_Processor -CimSession $CimSession
                                                Remove-PSSession -Session $DCPssSession
                                            }

                                            if ($CimSession) {
                                                $License = Get-CimInstance -Query 'Select * from SoftwareLicensingProduct' -CimSession $CimSession | Where-Object { $_.LicenseStatus -eq 1 }
                                                Remove-CimSession $CimSession
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
                                                $DCHWInfo += [pscustomobject]$inobj
                                            }

                                            if ($HealthCheck.DomainController.Diagnostic) {
                                                if ([int]([regex]::Matches($DCHWInfo.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                                                    $DCHWInfo | Set-Style -Style Warning -Property 'Physical Memory'
                                                }
                                            }
                                            if ($DCHWInfo) {
                                                Section -ExcludeFromTOC -Style NOTOCHeading5 'Hardware Inventory' {
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
                                                                Text "Microsoft recommend putting enough RAM 8GB+ to load the entire DIT into memory, plus accommodate the operating system and other installed applications, such as anti-virus, backup software, monitoring, and so on."
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } catch {
                                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Hardware Inventory Table)"
                                        }
                                    } catch {
                                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Hardware Section)"
                                    }
                                }
                            } catch {
                                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Section)"
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Section)"
            }
        }
        #---------------------------------------------------------------------------------------------#
        #                                 DNS IP Section                                              #
        #---------------------------------------------------------------------------------------------#
        try {
            $OutObj = @()
            foreach ($DC in $DCs) {
                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                    $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DNSIPConfiguration' -ErrorAction Stop } catch {
                        if (-Not $_.Exception.MessageId) {
                            $ErrorMessage = $_.FullyQualifiedErrorId
                        } else {$ErrorMessage = $_.Exception.MessageId}
                        Write-PScriboMessage -IsWarning "DNS IP Configuration Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                    }
                    # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DNSIPConfiguration'
                    try {
                        if ($DCPssSession) {
                            $DCIPAddress = Invoke-Command -Session $DCPssSession { [System.Net.Dns]::GetHostAddresses($using:DC).IPAddressToString }
                            $DNSSettings = Invoke-Command -Session $DCPssSession { Get-NetAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 }
                            $PrimaryDNSSoA = Invoke-Command -Session $DCPssSession { (Get-DnsServerResourceRecord -RRType Soa -ZoneName $using:Domain).RecordData.PrimaryServer }
                        }
                        $UnresolverDNS = @()
                        foreach ($DNSServer in $DNSSettings.ServerAddresses) {
                            if ($DCPssSession) {
                                $Unresolver = Invoke-Command -Session $DCPssSession { Resolve-DnsName -Server $using:DNSServer -Name $using:PrimaryDNSSoA -DnsOnly -ErrorAction SilentlyContinue }
                            }
                            if ([string]::IsNullOrEmpty($Unresolver)) {
                                $UnresolverDNS += $DNSServer
                            }
                        }
                        foreach ($DNSSetting in $DNSSettings) {
                            try {
                                $inObj = [ordered] @{
                                    'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                    'Interface' = $DNSSetting.InterfaceAlias
                                    'Prefered DNS' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[0]
                                    'Alternate DNS' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[1]
                                    'DNS 3' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[2]
                                    'DNS 4' = ConvertTo-EmptyToFiller $DNSSetting.ServerAddresses[3]
                                }
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning "$($DC.ToString().ToUpper().Split(".")[0]) DNS IP Configuration Section: $($_.Exception.Message)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "Domain Controller DNS IP Configuration Table Section: $($_.Exception.Message)"
                    }

                    if ($DCPssSession) {
                        Remove-PSSession -Session $DCPssSession
                    }
                }
            }

            if ($HealthCheck.DomainController.BestPractice) {
                $OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" -or $_.'Prefered DNS' -in $DCIPAddress } | Set-Style -Style Warning -Property 'Prefered DNS'
                $OutObj | Where-Object { $_.'Alternate DNS' -eq "--" } | Set-Style -Style Warning -Property 'Alternate DNS'
                $OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'Prefered DNS'
                $OutObj | Where-Object { $_.'Alternate DNS' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'Alternate DNS'
                $OutObj | Where-Object { $_.'DNS 3' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 3'
                $OutObj | Where-Object { $_.'DNS 4' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 4'
            }

            if ($OutObj) {
                Section -Style Heading4 "DNS IP Configuration" {
                    $TableParams = @{
                        Name = "DNS IP Configuration - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 20, 15, 15, 15, 15
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                    if ($HealthCheck.DomainController.BestPractice -and (($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" }) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $DCIPAddress }) -or ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--" }) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS -or $_.'Alternate DNS' -in $UnresolverDNS -or $_.'DNS 3' -in $UnresolverDNS -or $_.'DNS 4' -in $UnresolverDNS }))) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" }) {
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "DNS configuration on network adapter should include the loopback address, but not as the first entry."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -in $DCIPAddress }) {
                            BlankLine
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "DNS configuration on network adapter shouldn't include the Domain Controller own IP address as the first entry."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--" }) {
                            BlankLine
                            Paragraph {
                                Text "Best Practices:" -Bold
                                Text "For redundancy reasons, the DNS configuration on the network adapter should include an Alternate DNS address."
                            }
                        }
                        if ($OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS -or $_.'Alternate DNS' -in $UnresolverDNS -or $_.'DNS 3' -in $UnresolverDNS -or $_.'DNS 4' -in $UnresolverDNS }) {
                            BlankLine
                            Paragraph {
                                Text "Corrective Actions:" -Bold
                                Text "Network interfaces must be configured with DNS servers that can resolve names in the forest root domain. The following DNS server did not respond to the query for the forest root domain $($Domain.ToString().toUpper()): $(($UnresolverDNS -join ", "))"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "Domain Controller DNS IP Configuration Section: $($_.Exception.Message)"
        }

        try {
            $OutObj = @()
            foreach ($DC in $DCs) {
                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                    try {
                        $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'NTDS' -ErrorAction Stop } catch {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else {$ErrorMessage = $_.Exception.MessageId}
                            Write-PScriboMessage -IsWarning "NTDS Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'NTDS'
                        if ($DCPssSession) {
                            $NTDS = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'DSA Database File' }
                            $size = Invoke-Command -Session $DCPssSession -ScriptBlock { (Get-ItemProperty -Path $using:NTDS).Length }
                            $LogFiles = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'Database log files path' }
                            $SYSVOL = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters | Select-Object -ExpandProperty 'SysVol' }
                            Remove-PSSession -Session $DCPssSession
                        }
                        if ( $NTDS -and $size ) {
                            $inObj = [ordered] @{
                                'DC Name' = $DC.ToString().ToUpper().Split(".")[0]
                                'Database File' = $NTDS
                                'Database Size' = ConvertTo-FileSizeString $size
                                'Log Path' = $LogFiles
                                'SysVol Path' = $SYSVOL
                            }
                            $OutObj += [pscustomobject]$inobj
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (NTDS Item)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 'NTDS Information' {
                    $TableParams = @{
                        Name = "NTDS Database File Usage - $($Domain.ToString().ToUpper())"
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
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (NTDS Table)"
        }
        try {
            $OutObj = @()
            foreach ($DC in $DCs) {
                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                    try {
                        $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'TimeSource' -ErrorAction Stop } catch {
                            if (-Not $_.Exception.MessageId) {
                                $ErrorMessage = $_.FullyQualifiedErrorId
                            } else {$ErrorMessage = $_.Exception.MessageId}
                            Write-PScriboMessage -IsWarning "Time Source Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                        }
                        # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'TimeSource'
                        if ($DCPssSession) {
                            $NtpServer = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'NtpServer' }
                            $SourceType = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'Type' }
                            Remove-PSSession -Session $DCPssSession
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
                                $OutObj += [pscustomobject]$inobj
                            } catch {
                                Write-PScriboMessage -IsWarning  "$($_.Exception.Message) (Time Source Item)"
                            }
                        }
                    } catch {
                        Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Time Source Table)"
                    }
                }
            }

            if ($OutObj) {
                Section -Style Heading4 'Time Source Information' {
                    $TableParams = @{
                        Name = "Time Source Configuration - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 50, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }

                    $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Time Source)"
        }
        if ($HealthCheck.DomainController.Diagnostic) {
            try {
                $OutObj = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            $CimSession = try { New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication  -Name 'SRVRecordsStatus' -ErrorAction Stop } catch { Write-PScriboMessage -IsWarning "SRV Records Status Section: New-CimSession: Unable to connect to $($DC): $($_.Exception.MessageId)" }
                            $PDCEmulator = Invoke-Command -Session $TempPssSession { (Get-ADDomain $using:Domain -ErrorAction Stop).PDCEmulator }
                            if ($CimSession -and ($Domain -eq $ADSystem.RootDomain)) {
                                $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName _msdcs.$Domain -RRType Srv
                                $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0] }
                                if ($DC -in $PDCEmulator) {
                                    $PDC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.pdc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $PDC = 'NonPDC' }
                                if ($DC -in $ADSystem.GlobalCatalogs) {
                                    $GC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                } else { $GC = 'NonGC' }
                                $KDC = $SRVRR | Where-Object { $_.Hostname -eq "_kerberos._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                $DCRR = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                Remove-CimSession $CimSession
                            } else {
                                if ($CimSession) {
                                    $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType Srv
                                    $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType A | Where-Object { $_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0] }
                                    if ($DC -in $PDCEmulator) {
                                        $PDC = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.pdc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $PDC = 'NonPDC' }
                                    if ($DC -in $ADSystem.GlobalCatalogs) {
                                        $GC = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName "_msdcs.$($ADSystem.RootDomain)" -RRType Srv | Where-Object { $_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    } else { $GC = 'NonGC' }
                                    $KDC = $SRVRR | Where-Object { $_.Hostname -eq "_kerberos._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    $DCRR = $SRVRR | Where-Object { $_.Hostname -eq "_ldap._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)." }
                                    Remove-CimSession $CimSession
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
                                    $OutObj += [pscustomobject]$inobj
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
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (SRV Records Status Table)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 'SRV Records Status' {
                        $TableParams = @{
                            Name = "SRV Records Status - $($Domain.ToString().ToUpper())"
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
                                Text "The SRV record is a Domain Name System (DNS) resource record. It's used to identify computers hosting specific services. SRV resource records are used to locate domain controllers for Active Directory."
                            }
                        }
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (SRV Records Status)"
            }
        }
        try {
            if ($HealthCheck.DomainController.BestPractice) {
                $OutObj = foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllersFileShares' -ErrorAction Stop } catch {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else {$ErrorMessage = $_.Exception.MessageId}
                                Write-PScriboMessage -IsWarning "Domain Controllers File Shares Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllersFileShares'
                            if ($DCPssSession) {
                                $Shares = Invoke-Command -Session $DCPssSession -ErrorAction Stop { Get-SmbShare | Where-Object { $_.Description -ne 'Default share' -and $_.Description -notmatch 'Remote' -and $_.Name -ne 'NETLOGON' -and $_.Name -ne 'SYSVOL' } }
                            }
                            if ($Shares) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $FSObj = @()
                                    foreach ($Share in $Shares) {
                                        $inObj = [ordered] @{
                                            'Name' = $Share.Name
                                            'Path' = $Share.Path
                                            'Description' = ConvertTo-EmptyToFiller $Share.Description
                                        }
                                        $FSObj += [pscustomobject]$inobj
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
                            if ($DCPssSession) {
                                Remove-PSSession -Session $DCPssSession
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (File Shares Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading4 "File Shares" {
                        Paragraph "The following domain controllers have non-default file shares."
                        $OutObj
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Only netlogon, sysvol and the default administrative shares should exist on a Domain Controller. If possible, non default file shares should be moved to another server, preferably a dedicated file server."
                        }
                    }
                }
            }
        } catch {
            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (File Shares Table)"
        }
        if ($HealthCheck.DomainController.Software) {
            try {
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            $Software = @()
                            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerInstalledSoftware' -ErrorAction Stop } catch {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else {$ErrorMessage = $_.Exception.MessageId}
                                Write-PScriboMessage -IsWarning "Domain Controller Installed Software Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerInstalledSoftware'
                            if ($DCPssSession) {
                                $SoftwareX64 = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                                $SoftwareX86 = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName) } | Select-Object -Property DisplayName, Publisher, InstallDate | Sort-Object -Property DisplayName }
                                Remove-PSSession -Session $DCPssSession
                            }

                            If ($SoftwareX64) {
                                $Software += $SoftwareX64
                            }
                            If ($SoftwareX86) {
                                $Software += $SoftwareX86
                            }

                            if ( $Software ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $OutObj = @()
                                    foreach ($APP in $Software) {
                                        try {
                                            $inObj = [ordered] @{
                                                'Name' = $APP.DisplayName
                                                'Publisher' = ConvertTo-EmptyToFiller $APP.Publisher
                                                'Install Date' = ConvertTo-EmptyToFiller $APP.InstallDate
                                            }
                                            $OutObj += [pscustomobject]$inobj

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
                                            Text "Do not run other software or services on a Domain Controller."
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading4 'Installed Software' {
                        Paragraph "The following section provides a summary of additional software running on Domain Controllers from domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $DCObj
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Installed Software Section)"
            }
            try {
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            $Software = @()
                            $DCPssSession = try { New-PSSession -ComputerName $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerPendingMissingPatch' -ErrorAction Stop } catch {
                                if (-Not $_.Exception.MessageId) {
                                    $ErrorMessage = $_.FullyQualifiedErrorId
                                } else {$ErrorMessage = $_.Exception.MessageId}
                                Write-PScriboMessage -IsWarning "Domain Controller Pending Missing Patch Section: New-PSSession: Unable to connect to $($DC): $ErrorMessage"
                            }
                            # $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerPendingMissingPatch'
                            if ($DCPssSession ) {
                                $Updates = Invoke-Command -Session $DCPssSession -ScriptBlock { (New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title, KBArticleIDs }
                                Remove-PSSession -Session $DCPssSession
                            }

                            if ( $Updates ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading5 $($DC.ToString().ToUpper().Split(".")[0]) {
                                    $OutObj = @()
                                    foreach ($Update in $Updates) {
                                        try {
                                            $inObj = [ordered] @{
                                                'KB Article' = "KB$($Update.KBArticleIDs)"
                                                'Name' = $Update.Title
                                            }
                                            $OutObj += [pscustomobject]$inobj

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
                                            Text "It is critical to install security updates to protect your systems from malicious attacks. In the long run, it is also important to install software updates, not only to access new features, but also to be on the safe side in terms of security loop holes being discovered in outdated programs. And it is in your own best interest to install all other updates, which may potentially cause your system to become vulnerable to attack."
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading4 'Missing Windows Updates' {
                        Paragraph "The following section provides a summary of pending/missing windows updates on Domain Controllers from domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $DCObj
                    }
                }
            } catch {
                Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Section)"
            }
        }
    }

    end {}

}