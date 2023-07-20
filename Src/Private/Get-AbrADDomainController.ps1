function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.14
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
        Write-PscriboMessage "Collecting AD Domain Controller information."
    }

    process {
        try {
            $OutObj = @()
            Write-PscriboMessage "Discovering Active Directory Domain Controller information from $Domain."
            foreach ($DC in $DCs) {
                if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                    try {
                        Write-PscriboMessage "Collecting AD Domain Controllers information of $DC."
                        $DCInfo = Invoke-Command -Session $TempPssSession {Get-ADDomainController -Identity $using:DC -Server $using:DC}
                        $inObj = [ordered] @{
                            'DC Name' = ($DCInfo.Name).ToString().ToUpper()
                            'Domain Name' = $DCInfo.Domain
                            'Site' = $DCInfo.Site
                            'Global Catalog' = ConvertTo-TextYN $DCInfo.IsGlobalCatalog
                            'Read Only' = ConvertTo-TextYN $DCInfo.IsReadOnly
                            'IP Address' = $DCInfo.IPv4Address
                        }
                        $OutObj += [pscustomobject]$inobj
                    }
                    catch {
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Item)"
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
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Table)"
        }

        try {
            Write-PscriboMessage "Collecting AD Domain Controller Hardware information for domain $Domain"
            Section -Style Heading5 'Hardware Inventory' {
                Paragraph "The following section provides detailed Domain Controller hardware information for domain $($Domain.ToString().ToUpper())."
                BlankLine
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                $DCHWInfo = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller Hardware information for $DC."
                            $CimSession = New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerHardware'
                            $HW = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ComputerInfo }
                            $License =  Get-CimInstance -Query 'Select * from SoftwareLicensingProduct' -CimSession $CimSession | Where-Object { $_.LicenseStatus -eq 1 }
                            $HWCPU = Get-CimInstance -Class Win32_Processor -CimSession $CimSession
                            $HWBIOS = Get-CimInstance -Class Win32_Bios -CimSession $CimSession
                            Remove-PSSession -Session $DCPssSession
                            Remove-CimSession $CimSession
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
                                    'Physical Memory' = &{
                                        try {
                                            ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
                                        } catch {'0.00 GB'}
                                    }
                                }
                                $DCHWInfo += [pscustomobject]$inobj
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Hardware Inventory Item)"
                        }
                    }
                }

                if ($InfoLevel.Domain -ge 2) {
                    foreach ($DCHW in $DCHWInfo) {
                        Section -ExcludeFromTOC -Style NOTOCHeading6 $($DCHW.Name.ToString().ToUpper()) {
                            if ($HealthCheck.DomainController.Diagnostic) {
                                if ([int]([regex]::Matches($DCHW.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                                    $DCHW | Set-Style -Style Warning -Property 'Physical Memory'
                                }
                            }
                            $TableParams = @{
                                Name = "Hardware Inventory - $($DCHW.Name.ToString().ToUpper())"
                                List = $true
                                ColumnWidths = 40, 60
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $DCHW | Table @TableParams
                            if ($HealthCheck.DomainController.Diagnostic) {
                                if ([int]([regex]::Matches($DCHW.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
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
                } else {
                    if ($HealthCheck.DomainController.Diagnostic) {
                        $DCHWInfo | Where-Object {[int]([regex]::Matches($_.'Physical Memory', "\d+(\.*\d+)").value) -lt 8} | Set-Style -Style Warning -Property 'Physical Memory'
                    }
                    $TableParams = @{
                        Name = "Hardware Inventory - $($Domain.ToString().ToUpper())"
                        List = $false
                        Columns = 'Name', 'Number of Processors', 'Number of CPU Cores', 'Physical Memory'
                        ColumnWidths = 25, 25, 25, 25
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $DCHWInfo | Table @TableParams
                    if ($HealthCheck.DomainController.Diagnostic) {
                        if ($DCHWInfo | Where-Object {[int]([regex]::Matches($_.'Physical Memory', "\d+(\.*\d+)").value) -lt 8}) {
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
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Hardware Table)"
        }
        #---------------------------------------------------------------------------------------------#
        #                                 DNS IP Section                                              #
        #---------------------------------------------------------------------------------------------#
        try {
            Section -Style Heading5 "DNS IP Configuration" {
                $OutObj = @()
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        Write-PscriboMessage "Collecting DNS IP Configuration information from $($DC)."
                        $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DNSIPConfiguration'
                        try {
                            $DCIPAddress = Invoke-Command -Session $DCPssSession {[System.Net.Dns]::GetHostAddresses($using:DC).IPAddressToString}
                            $DNSSettings = Invoke-Command -Session $DCPssSession { Get-NetAdapter | Get-DnsClientServerAddress -AddressFamily IPv4 }
                            $PrimaryDNSSoA = Invoke-Command -Session $DCPssSession { (Get-DnsServerResourceRecord -RRType Soa -ZoneName $using:Domain).RecordData.PrimaryServer }
                            $UnresolverDNS = @()
                            foreach ($DNSServer in $DNSSettings.ServerAddresses) {
                                $Unresolver = Invoke-Command -Session $DCPssSession { Resolve-DnsName -Server $using:DNSServer -Name $using:PrimaryDNSSoA -DnsOnly -ErrorAction SilentlyContinue }
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
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning "$($DC.ToString().ToUpper().Split(".")[0]) DNS IP Configuration Section: $($_.Exception.Message)"
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "Domain Controller DNS IP Configuration Table Section: $($_.Exception.Message)"
                        }

                        if ($DCPssSession) {
                            Remove-PSSession -Session $DCPssSession
                        }
                    }
                }

                if ($HealthCheck.DomainController.BestPractice) {
                    $OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1" -or $_.'Prefered DNS' -in $DCIPAddress } | Set-Style -Style Warning -Property 'Prefered DNS'
                    $OutObj | Where-Object { $_.'Alternate DNS' -eq "--" } | Set-Style -Style Warning -Property 'Alternate DNS'
                    $OutObj | Where-Object { $_.'Prefered DNS'-in $UnresolverDNS } | Set-Style -Style Critical -Property 'Prefered DNS'
                    $OutObj | Where-Object { $_.'Alternate DNS'-in $UnresolverDNS } | Set-Style -Style Critical -Property 'Alternate DNS'
                    $OutObj | Where-Object { $_.'DNS 3'-in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 3'
                    $OutObj | Where-Object { $_.'DNS 4' -in $UnresolverDNS } | Set-Style -Style Critical -Property 'DNS 4'
                }

                $TableParams = @{
                    Name = "DNS IP Configuration - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 20, 20, 15, 15, 15, 15
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
                if ($HealthCheck.DomainController.BestPractice -and (($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1"}) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $DCIPAddress }) -or ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--"}) -or ($OutObj | Where-Object { $_.'Prefered DNS' -in $UnresolverDNS -or $_.'Alternate DNS' -in $UnresolverDNS -or $_.'DNS 3' -in $UnresolverDNS -or $_.'DNS 4' -in $UnresolverDNS }))) {
                    Paragraph "Health Check:" -Bold -Underline
                    BlankLine
                    if ($OutObj | Where-Object { $_.'Prefered DNS' -eq "127.0.0.1"}) {
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
                    if ($OutObj | Where-Object { $_.'Alternate DNS' -eq "--"}) {
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
        catch {
            Write-PscriboMessage -IsWarning "Domain Controller DNS IP Configuration Section: $($_.Exception.Message)"
        }

        try {
            if ($HealthCheck.DomainController.BestPractice) {
                Write-PscriboMessage "Discovering Active Directory File Shares information from $Domain."
                $OutObj = foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controllers file shares information of $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllersFileShares'
                            $Shares = Invoke-Command -Session $DCPssSession { Get-SmbShare | Where-Object { $_.Description -ne 'Default share' -and $_.Description -notmatch 'Remote' -and $_.Name -ne 'NETLOGON' -and $_.Name -ne 'SYSVOL' } }
                            if ($Shares) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $($DC.ToString().ToUpper().Split(".")[0]) {
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
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (File Shares Item)"
                        }
                    }
                }

                if ($OutObj) {
                    Section -Style Heading5 "File Shares" {
                        Paragraph "The following domain controllers have non-default file shares."
                        $OutObj
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "Only netlogon, sysvol and the default administrative shares should exist on a Domain Controller. If possible, non default file shares should be moved to another server, preferably a dedicated file server. "
                        }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (File Shares Table)"
        }

        try {
            Write-PscriboMessage "Collecting AD Domain Controller NTDS information."
            Section -Style Heading5 'NTDS Information' {
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller NTDS information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'NTDS'
                            $NTDS = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'DSA Database File'}
                            $size = Invoke-Command -Session $DCPssSession -ScriptBlock {(Get-ItemProperty -Path $using:NTDS).Length}
                            $LogFiles = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\NTDS\Parameters | Select-Object -ExpandProperty 'Database log files path'}
                            $SYSVOL = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters | Select-Object -ExpandProperty 'SysVol'}
                            Remove-PSSession -Session $DCPssSession
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
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (NTDS Item)"
                        }
                    }
                }

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
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (NTDS Table)"
        }
        try {
            Write-PscriboMessage "Collecting AD Domain Controller Time Source information."
            Section -Style Heading5 'Time Source Information' {
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller Time Source information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'TimeSource'
                            $NtpServer = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'NtpServer'}
                            $SourceType = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'Type'}
                            Remove-PSSession -Session $DCPssSession
                            if ( $NtpServer -and $SourceType ) {
                                try {
                                    $inObj = [ordered] @{
                                        'Name' = $DC.ToString().ToUpper().Split(".")[0]
                                        'Time Server' = Switch ($NtpServer) {
                                            'time.windows.com,0x8' {"Domain Hierarchy"}
                                            'time.windows.com' {"Domain Hierarchy"}
                                            '0x8' {"Domain Hierarchy"}
                                            default {$NtpServer}
                                        }
                                        'Type' = Switch ($SourceType) {
                                            'NTP' {"MANUAL (NTP)"}
                                            'NT5DS' {"DOMHIER"}
                                            default {$SourceType}
                                        }
                                    }
                                    $OutObj += [pscustomobject]$inobj
                                }
                                catch {
                                    Write-PscriboMessage -IsWarning  "$($_.Exception.Message) (Time Source Item)"
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Time Source Table)"
                        }
                    }
                }

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
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Time Source)"
        }
        if ($HealthCheck.DomainController.Diagnostic) {
            try {
                Write-PscriboMessage "Collecting AD Domain Controller SRV Records Status."
                Section -Style Heading5 'SRV Records Status' {
                    $OutObj = @()
                    Write-PscriboMessage "Discovering Active Directory Domain Controller SRV Records Status in $Domain."
                    foreach ($DC in $DCs) {
                        if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                            try {
                                Write-PscriboMessage "Collecting AD Domain Controller SRV Records Status for $DC."
                                $CimSession = New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                                $PDCEmulator = Invoke-Command -Session $TempPssSession {(Get-ADDomain $using:Domain -ErrorAction Stop).PDCEmulator}
                                if ($Domain -eq $ADSystem.RootDomain) {
                                    $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName _msdcs.$Domain -RRType Srv
                                    $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType A | Where-Object {$_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0]}
                                    if ($DC -in $PDCEmulator) {
                                        $PDC = $SRVRR | Where-Object {$_.Hostname -eq "_ldap._tcp.pdc" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    } else {$PDC = 'NonPDC'}
                                    if ($DC -in $ADSystem.GlobalCatalogs) {
                                        $GC = $SRVRR | Where-Object {$_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    } else {$GC = 'NonGC'}
                                    $KDC = $SRVRR | Where-Object {$_.Hostname -eq "_kerberos._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    $DCRR = $SRVRR | Where-Object {$_.Hostname -eq "_ldap._tcp.dc" -and $_.RecordData.DomainName -eq "$($DC)."}
                                } else {
                                    $SRVRR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType Srv
                                    $DCARR = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName $Domain -RRType A | Where-Object {$_.Hostname -eq $DC.ToString().ToUpper().Split(".")[0]}
                                    if ($DC -in $PDCEmulator) {
                                        $PDC = $SRVRR | Where-Object {$_.Hostname -eq "_ldap._tcp.pdc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    } else {$PDC = 'NonPDC'}
                                    if ($DC -in $ADSystem.GlobalCatalogs) {
                                        $GC = Get-DnsServerResourceRecord -CimSession $CimSession -ZoneName "_msdcs.$($ADSystem.RootDomain)" -RRType Srv | Where-Object {$_.Hostname -eq "_ldap._tcp.gc" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    } else {$GC = 'NonGC'}
                                    $KDC = $SRVRR | Where-Object {$_.Hostname -eq "_kerberos._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)."}
                                    $DCRR = $SRVRR | Where-Object {$_.Hostname -eq "_ldap._tcp.dc._msdcs" -and $_.RecordData.DomainName -eq "$($DC)."}
                                }
                                Remove-CimSession $CimSession
                                if ( $SRVRR ) {
                                    try {
                                        $inObj = [ordered] @{
                                            'Name' = $DC.ToString().ToUpper().Split(".")[0]
                                            'A Record' = Switch ([string]::IsNullOrEmpty($DCARR)) {
                                                $True {'Fail'}
                                                default {'OK'}
                                            }
                                            'KDC SRV' = Switch ([string]::IsNullOrEmpty($KDC)) {
                                                $True {'Fail'}
                                                default {'OK'}
                                            }
                                            'PDC SRV' = Switch ([string]::IsNullOrEmpty($PDC)) {
                                                $True {'Fail'}
                                                $False {
                                                    Switch ($PDC) {
                                                        'NonPDC' {'Non PDC'}
                                                        default {'OK'}
                                                    }
                                                }
                                            }
                                            'GC SRV' = Switch ([string]::IsNullOrEmpty($GC)) {
                                                $True {'Fail'}
                                                $False {
                                                    Switch ($GC) {
                                                        'NonGC' {'Non GC'}
                                                        default {'OK'}
                                                    }
                                                }
                                            }
                                            'DC SRV' = Switch ([string]::IsNullOrEmpty($DCRR)) {
                                                $True {'Fail'}
                                                default {'OK'}
                                            }
                                        }
                                        $OutObj += [pscustomobject]$inobj
                                    }
                                    catch {
                                        Write-PscriboMessage -IsWarning  "$($_.Exception.Message) (SRV Records Status Item)"
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
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (SRV Records Status Table)"
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "SRV Records Status - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 20, 16, 16, 16, 16, 16
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                    if ( $OutObj | Where-Object { $_.'KDC SRV' -eq 'Fail' -or  $_.'PDC SRV' -eq 'Fail' -or  $_.'GC SRV' -eq 'Fail' -or  $_.'DC SRV' -eq 'Fail' }) {
                        Paragraph "Health Check:" -Bold -Underline
                        BlankLine
                        Paragraph {
                            Text "Best Practice:" -Bold
                            Text "The SRV record is a Domain Name System (DNS) resource record. It's used to identify computers hosting specific services. SRV resource records are used to locate domain controllers for Active Directory."
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (SRV Records Status)"
            }
        }
        if ($HealthCheck.DomainController.Software) {
            try {
                Write-PscriboMessage "Collecting additional software running on the Domain Controller."
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        try {
                            $Software = @()
                            Write-PscriboMessage "Collecting AD Domain Controller installed software information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerInstalledSoftware'
                            $SoftwareX64 = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName)} | Select-Object -Property DisplayName,Publisher,InstallDate | Sort-Object -Property DisplayName}
                            $SoftwareX86 = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*" -and $_.DisplayName -notlike "Microsoft*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName)} | Select-Object -Property DisplayName,Publisher,InstallDate | Sort-Object -Property DisplayName}
                            Remove-PSSession -Session $DCPssSession

                            If ($SoftwareX64) {
                                $Software += $SoftwareX64
                            }
                            If ($SoftwareX86) {
                                $Software += $SoftwareX86
                            }

                            if ( $Software ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $($DC.ToString().ToUpper().Split(".")[0]) {
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
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
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
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading5 'Installed Software' {
                        Paragraph "The following section provides a summary of additional software running on Domain Controllers from domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $DCObj
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Section)"
            }
            try {
                $DCObj = @()
                $DCObj += foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 2) {
                        Write-PscriboMessage "Collecting pending/missing patch information from Domain Controller $($DC)."
                        try {
                            $Software = @()
                            Write-PscriboMessage "Collecting AD Domain Controller pending/missing patch information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication -Name 'DomainControllerPendingMissingPatch'
                            $Updates = Invoke-Command -Session $DCPssSession -ScriptBlock {(New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | Select-Object Title,KBArticleIDs}
                            Remove-PSSession -Session $DCPssSession

                            if ( $Updates ) {
                                Section -ExcludeFromTOC -Style NOTOCHeading6 $($DC.ToString().ToUpper().Split(".")[0]) {
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
                                        }
                                        catch {
                                            Write-PscriboMessage -IsWarning $_.Exception.Message
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
                                        Paragraph  {
                                            Text "Security Best Practices:" -Bold
                                            Text "It is critical to install security updates to protect your systems from malicious attacks. In the long run, it is also important to install software updates, not only to access new features, but also to be on the safe side in terms of security loop holes being discovered in outdated programs. And it is in your own best interest to install all other updates, which may potentially cause your system to become vulnerable to attack."
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Installed Software Table)"
                        }
                    }
                }
                if ($DCObj) {
                    Section -Style Heading5 'Missing Windows Updates' {
                        Paragraph "The following section provides a summary of pending/missing windows updates on Domain Controllers from domain $($Domain.ToString().ToUpper())."
                        BlankLine
                        $DCObj
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Section)"
            }
        }
    }

    end {}

}