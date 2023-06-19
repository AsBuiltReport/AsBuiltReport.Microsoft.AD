function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.7.11
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
                if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
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

            $TableParams = @{
                Name = "Domain Controllers - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 25, 25, 15, 10, 10, 15
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
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
                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller Hardware information for $DC."
                            $CimSession = New-CimSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
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
                                    'Windows Current Version' = $HW.WindowsCurrentVersion
                                    'Windows Build Number' = $HW.OsVersion
                                    'Windows Install Type' = $HW.WindowsInstallationType
                                    'AD Domain' = $HW.CsDomain
                                    'Windows Installation Date' = $HW.OsInstallDate
                                    'Time Zone' = $HW.TimeZone
                                    'License Type' = $License.ProductKeyChannel
                                    'Partial Product Key' = $License.PartialProductKey
                                    'Manufacturer' = $HW.CsManufacturer
                                    'Model' = $HW.CsModel
                                    'Serial Number' = $HostBIOS.SerialNumber
                                    'Bios Type' = $HW.BiosFirmwareType
                                    'BIOS Version' = $HostBIOS.Version
                                    'Processor Manufacturer' = $HWCPU[0].Manufacturer
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
                                ColumnWidths = 50, 50
                            }
                            if ($Report.ShowTableCaptions) {
                                $TableParams['Caption'] = "- $($TableParams.Name)"
                            }
                            $DCHW | Table @TableParams
                            if ($HealthCheck.DomainController.Diagnostic) {
                                if ([int]([regex]::Matches($DCHW.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                                    Paragraph "Health Check:" -Italic -Bold -Underline
                                    BlankLine
                                    Paragraph "Best Practice: Microsoft recommend putting enough RAM 8GB+ to load the entire DIT into memory, plus accommodate the operating system and other installed applications, such as anti-virus, backup software, monitoring, and so on." -Italic -Bold
                                 }
                            }
                        }
                    }
                } else {
                    if ($HealthCheck.DomainController.Diagnostic) {
                        if ([int]([regex]::Matches($DCHWInfo.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                            $DCHWInfo | Set-Style -Style Warning -Property 'Physical Memory'
                        }
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
                        if ([int]([regex]::Matches($DCHWInfo.'Physical Memory', "\d+(\.*\d+)").value) -lt 8) {
                            Paragraph "Health Check:" -Italic -Bold -Underline
                            BlankLine
                            Paragraph "Best Practice: Microsoft recommend putting enough RAM 8GB+ to load the entire DIT into memory, plus accommodate the operating system and other installed applications, such as anti-virus, backup software, monitoring, and so on." -Italic -Bold
                         }
                    }
                }
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Hardware Table)"
        }

        try {
            Write-PscriboMessage "Collecting AD Domain Controller NTDS information."
            Section -Style Heading5 'NTDS Information' {
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                foreach ($DC in $DCs) {
                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller NTDS information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
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
                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller Time Source information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
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
                        if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
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
                        Paragraph "Health Check:" -Italic -Bold -Underline
                        BlankLine
                        Paragraph "Best Practice: The SRV record is a Domain Name System (DNS) resource record. It's used to identify computers hosting specific services. SRV resource records are used to locate domain controllers for Active Directory." -Italic -Bold
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
                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                        try {
                            $Software = @()
                            Write-PscriboMessage "Collecting AD Domain Controller installed software information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
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
                                        Paragraph "Health Check:" -Italic -Bold -Underline
                                        BlankLine
                                        Paragraph "Best Practices: Do not run other software or services on a Domain Controller." -Italic -Bold
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
                    if (Test-Connection -ComputerName $DC -Quiet -Count 1) {
                        Write-PscriboMessage "Collecting pending/missing patch information from Domain Controller $($DC)."
                        try {
                            $Software = @()
                            Write-PscriboMessage "Collecting AD Domain Controller installed software information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
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
                                        ColumnWidths = 50, 50
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Sort-Object -Property 'Name' | Table @TableParams
                                    if ($HealthCheck.DomainController.Software) {
                                        Paragraph "Health Check:" -Italic -Bold -Underline
                                        BlankLine
                                        Paragraph "Security Best Practices: It is critical to install security updates to protect your systems from malicious attacks. In the long run, it is also important to install software updates, not only to access new features, but also to be on the safe side in terms of security loop holes being discovered in outdated programs. And it is in your own best interest to install all other updates, which may potentially cause your system to become vulnerable to attack." -Italic -Bold
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