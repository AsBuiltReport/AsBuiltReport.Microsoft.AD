function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.6.3
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
            $Domain
    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Controller information."
    }

    process {
        try {
            $OutObj = @()
            Write-PscriboMessage "Discovering Active Directory Domain Controller information from $Domain."
            $DCs = Invoke-Command -Session $TempPssSession {Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers}
            if ($DCs) {
                foreach ($DC in $DCs) {
                    Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                    try {
                        Write-PscriboMessage "Collecting AD Domain Controller Summary information of $DC."
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
                        Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Summary)"
                    }
                }

                $TableParams = @{
                    Name = "Domain Controller Summary - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 25, 25, 15, 10, 10, 15
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Sort-Object -Property 'DC Name' | Table @TableParams
            }
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Summary)"
        }

        if ($InfoLevel.Domain -ge 2) {
            try {
                Write-PscriboMessage "Collecting AD Domain Controller Hardware information for domain $Domain"
                Section -Style Heading6 'Hardware Inventory' {
                    Paragraph "The following section provides a summary of the Domain Controller Hardware for $($Domain.ToString().ToUpper())."
                    BlankLine
                    $OutObj = @()
                    Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                    if ($DCs) {
                        foreach ($DC in $DCs) {
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
                                        'Name' = $HW.CsDNSHostName
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
                                        'Number of Processors' = $HWCPU.Length
                                        'Number of CPU Cores' = $HWCPU[0].NumberOfCores
                                        'Number of Logical Cores' = $HWCPU[0].NumberOfLogicalProcessors
                                        'Physical Memory (GB)' = ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
                                    }
                                    $OutObj = [pscustomobject]$inobj

                                    $TableParams = @{
                                        Name = "Domain Controller Hardware - $($HW.CsDNSHostName.ToString().ToUpper())"
                                        List = $true
                                        ColumnWidths = 40, 60
                                    }
                                    if ($Report.ShowTableCaptions) {
                                        $TableParams['Caption'] = "- $($TableParams.Name)"
                                    }
                                    $OutObj | Table @TableParams
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Hardware Summary)"
                            }
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Domain Controller Summary)"
            }
        }
        try {
            Write-PscriboMessage "Collecting AD Domain Controller NTDS information."
            Section -Style Heading6 'NTDS Information' {
                Paragraph "The following section provides a summary of the Domain Controller NTDS file size on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                if ($DCs) {
                    foreach ($DC in $DCs) {
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
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (NTDS Summary)"
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
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (NTDS Summary)"
        }
        try {
            Write-PscriboMessage "Collecting AD Domain Controller Time Source information."
            Section -Style Heading6 'Time Source Information' {
                Paragraph "The following section provides a summary of the Domain Controller Time Source configuration on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                if ($DCs) {
                    Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                    foreach ($DC in $DCs) {
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
                                    Write-PscriboMessage -IsWarning $_.Exception.Message
                                }
                            }
                        }
                        catch {
                            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Time Source)"
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
        }
        catch {
            Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Time Source)"
        }
        if ($HealthCheck.DomainController.Software) {
            try {
                Write-PscriboMessage "Collecting additional software running on the Domain Controller."
                Section -Style Heading6 'HealthCheck - Installed Software on DC' {
                    Paragraph "The following section provides a summary of additional software running on $($Domain.ToString().ToUpper())."
                    BlankLine
                    Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                    if ($DCs) {
                        foreach ($DC in $DCs) {
                            try {
                                $OutObj = @()
                                Write-PscriboMessage "Collecting AD Domain Controller installed software information for $DC."
                                $DCPssSession = New-PSSession $DC -Credential $Credential -Authentication $Options.PSDefaultAuthentication
                                $Software = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {($_.Publisher -notlike "Microsoft*" -and $_.DisplayName -notlike "VMware*") -and ($Null -ne $_.Publisher -or $Null -ne $_.DisplayName)} | Select-Object -Property DisplayName,Publisher,InstallDate | Sort-Object -Property DisplayName}
                                Remove-PSSession -Session $DCPssSession
                                if ( $Software ) {
                                    Section -Style Heading6 "$($DC.ToString().ToUpper().Split(".")[0]) additional software" {
                                        Paragraph "The following section provides a summary of additional software running on $($DC.ToString().ToUpper().Split(".")[0])."
                                        BlankLine
                                        foreach ($APP in $Software) {
                                            try {
                                                $inObj = [ordered] @{
                                                    'Name' = $APP.DisplayName
                                                    'Publisher' = $APP.Publisher
                                                    'Install Date' = $APP.InstallDate
                                                }
                                                $OutObj = [pscustomobject]$inobj
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
                                    }
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "$($_.Exception.Message) (Installed Software)"
                            }
                        }
                    }
                }
            }
            catch {
                Write-PscriboMessage -IsWarning $($_.Exception.Message)
            }
        }
    }

    end {}

}