function Get-AbrADDomainController {
    <#
    .SYNOPSIS
    Used by As Built Report to retrieve Microsoft AD Domain Controller information.
    .DESCRIPTION

    .NOTES
        Version:        0.3.0
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
            $Session,
            [PSCredential]
            $Cred
    )

    begin {
        Write-PscriboMessage "Collecting AD Domain Controller information."
    }

    process {
        $OutObj = @()
        if ($Domain) {
            foreach ($Item in $Domain) {
                Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                foreach ($DC in $DCs) {
                    Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                    try {
                        Write-PscriboMessage "Collecting AD Domain Controller Summary information of $DC."
                        $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                        $DCInfo = Invoke-Command -Session $DCPssSession {Get-ADDomainController -Identity $using:DC}
                        Remove-PSSession -Session $DCPssSession
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
                        Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                        Write-PscriboMessage -IsDebug $_.Exception.Message
                    }
                }
            }

            $TableParams = @{
                Name = "AD Domain Controller Summary Information - $($Domain.ToString().ToUpper())"
                List = $false
                ColumnWidths = 25, 25, 15, 10, 10, 15
            }
            if ($Report.ShowTableCaptions) {
                $TableParams['Caption'] = "- $($TableParams.Name)"
            }
            $OutObj | Table @TableParams
        }
        if ($InfoLevel.Domain -ge 2) {
            Write-PscriboMessage "Collecting AD Domain Controller Hardware information for domain $Domain"
            Section -Style Heading6 'Domain Controller Hardware Summary' {
                Paragraph "The following section provides a summary of the Domain Controller Hardware for $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                        $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                        foreach ($DC in $DCs) {
                            try {
                                Write-PscriboMessage "Collecting AD Domain Controller Hardware information for $DC."
                                $CimSession = New-CimSession $DC -Credential $Cred -Authentication Default
                                $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
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
                                    $OutObj += [pscustomobject]$inobj
                                }
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "AD Domain Controller Hardware Information - $($Domain.ToString().ToUpper())"
                        List = $true
                        ColumnWidths = 40, 60
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
        Write-PscriboMessage "Collecting AD Domain Controller NTDS information."
        Section -Style Heading6 'Domain Controller NTDS Summary' {
            Paragraph "The following section provides a summary of the Domain Controller NTDS file size on $($Domain.ToString().ToUpper())."
            BlankLine
            $OutObj = @()
            if ($Domain) {
                foreach ($Item in $Domain) {
                    Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                    $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                    Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                    foreach ($DC in $DCs) {
                        try {
                            Write-PscriboMessage "Collecting AD Domain Controller NTDS information for $DC."
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
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
                            Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                            Write-PscriboMessage -IsDebug $_.Exception.Message
                        }
                    }
                }

                $TableParams = @{
                    Name = "Domain Controller NTDS Database File Usage Information - $($Domain.ToString().ToUpper())"
                    List = $false
                    ColumnWidths = 20, 22, 14, 22, 22
                }
                if ($Report.ShowTableCaptions) {
                    $TableParams['Caption'] = "- $($TableParams.Name)"
                }
                $OutObj | Table @TableParams
            }
            Write-PscriboMessage "Collecting AD Domain Controller Time Source information."
            Section -Style Heading6 'Domain Controller Time Source Summary' {
                Paragraph "The following section provides a summary of the Domain Controller Time Source configuration on $($Domain.ToString().ToUpper())."
                BlankLine
                $OutObj = @()
                if ($Domain) {
                    foreach ($Item in $Domain) {
                        Write-PscriboMessage "Discovering Active Directory Domain Controller information in $Domain."
                        $DCs =  Invoke-Command -Session $Session {Get-ADDomain -Identity $using:Item | Select-Object -ExpandProperty ReplicaDirectoryServers}
                        Write-PscriboMessage "Discovered '$(($DCs | Measure-Object).Count)' Active Directory Domain Controller in domain $Domain."
                        foreach ($DC in $DCs) {
                            try {
                                Write-PscriboMessage "Collecting AD Domain Controller Time Source information for $DC."
                                $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                                $NtpServer = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'NtpServer'}
                                $SourceType = Invoke-Command -Session $DCPssSession -ScriptBlock {Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Services\W32Time\Parameters | Select-Object -ExpandProperty 'Type'}
                                Remove-PSSession -Session $DCPssSession
                                if ( $NtpServer -and $SourceType ) {
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
                            }
                            catch {
                                Write-PscriboMessage -IsWarning "Error: Connecting to remote server $DC failed: WinRM cannot complete the operation."
                                Write-PscriboMessage -IsDebug $_.Exception.Message
                            }
                        }
                    }

                    $TableParams = @{
                        Name = "Domain Controller Time Source Configuration - $($Domain.ToString().ToUpper())"
                        List = $false
                        ColumnWidths = 30, 50, 20
                    }
                    if ($Report.ShowTableCaptions) {
                        $TableParams['Caption'] = "- $($TableParams.Name)"
                    }
                    $OutObj | Table @TableParams
                }
            }
        }
    }

    end {}

}