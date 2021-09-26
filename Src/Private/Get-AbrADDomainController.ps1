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
                            $DCPssSession = New-PSSession $DC -Credential $Cred -Authentication Default
                            $HW = Invoke-Command -Session $DCPssSession -ScriptBlock { Get-ComputerInfo }
                            Remove-PSSession -Session $DCPssSession
                            if ($HW) {
                                $inObj = [ordered] @{
                                    'Name' = $HW.CsDNSHostName
                                    'WindowsProductName' = $HW.WindowsProductName
                                    'Manufacturer' = $HW.CsManufacturer
                                    'CsModel' = $HW.CsModel
                                    'Bios Type' = $HW.BiosFirmwareType
                                    'CPU Socket' = $HW.CsNumberOfProcessors
                                    'CPU Cores' = $HW.CsNumberOfLogicalProcessors
                                    'Total RAM' = ConvertTo-FileSizeString $HW.CsTotalPhysicalMemory
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
                            Remove-PSSession -Session $DCPssSession
                            if ( $NTDS -and $size ) {
                                $inObj = [ordered] @{
                                    'Name' = $DC
                                    'DSA Database File' = $NTDS
                                    'Size' = ConvertTo-FileSizeString $size
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
                    ColumnWidths = 40, 40, 20
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
                                        'Name' = $DC
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
                        ColumnWidths = 40, 40, 20
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