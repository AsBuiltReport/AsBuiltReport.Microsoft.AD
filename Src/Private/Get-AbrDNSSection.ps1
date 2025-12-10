function Get-AbrDNSSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD DNS Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.8
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
        [ref]$DomainStatus
    )

    begin {
        Write-PScriboMessage -Message "Collecting DNS server information from $ForestInfo."
        Show-AbrDebugExecutionTime -Start -TitleMessage "DNS Section"
    }

    process {
        if ($InfoLevel.DNS -ge 1) {
            $DNSDomainObj = foreach ($Domain in [string[]]($OrderedDomains | Where-Object { $_ -notin $Options.Exclude.Domains })) {
                if ($Domain -and ($Domain -notin $DomainStatus.Value.Name)) {
                    if ($ValidDC = Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                        try {
                            if ($DomainInfo = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain }) {
                                $DCs = Invoke-CommandWithTimeout -Session $TempPssSession -ScriptBlock { Get-ADDomain -Identity $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } } | Sort-Object

                                Section -Style Heading2 "$($DomainInfo.DNSRoot.ToString().ToUpper())" {
                                    Paragraph "The following section provides a comprehensive summary of the DNS service configuration and settings for this domain."
                                    BlankLine
                                    if ($TempCIMSession) {
                                        Get-AbrADDNSInfrastructure -Domain $DomainInfo -DCs $DCs
                                    }
                                    foreach ($DC in $DCs) {
                                        if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                            Get-AbrADDNSZone -Domain $DomainInfo -DC $DC
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage -Message "$($DomainInfo.DNSRoot) disabled in Exclude.Domain variable"
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning -Message "$($_.Exception.Message) (Domain Name System Information)"
                        }
                    } else {
                        Write-PScriboMessage -IsWarning -Message "Unable to get an available DC in $($DomainInfo.DNSRoot) domain. Removing it from the report."
                    }
                }
            }
            if ($DNSDomainObj) {
                Section -Style Heading1 "DNS Configuration" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                        BlankLine
                    }
                    if (-not $Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a comprehensive overview of the DNS infrastructure configuration and settings within the Active Directory environment."
                        BlankLine
                    }
                    $DNSDomainObj
                }
            }
        }
    }
    end {
        Show-AbrDebugExecutionTime -End -TitleMessage "DNS Section"
    }
}
