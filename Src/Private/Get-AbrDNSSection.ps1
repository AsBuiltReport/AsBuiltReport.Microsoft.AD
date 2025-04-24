function Get-AbrDNSSection {
    <#
    .SYNOPSIS
    Used by As Built Report to build Microsoft AD DNS Section.
    .DESCRIPTION

    .NOTES
        Version:        0.9.4
        Author:         Jonathan Colon
        Twitter:        @jcolonfzenpr
        Github:         rebelinux
    .EXAMPLE

    .LINK

    #>
    [CmdletBinding()]
    param (
    )

    begin {
        Write-PScriboMessage "Collecting DNS server information from $ForestInfo."
    }

    process {
        if ($InfoLevel.DNS -ge 1) {
            $DNSDomainObj = foreach ($Domain in [string[]]($OrderedDomains | Where-Object { $_ -notin $Options.Exclude.Domains })) {
                if ($Domain -notin $DomainStatus.Value.Name) {
                    if (Get-ValidDCfromDomain -Domain $Domain -DCStatus ([ref]$DCStatus)) {
                        try {
                            if (Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain -ErrorAction Stop }) {
                                Section -Style Heading2 "$($Domain.ToString().ToUpper())" {
                                    Paragraph "The following section provides a configuration summary of the DNS service."
                                    BlankLine
                                    if ($TempCIMSession) {
                                        Get-AbrADDNSInfrastructure -Domain $Domain
                                    }
                                    $DCs = Invoke-Command -Session $TempPssSession { Get-ADDomain $using:Domain | Select-Object -ExpandProperty ReplicaDirectoryServers | Where-Object { $_ -notin ($using:Options).Exclude.DCs } }
                                    foreach ($DC in $DCs) {
                                        if (Get-DCWinRMState -ComputerName $DC -DCStatus ([ref]$DCStatus)) {
                                            Get-AbrADDNSZone -Domain $Domain -DC $DC
                                        }
                                    }
                                }
                            } else {
                                Write-PScriboMessage "$($Domain) disabled in Exclude.Domain variable"
                            }
                        } catch {
                            Write-PScriboMessage -IsWarning "$($_.Exception.Message) (Domain Name System Information)"
                        }
                    } else {
                        Write-PScriboMessage -IsWarning "Unable to get an available DC in $Domain domain. Removing it from the report."
                    }
                }
            }
            if ($DNSDomainObj) {
                Section -Style Heading1 "DNS Configuration" {
                    if ($Options.ShowDefinitionInfo) {
                        Paragraph "The Domain Name System (DNS) is a hierarchical and decentralized naming system for computers, services, or other resources connected to the Internet or a private network. It associates various information with domain names assigned to each of the participating entities. Most prominently, it translates more readily memorized domain names to the numerical IP addresses needed for locating and identifying computer services and devices with the underlying network protocols."
                        BlankLine
                    }
                    if (-Not $Options.ShowDefinitionInfo) {
                        Paragraph "The following section provides a summary of the Active Directory DNS Infrastructure Information."
                        BlankLine
                    }
                    $DNSDomainObj
                }
            }
        }
    }
    end {}
}
